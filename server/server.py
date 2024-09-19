import asyncio
import websockets
import logging
import json
import os
import base64
import hashlib
import traceback
import yaml
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from threading import Thread
from urllib.parse import urlparse, parse_qs
from shared.encryption import (
    load_or_generate_private_key,
    load_public_key,
    serialize_public_key,
    sign_message,
    verify_signature,
)
from auth import UserManager

logging.basicConfig(level=logging.INFO)

# Initialize UserManager
user_manager = UserManager("user_data.json")

# Global online users and client counters
online_users = {}  # Stores {fingerprint: websocket}
client_counters = {}  # Stores {fingerprint: last_counter}
server_counter = 0  # Server's message counter

# File storage
uploaded_files = {}  # Stores {file_id: file_path}

# File upload directory
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# Load neighbor server addresses from configuration file
def load_neighbors(config_file):
    """
    Load neighbor server addresses from configuration file.
    """
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
            return config.get("neighbors", [])
    else:
        return []


neighbor_addresses = load_neighbors("config.yaml")
neighbor_connections = {}  # Stores {address: websocket}

# Server's own fingerprint
server_private_key = load_or_generate_private_key("server_private_key.pem")
server_public_key_pem = serialize_public_key(server_private_key.public_key())
server_fingerprint = hashlib.sha256(server_public_key_pem.encode("utf-8")).hexdigest()


async def handle_client(websocket, path):
    """
    Handles communication with a connected client.
    """
    global server_counter
    try:
        logging.info(f"New client connected from {websocket.remote_address}")
        # Receive 'hello' message
        message_str = await websocket.recv()
        message = json.loads(message_str)
        client_public_key = await handle_hello_message(websocket, message)
        # Start receiving messages from the client
        await receive_client_messages(websocket, client_public_key)
    except Exception as e:
        logging.error(f"Error handling client: {e}")
        traceback.print_exc()
    finally:
        # Remove client from online users upon disconnection
        fingerprint = getattr(websocket, "fingerprint", None)
        if fingerprint in online_users:
            del online_users[fingerprint]
            del client_counters[fingerprint]
            logging.info(f"User {fingerprint} disconnected.")
            # Send updated client list to all connected clients
            for client_ws in online_users.values():
                try:
                    await send_client_list(client_ws)
                except Exception as e:
                    logging.error(f"Error sending client list to client: {e}")
            # Send client_update to neighbors
            await broadcast_client_update()


async def handle_hello_message(websocket, message):
    """
    Handle the 'hello' message from the client.
    """
    global server_counter
    data = message.get("data")
    counter = message.get("counter")
    signature_b64 = message.get("signature")
    msg_type = data.get("type")

    if msg_type != "hello":
        logging.warning("Expected 'hello' message type.")
        await websocket.close()
        return

    public_key_pem = data.get("public_key")
    client_public_key = load_public_key(public_key_pem.encode("utf-8"))
    fingerprint = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()

    username = data.get("username")
    if not username:
        logging.warning("Username not provided.")
        await websocket.close()
        return

    # Verify signature
    message_json = json.dumps(data)
    if not verify_signature(client_public_key, message_json, signature_b64, counter):
        logging.warning("Signature verification failed for hello message.")
        await websocket.close()
        return

    # Register user
    user_manager.register_user(public_key_pem, username)

    # Store client's websocket and counters
    online_users[fingerprint] = websocket
    client_counters[fingerprint] = counter
    websocket.fingerprint = fingerprint

    logging.info(f"User {username} ({fingerprint}) connected.")

    # Send 'server_hello' message
    data = {
        "type": "server_hello",
        "public_key": server_public_key_pem,
        "server_fingerprint": server_fingerprint,
    }
    server_counter += 1
    message_json = json.dumps(data)
    signature = sign_message(server_private_key, message_json, server_counter)
    message = {
        "type": "signed_data",
        "data": data,
        "counter": server_counter,
        "signature": signature,
    }
    await websocket.send(json.dumps(message))
    logging.info("Sent 'server_hello' message.")

    # Send updated client list to all connected clients
    for client_ws in online_users.values():
        try:
            await send_client_list(client_ws)
        except Exception as e:
            logging.error(f"Error sending client list to client: {e}")

    # Send client_update to neighbors
    await broadcast_client_update()

    # Return client_public_key for further communication
    return client_public_key


async def receive_client_messages(websocket, client_public_key):
    """
    Receive and handle messages from the client.
    """
    try:
        async for message_str in websocket:
            logging.info(f"Received message from client: {message_str}")
            message = json.loads(message_str)
            msg_type = message.get("type")
            if msg_type == "signed_data":
                await handle_signed_message(websocket, message, client_public_key)
            else:
                logging.warning(f"Unknown message type: {msg_type}")
    except Exception as e:
        logging.error(f"Error receiving messages from client: {e}")
        traceback.print_exc()
    finally:
        # Client disconnected
        pass


async def handle_signed_message(websocket, message, client_public_key):
    """
    Handle signed messages from the client.
    """
    global server_counter
    data = message.get("data")
    counter = message.get("counter")
    signature_b64 = message.get("signature")

    # Verify signature
    message_json = json.dumps(data)
    if not verify_signature(client_public_key, message_json, signature_b64, counter):
        logging.warning("Signature verification failed.")
        return

    # Verify counter
    fingerprint = websocket.fingerprint
    last_counter = client_counters.get(fingerprint, 0)
    if counter <= last_counter:
        logging.warning("Replay attack detected. Counter not incremented.")
        return
    client_counters[fingerprint] = counter

    msg_type = data.get("type")
    if msg_type == "public_chat":
        await handle_public_chat(data, fingerprint)
    elif msg_type == "chat":
        await handle_private_chat(data, fingerprint)
    elif msg_type == "client_list_request":
        await send_client_list(websocket)
    else:
        logging.warning(f"Unknown signed message type: {msg_type}")


async def handle_public_chat(data, sender_fingerprint):
    """
    Handle public chat messages.
    """
    message_text = data.get("message")
    sender_username = data.get("sender")

    # Broadcast the message to all connected clients
    for client_ws in online_users.values():
        try:
            await client_ws.send(
                json.dumps(
                    {
                        "type": "public_chat",
                        "sender": sender_username,
                        "message": message_text,
                    }
                )
            )
        except Exception as e:
            logging.error(f"Error sending public chat message: {e}")

    # Forward the message to neighbor servers
    await broadcast_message_to_neighbors(data)


async def handle_private_chat(data, sender_fingerprint):
    """
    Handle private chat messages.
    """
    global server_counter

    recipients = data.get("recipients", [])
    if not recipients:
        logging.warning("No recipients specified in private chat.")
        return

    for recipient_fingerprint in recipients:
        recipient_ws = online_users.get(recipient_fingerprint)
        if recipient_ws:
            # Recipient is connected to this server
            # Forward the message to the recipient
            await recipient_ws.send(
                json.dumps(
                    {
                        "type": "signed_data",
                        "data": data,
                        "counter": server_counter,
                        "signature": "",  # Not required here
                    }
                )
            )
            logging.info(f"Forwarded private message to {recipient_fingerprint}")
        else:
            # Recipient is connected to another server
            # Forward the message to neighbor servers
            await broadcast_message_to_neighbors(data)
            logging.info(f"Forwarded private message to neighbor servers")


async def send_client_list(websocket):
    """
    Send the list of all registered clients, marking online users.
    """
    global server_counter
    servers = []

    # Include this server's clients
    clients = []
    all_users = user_manager.get_all_users()
    for fingerprint, user_info in all_users.items():
        username = user_info.get("username")
        public_key_pem = user_info.get("public_key")
        is_online = fingerprint in online_users
        client_entry = {
            "username": username,
            "fingerprint": fingerprint,
            "public_key": public_key_pem,
            "online": is_online,
        }
        clients.append(client_entry)

    # Sort clients: online first, then offline, both alphabetically by username
    clients.sort(key=lambda x: (not x["online"], x["username"].lower()))

    servers.append({"address": server_fingerprint, "clients": clients})

    # Include neighbors' clients
    for neighbor_fingerprint, neighbor_clients in neighbor_client_lists.items():
        servers.append({"address": neighbor_fingerprint, "clients": neighbor_clients})

    data = {"type": "client_list", "servers": servers}
    server_counter += 1
    message_json = json.dumps(data)
    signature = sign_message(server_private_key, message_json, server_counter)
    message = {
        "type": "signed_data",
        "data": data,
        "counter": server_counter,
        "signature": signature,
    }
    try:
        await websocket.send(json.dumps(message))
        logging.info("Sent client list.")
    except Exception as e:
        logging.error(f"Error sending client list: {e}")


# File upload handler
class FileUploadHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/upload":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            file_id = hashlib.sha256(post_data).hexdigest()
            file_path = os.path.join(UPLOAD_DIR, file_id)
            with open(file_path, "wb") as f:
                f.write(post_data)
            uploaded_files[file_id] = file_path
            response = {
                "file_url": f"http://localhost:8000/api/download?file_id={file_id}"
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
            logging.info(f"File uploaded with ID: {file_id}")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/api/download":
            query = parse_qs(parsed_path.query)
            file_id = query.get("file_id", [None])[0]
            if file_id and file_id in uploaded_files:
                file_path = uploaded_files[file_id]
                with open(file_path, "rb") as f:
                    file_data = f.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(file_data)
                logging.info(f"File {file_id} downloaded.")
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def start_http_server():
    httpd = TCPServer(("localhost", 8000), FileUploadHandler)
    logging.info("HTTP server started on http://localhost:8000")
    httpd.serve_forever()


# Neighbor server connections
neighbor_client_lists = {}  # Stores {fingerprint: clients}


async def connect_to_neighbors():
    """
    Connect to neighbor servers.
    """
    for address in neighbor_addresses:
        try:
            websocket = await websockets.connect(address)
            neighbor_connections[address] = websocket
            logging.info(f"Connected to neighbor server at {address}")
            # Send server_hello message
            await send_server_hello(websocket)
            # Send client_update_request
            await send_client_update_request(websocket)
            # Start listening to messages from neighbor
            asyncio.create_task(handle_neighbor_messages(websocket))
        except Exception as e:
            logging.error(f"Failed to connect to neighbor {address}: {e}")


async def send_server_hello(websocket):
    """
    Send server_hello message to neighbor server.
    """
    global server_counter
    data = {
        "type": "server_hello",
        "sender": server_fingerprint,
    }
    server_counter += 1
    message_json = json.dumps(data)
    signature = sign_message(server_private_key, message_json, server_counter)
    message = {
        "type": "signed_data",
        "data": data,
        "counter": server_counter,
        "signature": signature,
    }
    await websocket.send(json.dumps(message))
    logging.info("Sent server_hello to neighbor.")


async def send_client_update_request(websocket):
    """
    Send client_update_request message to neighbor server.
    """
    global server_counter
    data = {"type": "client_update_request", "sender": server_fingerprint}
    server_counter += 1
    message_json = json.dumps(data)
    signature = sign_message(server_private_key, message_json, server_counter)
    message = {
        "type": "signed_data",
        "data": data,
        "counter": server_counter,
        "signature": signature,
    }
    await websocket.send(json.dumps(message))
    logging.info("Sent client_update_request to neighbor.")


async def handle_neighbor_messages(websocket):
    """
    Handle messages from neighbor server.
    """
    try:
        async for message_str in websocket:
            message = json.loads(message_str)
            msg_type = message.get("type")
            if msg_type == "signed_data":
                await handle_signed_neighbor_message(websocket, message)
            else:
                logging.warning(f"Unknown message type from neighbor: {msg_type}")
    except Exception as e:
        logging.error(f"Error handling messages from neighbor: {e}")


async def handle_signed_neighbor_message(websocket, message):
    """
    Handle signed messages from neighbor server.
    """
    data = message.get("data")
    counter = message.get("counter")
    signature_b64 = message.get("signature")

    # In this example, we skip signature verification
    msg_type = data.get("type")
    if msg_type == "client_update":
        await handle_client_update(data)
    elif msg_type == "client_update_request":
        await send_client_update(websocket)
    elif msg_type == "chat":
        await forward_chat_to_clients(data)
    elif msg_type == "public_chat":
        await forward_public_chat_to_clients(data)
    else:
        logging.warning(f"Unknown signed message type from neighbor: {msg_type}")


async def handle_client_update(data):
    """
    Handle client_update message from neighbor server.
    """
    sender = data.get("sender")
    servers = data.get("servers", [])
    for server_info in servers:
        address = server_info.get("address")
        clients = server_info.get("clients", [])
        neighbor_client_lists[address] = clients
        for client_info in clients:
            fingerprint = client_info.get("fingerprint")
            username = client_info.get("username")
            public_key_pem = client_info.get("public_key")
            # Register user if not exists
            if not user_manager.get_user_info(fingerprint):
                user_manager.register_user(public_key_pem, username)
    logging.info("Updated client list from neighbor.")

    # Send updated client list to all connected clients
    for client_ws in online_users.values():
        try:
            await send_client_list(client_ws)
        except Exception as e:
            logging.error(f"Error sending client list to client: {e}")


async def send_client_update(websocket):
    """
    Send client_update message to neighbor server.
    """
    global server_counter
    servers = []

    # Include this server's clients
    clients = []
    all_users = user_manager.get_all_users()
    for fingerprint, user_info in all_users.items():
        username = user_info.get("username")
        public_key_pem = user_info.get("public_key")
        is_online = fingerprint in online_users
        client_entry = {
            "username": username,
            "fingerprint": fingerprint,
            "public_key": public_key_pem,
            "online": is_online,
        }
        clients.append(client_entry)

    servers.append({"address": server_fingerprint, "clients": clients})

    data = {"type": "client_update", "sender": server_fingerprint, "servers": servers}
    server_counter += 1
    message_json = json.dumps(data)
    signature = sign_message(server_private_key, message_json, server_counter)
    message = {
        "type": "signed_data",
        "data": data,
        "counter": server_counter,
        "signature": signature,
    }
    await websocket.send(json.dumps(message))
    logging.info("Sent client_update to neighbor.")


async def broadcast_client_update():
    """
    Broadcast client_update to all neighbor servers.
    """
    for websocket in neighbor_connections.values():
        await send_client_update(websocket)


async def broadcast_message_to_neighbors(data):
    """
    Broadcast a message to all neighbor servers.
    """
    global server_counter
    for websocket in neighbor_connections.values():
        server_counter += 1
        message_json = json.dumps(data)
        signature = sign_message(server_private_key, message_json, server_counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": server_counter,
            "signature": signature,
        }
        await websocket.send(json.dumps(message))
        logging.info("Broadcasted message to neighbor.")


async def forward_chat_to_clients(data):
    """
    Forward chat message received from neighbor server to local clients.
    """
    recipients = data.get("recipients", [])
    if not recipients:
        logging.warning("No recipients specified in private chat.")
        return

    for recipient_fingerprint in recipients:
        recipient_ws = online_users.get(recipient_fingerprint)
        if recipient_ws:
            # Recipient is connected to this server
            await recipient_ws.send(
                json.dumps(
                    {
                        "type": "signed_data",
                        "data": data,
                        "counter": 0,  # Counter not relevant here
                        "signature": "",  # Signature not required for forwarding
                    }
                )
            )
            logging.info(f"Forwarded chat message to {recipient_fingerprint}")


async def forward_public_chat_to_clients(data):
    """
    Forward public chat message to local clients.
    """
    for client_ws in online_users.values():
        try:
            await client_ws.send(
                json.dumps(
                    {
                        "type": "public_chat",
                        "sender": data.get("sender"),
                        "message": data.get("message"),
                    }
                )
            )
        except Exception as e:
            logging.error(f"Error sending public chat message: {e}")


async def start_server():
    """
    Start the chat server and the HTTP server.
    """
    # Start HTTP server in a separate thread
    http_thread = Thread(target=start_http_server)
    http_thread.daemon = True
    http_thread.start()

    # Start WebSocket server
    server = await websockets.serve(handle_client, "localhost", 8080)
    logging.info("WebSocket server started and listening on ws://localhost:8080")

    # Connect to neighbor servers
    await connect_to_neighbors()

    # Keep the server running
    await asyncio.Future()  # Run forever


if __name__ == "__main__":
    asyncio.run(start_server())
