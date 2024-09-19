import asyncio
import json
import logging
import base64
import hashlib
import os
import traceback
import socket
import errno  # 导入 errno 模块
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from shared.encryption import (
    load_or_generate_private_key,
    serialize_public_key,
    sign_message,
    verify_signature,
    load_public_key,
)
import argparse
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)


class Client:
    """
    Chat client that connects to the server and communicates with other users.
    """

    def __init__(self, server_uri, host, port):
        self.server_uri = server_uri
        self.websocket = None
        self.private_key = None
        self.public_key_pem = None
        self.fingerprint = None
        self.counter = 0
        self.server_counter = 0
        self.username = ""
        self.user_public_keys = {}  # Stores public keys and info of other users
        self.host = host  # Host for client server
        self.port = port  # Port for client server
        self.client_server = None  # Server for handling incoming connections

    async def connect(self):
        """
        Connect to the server and perform initial handshake.
        """
        self.reader, self.writer = await asyncio.wait_for(
        asyncio.open_connection(self.server_uri.hostname, self.server_uri.port),
        timeout=10,
    )
        self.websocket = (self.reader, self.writer)
        
        logging.info(f"Connected to server at {self.server_uri.geturl()}")

        # Prompt for username
        self.username = input("Enter your username: ")

        # Load or generate private key
        key_filename = f"{self.username}_private_key.pem"
        self.private_key = load_or_generate_private_key(key_filename)
        self.public_key_pem = serialize_public_key(self.private_key.public_key())
        self.fingerprint = hashlib.sha256(
            self.public_key_pem.encode("utf-8")
        ).hexdigest()

        # Start client server for handling incoming connections
        await self.start_client_server()

        # Send 'hello' message to server
        await self.send_hello()

        # Start tasks for receiving messages and handling user input
        receive_task = asyncio.create_task(self.receive_messages())
        input_task = asyncio.create_task(self.handle_user_input())

        await asyncio.gather(receive_task, input_task)

    async def start_client_server(self):
        """
        Start a server to receive messages from other clients.
        """
        max_port = 65535
        port_found = False
        while not port_found and self.port <= max_port:
            try:
                server = await asyncio.start_server(
                    self.handle_client_connection, self.host, self.port
                )
                port_found = True
            except OSError as e:
                if (
                    e.errno == errno.EADDRINUSE
                ):  # 使用 errno.EADDRINUSE 检查端口占用错误
                    logging.warning(f"Port {self.port} is in use. Trying next port.")
                    self.port += 1
                else:
                    logging.error(f"Error starting server on port {self.port}: {e}")
                    raise e

        if not port_found:
            logging.error("No available port found for client server.")
            raise Exception("No available port for client server.")

        addr = server.sockets[0].getsockname()
        logging.info(f"Client server started on {addr}")
        self.client_server = server
        asyncio.create_task(self.client_server.serve_forever())

    async def handle_client_connection(self, reader, writer):
        """
        Handle incoming connections from other clients.
        """
        try:
            data = await reader.read(4096)
            message_str = data.decode("utf-8")
            message = json.loads(message_str)
            msg_type = message.get("type")

            if msg_type == "chat":
                await self.handle_incoming_chat(message)
            elif msg_type == "file_transfer":
                await self.handle_incoming_file(reader, writer, message)
            else:
                logging.warning(f"Unknown message type from client: {msg_type}")
        except Exception as e:
            logging.error(f"Error handling client connection: {e}")
            traceback.print_exc()
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_incoming_chat(self, message):
        """
        Handle incoming chat message from another client.
        """
        sender_username = message.get("sender")
        ciphertext_b64 = message.get("ciphertext")
        signature_b64 = message.get("signature")
        iv_b64 = message.get("iv")

        sender_info = self.user_public_keys.get(sender_username)
        if not sender_info:
            logging.warning(f"Received message from unknown user {sender_username}")
            return

        # Verify signature
        message_data = {
            "type": "chat",
            "sender": sender_username,
            "ciphertext": ciphertext_b64,
            "iv": iv_b64,
        }
        message_json = json.dumps(message_data, sort_keys=True, separators=(",", ":"))
        sender_public_key = sender_info["public_key"]
        if not verify_signature(sender_public_key, message_json, signature_b64, 0):
            logging.warning("Signature verification failed for incoming chat message.")
            return

        # Decrypt message
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        shared_key = self.private_key.exchange(padding.PKCS1v15(), sender_public_key)
        plaintext = self.decrypt_message(shared_key, iv, ciphertext)
        print(f"\n[Private] {sender_username}: {plaintext}")

    def decrypt_message(self, shared_key, iv, ciphertext):
        """
        Decrypt the message using shared key.
        """
        aesgcm = AESGCM(shared_key[:32])
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext.decode("utf-8")

    async def send_hello(self):
        """
        Send a 'hello' message to the server with the public key.
        """
        data = {
            "type": "hello",
            "username": self.username,
            "public_key": self.public_key_pem,
            "host": self.host,
            "port": self.port,
        }
        self.counter += 1
        message_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        signature = sign_message(self.private_key, message_json, self.counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        writer = self.websocket[1]
        writer.write((json.dumps(message) + "\n").encode("utf-8"))
        await writer.drain()
        logging.info("Sent hello message.")

    async def receive_messages(self):
        """
        Receive messages from the server.
        """
        reader = self.websocket[0]
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                message_str = data.decode("utf-8").strip()
                try:
                    message = json.loads(message_str)
                    msg_type = message.get("type")
                    if msg_type == "signed_data":
                        await self.handle_signed_message(message)
                    else:
                        logging.warning(f"Unknown message type from server: {msg_type}")
                except Exception as e:
                    logging.error(f"Error processing message: {e}")
                    traceback.print_exc()
        except Exception as e:
            logging.error(f"Error receiving messages: {e}")
            traceback.print_exc()

    async def handle_signed_message(self, message):
        """
        Handle signed messages from the server.
        """
        data = message.get("data")
        counter = message.get("counter")
        signature_b64 = message.get("signature")

        # Verify server's signature
        if not hasattr(self, "server_public_key"):
            # Load server public key from the 'server_hello' message
            if data.get("type") == "server_hello":
                server_public_key_pem = data.get("public_key")
                self.server_public_key = serialization.load_pem_public_key(
                    server_public_key_pem.encode("utf-8")
                )
                server_fingerprint = hashlib.sha256(
                    server_public_key_pem.encode("utf-8")
                ).hexdigest()
                logging.info(f"Connected to server {server_fingerprint}")
            else:
                logging.warning("Server public key not established.")
                return

        # Verify signature
        message_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        if not verify_signature(
            self.server_public_key, message_json, signature_b64, counter
        ):
            logging.warning("Signature verification failed.")
            return

        # Verify counter
        if counter <= self.server_counter:
            logging.warning("Replay attack detected. Counter not incremented.")
            return
        self.server_counter = counter

        # Handle message based on type
        msg_type = data.get("type")
        if msg_type == "client_list":
            await self.handle_client_list(data)
        elif msg_type == "server_hello":
            pass  # Already handled
        else:
            logging.warning(f"Unknown signed message type: {msg_type}")

    async def handle_client_list(self, data):
        """
        Handle the client list received from the server.
        """
        clients_list = data.get("clients", [])
        users = []
        for client_info in clients_list:
            username = client_info.get("username")
            fingerprint = client_info.get("fingerprint")
            public_key_pem = client_info.get("public_key")
            host = client_info.get("host")
            port = client_info.get("port")
            if fingerprint != self.fingerprint:
                public_key = load_public_key(public_key_pem.encode("utf-8"))
                self.user_public_keys[username] = {
                    "public_key": public_key,
                    "fingerprint": fingerprint,
                    "host": host,
                    "port": port,
                }
                users.append(username)
        print("\nUpdated client list:")
        for user in users:
            print(user)

    async def handle_user_input(self):
        """
        Handle user input commands.
        """
        print("Enter command: ", end="", flush=True)
        while True:
            try:
                user_input = await asyncio.get_event_loop().run_in_executor(None, input)
                if user_input.startswith("/msg "):
                    try:
                        _, recipient_username, message_text = user_input.split(" ", 2)
                    except ValueError:
                        print("Usage: /msg <username> <message>")
                        continue
                    await self.send_private_message(recipient_username, message_text)
                elif user_input.startswith("/list"):
                    await self.request_client_list()
                elif user_input.startswith("/help"):
                    self.show_help()
                elif user_input.lower() == "quit":
                    print("Exiting...")
                    self.client_server.close()
                    self.websocket[1].close()
                    break
                else:
                    print("Unknown command. Type /help for a list of commands.")
            except Exception as e:
                logging.error(f"An error occurred in handle_user_input: {e}")
                traceback.print_exc()
            finally:
                print("Enter command: ", end="", flush=True)

    async def send_private_message(self, recipient_username, message_text):
        """
        Send a private message to another user.
        """
        recipient_info = self.user_public_keys.get(recipient_username)
        if not recipient_info:
            print(f"User {recipient_username} not found.")
            return

        recipient_host = recipient_info.get("host")
        recipient_port = recipient_info.get("port")
        recipient_public_key = recipient_info.get("public_key")

        # Establish shared key
        shared_key = self.private_key.exchange(padding.PKCS1v15(), recipient_public_key)

        # Encrypt message
        iv = os.urandom(12)
        aesgcm = AESGCM(shared_key[:32])
        ciphertext = aesgcm.encrypt(iv, message_text.encode("utf-8"), None)

        # Prepare message
        message_data = {
            "type": "chat",
            "sender": self.username,
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
        }
        message_json = json.dumps(message_data, sort_keys=True, separators=(",", ":"))
        signature = sign_message(self.private_key, message_json, 0)
        message = {**message_data, "signature": signature}

        try:
            reader, writer = await asyncio.open_connection(
                recipient_host, recipient_port
            )
            writer.write(json.dumps(message).encode("utf-8"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            print(f"Message sent to {recipient_username}.")
        except Exception as e:
            logging.error(f"Error sending message: {e}")
            print(f"Failed to send message to {recipient_username}.")

    async def request_client_list(self):
        """
        Request the client list from the server.
        """
        data = {"type": "client_list_request"}
        self.counter += 1
        message_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        signature = sign_message(self.private_key, message_json, self.counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        writer = self.websocket[1]
        writer.write((json.dumps(message) + "\n").encode("utf-8"))
        await writer.drain()
        logging.info("Client list request sent.")

    def show_help(self):
        """
        Display help information for available commands.
        """
        help_text = """
Available commands:
    /list                     - Show online users.
    /msg <username> <message> - Send a private message to a user.
    /help                     - Show this help message.
    quit                      - Exit the chat.
"""
        print(help_text)


def main():
    parser = argparse.ArgumentParser(description="P2P Chat Client")
    parser.add_argument("--host", default="0.0.0.0", help="Host for client server")
    parser.add_argument("--port", type=int, default=9000, help="Port for client server")
    parser.add_argument("--server", default="localhost:8080", help="Server address")
    args = parser.parse_args()

    server_uri = urlparse(f"tcp://{args.server}")
    client = Client(server_uri, args.host, args.port)
    asyncio.run(client.connect())


if __name__ == "__main__":
    main()
