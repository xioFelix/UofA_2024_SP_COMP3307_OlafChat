import asyncio
import json
import logging
import hashlib
import traceback
from urllib.parse import urlparse
import errno
from shared.encryption import (
    load_or_generate_private_key,
    serialize_public_key,
    sign_message,
    verify_signature,
    load_public_key,
)
import argparse

logging.basicConfig(level=logging.INFO)


class Server:
    """
    Chat server for client registration and client list management.
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.clients = {}  # Stores client info
        self.private_key = load_or_generate_private_key("server_private_key.pem")
        self.public_key_pem = serialize_public_key(self.private_key.public_key())
        self.fingerprint = hashlib.sha256(
            self.public_key_pem.encode("utf-8")
        ).hexdigest()
        self.counter = 0
        self.connected_clients = []  # 存储连接的客户端

    async def start(self):
        """
        Start the server and listen for incoming connections.
        """
        server = await asyncio.start_server(
            self.handle_client_connection, self.host, self.port
        )
        addr = server.sockets[0].getsockname()
        logging.info(f"Server started on {addr}")
        self.server = server
        async with server:
            await server.serve_forever()

    async def handle_client_connection(self, reader, writer):
        """
        Handle incoming connections from clients.
        """
        self.connected_clients.append((reader, writer))
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                message_str = data.decode("utf-8").strip()
                if not message_str:
                    continue
                message = json.loads(message_str)
                msg_type = message.get("type")
                if msg_type == "signed_data":
                    await self.handle_signed_message(reader, writer, message)
                else:
                    logging.warning(f"Unknown message type from client: {msg_type}")
        except Exception as e:
            logging.error(f"Error handling client connection: {e}")
            traceback.print_exc()
        finally:
            writer.close()
            await writer.wait_closed()
            self.connected_clients.remove((reader, writer))

    async def handle_signed_message(self, reader, writer, message):
        """
        Handle signed messages from clients.
        """
        data = message.get("data")
        counter = message.get("counter")
        signature_b64 = message.get("signature")
        msg_type = data.get("type")

        if msg_type == "hello":
            await self.handle_hello_message(writer, data, signature_b64, counter)
        elif msg_type == "client_list_request":
            await self.send_client_list(writer)
        else:
            logging.warning(f"Unknown signed message type: {msg_type}")

    async def handle_hello_message(self, writer, data, signature_b64, counter):
        """
        Handle 'hello' message from client.
        """
        public_key_pem = data.get("public_key")
        client_public_key = load_public_key(public_key_pem.encode("utf-8"))
        username = data.get("username")
        host = data.get("host")
        port = data.get("port")

        # Verify signature
        message_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        if not verify_signature(
            client_public_key, message_json, signature_b64, counter
        ):
            logging.warning("Signature verification failed for hello message.")
            return

        fingerprint = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()

        # Register client
        self.clients[fingerprint] = {
            "username": username,
            "public_key_pem": public_key_pem,
            "host": host,
            "port": port,
        }
        logging.info(f"User {username} registered with fingerprint {fingerprint}")

        # Send 'server_hello' message
        data = {"type": "server_hello", "public_key": self.public_key_pem}
        self.counter += 1
        message_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        signature = sign_message(self.private_key, message_json, self.counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        writer.write((json.dumps(message) + "\n").encode("utf-8"))
        await writer.drain()
        logging.info("Sent server_hello message.")

    async def send_client_list(self, writer):
        """
        Send the list of all registered clients.
        """
        data = {
            "type": "client_list",
            "clients": [
                {
                    "username": info["username"],
                    "fingerprint": fingerprint,
                    "public_key": info["public_key_pem"],
                    "host": info["host"],
                    "port": info["port"],
                }
                for fingerprint, info in self.clients.items()
            ],
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
        writer.write((json.dumps(message) + "\n").encode("utf-8"))
        await writer.drain()
        logging.info("Sent client list.")


def main():
    parser = argparse.ArgumentParser(description="P2P Chat Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host for server")
    parser.add_argument("--port", type=int, default=8080, help="Port for server")
    args = parser.parse_args()

    server = Server(args.host, args.port)
    asyncio.run(server.start())


if __name__ == "__main__":
    main()
