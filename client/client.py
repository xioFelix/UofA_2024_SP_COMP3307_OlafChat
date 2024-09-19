import asyncio
import websockets
import json
import logging
import base64
import hashlib
import os
import traceback
import requests

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shared.encryption import (
    load_or_generate_private_key,
    serialize_public_key,
    sign_message,
    verify_signature,
    load_public_key,
)
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)


class Client:
    """
    Chat client that connects to the server and communicates with other users.
    """

    def __init__(self, uri, http_uri):
        self.uri = uri
        self.http_uri = http_uri
        self.websocket = None
        self.private_key = None
        self.server_public_key = None
        self.fingerprint = None
        self.counter = 0
        self.server_counter = 0
        self.logged_in = False
        self.user_public_keys = {}  # Store other users' public keys and info

    async def connect(self):
        """
        Connect to the server and perform initial handshake.
        """
        self.websocket = await websockets.connect(self.uri)
        logging.info(f"Connected to server at {self.uri}")

        # Prompt for username
        self.username = input("Enter your username: ")

        # Load or generate private key
        key_filename = f"{self.username}_private_key.pem"
        self.private_key = load_or_generate_private_key(key_filename)

        # Generate fingerprint
        public_key_pem = serialize_public_key(self.private_key.public_key())
        self.fingerprint = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()

        # Send 'hello' message
        await self.send_hello()

        # **立即请求客户端列表**
        await self.send_client_list_request()

        # Start tasks for receiving messages and handling user input
        receive_task = asyncio.create_task(self.receive_messages())
        input_task = asyncio.create_task(self.handle_user_input())

        await asyncio.gather(receive_task, input_task)

    async def send_hello(self):
        """
        Send a 'hello' message to the server with the public key.
        """
        data = {
            "type": "hello",
            "public_key": serialize_public_key(self.private_key.public_key()),
            "username": self.username,
        }
        self.counter += 1
        message_json = json.dumps(data)
        signature = sign_message(self.private_key, message_json, self.counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        await self.websocket.send(json.dumps(message))
        logging.info("Sent hello message.")

    async def receive_messages(self):
        """
        Receive messages from the server.
        """
        try:
            async for message_str in self.websocket:
                try:
                    message = json.loads(message_str)
                    msg_type = message.get("type")
                    if msg_type == "signed_data":
                        await self.handle_signed_message(message)
                    elif msg_type == "public_chat":
                        sender_username = message.get("sender")
                        message_text = message.get("message")
                        print(f"\n[Public] {sender_username}: {message_text}")
                    else:
                        logging.warning(f"Unknown message type: {msg_type}")
                except Exception as e:
                    logging.error(f"Error receiving message: {e}")
                finally:
                    print("Enter command: ", end="", flush=True)
        except Exception as e:
            logging.error(f"Error in receive_messages: {e}")
            traceback.print_exc()

    async def handle_signed_message(self, message):
        """
        Handle signed messages from the server.
        """
        data = message.get("data")
        counter = message.get("counter")
        signature_b64 = message.get("signature")

        # Verify server's signature
        if not self.server_public_key:
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
        message_json = json.dumps(data)
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
        if msg_type == "chat":
            await self.handle_chat_message(data)
        elif msg_type == "public_chat":
            sender_username = data.get("sender")
            message_text = data.get("message")
            print(f"\n[Public] {sender_username}: {message_text}")
        elif msg_type == "client_list":
            await self.handle_client_list(data)
        elif msg_type == "server_hello":
            # Server hello message already handled
            pass
        else:
            logging.warning(f"Unknown signed message type: {msg_type}")

    async def handle_chat_message(self, data):
        """
        Handle private chat messages.
        """
        iv_b64 = data.get("iv")
        symm_keys_b64 = data.get("symm_keys")
        chat_b64 = data.get("chat")

        # Decrypt the symmetric key
        symm_key = None
        for symm_key_enc_b64 in symm_keys_b64:
            symm_key_enc = base64.b64decode(symm_key_enc_b64)
            try:
                symm_key = self.private_key.decrypt(
                    symm_key_enc,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                break
            except Exception:
                continue
        if symm_key is None:
            logging.warning("Failed to decrypt symmetric key.")
            return

        # Decrypt the message
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(chat_b64)
        aesgcm = AESGCM(symm_key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            chat_data = json.loads(plaintext.decode("utf-8"))
            sender_fingerprint_b64 = chat_data.get("participants", [])[0]
            sender_fingerprint = base64.b64decode(sender_fingerprint_b64).decode(
                "utf-8"
            )
            sender_username = await self.get_username_by_fingerprint(sender_fingerprint)
            message_text = chat_data.get("message")
            print(f"\n[Private] {sender_username}: {message_text}")
        except Exception as e:
            logging.warning(f"Failed to decrypt message: {e}")

    async def handle_client_list(self, data):
        """
        Handle the client list received from the server.
        """
        servers = data.get("servers", [])
        users = []
        for server_info in servers:
            address = server_info.get("address")
            clients_list = server_info.get("clients", [])
            for client_info in clients_list:
                username = client_info.get("username")
                fingerprint = client_info.get("fingerprint")
                public_key_pem = client_info.get("public_key")
                is_online = client_info.get("online")
                if fingerprint != self.fingerprint:
                    public_key = load_public_key(public_key_pem.encode("utf-8"))
                    self.user_public_keys[username] = {
                        "public_key": public_key,
                        "fingerprint": fingerprint,
                        "online": is_online,
                    }
                    users.append(
                        {
                            "username": username,
                            "fingerprint": fingerprint,
                            "online": is_online,
                        }
                    )
        # Sort users: online first, then offline, both alphabetically by username
        users.sort(key=lambda x: (not x["online"], x["username"].lower()))
        print("\nUpdated client list:")
        for user in users:
            status = "online" if user["online"] else "offline"
            print(f"{user['username']} ({status})")

    async def get_username_by_fingerprint(self, fingerprint):
        """
        Retrieve username by fingerprint.
        """
        for username, info in self.user_public_keys.items():
            if info["fingerprint"] == fingerprint:
                return username
        return "Unknown"

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
                elif user_input.startswith("/public "):
                    message_text = user_input[8:]
                    await self.send_public_message(message_text)
                elif user_input == "/list":
                    await self.send_client_list_request()
                elif user_input.lower() == "/help":
                    self.show_help()
                elif user_input.lower() == "/upload":
                    await self.upload_file()
                elif user_input.lower().startswith("/download "):
                    _, file_url = user_input.split(" ", 1)
                    await self.download_file(file_url)
                elif user_input.lower() == "quit":
                    print("Exiting...")
                    await self.websocket.close()
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
            print("Recipient not found in client list.")
            return

        recipient_fingerprint = recipient_info["fingerprint"]
        recipient_public_key = recipient_info["public_key"]

        if recipient_public_key is None:
            print("Failed to retrieve recipient's public key.")
            return

        # Generate symmetric key
        symm_key = AESGCM.generate_key(bit_length=256)

        # Encrypt the message
        iv = os.urandom(16)
        aesgcm = AESGCM(symm_key)
        chat_data = {
            "participants": [
                base64.b64encode(self.fingerprint.encode("utf-8")).decode("utf-8"),
                base64.b64encode(recipient_fingerprint.encode("utf-8")).decode("utf-8"),
            ],
            "message": message_text,
        }
        plaintext = json.dumps(chat_data).encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        # Encrypt the symmetric key
        symm_key_enc = recipient_public_key.encrypt(
            symm_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # Prepare data
        data = {
            "type": "chat",
            "destination_servers": [],  # Empty means send to own server
            "recipients": [recipient_fingerprint],  # 添加收件人的指纹
            "iv": base64.b64encode(iv).decode("utf-8"),
            "symm_keys": [base64.b64encode(symm_key_enc).decode("utf-8")],
            "chat": base64.b64encode(ciphertext).decode("utf-8"),
            # **移除 "participants" 字段**
        }
        self.counter += 1
        message_json = json.dumps(data)
        signature = sign_message(self.private_key, message_json, self.counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        await self.websocket.send(json.dumps(message))
        print("Private message sent.")

    async def send_public_message(self, message_text):
        """
        Send a public message to all users.
        """
        data = {
            "type": "public_chat",
            "sender": self.username,
            "message": message_text,
        }
        self.counter += 1
        message_json = json.dumps(data)
        signature = sign_message(self.private_key, message_json, self.counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        await self.websocket.send(json.dumps(message))
        print("Public message sent.")

    async def send_client_list_request(self):
        """
        Request the client list from the server.
        """
        data = {"type": "client_list_request"}
        self.counter += 1
        message_json = json.dumps(data)
        signature = sign_message(self.private_key, message_json, self.counter)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        await self.websocket.send(json.dumps(message))
        print("Client list request sent.")

    async def upload_file(self):
        """
        Upload a file to the server.
        """
        file_path = input("Enter the file path to upload: ")
        if not os.path.isfile(file_path):
            print("File not found.")
            return

        with open(file_path, "rb") as f:
            file_data = f.read()

        url = f"{self.http_uri}/api/upload"
        try:
            response = requests.post(url, data=file_data)
            if response.status_code == 200:
                file_url = response.json().get("file_url")
                print(f"File uploaded successfully. File URL: {file_url}")
            else:
                print(f"Failed to upload file. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error uploading file: {e}")

    async def download_file(self, file_url):
        """
        Download a file from the server.
        """
        try:
            response = requests.get(file_url)
            if response.status_code == 200:
                filename = input("Enter the filename to save as: ")
                with open(filename, "wb") as f:
                    f.write(response.content)
                print(f"File downloaded successfully and saved as {filename}.")
            else:
                print(f"Failed to download file. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error downloading file: {e}")

    def show_help(self):
        """
        Display help information for available commands.
        """
        help_text = """
Available commands:
/list                     - Show online users.
/msg <username> <message> - Send a private message to a user.
/public <message>         - Send a public message.
/upload                   - Upload a file.
/download <file_url>      - Download a file.
/help                     - Show this help message.
quit                      - Exit the chat.
"""
        print(help_text)


def main():
    client = Client("ws://localhost:8080", "http://localhost:8000")
    asyncio.run(client.connect())


if __name__ == "__main__":
    main()
