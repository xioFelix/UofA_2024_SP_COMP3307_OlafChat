import socket
import os
from protocol.message_format import create_message
from shared.encryption import encrypt_message, sign_message
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class Client:
    def __init__(self, server_ip, server_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_ip, server_port))
        self.private_key = self.load_or_generate_private_key()
        self.server_public_key = self.receive_public_key()
        self.counter = 0
        self.send_hello()

    # Load the private key from a file or generate a new one
    def load_or_generate_private_key(self):
        if os.path.exists("client_private_key.pem"):
            with open("client_private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None
                )
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open("client_private_key.pem", "wb") as key_file:
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                key_file.write(pem)
        return private_key

    def receive_public_key(self):
        pem_data = self.sock.recv(1024)
        public_key = serialization.load_pem_public_key(pem_data)
        return public_key

    def send_hello(self):
        self.counter += 1
        hello_message = create_message("hello", {}, self.private_key, self.counter)
        print(f"Sending hello message: {hello_message}")
        self.sock.send(hello_message.encode())

    def send_message(self, message_type, data):
        self.counter += 1
        # Create the message and sign it
        json_message = create_message(
            message_type, data, self.private_key, self.counter
        )
        signature = sign_message(self.private_key, json_message)
        encrypted_message = encrypt_message(
            json_message, self.server_public_key, signature
        )
        self.sock.send(encrypted_message)

    def start(self):
        while True:
            message = input("Enter message: ")
            if message.lower() == "quit":
                print("Client disconnected.")
                break
            try:
                self.send_message("chat", {"message": message})
            except Exception as e:
                print(f"Error sending message: {e}")
                break

        self.sock.close()


if __name__ == "__main__":
    client = Client("127.0.0.1", 8080)
    client.start()
