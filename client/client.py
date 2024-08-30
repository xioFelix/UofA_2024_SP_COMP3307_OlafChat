import sys
from connection import ClientConnection
from encryption import encrypt_message, decrypt_message


class Client:
    def __init__(self, server_ip, server_port):
        self.connection = ClientConnection(server_ip, server_port)

    def send_message(self, message):
        encrypted_message = encrypt_message(message)
        self.connection.send(encrypted_message)

    def receive_message(self):
        encrypted_message = self.connection.receive()
        message = decrypt_message(encrypted_message)
        return message

    def start(self):
        print("Client started. Type 'quit' to exit.")
        while True:
            message = input("Enter message: ")
            if message.lower() == "quit":
                break
            self.send_message(message)
            print("Message sent.")
            response = self.receive_message()
            print("Received:", response)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <server_ip> <server_port>")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])

    client = Client(server_ip, server_port)
    client.start()
