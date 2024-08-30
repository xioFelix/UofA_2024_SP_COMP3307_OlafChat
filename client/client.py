import socket
from encryption import encrypt_message
from cryptography.hazmat.primitives import serialization


class Client:
    def __init__(self, server_ip, server_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_ip, server_port))
        self.server_public_key = self.receive_public_key()

    def receive_public_key(self):
        # 接收来自服务器的公钥
        pem_data = self.sock.recv(1024)  # 假设公钥小于1024字节
        public_key = serialization.load_pem_public_key(pem_data)
        return public_key

    def send_message(self, message):
        encrypted_message = encrypt_message(message, self.server_public_key)
        self.sock.send(encrypted_message)

    def start(self):
        while True:
            message = input("Enter message: ")
            if message.lower() == "quit":
                print("Client disconnected.")
                break
            self.send_message(message)


if __name__ == "__main__":
    client = Client("127.0.0.1", 8080)  # 假设服务器运行在本地并监听8080端口
    client.start()
