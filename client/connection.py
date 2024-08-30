import socket


class ClientConnection:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_ip, self.server_port))

    def send(self, data):
        self.sock.sendall(data)

    def receive(self):
        return self.sock.recv(1024)
