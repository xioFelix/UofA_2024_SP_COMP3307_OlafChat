import socket


class ServerConnection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)

    def accept_connection(self):
        client_sock, client_address = self.sock.accept()
        print(f"Accepted connection from {client_address}")
        return client_sock
