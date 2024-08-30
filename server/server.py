from connection import ServerConnection
from encryption import encrypt_message, decrypt_message


class Server:
    def __init__(self, host, port):
        self.connection = ServerConnection(host, port)
        self.clients = []

    def start(self):
        print("Server started.")
        while True:
            client_sock = self.connection.accept_connection()
            print("New client connected.")
            self.clients.append(client_sock)
            self.handle_client(client_sock)

    def handle_client(self, client_sock):
        while True:
            try:
                encrypted_message = client_sock.recv(1024)
                if not encrypted_message:
                    break
                message = decrypt_message(encrypted_message)
                print("Received:", message)
                response = "Message received: " + message
                encrypted_response = encrypt_message(response)
                client_sock.sendall(encrypted_response)
            except ConnectionResetError:
                break
        print("Client disconnected.")
        self.clients.remove(client_sock)
        client_sock.close()


if __name__ == "__main__":
    server = Server("127.0.0.1", 8080)
    server.start()
