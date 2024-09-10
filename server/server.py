import socket
import logging
from cryptography.hazmat.primitives import serialization
from server.encryption import get_private_key, decrypt_message
from protocol.message_format import parse_and_verify_message

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# 获取私钥
private_key = get_private_key()

def handle_client(client_sock):
    logging.info("Handling new client connection")

    # 获取服务器的公钥
    public_key = private_key.public_key()

    # 将公钥以PEM格式发送给客户端，并记录公钥
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client_sock.send(public_key_pem)
    logging.info(f"Sent public key to client:\n{public_key_pem.decode('utf-8')}")

    client_public_key = None

    # Receive and process encrypted messages from clients
    while True:
        try:
            if client_public_key is None:
                # Receive unencrypted public key directly
                public_key_pem = client_sock.recv(1024)  # 假设公钥小于1024字节
                client_public_key = serialization.load_pem_public_key(public_key_pem)
                logging.info("Received client's public key")
                continue

            encrypted_message = client_sock.recv(4096)
            if not encrypted_message:
                logging.info("Client disconnected")
                break

            # 记录收到的加密消息
            logging.info(f"Received encrypted message:\n{encrypted_message.hex()}")

            # 使用私钥解密消息
            decrypted_message = decrypt_message(encrypted_message, private_key)
            logging.info(f"Decrypted message: {decrypted_message}")

            if client_public_key is None:
                # If there is no client public key yet, assume this is a "hello" message
                data = serialization.load_pem_public_key(decrypted_message.encode())
                client_public_key = data
                logging.info("Received client's public key")
                continue

            data, counter = parse_and_verify_message(decrypted_message, client_public_key)
            
            if data["type"] == "chat":
                logging.info(f"Received chat message: {data['message']}")
            else:
                logging.warning(f"Received unknown message type: {data['type']}")

        except Exception as e:
            logging.error(f"Error processing message: {e}")
            # No break here, keep the connection open

    client_sock.close()
    logging.info("Closed client connection")

def start_server():
    logging.info("Starting server...")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("0.0.0.0", 8080))
    server_sock.listen(5)
    logging.info("Server started and listening on port 8080")

    while True:
        client_sock, addr = server_sock.accept()
        logging.info(f"Accepted connection from {addr}")
        handle_client(client_sock)

if __name__ == "__main__":
    start_server()