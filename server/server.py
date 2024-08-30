import socket
import logging
from cryptography.hazmat.primitives import serialization
from .encryption import get_private_key, decrypt_message

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

    # 接收并处理来自客户端的加密消息
    while True:
        encrypted_message = client_sock.recv(4096)  # 假设消息小于4096字节
        if not encrypted_message:
            logging.info("Client disconnected")
            break

        # 记录收到的加密消息
        logging.info(f"Received encrypted message:\n{encrypted_message.hex()}")

        # 使用私钥解密消息
        try:
            decrypted_message = decrypt_message(encrypted_message, private_key)
            logging.info(f"Received and decrypted message: {decrypted_message}")
        except Exception as e:
            logging.error(f"Error decrypting message: {e}")
            break

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
