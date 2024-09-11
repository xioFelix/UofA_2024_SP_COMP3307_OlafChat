import socket
import logging
import json
import base64
from cryptography.hazmat.primitives import serialization
from protocol.message_format import parse_and_verify_message
from shared.encryption import get_private_key, decrypt_message
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Retrieve the private key for the server
private_key = get_private_key()

# Dictionary to store the latest counter value for each client to prevent replay attacks
client_counters = {}


# Function to verify the message signature using the client's public key
def verify_signature(public_key, message, signature):
    try:
        # Convert message to bytes if not already
        if isinstance(message, str):
            message = message.encode("utf-8")

        # Verify signature
        public_key.verify(
            signature,
            message,  # Now it's already bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        logging.info("Signature verified successfully.")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False


# Function to check for replay attacks based on the message counter
def is_replay_attack(client_id, counter):
    if client_id not in client_counters:
        client_counters[client_id] = counter
        return False
    elif counter > client_counters[client_id]:
        client_counters[client_id] = counter
        return False
    else:
        logging.error(
            f"Replay attack detected from client {client_id}. Counter: {counter}"
        )
        return True


# Function to handle incoming client connections
def handle_client(client_sock):
    logging.info("Handling new client connection")

    # Send the server's public key to the client
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client_sock.send(public_key_pem)
    logging.info(f"Sent public key to client:\n{public_key_pem.decode('utf-8')}")
    client_public_key = None

    while True:
        try:
            message = client_sock.recv(4096)
            if not message:
                logging.info("Client disconnected")
                break

            if client_public_key is None:
                # Handle the initial hello message
                decoded_message = message.decode()
                data = json.loads(decoded_message)
                if data["data"]["type"] == "hello":
                    client_public_key = serialization.load_pem_public_key(
                        data["data"]["public_key"].encode()
                    )
                    logging.info("Received client's public key from hello message")
                else:
                    logging.warning(
                        f"Expected hello message, but received {data['data']['type']}"
                    )
            else:
                # Handle subsequent encrypted messages
                logging.info(f"Received encrypted message: {message.hex()}")
                decrypted_message = decrypt_message(message, private_key)
                logging.info(f"Decrypted message: {decrypted_message}")

                # Convert decrypted message from JSON string to a dictionary
                try:
                    decrypted_message = json.loads(decrypted_message)
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to decode decrypted message as JSON: {e}")
                    continue

                # Decode the base64-encoded signature and verify it
                try:
                    signature = base64.b64decode(decrypted_message["signature"])
                    if not verify_signature(
                        client_public_key,
                        json.dumps(decrypted_message["data"]),
                        signature,
                    ):
                        logging.error(
                            "Signature verification failed. Rejecting message."
                        )
                        continue
                except Exception as e:
                    logging.error(f"Error processing message signature: {e}")
                    continue

                # Check for replay attacks
                client_id = client_sock.getpeername()[
                    0
                ]  # Use client's IP address as an identifier
                if is_replay_attack(client_id, decrypted_message["counter"]):
                    logging.error(f"Replay attack detected from client {client_id}.")
                    continue

                # Handle chat messages
                if decrypted_message["data"]["type"] == "chat":
                    logging.info(
                        f"Received chat message: {decrypted_message['data']['message']}"
                    )
                else:
                    logging.warning(
                        f"Received unknown message type: {decrypted_message['data']['type']}"
                    )

        except Exception as e:
            logging.error(f"Error decrypting or parsing message: {e}")

    client_sock.close()
    logging.info("Closed client connection")


# Start the server
def start_server():
    logging.info("Starting server...")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("0.0.0.0", 8080))
    server_sock.listen(5)
    logging.info("Server started and listening on port 8080")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            logging.info(f"Accepted connection from {addr}")
            handle_client(client_sock)
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
    finally:
        server_sock.close()  # Close the server socket
        logging.info("Server socket closed.")


if __name__ == "__main__":
    start_server()
