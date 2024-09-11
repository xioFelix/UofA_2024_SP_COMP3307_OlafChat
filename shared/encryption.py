from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64
import json


# RSA key generation (in actual application, the key should be pre-generated and safely stored)
# In this demonstration, suppose you already have the private key of the server and the public key of the client.

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


def get_private_key():
    return private_key


# The function to decrypt the AES key
def decrypt_aes_key(encrypted_key, rsa_private_key):
    aes_key = rsa_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key


# The function to decrypt messages
def decrypt_message(encrypted_message, rsa_private_key):
    # Convert the message back from JSON format
    message_data = json.loads(encrypted_message.decode("utf-8"))

    # Decode the base64 encoded parts
    encrypted_key = base64.b64decode(message_data["encrypted_key"])
    iv = base64.b64decode(message_data["iv"])
    encrypted_content = base64.b64decode(message_data["encrypted_message"])

    # Decrypt the AES key
    aes_key = decrypt_aes_key(encrypted_key, rsa_private_key)

    # Use the decrypted AES key to decrypt the message
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(encrypted_content) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()


# Encrypt the AES key
def encrypt_aes_key(aes_key, rsa_public_key):
    encrypted_key = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_key


# Function to sign the message
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")  # Base64 encode the signature


# Encrypt the message along with its signature
def encrypt_message(message, rsa_public_key, signature):
    aes_key = os.urandom(32)  # Generate a random AES key
    iv = os.urandom(16)  # Generate random IV

    # Encrypt the AES key
    encrypted_key = encrypt_aes_key(aes_key, rsa_public_key)

    # Use AES to encrypt the message
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Construct a JSON object to send over the network
    message_with_signature = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
        "signature": signature,
    }

    return json.dumps(message_with_signature).encode(
        "utf-8"
    )  # Convert JSON to bytes for sending
