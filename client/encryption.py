from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os


# The function of encrypting the AES key
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


# Functions to encrypt messages
def encrypt_message(message, rsa_public_key):
    aes_key = os.urandom(32)  # Generate a random AES key
    iv = os.urandom(16)  # Generate random IV

    # Encrypt the AES key
    encrypted_key = encrypt_aes_key(aes_key, rsa_public_key)

    # Use AES to encrypt messages
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return (
        encrypted_key + iv + encrypted_message
    )  # Return the encrypted AES key, IV and encrypted message


# The function of decrypting messages (usually not required to be used in the client, but can be retained to prevent two-way encrypted communication)
def decrypt_message(encrypted_message, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()
