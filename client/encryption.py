from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

KEY = os.urandom(32)  # This should be securely shared between server and client
IV = os.urandom(16)


def encrypt_message(message):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return IV + encrypted_message  # Prepend IV for decryption


def decrypt_message(encrypted_message):
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()
