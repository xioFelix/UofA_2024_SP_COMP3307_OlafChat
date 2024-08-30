from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

KEY = b"sixteen byte key"  # Replace with your actual key
IV = b"sixteen byte iv."  # Replace with your actual IV


def encrypt_message(message):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    encryptor = cipher.encryptor()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return IV + encrypted_message  # Prepend IV for decryption

def decrypt_message(encrypted_message):
    iv = encrypted_message[:16]  # Extract the IV from the beginning
    encrypted_message = encrypted_message[
        16:
    ]  # The rest is the actual encrypted message

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()
