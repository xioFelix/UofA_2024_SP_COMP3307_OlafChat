# shared/encryption.py

import os
import base64
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Load or generate RSA private key
def load_or_generate_private_key(key_path):
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )
        logging.info(f"Loaded existing private key from {key_path}.")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as key_file:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_file.write(pem)
        logging.info(f"Generated new private key and saved to {key_path}.")
    return private_key


# Load RSA public key from PEM data
def load_public_key(pem_data):
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


# Serialize RSA public key to PEM format
def serialize_public_key(public_key):
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_pem


# RSA encrypt
def rsa_encrypt(public_key, data):
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted


# RSA decrypt
def rsa_decrypt(private_key, encrypted_data):
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted


# AES encrypt
def aes_encrypt(aes_key, plaintext):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted


# AES decrypt
def aes_decrypt(aes_key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# Generate AES key
def generate_aes_key():
    return os.urandom(32)


# Sign message
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


# Verify signature
def verify_signature(public_key, message, signature):
    try:
        signature_bytes = base64.b64decode(signature)
        public_key.verify(
            signature_bytes,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        logging.info("Signature verified successfully.")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False


# Encrypt message with AES and RSA
def encrypt_message(message, recipient_public_key):
    aes_key = generate_aes_key()
    iv, encrypted_message = aes_encrypt(aes_key, message.encode())
    encrypted_key = rsa_encrypt(recipient_public_key, aes_key)
    message_package = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
    }
    return json.dumps(message_package)


# Decrypt message with AES and RSA
def decrypt_message(message_package_json, private_key):
    message_package = json.loads(message_package_json)
    encrypted_key = base64.b64decode(message_package["encrypted_key"])
    iv = base64.b64decode(message_package["iv"])
    encrypted_message = base64.b64decode(message_package["encrypted_message"])

    aes_key = rsa_decrypt(private_key, encrypted_key)
    plaintext = aes_decrypt(aes_key, iv, encrypted_message)
    return plaintext.decode("utf-8")
