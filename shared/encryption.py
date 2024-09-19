import os
import base64
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_or_generate_private_key(key_path):
    """
    Load an existing RSA private key from the specified path,
    or generate a new one if it doesn't exist.
    """
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
                format=serialization.PrivateFormat.PKCS8,  # 使用 PKCS8 格式
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_file.write(pem)
        logging.info(f"Generated new private key and saved to {key_path}.")
    return private_key


def load_public_key(pem_data):
    """
    Load an RSA public key from PEM data.
    """
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def serialize_public_key(public_key):
    """
    Serialize an RSA public key to PEM format.
    """
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_pem.decode("utf-8")


def rsa_encrypt(public_key, data):
    """
    Encrypt data using RSA public key encryption with OAEP padding.
    """
    encrypted = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),  # 使用 SHA-256
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted


def rsa_decrypt(private_key, encrypted_data):
    """
    Decrypt data using RSA private key decryption with OAEP padding.
    """
    decrypted = private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),  # 使用 SHA-256
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted


def aes_encrypt(aes_key, plaintext):
    """
    Encrypt plaintext using AES-GCM symmetric encryption.
    """
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(16)  # 16 字节的 IV
    encrypted = aesgcm.encrypt(iv, plaintext, None)
    return iv, encrypted


def aes_decrypt(aes_key, iv, ciphertext):
    """
    Decrypt ciphertext using AES-GCM symmetric decryption.
    """
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext


def generate_aes_key():
    """
    Generate a random 256-bit AES key.
    """
    return AESGCM.generate_key(bit_length=256)  # 生成 256 位的 AES 密钥


def sign_message(private_key, message, counter):
    """
    Sign a message using RSA private key with PSS padding and include counter.
    """
    signer_data = message + str(counter)
    signature = private_key.sign(
        signer_data.encode("utf-8"),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=32,  # 固定 32 字节的盐长度
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, message, signature_b64, counter):
    """
    Verify a message signature using RSA public key with PSS padding and counter.
    """
    signature = base64.b64decode(signature_b64)
    signer_data = message + str(counter)
    try:
        public_key.verify(
            signature,
            signer_data.encode("utf-8"),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=32,  # 固定 32 字节的盐长度
            ),
            hashes.SHA256(),
        )
        logging.info("Signature verified successfully.")
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False
