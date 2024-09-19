import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def load_or_generate_private_key(filename):
    """
    Load an existing private key from a file or generate a new one.
    """
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(filename, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    return private_key


def serialize_public_key(public_key):
    """
    Serialize a public key to PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def sign_message(private_key, message, counter):
    """
    Sign a message with a private key and counter.
    """
    signer_data = f"{counter}:{message}".encode("utf-8")
    signature = private_key.sign(
        signer_data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, message, signature_b64, counter):
    """
    Verify a signature with a public key and counter.
    """
    signature = base64.b64decode(signature_b64)
    signer_data = f"{counter}:{message}".encode("utf-8")
    try:
        public_key.verify(
            signature,
            signer_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def load_public_key(pem_data):
    """
    Load a public key from PEM data.
    """
    return serialization.load_pem_public_key(pem_data)
