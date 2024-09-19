import json
import os


class UserManager:
    def __init__(self, filename):
        self.filename = filename
        self.users = self.load_users()

    def load_users(self):
        if os.path.exists(self.filename):
            with open(self.filename, "r") as f:
                return json.load(f)
        else:
            return {}

    def save_users(self):
        with open(self.filename, "w") as f:
            json.dump(self.users, f)

    def register_user(self, public_key_pem, username, file_transfer_port):
        fingerprint = self.compute_fingerprint(public_key_pem)
        if fingerprint not in self.users:
            self.users[fingerprint] = {
                "username": username,
                "public_key": public_key_pem,
                "file_transfer_port": file_transfer_port,
            }
            self.save_users()

    def get_user_info(self, fingerprint):
        return self.users.get(fingerprint)

    def get_all_users(self):
        return self.users

    def compute_fingerprint(self, public_key_pem):
        import hashlib

        return hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()
