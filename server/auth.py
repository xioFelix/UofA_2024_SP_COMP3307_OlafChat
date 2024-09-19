import json
import os
import hashlib


class UserManager:
    """
    UserManager handles user registration and retrieval.
    """

    def __init__(self, user_data_file):
        self.user_data_file = user_data_file
        self.users = {}
        self.load_users()

    def load_users(self):
        """
        Load users from the user data file.
        """
        if os.path.exists(self.user_data_file):
            with open(self.user_data_file, "r") as f:
                self.users = json.load(f)
        else:
            self.users = {}

    def save_users(self):
        """
        Save users to the user_data file.
        """
        with open(self.user_data_file, "w") as f:
            json.dump(self.users, f)

    def register_user(self, public_key_pem, username):
        """
        Register a new user with public key and username.
        """
        fingerprint = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()
        self.users[fingerprint] = {"public_key": public_key_pem, "username": username}
        self.save_users()

    def get_user_info(self, fingerprint):
        """
        Get the user info (public key and username) by fingerprint.
        """
        return self.users.get(fingerprint)

    def get_all_users(self):
        """
        Get all registered users.
        """
        return self.users
