import unittest
from client.client import Client


class TestClient(unittest.TestCase):
    def test_client_creation(self):
        client = Client("127.0.0.1", 8080)
        self.assertIsNotNone(client)

    # Add more tests for sending and receiving messages


if __name__ == "__main__":
    unittest.main()
