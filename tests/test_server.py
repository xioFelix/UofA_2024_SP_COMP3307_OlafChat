import unittest
from server.server import Server


class TestServer(unittest.TestCase):
    def test_server_creation(self):
        server = Server("127.0.0.1", 8080)
        self.assertIsNotNone(server)

    # Add more tests for accepting connections and handling messages


if __name__ == "__main__":
    unittest.main()
