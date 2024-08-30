# Here, you would define your OLAF protocol specifics
# This is a placeholder for where you might implement message formatting, handshake protocols, etc.


class OLAFProtocol:
    @staticmethod
    def format_message(message, sender, receiver):
        return f"{sender}:{receiver}:{message}"

    @staticmethod
    def parse_message(formatted_message):
        parts = formatted_message.split(":")
        return {"sender": parts[0], "receiver": parts[1], "message": parts[2]}
