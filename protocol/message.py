from olaf_protocol import OLAFProtocol


def create_message(sender, receiver, message):
    return OLAFProtocol.format_message(message, sender, receiver)


def parse_message(formatted_message):
    return OLAFProtocol.parse_message(formatted_message)
