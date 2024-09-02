# OLAF Chat System

## Overview

The OLAF Chat System is a secure, distributed chat application that uses AES encryption to ensure the confidentiality of messages exchanged between clients and servers. This project is part of an Advanced Secure Programming assignment, focusing on secure communication protocols.

## Features

- **Client-Server Communication**: Secure messaging between clients and servers using a simple client-server architecture.
- **AES Encryption**: Messages are encrypted using AES in CBC mode, ensuring confidentiality during transmission.
- **Authentication**: Servers authenticate clients upon connection.
- **Decryption**: Clients can decrypt received messages for secure communication.

## Getting Started

### Prerequisites

- Python 3.x installed on your system.
- Install the required dependencies listed in `requirements.txt`.

### Installation

1. **Clone the Repository**:

   ```bash
   https://github.com/<Your User Name>/UofA_2024_SP_OlafChat.git
   cd UofA_2024_SP_OlafChat
   ```

2. **Install Dependencies**:

   Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

### Running the Server

1. **Start the Server**:

   The server is responsible for accepting client connections and relaying encrypted messages.

   ```bash
   python3 -m server.server
   ```

   When the server starts, it will listen for incoming connections from clients. Upon receiving a connection, it will authenticate the client and wait for messages.

2. **Server Output**:

   The server will display output indicating when a client connects and when messages are received.

### Running the Client

1. **Start the Client**:

   The client connects to the server and allows the user to send encrypted messages.

   ```bash
   ./scripts/run_client.sh
   ```

2. **Sending Messages**:

   Once the client is connected, you can type messages into the console. These messages will be encrypted and sent to the server.

3. **Receiving Messages**:

   The client will display decrypted messages received from the server.

4. **Exit the Client**:

   To exit the client, type `quit`.

### Encryption and Decryption

- **Encryption**: Messages are encrypted using AES with CBC mode. The encryption process includes padding to ensure the message length is a multiple of the block size.
- **Decryption**: Received messages are decrypted using the same AES key and initialization vector (IV) used for encryption.

### Example Workflow

1. **Start the Server**:
   - Run `python3 -m server.server` to start the server.
   - If the command above doesn't work, try to run `python3 -m server.server`.

2. **Start the Client**:
   - Run `python3 -m client.client 127.0.0.1 8080` (assuming the server is running locally on port 8080).
   - If the command above doesn't work, try to run `python -m client.client 127.0.0.1 8080`.

3. **Send and Receive Messages**:
   - The client can send a message by typing in the console.
   - The server will receive, decrypt, and display the message.
   - The server can send a response, which the client will decrypt and display.

### Project Structure

- **client/**: Contains the client-side implementation.
- **server/**: Contains the server-side implementation.
- **protocol/**: Houses the OLAF protocol implementation and message handling (if applicable).
- **tests/**: Contains unit and integration tests.
- **docs/**: Documentation files for the project.
- **scripts/**: Shell scripts to run the client and server.
- **requirements.txt**: List of Python dependencies.

### Troubleshooting

- **Connection Refused**: Ensure that the server is running and the IP address and port are correct.
- **Invalid Padding Error**: This usually means the message was not padded correctly before encryption or was tampered with during transmission.
- **Invalid IV Size**: Ensure that the IV is correctly extracted and passed during the decryption process.

### Contribution

If you would like to contribute to this project, feel free to fork the repository and submit a pull request. All contributions are welcome!

### License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
