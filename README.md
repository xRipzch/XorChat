# XorChat

- ** Current Version: 0.4 **

XorChat is a simple peer-to-peer chat application written in Python. It uses an XOR-based cipher for basic message encryption and decryption, and communicates using JSON messages over TCP sockets.

## Features

- **XOR Encryption**: Encrypts and decrypts messages using a simple XOR cipher.
- **Peer-to-Peer Communication**: Connects to peers directly over TCP.
- **Session Key Management**: Uses a randomly generated session key which can be updated during a session.
- **Command-Based Interface**: Supports commands such as:
  - `/help` - Display help
  - `/alias <new_alias>` - Change your alias
  - `/reset` - Update the session key and notify connected peers
  - `/connect <IP> <PORT>` - Connect to a new peer
  - `/exit` - Exit the application

## Getting Started

1. **Requirements**: Ensure you have Python installed on your system.
2. **Run the Application**:
   - Open a terminal and run:
     ```sh
     python application/xorchat.py
     ```
     Or use PyInstaller / Nuitka!
3. **Usage**:
   - Choose an alias and a port to listen on.
   - Use the commands listed above to interact with peers.

For more details, check out the main code in [application/xorchat.py](application/xorchat.py).
