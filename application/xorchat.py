import socket
import threading
import json
import os
import sys

# Global session key (generated at startup)
session_key = os.urandom(16)
alias = None
connections = []  # List of active peer connections
lock = threading.Lock()  # For thread safety

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    """Performs XOR cipher on data using the given key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def send_json(conn: socket.socket, obj: dict):
    """Sends a JSON object over a socket, terminated with a newline."""
    try:
        message = json.dumps(obj) + "\n"
        conn.sendall(message.encode())
    except Exception as e:
        print("Error sending:", e)

def handle_connection(conn: socket.socket, addr):
    """Handles an incoming connection from a peer."""
    global session_key
    buffer = ""
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data.decode()
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if msg.get("type") == "chat":
                        # Decrypt the message using the current session key
                        enc_msg = bytes.fromhex(msg.get("message", ""))
                        plain = xor_encrypt_decrypt(enc_msg, session_key)
                        sender = msg.get("alias", "Unknown")
                        print(f"\n[{sender}]: {plain.decode(errors='ignore')}")
                        print(">> ", end="", flush=True)
                    elif msg.get("type") == "key_update":
                        # Update the session key
                        new_key = bytes.fromhex(msg.get("session_key", ""))
                        session_key = new_key
                        print("\nSession key updated from peer!")
                        print(">> ", end="", flush=True)
                except Exception as e:
                    print("Error receiving message:", e)
    except Exception as e:
        print("Connection to", addr, "terminated:", e)
    finally:
        conn.close()
        with lock:
            if conn in connections:
                connections.remove(conn)
        print(f"Connection to {addr} closed.")

def start_server(listen_port: int):
    """Starts a server that listens on the specified port for new peer connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", listen_port))
    server.listen(5)
    print(f"Server running and listening on port {listen_port}...")
    while True:
        conn, addr = server.accept()
        print(f"Connection received from {addr}")
        # As the host, send the current session key to the new connection
        send_json(conn, {"type": "key_update", "session_key": session_key.hex()})
        with lock:
            connections.append(conn)
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()

def connect_to_peer(peer_ip: str, peer_port: int):
    """Connects to a peer and receives the session key from the host."""
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((peer_ip, peer_port))
        print(f"Connected to peer at {peer_ip}:{peer_port}")
        # As a client, wait to receive the session key from the host
        buffer = ""
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data.decode()
            if "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                msg = json.loads(line)
                if msg.get("type") == "key_update":
                    new_key = bytes.fromhex(msg.get("session_key", ""))
                    global session_key
                    session_key = new_key
                    print("Received session key from peer.")
                    break
        with lock:
            connections.append(conn)
        threading.Thread(target=handle_connection, args=(conn, (peer_ip, peer_port)), daemon=True).start()
    except Exception as e:
        print("Could not connect to peer:", e)

def show_help():
    """Displays a list of available commands."""
    print("Available commands:")
    print("/help                - Display this help")
    print("/alias <new_alias>   - Change your alias")
    print("/reset               - Generate a new session key (host sends update to peers)")
    print("/connect <IP> <PORT> - Connect to a peer")
    print("/exit                - Exit the program")

def main():
    global alias, session_key
    alias = input("Choose an alias: ").strip()
    try:
        listen_port = int(input("Enter port to listen on (e.g., 12345): "))
    except:
        listen_port = 12345
    # Start the server thread
    threading.Thread(target=start_server, args=(listen_port,), daemon=True).start()
    print(f"Welcome to XorChat, {alias}!")
    show_help()
    print(">> ", end="", flush=True)
    while True:
        try:
            user_input = input(">> ").strip()
            if not user_input:
                continue
            if user_input.startswith("/"):
                parts = user_input.split()
                command = parts[0].lower()
                if command == "/help":
                    show_help()
                elif command == "/alias":
                    if len(parts) > 1:
                        alias = parts[1]
                        print(f"Alias updated to {alias}")
                    else:
                        print("Usage: /alias <new_alias>")
                elif command == "/reset":
                    # Host generates a new session key and sends it to all connected peers
                    session_key = os.urandom(16)
                    print("New session key generated.")
                    with lock:
                        for conn in connections:
                            send_json(conn, {"type": "key_update", "session_key": session_key.hex()})
                elif command == "/connect":
                    if len(parts) >= 3:
                        peer_ip = parts[1]
                        try:
                            peer_port = int(parts[2])
                            connect_to_peer(peer_ip, peer_port)
                        except:
                            print("Invalid port.")
                    else:
                        print("Usage: /connect <IP> <PORT>")
                elif command == "/exit":
                    print("Exiting XorChat.")
                    sys.exit(0)
                else:
                    print("Unknown command. Type /help for assistance.")
            else:
                # Normal message: encrypt and send to all connected peers
                encrypted = xor_encrypt_decrypt(user_input.encode(), session_key)
                msg_obj = {
                    "type": "chat",
                    "alias": alias,
                    "message": encrypted.hex()
                }
                # Display the decrypted message locally
                print(f"[{alias}]: {user_input}")
                with lock:
                    for conn in connections:
                        send_json(conn, msg_obj)
        except EOFError:
            break
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    main()
