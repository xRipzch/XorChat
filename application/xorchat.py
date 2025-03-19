import os
import json
import threading
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room

# Global session key (generated at startup)
session_key = os.urandom(16)
connections = {}  # Dictionary to track socket connections by session ID
lock = threading.Lock()  # For thread safety

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    """Performs XOR cipher on data using the given key."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    """Serve the main terminal interface."""
    return render_template('terminal.html')

@socketio.on('connect')
def on_connect():
    """Handle new client connections."""
    connections[request.sid] = {
        'alias': None,
        'room': 'lobby'
    }
    emit('system_message', {'message': 'Connected to XorChat server. Choose an alias to begin.'})

@socketio.on('disconnect')
def on_disconnect():
    """Handle client disconnection."""
    if request.sid in connections:
        alias = connections[request.sid]['alias'] or 'Unknown'
        room = connections[request.sid]['room']
        del connections[request.sid]
        emit('system_message', {'message': f'{alias} has left the chat.'}, 
             room=room, include_self=False)

@socketio.on('set_alias')
def on_set_alias(data):
    """Set user alias."""
    if request.sid in connections:
        alias = data.get('alias', 'Anonymous')
        connections[request.sid]['alias'] = alias
        emit('system_message', {'message': f'Your alias is now: {alias}'})

@socketio.on('send_message')
def on_send_message(data):
    """Handle incoming chat messages."""
    if request.sid in connections:
        sender = connections[request.sid]['alias'] or 'Unknown'
        room = connections[request.sid]['room']
        
        # Encrypt the message
        plaintext = data.get('message', '').encode()
        encrypted = xor_encrypt_decrypt(plaintext, session_key)
        
        # Broadcast to all users in the room
        emit('chat_message', {
            'type': 'chat',
            'alias': sender,
            'message': encrypted.hex()
        }, room=room)

@socketio.on('command')
def on_command(data):
    """Process chat commands."""
    global session_key
    cmd = data.get('command', '').strip()
    
    if cmd.startswith('/help'):
        emit('system_message', {'message': 'Available commands:'})
        emit('system_message', {'message': '/alias <new_alias>   - Change your alias'})
        emit('system_message', {'message': '/reset               - Generate a new session key'})
        emit('system_message', {'message': '/connect <room>      - Join a chat room'})
        
    elif cmd.startswith('/alias '):
        new_alias = cmd.split(' ', 1)[1]
        connections[request.sid]['alias'] = new_alias
        emit('system_message', {'message': f'Alias updated to {new_alias}'})
        
    elif cmd == '/reset':
        session_key = os.urandom(16)
        emit('system_message', {'message': 'New session key generated.'})
        room = connections[request.sid]['room']
        emit('key_update', {'session_key': session_key.hex()}, room=room)
        
    elif cmd.startswith('/connect '):
        new_room = cmd.split(' ', 1)[1]
        old_room = connections[request.sid]['room']
        alias = connections[request.sid]['alias'] or 'Anonymous'
        
        # Leave the current room
        leave_room(old_room)
        emit('system_message', {'message': f'{alias} has left the room.'}, 
             room=old_room, include_self=False)
             
        # Join the new room
        join_room(new_room)
        connections[request.sid]['room'] = new_room
        emit('system_message', {'message': f'You joined room: {new_room}'})
        emit('system_message', {'message': f'{alias} has joined the room.'}, 
             room=new_room, include_self=False)
             
        # Send session key to the new user
        emit('key_update', {'session_key': session_key.hex()})
    
    else:
        emit('system_message', {'message': 'Unknown command. Type /help for assistance.'})

if __name__ == "__main__":
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
