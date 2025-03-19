// XorChat terminal interface client script
const socket = io();
const terminal = document.getElementById('terminal-output');
const input = document.getElementById('terminal-input');
let alias = null;
let sessionKey = null;

// Add a message to the terminal
function addMessage(content, className) {
    const message = document.createElement('div');
    message.className = `message ${className || ''}`;
    message.textContent = content;
    terminal.appendChild(message);
    terminal.scrollTop = terminal.scrollHeight;
}

// Handle sending messages
input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        const msg = input.value.trim();
        input.value = '';
        
        if (!msg) return;
        
        // Handle commands
        if (msg.startsWith('/')) {
            socket.emit('command', { command: msg });
        }
        // Set alias if not set yet
        else if (!alias) {
            alias = msg;
            socket.emit('set_alias', { alias });
        }
        // Regular message
        else {
            addMessage(`[${alias}]: ${msg}`, 'user');
            socket.emit('send_message', { message: msg });
        }
    }
});

// XOR function for encrypting/decrypting messages
function xorEncryptDecrypt(data, key) {
    let result = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        result[i] = data[i] ^ key[i % key.length];
    }
    return result;
}

// Convert hex string to bytes array
function hexToBytes(hex) {
    let bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

// Handle system messages
socket.on('system_message', (data) => {
    addMessage(data.message, 'system');
});

// Handle chat messages
socket.on('chat_message', (data) => {
    if (data.alias === alias) return; // Skip messages from self
    
    // Decrypt the message
    if (sessionKey) {
        try {
            const encryptedMsg = hexToBytes(data.message);
            const decryptedMsg = xorEncryptDecrypt(encryptedMsg, sessionKey);
            const textDecoder = new TextDecoder();
            const plaintext = textDecoder.decode(decryptedMsg);
            
            addMessage(`[${data.alias}]: ${plaintext}`, 'received');
        } catch (error) {
            addMessage(`Error decrypting message from ${data.alias}`, 'error');
        }
    } else {
        addMessage(`Encrypted message from ${data.alias} (no session key)`, 'error');
    }
});

// Handle session key updates
socket.on('key_update', (data) => {
    sessionKey = hexToBytes(data.session_key);
    addMessage('Session key updated!', 'system');
});

// Show welcome message
addMessage('Welcome to XorChat!', 'system');
addMessage('Please enter your alias to begin.', 'system');

// Handle terminal controls
document.querySelector('.close').addEventListener('click', () => {
    addMessage('Terminal session can\'t be closed in web mode.', 'error');
});

document.querySelector('.minimize').addEventListener('click', () => {
    addMessage('Terminal minimization not available in web mode.', 'system');
});

document.querySelector('.maximize').addEventListener('click', () => {
    document.querySelector('.terminal').classList.toggle('maximized');
});
