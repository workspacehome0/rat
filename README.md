# RAT - Remote Administration Tool with Blockchain Session Persistence

A sophisticated remote administration tool featuring blockchain-based session persistence for secure and verifiable session tracking.

## Features

### Core Capabilities
- **Remote Command Execution**: Execute commands on target systems
- **Session Management**: Track and manage multiple concurrent sessions
- **Screenshot Capture**: Take screenshots of target systems
- **Live Streaming**: Real-time screen monitoring
- **File Operations**: Upload/download files to/from targets
- **Terminal Access**: Multiple independent terminal sessions per target

### Advanced Features
- **Blockchain Session Persistence**: All session events are recorded in an immutable blockchain
- **Payload Generator**: Automatically generate custom payloads for different targets
- **Reverse SOCKS Proxy**: Tunnel traffic through compromised systems
- **Automatic Persistence**: Payloads can install themselves for automatic startup
- **Session Verification**: Verify the integrity of session history using blockchain

## Architecture

### Components

1. **RAT Server** (`rat_server_fixed.py`)
   - Main control server with GUI interface
   - Manages connections from target systems
   - Provides command and control functionality
   - Port: 4444 (default)

2. **Blockchain Server** (`blockchain_server.py`)
   - Maintains blockchain of all session events
   - Provides session history and verification
   - Stores blockchain to disk for persistence
   - Port: 5444 (default)

3. **Payload Generator** (`payload_generator.py`)
   - Generates custom payloads for target systems
   - Configurable server IP, port, and features
   - Supports persistence and blockchain integration

4. **Control Interface** (`rat_control.py`)
   - Unified control for starting/stopping services
   - Manages both RAT and blockchain servers

5. **Client Payload** (generated)
   - Lightweight client that runs on target systems
   - Connects back to C2 server
   - Records events to blockchain
   - Optional persistence mechanism

## Installation

### Prerequisites

```bash
# Python 3.7 or higher
python3 --version

# Required packages
pip3 install pillow  # For screenshot functionality
```

### Setup

```bash
# Clone the repository
git clone https://github.com/workspacehome0/rat.git
cd rat

# Make scripts executable
chmod +x *.py
```

## Usage

### Quick Start

1. **Start All Services**:
   ```bash
   python3 rat_control.py
   ```
   This starts both the blockchain server and RAT server.

2. **Generate Payload**:
   - Click "Generate Payload" in the GUI
   - Enter your server IP address
   - Choose output location
   - Deploy payload to target system

3. **Execute Payload on Target**:
   ```bash
   # On target system
   python3 payload.py
   ```

4. **Control Target**:
   - View connected sessions in the GUI
   - Select a session to interact
   - Use command buttons or terminal

### Manual Start

#### Start Blockchain Server
```bash
python3 blockchain_server.py --host 0.0.0.0 --port 5444
```

#### Start RAT Server
```bash
python3 rat_server_fixed.py
```

### Generate Payload

#### Using GUI
1. Start RAT server
2. Click "Generate Payload" button
3. Configure settings
4. Save payload file

#### Using Command Line
```python
from payload_generator import PayloadGenerator

gen = PayloadGenerator()
result = gen.generate_payload(
    server_ip="192.168.1.100",
    server_port=4444,
    output_file="payload.py",
    persistence=True,
    blockchain_enabled=True
)
print(result)
```

## Blockchain Session Persistence

### How It Works

The blockchain session persistence system records all session events in an immutable blockchain structure:

1. **Session Initialization**: When a payload connects, a genesis block is created
2. **Event Recording**: Every command, connection, and action is recorded as a block
3. **Chain Verification**: The blockchain can be verified for integrity
4. **Persistence**: Blockchain is saved to disk and can be restored
5. **Synchronization**: Clients sync their local blockchain to the server

### Blockchain Structure

Each block contains:
- **Index**: Sequential block number
- **Timestamp**: When the event occurred
- **Session ID**: Unique identifier for the session
- **Event Type**: Type of event (connection, command, etc.)
- **Data**: Event-specific data
- **Previous Hash**: Hash of the previous block
- **Hash**: SHA-256 hash of the current block

### Event Types

- `session_init`: Initial connection
- `system_info_collected`: System information gathered
- `command_received`: Command received from server
- `command_executed`: Command execution completed
- `connected_to_server`: Successfully connected to C2
- `disconnected`: Connection lost
- `persistence_installed`: Persistence mechanism installed

### Querying Blockchain

```python
import socket
import json

# Connect to blockchain server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 5444))

# Get session history
request = {
    'type': 'get_session',
    'session_id': 'abc123def456'
}

sock.send(json.dumps(request).encode() + b'\n')
response = json.loads(sock.recv(4096).decode())

print(response['history'])
sock.close()
```

### Verify Blockchain Integrity

```python
request = {'type': 'verify'}
sock.send(json.dumps(request).encode() + b'\n')
response = json.loads(sock.recv(4096).decode())

print(f"Valid: {response['is_valid']}")
print(f"Message: {response['message']}")
```

## Configuration

### Server Configuration

Edit `rat_server_fixed.py`:
```python
# Default port
port = 4444

# Blockchain server port
blockchain_port = 5444
```

### Payload Configuration

When generating payloads, you can configure:
- **Server IP**: C2 server address
- **Server Port**: C2 server port
- **Persistence**: Enable/disable automatic startup
- **Blockchain**: Enable/disable blockchain tracking

## Security Considerations

### Important Warnings

⚠️ **This tool is for educational and authorized testing purposes only.**

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Be aware of applicable laws and regulations in your jurisdiction

### Security Features

1. **Session Verification**: Blockchain ensures session integrity
2. **Encrypted Storage**: Blockchain data is hashed and verifiable
3. **Audit Trail**: Complete history of all actions
4. **Tamper Detection**: Any modification to blockchain is detectable

### Recommendations

- Use strong network segmentation
- Monitor blockchain for unusual activity
- Regularly verify blockchain integrity
- Keep blockchain backups secure
- Use VPN or secure channels for C2 communication

## API Reference

### PayloadGenerator

```python
class PayloadGenerator:
    def generate_payload(self, server_ip, server_port, output_file, 
                        persistence=True, blockchain_enabled=True,
                        blockchain_host=None, blockchain_port=None)
```

Generates a Python payload with specified configuration.

**Parameters:**
- `server_ip` (str): C2 server IP address
- `server_port` (int): C2 server port
- `output_file` (str): Path to save the payload
- `persistence` (bool): Enable persistence mechanism
- `blockchain_enabled` (bool): Enable blockchain tracking
- `blockchain_host` (str): Blockchain server host
- `blockchain_port` (int): Blockchain server port

**Returns:** Dictionary with session_id, output_file, server, and blockchain_enabled

### BlockchainServer

```python
class BlockchainServer:
    def __init__(self, host='0.0.0.0', port=5444, blockchain_file='blockchain.json')
    def start(self)
    def stop(self)
```

Manages blockchain persistence for session tracking.

### Blockchain API Endpoints

#### Sync Blockchain
```json
{
  "type": "blockchain_sync",
  "session_id": "abc123",
  "chain": [...]
}
```

#### Get Session History
```json
{
  "type": "get_session",
  "session_id": "abc123"
}
```

#### Get Statistics
```json
{
  "type": "get_stats"
}
```

#### Add Event
```json
{
  "type": "add_event",
  "session_id": "abc123",
  "event_type": "custom_event",
  "data": {...}
}
```

#### Verify Blockchain
```json
{
  "type": "verify"
}
```

## Troubleshooting

### Common Issues

#### Payload Won't Connect
- Check firewall settings on server
- Verify server IP and port are correct
- Ensure server is running and listening
- Check network connectivity

#### Blockchain Sync Fails
- Verify blockchain server is running on port 5444
- Check blockchain_server.py logs
- Ensure blockchain.json is writable

#### GUI Won't Start
- Install required dependencies: `pip3 install pillow`
- Check if tkinter is installed: `python3 -m tkinter`
- Run from terminal to see error messages

#### Permission Denied
- Run with appropriate permissions
- On Linux/Mac: `chmod +x *.py`
- Check file ownership

### Debug Mode

Enable debug output:
```bash
# Blockchain server with verbose output
python3 blockchain_server.py --host 0.0.0.0 --port 5444

# Check logs
tail -f blockchain.json
```

## File Structure

```
rat/
├── rat_server_fixed.py      # Main RAT server with GUI
├── blockchain_server.py     # Blockchain persistence server
├── payload_generator.py     # Payload generation module
├── rat_control.py          # Unified control interface
├── chrome.py               # Chrome proxy support
├── tsmin_py3.py           # Minimal client component
├── tsocks_py3.py          # SOCKS proxy component
├── blockchain.json        # Blockchain data (generated)
├── test_payload.py        # Example payload (generated)
└── README.md              # This file
```

## Development

### Adding New Features

1. **New Event Types**: Add to BlockchainSession in payload
2. **New Commands**: Extend RATServer.send_command()
3. **GUI Enhancements**: Modify RATGUI class
4. **Blockchain Queries**: Add new message types to BlockchainServer

### Testing

```bash
# Test payload generation
python3 payload_generator.py

# Test blockchain server
python3 blockchain_server.py --port 5444

# Test in isolated environment
# Use virtual machines for safe testing
```

## License

This project is provided for educational purposes only. Use responsibly and legally.

## Disclaimer

The authors and contributors are not responsible for any misuse of this software. This tool is intended for security research, penetration testing, and educational purposes only. Always obtain proper authorization before testing systems you do not own.

## Contributing

Contributions are welcome! Please ensure all contributions:
- Follow the existing code style
- Include appropriate documentation
- Are tested in isolated environments
- Do not include malicious functionality

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/workspacehome0/rat/issues
- Documentation: See this README

## Changelog

### Version 2.0 (Current)
- Added blockchain session persistence
- Implemented payload generator
- Enhanced GUI interface
- Added session verification
- Improved error handling

### Version 1.0
- Initial release
- Basic RAT functionality
- SOCKS proxy support
- Screenshot capability

## Acknowledgments

Built upon proven RAT architectures with modern blockchain technology for enhanced session tracking and verification.

