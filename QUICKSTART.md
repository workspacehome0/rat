# Quick Start Guide

Get up and running with RAT in 5 minutes.

## Prerequisites

```bash
# Install Python dependencies
pip3 install pillow
```

## Step 1: Start the Services

```bash
cd rat
python3 rat_control.py
```

You should see:
```
============================================================
RAT Control Interface
Remote Administration Tool with Blockchain Persistence
============================================================

[+] Starting blockchain server on port 5444...
[✓] Blockchain server started (PID: 12345)
[+] Starting RAT server on port 4444...
[✓] RAT server started (PID: 12346)

============================================================
[✓] All services started successfully!

Services running:
  - Blockchain Server: Port 5444
  - RAT C2 Server: Port 4444

Press Ctrl+C to stop all services
============================================================
```

## Step 2: Generate a Payload

1. In the RAT GUI that opens, click **"Generate Payload"**
2. Enter your server IP (use `127.0.0.1` for local testing)
3. Enter server port (default: `4444`)
4. Choose where to save the payload (e.g., `my_payload.py`)
5. Click Save

You'll see a confirmation with the session ID.

## Step 3: Deploy Payload

### For Testing (Local)

Open a new terminal and run:
```bash
python3 my_payload.py
```

### For Remote Target

Transfer the payload to the target system and execute:
```bash
# Linux/Mac
python3 my_payload.py

# Windows
python my_payload.py
```

## Step 4: Control the Target

1. In the RAT GUI, you'll see the new session appear in the session list
2. Click on the session to select it
3. View system information in the details panel
4. Use the control buttons:
   - **Terminal**: Open command shell
   - **Screenshot**: Capture screen
   - **Live Stream**: Real-time screen view
   - **File Manager**: Browse files

## Step 5: Execute Commands

### Using Terminal
1. Click **"New Terminal"**
2. Type commands in the input box
3. Press Enter to execute
4. View output in the terminal window

### Using Command Buttons
- Click any pre-configured command button
- View results in the log panel

## Step 6: View Blockchain History

The blockchain automatically tracks all session events. To query:

```python
import socket
import json

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 5444))

# Get all sessions
request = {'type': 'get_stats'}
sock.send(json.dumps(request).encode() + b'\n')
response = json.loads(sock.recv(4096).decode())

print(f"Total sessions: {response['stats']['total_sessions']}")
print(f"Total blocks: {response['stats']['total_blocks']}")

sock.close()
```

## Common Commands

### System Information
```bash
# Windows
systeminfo
whoami
ipconfig

# Linux/Mac
uname -a
whoami
ifconfig
```

### File Operations
```bash
# List files
dir          # Windows
ls -la       # Linux/Mac

# Current directory
cd           # Windows
pwd          # Linux/Mac
```

### Network Information
```bash
# Windows
netstat -an
arp -a

# Linux/Mac
netstat -an
arp -a
```

## Stopping the Services

Press `Ctrl+C` in the terminal where `rat_control.py` is running.

## Testing Checklist

- [ ] Services started successfully
- [ ] Payload generated
- [ ] Payload connected to server
- [ ] Session appears in GUI
- [ ] Commands execute successfully
- [ ] Screenshot works
- [ ] Blockchain records events
- [ ] Services stop cleanly

## Troubleshooting

### Payload Won't Connect
```bash
# Check if server is listening
netstat -an | grep 4444

# Check firewall
# Windows: Windows Defender Firewall
# Linux: sudo ufw status
```

### GUI Won't Start
```bash
# Install tkinter
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter
```

### Permission Errors
```bash
# Make scripts executable
chmod +x *.py

# Run with sudo if needed (not recommended)
sudo python3 rat_control.py
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore blockchain API for custom queries
- Customize payloads for specific targets
- Set up secure C2 infrastructure

## Security Reminder

⚠️ **Only use on systems you own or have explicit permission to test.**

This tool is for educational and authorized security testing only. Unauthorized access to computer systems is illegal.

## Support

- GitHub Issues: https://github.com/workspacehome0/rat/issues
- Documentation: README.md

