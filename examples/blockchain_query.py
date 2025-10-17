#!/usr/bin/env python3
"""
Example: Query Blockchain for Session History
"""

import socket
import json
import sys

def query_blockchain(host='localhost', port=5444):
    """Query blockchain server for information"""
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        print(f"[+] Connected to blockchain server at {host}:{port}\n")
        
        # Get statistics
        print("=" * 60)
        print("BLOCKCHAIN STATISTICS")
        print("=" * 60)
        
        request = {'type': 'get_stats'}
        sock.send(json.dumps(request).encode() + b'\n')
        response = json.loads(sock.recv(4096).decode())
        
        if response['status'] == 'success':
            stats = response['stats']
            print(f"Total Blocks: {stats['total_blocks']}")
            print(f"Total Sessions: {stats['total_sessions']}")
            print(f"Blockchain Valid: {stats['is_valid']}")
            print(f"\nActive Sessions:")
            for session_id in stats['sessions']:
                print(f"  - {session_id}")
        
        sock.close()
        
        # Get detailed session history for each session
        if stats['sessions']:
            print("\n" + "=" * 60)
            print("SESSION DETAILS")
            print("=" * 60)
            
            for session_id in stats['sessions']:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                
                request = {
                    'type': 'get_session',
                    'session_id': session_id
                }
                
                sock.send(json.dumps(request).encode() + b'\n')
                response = json.loads(sock.recv(8192).decode())
                
                if response['status'] == 'success':
                    history = response['history']
                    print(f"\nSession: {session_id}")
                    print(f"Total Events: {len(history)}")
                    print("\nEvent Timeline:")
                    
                    for block in history[:10]:  # Show first 10 events
                        print(f"  [{block['timestamp']}] {block['event_type']}")
                        if block['data']:
                            print(f"    Data: {str(block['data'])[:100]}")
                    
                    if len(history) > 10:
                        print(f"  ... and {len(history) - 10} more events")
                
                sock.close()
        
        # Verify blockchain integrity
        print("\n" + "=" * 60)
        print("BLOCKCHAIN VERIFICATION")
        print("=" * 60)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        request = {'type': 'verify'}
        sock.send(json.dumps(request).encode() + b'\n')
        response = json.loads(sock.recv(4096).decode())
        
        if response['status'] == 'success':
            print(f"Blockchain Valid: {response['is_valid']}")
            print(f"Message: {response['message']}")
        
        sock.close()
        
    except ConnectionRefusedError:
        print(f"[!] Error: Could not connect to blockchain server at {host}:{port}")
        print("[!] Make sure the blockchain server is running:")
        print("    python3 blockchain_server.py")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Query blockchain for session history')
    parser.add_argument('--host', default='localhost', help='Blockchain server host')
    parser.add_argument('--port', type=int, default=5444, help='Blockchain server port')
    
    args = parser.parse_args()
    
    query_blockchain(args.host, args.port)

