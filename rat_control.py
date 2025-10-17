#!/usr/bin/env python3
"""
RAT Control Interface
Integrated control for RAT server and blockchain persistence
"""

import sys
import os
import subprocess
import threading
import time
import signal

class RATControl:
    """Control interface for RAT system"""
    
    def __init__(self):
        self.rat_server_process = None
        self.blockchain_process = None
        self.running = False
    
    def start_blockchain_server(self, port=5444):
        """Start blockchain persistence server"""
        print(f"[+] Starting blockchain server on port {port}...")
        
        try:
            self.blockchain_process = subprocess.Popen(
                [sys.executable, 'blockchain_server.py', '--port', str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            time.sleep(2)
            
            if self.blockchain_process.poll() is None:
                print(f"[✓] Blockchain server started (PID: {self.blockchain_process.pid})")
                return True
            else:
                print("[✗] Blockchain server failed to start")
                return False
                
        except Exception as e:
            print(f"[✗] Error starting blockchain server: {e}")
            return False
    
    def start_rat_server(self, port=4444):
        """Start RAT C2 server"""
        print(f"[+] Starting RAT server on port {port}...")
        
        try:
            self.rat_server_process = subprocess.Popen(
                [sys.executable, 'rat_server_fixed.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            time.sleep(2)
            
            if self.rat_server_process.poll() is None:
                print(f"[✓] RAT server started (PID: {self.rat_server_process.pid})")
                print(f"[i] GUI should be opening...")
                return True
            else:
                print("[✗] RAT server failed to start")
                return False
                
        except Exception as e:
            print(f"[✗] Error starting RAT server: {e}")
            return False
    
    def stop_all(self):
        """Stop all services"""
        print("\n[+] Stopping all services...")
        
        if self.rat_server_process:
            try:
                self.rat_server_process.terminate()
                self.rat_server_process.wait(timeout=5)
                print("[✓] RAT server stopped")
            except Exception as e:
                print(f"[!] Error stopping RAT server: {e}")
        
        if self.blockchain_process:
            try:
                self.blockchain_process.terminate()
                self.blockchain_process.wait(timeout=5)
                print("[✓] Blockchain server stopped")
            except Exception as e:
                print(f"[!] Error stopping blockchain server: {e}")
        
        self.running = False
    
    def monitor_processes(self):
        """Monitor running processes"""
        while self.running:
            time.sleep(5)
            
            # Check blockchain server
            if self.blockchain_process and self.blockchain_process.poll() is not None:
                print("[!] Blockchain server stopped unexpectedly")
            
            # Check RAT server
            if self.rat_server_process and self.rat_server_process.poll() is not None:
                print("[!] RAT server stopped unexpectedly")
                self.stop_all()
                break
    
    def run(self):
        """Run the control interface"""
        print("=" * 60)
        print("RAT Control Interface")
        print("Remote Administration Tool with Blockchain Persistence")
        print("=" * 60)
        print()
        
        # Start blockchain server
        if not self.start_blockchain_server():
            print("[✗] Failed to start blockchain server")
            return
        
        time.sleep(1)
        
        # Start RAT server
        if not self.start_rat_server():
            print("[✗] Failed to start RAT server")
            self.stop_all()
            return
        
        print()
        print("=" * 60)
        print("[✓] All services started successfully!")
        print()
        print("Services running:")
        print("  - Blockchain Server: Port 5444")
        print("  - RAT C2 Server: Port 4444")
        print()
        print("Press Ctrl+C to stop all services")
        print("=" * 60)
        
        self.running = True
        
        # Set up signal handler
        def signal_handler(sig, frame):
            self.stop_all()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Monitor processes
        try:
            self.monitor_processes()
        except KeyboardInterrupt:
            self.stop_all()

def main():
    """Main function"""
    control = RATControl()
    control.run()

if __name__ == "__main__":
    main()

