#!/usr/bin/env python3
#coding:utf-8
'''
How to generate key and cert, on Windows/Linux run:
openssl req -new -x509 -keyout cert.pem -out cert.pem -days 1095 -nodes
'''

import socket
import struct
import argparse
import sys
import threading
import select
import ssl

BUF_SIZE = 4096
FLAG = 0
CMD = b"ok"  # Changed to bytes for Python 3
DEBUG = False
SSL = False
CERT = None

class Socks5proxy(object):

    def exchange_data(self, sock, remote):  # forward data
        global DEBUG
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
                    if DEBUG:
                        print(f"[*] Current active thread: {threading.active_count()}")
                        print("[*] Forwarding data...")
        except Exception as e:  # Python 3 syntax
            if DEBUG:
                print(f"[-] Exchange error: {e}")
            try:
                sock.send(b"socket error")
            except:
                pass
            try:
                remote.close()
            except:
                pass
            try:
                sock.close()
            except:
                pass
        except KeyboardInterrupt:
            try:
                remote.close()
            except:
                pass
            try:
                sock.close()
            except:
                pass
            sys.exit(1)

    def remote(self, ipaddr, port, mode, c):  # forward client request
        global FLAG
        global DEBUG
        try:
            r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            r.connect((ipaddr, port))
            if mode == 1:  # tcp type
                reply = b"\x05\x00\x00\x01"
                FLAG = 1
                if DEBUG:
                    print(f"[*] Connect success: {ipaddr}:{port}")
            else:  # udp not support
                reply = b"\x05\x07\x00\x01"
                FLAG = 0
            local = r.getsockname()
            reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
        except Exception as e:  # Python 3 syntax
            print(f"[-] Connect error: {e}")
            reply = b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
            FLAG = 0
            if DEBUG:
                print(f"[-] Connect fail: {ipaddr}:{port}")
        c.send(reply)
        return r

    def local_socks5(self, port):  # local socks5 server mode
        global BUF_SIZE
        global FLAG
        global DEBUG

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(100)
            print(f"[*] Socks5 server start on 0.0.0.0:{port}")
            while True:
                c, address = s.accept()
                if not FLAG:
                    print(f"[*] Client from: {address[0]}")
                    FLAG = 1
                c.recv(BUF_SIZE)
                c.send(b"\x05\x00")
                data = c.recv(BUF_SIZE)
                if not data[1]:
                    continue
                mode = data[1]  # Python 3: no need for ord()
                addrtype = data[3]
                if addrtype == 1:  # IPv4
                    addr = socket.inet_ntoa(data[4:8])
                    port = struct.unpack('!H', data[8:10])[0]
                elif addrtype == 3:  # Domain name
                    length = data[4]  # Python 3: no need for struct.unpack
                    addr = data[5:5 + length].decode('utf-8')
                    port = struct.unpack('!H', data[5 + length:5 + length + 2])[0]
                r = self.remote(addr, port, mode, c)
                if FLAG:
                    threading.Thread(target=self.exchange_data, args=(r, c)).start()
        except Exception as e:  # Python 3 syntax
            if DEBUG:
                print(f"[-] Server error: {e}")
            try:
                s.close()
            except:
                pass
            print("[-] Socks5 server start fail...")
            sys.exit(1)
        except KeyboardInterrupt:
            print("[-] Exit...")
            try:
                s.close()
            except:
                pass
            sys.exit(1)

    def reverse_socks5_main(self, daddr, dport):  # reverse socks5 mode main
        global BUF_SIZE
        global FLAG
        global CMD
        global DEBUG
        global SSL
        try:
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if SSL:
                s1 = ssl.wrap_socket(s1, ssl_version=ssl.PROTOCOL_TLS)
                if DEBUG:
                    print(f"[*] Cipher: {s1.cipher()}")
            s1.connect((daddr, dport))
            print(f"[*] Connected to relay server success: {daddr}:{dport}")
            while True:  # loop and recv forward server send a cmd and product a new socket to do with socks5 proxy
                flag = s1.recv(BUF_SIZE)
                if flag == CMD:
                    threading.Thread(target=self.reverse_socks5_hand, args=(daddr, dport)).start()
        except Exception as e:  # Python 3 syntax
            if DEBUG:
                print(f"[-] Reverse main error: {e}")
            print("[-] Connect relay server fail...")
            try:
                s1.close()
            except:
                pass
            sys.exit(1)
        except KeyboardInterrupt:
            print("[-] Exit...")
            try:
                s1.close()
            except:
                pass
            sys.exit(1)

    def reverse_socks5_hand(self, daddr, dport):  # reverse socks5 mode handshake
        global DEBUG
        global SSL
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if SSL:
                s2 = ssl.wrap_socket(s2, ssl_version=ssl.PROTOCOL_TLS)
                if DEBUG:
                    print(f"[*] Cipher: {s2.cipher()}")
            s2.connect((daddr, dport))
            if DEBUG:
                print("[*] New socket start...")
            s2.recv(BUF_SIZE)
            s2.send(b"\x05\x00")
            data = s2.recv(BUF_SIZE)
            if data:
                mode = data[1]  # Python 3: no need for ord()
                addrtype = data[3]
                if addrtype == 1:  # IPv4
                    addr = socket.inet_ntoa(data[4:8])
                    port = struct.unpack('!H', data[8:10])[0]
                elif addrtype == 3:  # Domain name
                    length = data[4]  # Python 3: no need for struct.unpack
                    addr = data[5:5 + length].decode('utf-8')
                    port = struct.unpack('!H', data[5 + length:5 + length + 2])[0]
                r = self.remote(addr, port, mode, s2)  # forward requests
                self.exchange_data(s2, r)
            else:
                try:
                    s2.close()
                except:
                    pass
        except Exception as e:  # Python 3 syntax
            if DEBUG:
                print(f"[-] Reverse hand error: {e}")
            try:
                s2.close()
            except:
                pass
        except KeyboardInterrupt:
            print("[-] Exit...")
            try:
                s2.close()
            except:
                pass
            sys.exit(1)

    def forward_translate(self, s, c):  # port data exchange
        global BUF_SIZE
        global DEBUG
        try:
            conlist = [c, s]
            while True:
                r, w, e = select.select(conlist, [], [])
                if c in r:
                    data = c.recv(BUF_SIZE)
                    if not data or s.send(data) <= 0:
                        c.close()
                        s.close()
                        break
                if s in r:
                    data = s.recv(BUF_SIZE)
                    if not data or c.send(data) <= 0:
                        s.close()
                        c.close()
                        break
                    if DEBUG:
                        print(f"[*] Current active thread: {threading.active_count()}")
                        print("[*] Forwarding data...")
        except Exception as e:  # Python 3 syntax
            if DEBUG:
                print(f"[-] Forward translate error: {e}")
            try:
                s.close()
            except:
                pass
            try:
                c.close()
            except:
                pass
        except KeyboardInterrupt:
            print("[-] Exit...")
            try:
                s.close()
            except:
                pass
            try:
                c.close()
            except:
                pass
            sys.exit(1)

    def forward_main(self, ports):  # forward mode
        global BUF_SIZE
        global CMD
        global DEBUG
        global SSL
        global CERT

        try:
            sock_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # listen on port1 socks5 server rev
            sock_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_s.bind(("0.0.0.0", ports[0]))
            sock_s.listen(100)
            print(f"[*] Listen on 0.0.0.0:{ports[0]}")
        except Exception as e:  # Python 3 syntax
            print(f"[-] Port {ports[0]} has been used or permission denied!")
            if DEBUG:
                print(f"[-] Error: {e}")
            sys.exit(1)

        try:
            sock_c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # port 2
            sock_c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_c.bind(("0.0.0.0", ports[1]))
            sock_c.listen(100)
            print(f"[*] Listen on 0.0.0.0:{ports[1]}")
        except Exception as e:  # Python 3 syntax
            print(f"[-] Port {ports[1]} has been used or permission denied!")
            if DEBUG:
                print(f"[-] Error: {e}")
            sys.exit(1)

        try:
            inputs = [sock_s, sock_c]
            con_cmd = None
            first_con = 1
            while True:  # Asynchronous I/O
                rs, ws, es = select.select(inputs, [], [])
                if sock_s in rs:
                    if not con_cmd:  # accept server reverse socket as cmd socket
                        con_s, address1 = sock_s.accept()
                        if SSL:
                            con_s = ssl.wrap_socket(con_s,
                                                  server_side=True,
                                                  certfile=CERT,
                                                  keyfile=CERT,
                                                  ssl_version=ssl.PROTOCOL_TLS)
                            if DEBUG:
                                print(f"[*] Cipher: {con_s.cipher()}")
                        print(f"[*] Client from: {address1[0]}:{address1[1]} on Port {ports[0]}")
                        con_cmd = con_s

                if sock_c in rs:
                    con_c, address2 = sock_c.accept()
                    if DEBUG:
                        print(f"[*] Client from: {address2[0]}:{address2[1]} on Port {ports[1]}")
                    else:
                        if first_con:  # first client connect print client connect information
                            print(f"[*] Client from: {address2[0]}:{address2[1]} on Port {ports[1]}")
                            first_con = 0
                    if con_cmd:  # if cmd socket connected, send cmd, let server product a new socket
                        con_cmd.send(CMD)
                        con_s_tun, con_s_tun_addr = sock_s.accept()  # data transport socket
                        if SSL:
                            con_s_tun = ssl.wrap_socket(con_s_tun,
                                                      server_side=True,
                                                      certfile=CERT,
                                                      keyfile=CERT,
                                                      ssl_version=ssl.PROTOCOL_TLS)
                            if DEBUG:
                                print(f"[*] Cipher: {con_s_tun.cipher()}")
                        threading.Thread(target=self.forward_translate, args=(con_s_tun, con_c)).start()
        except KeyboardInterrupt:
            print("[-] Exit...")
            try:
                sock_s.close()
            except:
                pass
            try:
                sock_c.close()
            except:
                pass
            sys.exit(1)

def main():
    global DEBUG
    global SSL
    global CERT
    parser = argparse.ArgumentParser(prog='tsocks_py3',
                        description='tsocks v2.0 - Python 3 Windows Compatible',
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                        usage='''%(prog)s [options]
  tsocks_py3 -s -p 1028           Socks5 server mode
  tsocks_py3 -s -r 1.1.1.1 -p 8001    Reverse socks5 server mode
  tsocks_py3 -f 8001 8002         Port forward mode
  tsocks_py3 -s -S -r 1.1.1.1 -p 443  Reverse socks5 over ssl
  tsocks_py3 -f 443 8002 -S -c cert.pem    Port forward over ssl
  -----------------------------------------------------------------------
  Generate cert (Windows with OpenSSL):
  openssl req -new -x509 -keyout cert.pem -out cert.pem -days 1095 -nodes''')
    
    parser.add_argument('-s', '--server', action="store_true", default=False,
                       help='Socks5 server mode')
    parser.add_argument('-p', '--port', metavar="PORT", dest='port', type=int, default=1080,
                       help='Socks5 server mode listen port or remote port')
    parser.add_argument('-r', '--remote', metavar="REMOTE_IP", type=str, default=None,
                       help='Reverse socks5 server mode, set remote relay IP')
    parser.add_argument('-f', '--forward', nargs=2, metavar=('PORT_1', 'PORT_2'), type=int,
                       help='Set forward mode, server connect port_1, client connect port_2')
    parser.add_argument('-d', '--debug', action="store_true", default=False,
                       help='Set debug mode, will show debug information')
    parser.add_argument('-S', '--ssl', action="store_true", default=False,
                       help='Set use ssl, just support reverse proxy mode, relay server must also use ssl')
    parser.add_argument('-c', '--cert', metavar='CERT_FILE', type=str, default="cert.pem",
                       help='Set ssl cert file path, only set relay server')
    
    args = parser.parse_args()
    DEBUG = args.debug
    SSL = args.ssl
    CERT = args.cert

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    if args.server and args.forward:
        print("[-] Socks5 or forward mode only one...")
        sys.exit(1)
    
    if args.ssl and args.forward:
        try:
            with open(args.cert, 'r') as f:
                pass
        except Exception as e:  # Python 3 syntax
            if DEBUG:
                print(f"[-] Cert error: {e}")
            print("[-] Cert file not exist or error...")
            sys.exit(1)

    if args.server:
        if args.remote:  # start reverse socks5 mode
            while True:
                resocks5 = Socks5proxy()
                resocks5.reverse_socks5_main(args.remote, args.port)
        else:  # start local socks5 mode
            while True:
                losocks5 = Socks5proxy()
                losocks5.local_socks5(args.port)
    
    if args.forward:  # start port forward mode
        while True:
            lforward = Socks5proxy()
            lforward.forward_main(args.forward)

if __name__ == '__main__':
    main() 