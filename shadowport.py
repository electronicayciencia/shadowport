#!/usr/bin/env python3
"""
shadowport: Transparent TCP Tunnel with PCAP logging.
- Listens on local port, forwards to destination (IP or Hostname).
- Logs traffic to PCAP using REAL Client IP/Port and Destination IP.
- Optional metadata logging.
- Handles signals (Ctrl+C, SIGTERM) gracefully.
- No third-party libraries.
"""

import socket
import struct
import time
import sys
import argparse
import select
import signal
import os


class PcapWriter:
    """Minimal PCAP writer."""

    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'wb')
        self._write_global_header()

    def _write_global_header(self):
        # Magic, VerMajor, VerMinor, ThisZone, SigFigs, SnapLen, Network(LINKTYPE_ETHERNET=1)
        header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        self.file.flush()

    def write_packet(self, raw_bytes, ts=None):
        if ts is None:
            ts = time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        pkt_hdr = struct.pack('<IIII', sec, usec, len(raw_bytes), len(raw_bytes))
        self.file.write(pkt_hdr)
        self.file.write(raw_bytes)
        self.file.flush()

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()


class MetadataLogger:
    """Logs connection metadata to a text file."""

    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'a')
        # Write header if file is new/empty
        if os.path.getsize(filename) == 0:
            self.file.write("timestamp,client_ip,client_port,duration_sec,bytes_c2s,bytes_s2c\n")
            self.file.flush()

    def log_connection(self, client_ip, client_port, duration, bytes_c2s, bytes_s2c):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"{ts},{client_ip},{client_port},{duration:.2f},{bytes_c2s},{bytes_s2c}\n"
        self.file.write(line)
        self.file.flush()

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()


def ip_checksum(data: bytes) -> int:
    """Standard internet checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_packet(src_mac, dst_mac, src_ip, dst_ip,
                 src_port, dst_port, seq, ack, flags, payload, ip_id):
    """Build Ethernet+IP+TCP frame."""
    
    # --- TCP Header ---
    tcp_hdr_no_cksum = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq, ack,
        (5 << 4), flags,
        65535, 0, 0
    )

    # TCP Checksum
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, len(tcp_hdr_no_cksum) + len(payload)
    )
    cksum_data = pseudo + tcp_hdr_no_cksum + payload
    tcp_cksum = ip_checksum(cksum_data)

    tcp_header = tcp_hdr_no_cksum[:16] + struct.pack('!H', tcp_cksum) + tcp_hdr_no_cksum[18:]

    # --- IP Header ---
    total_len = 20 + len(tcp_header) + len(payload)
    ip_hdr_no_cksum = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, total_len,
        ip_id, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    )
    ip_cksum = ip_checksum(ip_hdr_no_cksum)
    ip_header = ip_hdr_no_cksum[:10] + struct.pack('!H', ip_cksum) + ip_hdr_no_cksum[12:]

    # --- Ethernet Header ---
    eth_header = dst_mac + src_mac + struct.pack('!H', 0x0800)

    return eth_header + ip_header + tcp_header + payload


class Shadowport:
    CLIENT_MAC = b'\x00\x11\x22\x33\x44\x55'
    SERVER_MAC = b'\x66\x77\x88\x99\xaa\xbb'

    def __init__(self, listen_host, listen_port, dest_host, dest_port, pcap_path, log_path, quiet=False):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.pcap_path = pcap_path
        self.log_path = log_path
        self.quiet = quiet
        self.pcap = None
        self.meta_log = None
        self.ip_id = 1
        self.running = True

    def _log(self, message):
        """Print to console only if not in quiet mode."""
        if not self.quiet:
            print(message)

    def log_packet(self, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        if src_ip == self.dest_host:
            src_mac, dst_mac = self.SERVER_MAC, self.CLIENT_MAC
        else:
            src_mac, dst_mac = self.CLIENT_MAC, self.SERVER_MAC
            
        frame = build_packet(
            src_mac, dst_mac,
            src_ip, dst_ip,
            src_port, dst_port,
            seq, ack, flags, payload, self.ip_id
        )
        self.pcap.write_packet(frame)
        self.ip_id = (self.ip_id + 1) & 0xFFFF

    def handle_client(self, client_sock, client_addr):
        client_ip = client_addr[0]
        client_port = client_addr[1]
        start_time = time.time()
        
        self._log(f"[+] Connection from {client_ip}:{client_port}")
        
        server_sock = None
        bytes_c2s = 0
        bytes_s2c = 0
        
        try:
            # Resolve hostname to IP for this specific connection
            # This ensures the PCAP has a valid IP even if dest_host was a name
            addr_info = socket.getaddrinfo(self.dest_host, self.dest_port, socket.AF_INET, socket.SOCK_STREAM)
            if not addr_info:
                raise Exception(f"Could not resolve {self.dest_host}")
            
            # Use the first available IPv4 address
            dest_ip = addr_info[0][4][0]
            
            server_sock = socket.create_connection((dest_ip, self.dest_port), timeout=10)
            self._log(f"[+] Connected to {self.dest_host} ({dest_ip}):{self.dest_port}")

            d_host = dest_ip
            d_port = self.dest_port

            c_seq, s_seq = 1000, 2000

            # Handshake
            self.log_packet(client_ip, d_host, client_port, d_port, c_seq, 0, 0x02, b'')
            c_seq += 1
            self.log_packet(d_host, client_ip, d_port, client_port, s_seq, c_seq, 0x12, b'')
            s_seq += 1
            self.log_packet(client_ip, d_host, client_port, d_port, c_seq, s_seq, 0x10, b'')

            client_sock.setblocking(False)
            server_sock.setblocking(False)

            sockets = [client_sock, server_sock]
            
            while self.running:
                try:
                    readable, _, _ = select.select(sockets, [], [], 1.0)
                except (ValueError, OSError):
                    break 

                for s in readable:
                    is_client = (s is client_sock)
                    peer = server_sock if is_client else client_sock
                    
                    try:
                        data = s.recv(65535)
                    except (ConnectionResetError, OSError):
                        data = b''
                    
                    if not data:
                        self._log(f"[-] {'Client' if is_client else 'Server'} closed connection")
                        
                        if is_client:
                            self.log_packet(client_ip, d_host, client_port, d_port, c_seq, s_seq, 0x01, b'')
                            c_seq += 1
                        else:
                            self.log_packet(d_host, client_ip, d_port, client_port, s_seq, c_seq, 0x01, b'')
                            s_seq += 1

                        try:
                            peer.shutdown(socket.SHUT_WR)
                        except:
                            pass
                        
                        if s in sockets:
                            sockets.remove(s)
                        
                        if not sockets:
                            return
                        continue

                    try:
                        peer.sendall(data)
                    except (BrokenPipeError, OSError):
                        break

                    if is_client:
                        self.log_packet(client_ip, d_host, client_port, d_port, c_seq, s_seq, 0x10, data)
                        c_seq += len(data)
                        bytes_c2s += len(data)
                    else:
                        self.log_packet(d_host, client_ip, d_port, client_port, s_seq, c_seq, 0x10, data)
                        s_seq += len(data)
                        bytes_s2c += len(data)

        except Exception as e:
            self._log(f"[!] Error handling connection: {e}")
        finally:
            duration = time.time() - start_time
            if self.meta_log:
                self.meta_log.log_connection(client_ip, client_port, duration, bytes_c2s, bytes_s2c)
            
            for s in [server_sock, client_sock]:
                if s:
                    try:
                        s.close()
                    except:
                        pass
            self._log(f"[*] Connection finished ({duration:.2f}s)")

    def run(self):
        self.pcap = PcapWriter(self.pcap_path)
        
        # Initialize metadata logger only if a path is provided
        if self.log_path:
            self.meta_log = MetadataLogger(self.log_path)
            self._log(f"[*] Metadata log: {self.log_path}")
        
        self._log(f"[*] shadowport started")
        self._log(f"[*] PCAP output: {self.pcap_path}")

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(1)
        srv.settimeout(1.0)
        
        self._log(f"[*] Listening on {self.listen_host}:{self.listen_port} -> {self.dest_host}:{self.dest_port}")
        if not self.quiet:
            print("[*] Press Ctrl+C to stop")

        try:
            while self.running:
                try:
                    client_sock, addr = srv.accept()
                    self.handle_client(client_sock, addr)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except KeyboardInterrupt:
            if not self.quiet:
                print("\n[*] Interrupt received")
        finally:
            self.running = False
            srv.close()
            if self.pcap:
                self.pcap.close()
            if self.meta_log:
                self.meta_log.close()
            self._log(f"[*] shadowport stopped")


def signal_handler(sig, frame):
    sys.exit(0)

def main():
    # Handle SIGTERM (Unix/Linux/Docker)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Handle SIGHUP only if available (Unix/Linux, not Windows)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, signal_handler)

    p = argparse.ArgumentParser(description='shadowport: Transparent TCP tunnel with capture')
    p.add_argument('-l', '--listen-port', type=int, required=True, help='Local port')
    p.add_argument('-d', '--dest-host', required=True, help='Destination host (IP or Hostname)')
    p.add_argument('-p', '--dest-port', type=int, required=True, help='Destination port')
    p.add_argument('-o', '--output', default='shadowport.pcap', help='PCAP file')
    p.add_argument('--log', default=None, help='Metadata log file (optional)')
    p.add_argument('--listen-host', default='0.0.0.0', help='Bind address')
    p.add_argument('-q', '--quiet', action='store_true', help='Run silently (no console output)')
    args = p.parse_args()

    tunnel = Shadowport(
        args.listen_host, 
        args.listen_port, 
        args.dest_host, 
        args.dest_port, 
        args.output, 
        args.log,
        args.quiet
    )
    tunnel.run()


if __name__ == '__main__':
    main()