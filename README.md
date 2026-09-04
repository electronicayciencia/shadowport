# Shadow Port

An user-space TCP packet capture tool. 

shadowport is a transparent TCP capturing tunnel. It allows you to intercept and log traffic to a PCAP file for Wireshark analysis without root access.

## Usage

No installation. Single python file with no dependencies.

### Basic Syntax

```bash
python shadowport.py -l <local_port> -d <dest_host> -p <dest_port> [options]
```

### Arguments

| Argument | Short | Description | Required |
| :--- | :--- | :--- | :--- |
| `--listen-port` | `-l` | Local port to listen on. | Yes |
| `--dest-host` | `-d` | Destination host (IP address or hostname). | Yes |
| `--dest-port` | `-p` | Destination port. | Yes |
| `--output` | `-o` | Output PCAP file path. Default: `shadowport.pcap`. | No |
| `--log` | | Path for metadata log file. If omitted, no log is created. | No |
| `--listen-host` | | Local bind address. Default: `0.0.0.0`. | No |
| `--quiet` | `-q` | Run silently. Suppresses console output. | No |

## Examples

### 1. DNS over TCP
Capture clear-text DNS queries by forwarding local TCP traffic to a DNS server.

```bash
python shadowport.py -l 5300 -d 8.8.8.8 -p 53 -o dns_tcp.pcap
```

Use a tool like `dig` to test:
```bash
dig @127.0.0.1 -p 5300 +tcp example.com
```

### 2. SSH Traffic (Encrypted)
Capture encrypted SSH sessions. While the payload is encrypted, you can analyze the handshake, key exchange or packet timing.

```bash
python shadowport.py -l 2200 -d ssh.example.com -p 22 -o ssh_capture.pcap
```

Connect via SSH:
```bash
ssh -p 2200 user@127.0.0.1
```

### 3. HTTP Service (Clear-text)
Capture HTTP traffic, including headers and body content.

```bash
python shadowport.py -l 8000 -d example.com -p 80 -o http_capture.pcap
```

Use `curl` to generate traffic. Use the Host header to present the correct hostname and port to the server.
```bash
curl -H "Host: example.com" http://127.0.0.1:8000
```

### 4. HTTPS Service (for TLS Handshake Debugging)
Capture encrypted HTTPS traffic. By using `curl --resolve` and Host header, you can force the client to connect to your local tunnel while maintaining the correct SNI (Server Name Indication) for the TLS handshake.

```bash
python shadowport.py -l 4430 -d example.com -p 443 -o https_capture.pcap
```

Use `curl` with the `--resolve` flag to map the domain to localhost on the listening port (4430). Use the `Host` header to set the correct hostname and port:

```bash
curl --resolve example.com:4430:127.0.0.1 -H "Host: example.com" https://example.com:4430/
```

Use `-k` in case of certificate error.


### 5. SSL/TLS Handshake Debugging with OpenSSL
Use `openssl s_client` to manually trigger a TLS handshake through the tunnel.

```bash
python shadowport.py -l 8443 -d example.com -p 443 -o ssl_handshake.pcap
```

Connect using `openssl` and specify the Server Name Indication (SNI) via the `-servername` flag:

```bash
openssl s_client -connect 127.0.0.1:8443 -servername example.com
```

Note: The PCAP will capture the Client Hello, Server Hello, Certificate exchange, and Key Exchange messages, allowing you to debug TLS configuration issues. But the traffic will remain encrypted.


## Limitations

- The Ethernet, IP, and TCP headers in the PCAP are fake. They contain correct sequence numbers and checksums for Wireshark reassembly but do not reflect physical network status (TTL, MAC addresses, etc.) nor actual TCP/IP frames (RST, FIN, ACK). Only the TCP payload is truly captured from the application.
- Each instance handles one client connection at a time.
- UDP traffic not supported.

## License

This project is provided as-is for educational and debugging purposes.
