# Shadow Port

User-space TCP packet capture tool. 

shadowport is a transparent TCP capturing tunnel. It allows you to log traffic from/to one port to a PCAP file without root access.

Python and C implementations available. Standalone, no installation, single file, no dependencies.


## Usage

Configure shadowport to listen on a local port and forward traffic to the target server.

```text
   Client App             Shadowport                Server
┌────────────────┐      ┌────────────┐       ┌─────────────┐
│                │      │            │       │             │
│    curl to     │ 4430 │  Forward   │  443  │ example.com │
│ 127.0.0.1:4430 │─────►│   & log    │──────►│             │
│                │◄─────│            │◄──────│             │
└────────────────┘      └──────┬─────┘       └─────────────┘
                               │
                          ┌────▼───┐
                          │ .pcap  │
                          └────────┘
```

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
| `--bind-host` |  `-b` | Local bind address. Default: `127.0.0.1`. | No |
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

Note the PCAP will capture the Client Hello, Server Hello, Certificate exchange, and Key Exchange messages. So you can debug TLS issues. But the traffic will remain encrypted.


### 6. Inter-Host Traffic Capture (Man-in-the-Middle)

Use `shadowport` on a third host to intercept and log traffic between two machines.

- Host A (Client) on `192.168.1.10`
- Host B (Shadowport) on `192.168.1.50`
- Host C (Server) on `192.168.1.100`

Start *shadowport* listening on all interfaces, forwarding to the target server:

```bash
python shadowport.py -l 8080 -d 192.168.1.100 -p 80 -b 0.0.0.0 -o inter_host.pcap
```

Configure host A client to connect to host B IP and port, not to host C server:

```bash
curl http://192.168.1.50:8080
```

All traffic between host A and host C will now pass through host B, where it is forwarded and logged.


## C Implementation

Standalone C version for POSIX environments without Python.

### Compilation

Compile the source code into a static binary:

```bash
gcc -static -o shadowport shadowport.c -O2
```

Name resolution is disabled by default because Glibc NSS does not support static compilation.

To enable it use `-DENABLE_DNS`:

```bash
gcc -DENABLE_DNS -o shadowport shadowport.c -O2
```

Musl does support static and name resolution:

```bash
# Install musl tools (Debian/Ubuntu/Raspbian)
sudo apt-get install musl-tools

# Compile
musl-gcc -static -DENABLE_DNS -o shadowport shadowport.c -O2
```

For MacOS (dynamic, DNS enabled):

```bash
clang -DENABLE_DNS -o shadowport shadowport.c -O2
```

### Usage

Same as Python version:

```bash
Usage: ./shadowport -l <port> -d <dest> -p <port> [options]

Required Arguments:
  -l <port>       Local port to listen on.
  -d <ip>         Destination IPv4 address.
  -p <port>       Destination port.

Optional Arguments:
  -b <ip>         Bind address. Default: 127.0.0.1.
  -o <file>       Output PCAP file. Default: shadowport.pcap.
  --log <file>    Metadata log file (CSV format).
  -q              Quiet mode (suppress console output).
  -h              Show this help message.
```

Example:

```bash
./shadowport -l 8080 -d 192.168.1.100 -p 80 -o capture.pcap
```


## Pre-compiled Binaries

Go to the Releases page.

Note: Static ARM builds do not support hostname resolution. MacOS builds are not statically linked.


## Limitations

- Control flags (RST, FIN, ACK) are logged to match the connection state, but not captured on the wire.
- The Ethernet, IP, and TCP headers are synthetic. Physical details like TTL or MAC addresses are fake.
- Each instance handles one client connection at a time.
- UDP traffic not supported.

## License

This project is provided as is for educational and debugging purposes.

## Acknowledgments

Developed with the assistance of Qwen AI.
