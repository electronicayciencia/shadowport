# Shadowport: Project Context & Design Decisions

> **Instruction for AI:** Use this document to understand the current state, architectural constraints, and technical decisions of the Shadowport project. All future code generation and advice must align with these premises.

## 1. Project Overview
**Shadowport** is a user-space TCP tunnel and packet capture tool. It acts as a transparent proxy, forwarding traffic from a local port to a remote destination while logging the TCP payload to a PCAP file for Wireshark analysis. It requires no root privileges.

**Core Features:**
- Transparent TCP forwarding.
- PCAP generation with synthetic but valid headers (Ethernet/IP/TCP).
- Metadata logging (CSV) with connection status tracking.
- Available in two implementations: Python (feature-rich) and C (portable/static).

## 2. Technical Premises & Constraints

### General Architecture
- **Default Bind Address:** `127.0.0.1` (Security-first default).
- **Protocol:** TCP only. UDP is not supported.
- **Concurrency:** Single-threaded, handling one client connection at a time per instance.
- **PCAP Headers:** Synthetic. Sequence numbers and checksums are valid for Wireshark reassembly, but physical attributes (TTL, MAC) are emulated.
- **TCP State:** 
  - `FIN` packets increment sequence numbers.
  - `RST` packets do **not** increment sequence numbers.
  - Graceful half-close (`SHUT_WR`) is used for FINs; immediate teardown for RSTs.

### Metadata Logging
- **Format:** CSV.
- **Header:** `timestamp,client_ip,client_port,dest_ip,dest_port,duration_sec,bytes_c2s,bytes_s2c,status`
- **Status Codes:** 
  - `OK`: Normal closure.
  - `REFUSED`: Connection actively refused by destination.
  - `RST`: Abrupt reset during transfer.
  - `DNS_ERROR`: Hostname resolution failed.
  - `TIMEOUT`: Connection attempt timed out.

## 3. Implementation Details

### Python Version (`shadowport.py`)
- **Dependencies:** Standard library only (`socket`, `struct`, `argparse`, `select`).
- **Hostname Support:** Full support via `socket.getaddrinfo`.
- **Signal Handling:** Graceful shutdown on `SIGINT`.

### C Version (`shadowport.c`)
- **Goal:** Fully static, single-file binary for maximum portability.
- **DNS Resolution Strategy:**
  - Controlled by the `ENABLE_DNS` preprocessor flag.
  - **If `ENABLE_DNS` is defined:** Uses `getaddrinfo` (requires `musl-gcc` for true static linking without glibc NSS warnings).
  - **If `ENABLE_DNS` is undefined:** Accepts only IPv4 addresses. Uses `inet_pton` for validation. Compatible with standard `gcc -static`.
- **I/O Model:** Non-blocking sockets (`fcntl`) + `select()`.
  - Prevents hanging on unreachable ports.
  - Allows graceful Ctrl+C (`SIGINT`) handling during connection attempts.
- **Connection Logic:** Implements non-blocking `connect()` with a 10-second timeout using `select()` on the write set.
- **Loop Safety:** Tracks `client_closed` and `server_closed` flags to prevent infinite loops after FIN/RST events.

## 4. Build & CI/CD (GitHub Actions)

### Workflow Configuration (`.github/workflows/build.yml`)
- **Triggers:** Push to `master`, PR to `master`, `workflow_dispatch`.
- **Permissions:** Requires `permissions: contents: write` for release management.

### Build Jobs
1.  **Linux x64:** 
    - Tool: `musl-gcc`
    - Flags: `-static -DENABLE_DNS`
    - Feature: Supports hostnames.
2.  **ARMv5:** 
    - Tool: `arm-linux-gnueabi-gcc`
    - Flags: `-static -march=armv5te`
    - Feature: IP-only (legacy embedded support).
3.  **ARMv7:** 
    - Tool: `arm-linux-gnueabihf-gcc`
    - Flags: `-static -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard`
    - Feature: IP-only (modern 32-bit ARM).

### Release Automation
- A final job `update-release` runs after all builds.
- Uses `actions/download-artifact@v4` and GitHub CLI (`gh`).
- Creates or updates a release tagged `latest`.
- **Critical Env Var:** `GH_REPO: ${{ github.repository }}` must be set to avoid git context errors in the artifact-only environment.
- Uses `--clobber` to replace existing assets.

## 5. Current File Structure
- `shadowport.py`: Python implementation.
- `shadowport.c`: C implementation (with `#ifdef ENABLE_DNS` blocks).
- `.github/workflows/build.yml`: CI/CD pipeline.
- `README.md`: Documentation with architecture diagrams and usage examples.
- `CONTEXT.md`: This file.

## 6. Command-Line Interface (CLI)
Both versions share similar arguments:
- `-l <port>`: Local listen port (Required).
- `-d <host/ip>`: Destination (Required).
- `-p <port>`: Destination port (Required).
- `-b <ip>`: Bind address (Default: `127.0.0.1`).
- `-o <file>`: Output PCAP (Default: `shadowport.pcap`).
- `--log <file>`: Metadata CSV log (Optional).
- `-q`: Quiet mode.

***

### How to use this file:
1.  **For Human Contributors:** Read this to understand why certain architectural choices (like musl vs. glibc) were made.
2.  **For AI Assistants:** Paste the entire content of this file at the beginning of a new chat session to instantly restore full project context.