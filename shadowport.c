#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>

#ifdef ENABLE_DNS
#include <netdb.h>
#endif

#define BUFFER_SIZE 65535
#define PCAP_MAGIC 0xa1b2c3d4
#define CLIENT_MAC "\x00\x11\x22\x33\x44\x55"
#define SERVER_MAC "\x66\x77\x88\x99\xaa\xbb"
#define VERSION "1.0"

// Global flag for signal handling
volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    running = 0;
}

// --- PCAP Structures ---

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} eth_header_t;

typedef struct {
    uint8_t ver_ihl;
    uint8_t dscp_ecn;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_flags;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

// --- Checksum Calculation ---

uint16_t calculate_checksum(uint16_t *addr, int len) {
    long sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// --- PCAP Writer ---

FILE *pcap_file = NULL;
uint16_t ip_id_counter = 1;

void init_pcap(const char *filename) {
    pcap_file = fopen(filename, "wb");
    if (!pcap_file) {
        perror("Failed to open PCAP file");
        exit(1);
    }
    
    pcap_global_header_t global_hdr;
    global_hdr.magic_number = PCAP_MAGIC;
    global_hdr.version_major = 2;
    global_hdr.version_minor = 4;
    global_hdr.thiszone = 0;
    global_hdr.sigfigs = 0;
    global_hdr.snaplen = 65535;
    global_hdr.network = 1; // Ethernet
    
    fwrite(&global_hdr, sizeof(global_hdr), 1, pcap_file);
    fflush(pcap_file);
}

void log_packet(const char *src_ip_str, const char *dst_ip_str,
                uint16_t src_port, uint16_t dst_port,
                uint32_t seq, uint32_t ack, uint8_t flags,
                const uint8_t *payload, size_t payload_len,
                int is_from_server) {
    
    if (!pcap_file) return;

    struct timeval tv;
    gettimeofday(&tv, NULL);

    size_t tcp_hdr_len = 20;
    size_t ip_hdr_len = 20;
    size_t eth_hdr_len = 14;
    size_t total_len = eth_hdr_len + ip_hdr_len + tcp_hdr_len + payload_len;
    
    unsigned char *packet = malloc(total_len);
    if (!packet) return;
    memset(packet, 0, total_len);

    // 1. TCP Header
    tcp_header_t *tcp = (tcp_header_t *)(packet + eth_hdr_len + ip_hdr_len);
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_num = htonl(seq);
    tcp->ack_num = htonl(ack);
    tcp->data_offset_flags = (5 << 4); // Data offset 5 words (20 bytes)
    tcp->flags = flags;
    tcp->window = htons(65535);
    
    // TCP Checksum
    struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } pseudo;
    
    pseudo.src_ip = inet_addr(src_ip_str);
    pseudo.dst_ip = inet_addr(dst_ip_str);
    pseudo.zero = 0;
    pseudo.protocol = 6; // TCP
    pseudo.tcp_len = htons(tcp_hdr_len + payload_len);
    
    size_t cksum_buf_len = sizeof(pseudo) + tcp_hdr_len + payload_len;
    unsigned char *cksum_buf = malloc(cksum_buf_len + 1); // +1 for padding safety
    memset(cksum_buf, 0, cksum_buf_len + 1);
    
    memcpy(cksum_buf, &pseudo, sizeof(pseudo));
    memcpy(cksum_buf + sizeof(pseudo), tcp, tcp_hdr_len);
    if (payload_len > 0) {
        memcpy(cksum_buf + sizeof(pseudo) + tcp_hdr_len, payload, payload_len);
    }
    
    tcp->checksum = calculate_checksum((uint16_t *)cksum_buf, cksum_buf_len);
    free(cksum_buf);

    // 2. IP Header
    ip_header_t *ip = (ip_header_t *)(packet + eth_hdr_len);
    ip->ver_ihl = 0x45;
    ip->total_len = htons(ip_hdr_len + tcp_hdr_len + payload_len);
    ip->id = htons(ip_id_counter++);
    ip->flags_frag = htons(0x4000); // Don't fragment
    ip->ttl = 64;
    ip->protocol = 6;
    ip->src_ip = inet_addr(src_ip_str);
    ip->dst_ip = inet_addr(dst_ip_str);
    ip->checksum = calculate_checksum((uint16_t *)ip, ip_hdr_len);

    // 3. Ethernet Header
    eth_header_t *eth = (eth_header_t *)packet;
    if (is_from_server) {
        memcpy(eth->src_mac, SERVER_MAC, 6);
        memcpy(eth->dst_mac, CLIENT_MAC, 6);
    } else {
        memcpy(eth->src_mac, CLIENT_MAC, 6);
        memcpy(eth->dst_mac, SERVER_MAC, 6);
    }
    eth->ethertype = htons(0x0800);

    // Payload
    if (payload_len > 0) {
        memcpy(packet + eth_hdr_len + ip_hdr_len + tcp_hdr_len, payload, payload_len);
    }

    // Write to PCAP
    pcap_packet_header_t pkt_hdr;
    pkt_hdr.ts_sec = tv.tv_sec;
    pkt_hdr.ts_usec = tv.tv_usec;
    pkt_hdr.incl_len = total_len;
    pkt_hdr.orig_len = total_len;

    fwrite(&pkt_hdr, sizeof(pkt_hdr), 1, pcap_file);
    fwrite(packet, total_len, 1, pcap_file);
    fflush(pcap_file);

    free(packet);
}

// --- Metadata Logger ---

FILE *meta_file = NULL;

void init_meta(const char *filename) {
    meta_file = fopen(filename, "a");
    if (meta_file) {
        if (ftell(meta_file) == 0) {
            fprintf(meta_file, "timestamp,client_ip,client_port,dest_ip,dest_port,duration_sec,bytes_c2s,bytes_s2c,status\n");
            fflush(meta_file);
        }
    }
}

void log_meta(const char *client_ip, int client_port, const char *dest_ip, int dest_port, 
              double duration, long bytes_c2s, long bytes_s2c, const char *status) {
    if (!meta_file) return;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
    
    fprintf(meta_file, "%s,%s,%d,%s,%d,%.2f,%ld,%ld,%s\n", 
            time_str, client_ip, client_port, dest_ip, dest_port, 
            duration, bytes_c2s, bytes_s2c, status);
    fflush(meta_file);
}

// --- Main Logic ---

void handle_client(int client_fd, struct sockaddr_in *client_addr, 
                   const char *dest_host_str, int dest_port, 
                   const char *pcap_path, const char *meta_path) {
    
    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip_str, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr->sin_port);
    
    printf("[+] Connection from %s:%d\n", client_ip_str, client_port);
    
    char dest_ip_str[INET_ADDRSTRLEN];
    struct in_addr dest_ip_addr;

#ifdef ENABLE_DNS
    // Resolve Destination using getaddrinfo
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", dest_port);
    
    if (getaddrinfo(dest_host_str, port_str, &hints, &res) != 0) {
        fprintf(stderr, "[!] DNS Resolution failed for %s\n", dest_host_str);
        log_meta(client_ip_str, client_port, dest_host_str, dest_port, 0, 0, 0, "DNS_ERROR");
        close(client_fd);
        return;
    }
    
    struct sockaddr_in *p = (struct sockaddr_in *)res->ai_addr;
    dest_ip_addr = p->sin_addr;
    inet_ntop(AF_INET, &dest_ip_addr, dest_ip_str, INET_ADDRSTRLEN);
    freeaddrinfo(res);
#else
    // Use raw IP
    if (inet_pton(AF_INET, dest_host_str, &dest_ip_addr) != 1) {
        fprintf(stderr, "[!] Invalid destination IP format. Hostnames not supported in this build.\n");
        close(client_fd);
        return;
    }
    strncpy(dest_ip_str, dest_host_str, INET_ADDRSTRLEN);
#endif

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        close(client_fd);
        return;
    }
    
    // Log SYN
    log_packet(client_ip_str, dest_ip_str, client_port, dest_port, 1000, 0, 0x02, NULL, 0, 0);
    
    // Connect
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(dest_port);
    server_addr.sin_addr = dest_ip_addr;
    
    // Set server socket to non-blocking for connect()
    fcntl(server_fd, F_SETFL, O_NONBLOCK);
    
    int conn_res = connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    if (conn_res < 0 && errno != EINPROGRESS) {
        perror("[!] Connection failed immediately");
        log_packet(dest_ip_str, client_ip_str, dest_port, client_port, 2000, 1001, 0x04, NULL, 0, 1);
        log_meta(client_ip_str, client_port, dest_ip_str, dest_port, 0, 0, 0, "REFUSED");
        close(client_fd);
        close(server_fd);
        return;
    }
    
    // Wait for connection to complete using select()
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(server_fd, &writefds);
    
    struct timeval timeout;
    timeout.tv_sec = 10; // 10 second timeout for connection
    timeout.tv_usec = 0;
    
    printf("[*] Connecting to %s:%d ...\n", dest_ip_str, dest_port);
    
    int activity = select(server_fd + 1, NULL, &writefds, NULL, &timeout);
    
    if (activity <= 0) {
        if (!running) {
            printf("\n[*] Interrupted during connection\n");
        } else {
            fprintf(stderr, "[!] Connection timed out\n");
        }
        log_packet(dest_ip_str, client_ip_str, dest_port, client_port, 2000, 1001, 0x04, NULL, 0, 1);
        log_meta(client_ip_str, client_port, dest_ip_str, dest_port, 0, 0, 0, "TIMEOUT");
        close(client_fd);
        close(server_fd);
        return;
    }
    
    // Check if connection actually succeeded
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(server_fd, SOL_SOCKET, SO_ERROR, &err, &len);
    
    if (err != 0) {
        fprintf(stderr, "[!] Connection failed: %s\n", strerror(err));
        log_packet(dest_ip_str, client_ip_str, dest_port, client_port, 2000, 1001, 0x04, NULL, 0, 1);
        log_meta(client_ip_str, client_port, dest_ip_str, dest_port, 0, 0, 0, "REFUSED");
        close(client_fd);
        close(server_fd);
        return;
    }
    
    printf("[+] Connected to %s (%s):%d\n", dest_host_str, dest_ip_str, dest_port);
    
    // Log SYN-ACK and ACK
    log_packet(dest_ip_str, client_ip_str, dest_port, client_port, 2000, 1001, 0x12, NULL, 0, 1);
    log_packet(client_ip_str, dest_ip_str, client_port, dest_port, 1001, 2001, 0x10, NULL, 0, 0);
    
    uint32_t c_seq = 1001;
    uint32_t s_seq = 2001;
    long bytes_c2s = 0;
    long bytes_s2c = 0;
    time_t start_time = time(NULL);
    const char *status = "OK";
    
    int client_closed = 0;
    int server_closed = 0;
    
    while (running && !(client_closed && server_closed)) {
        fd_set readfds;
        FD_ZERO(&readfds);
        
        int max_fd = -1;
        if (!client_closed) {
            FD_SET(client_fd, &readfds);
            if (client_fd > max_fd) max_fd = client_fd;
        }
        if (!server_closed) {
            FD_SET(server_fd, &readfds);
            if (server_fd > max_fd) max_fd = server_fd;
        }
        
        if (max_fd < 0) break;
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        // Client to Server
        if (!client_closed && FD_ISSET(client_fd, &readfds)) {
            char buf[BUFFER_SIZE];
            ssize_t n = recv(client_fd, buf, BUFFER_SIZE, 0);
            
            if (n <= 0) {
                if (n == 0) {
                    printf("[-] Client closed connection (FIN)\n");
                    log_packet(client_ip_str, dest_ip_str, client_port, dest_port, c_seq, s_seq, 0x01, NULL, 0, 0);
                    c_seq++;
                    shutdown(server_fd, SHUT_WR);
                } else if (errno == ECONNRESET) {
                    printf("[-] Client sent RST\n");
                    log_packet(client_ip_str, dest_ip_str, client_port, dest_port, c_seq, s_seq, 0x04, NULL, 0, 0);
                    status = "RST";
                }
                client_closed = 1;
                continue;
            }
            
            send(server_fd, buf, n, MSG_NOSIGNAL);
            log_packet(client_ip_str, dest_ip_str, client_port, dest_port, c_seq, s_seq, 0x10, (uint8_t*)buf, n, 0);
            c_seq += n;
            bytes_c2s += n;
        }
        
        // Server to Client
        if (!server_closed && FD_ISSET(server_fd, &readfds)) {
            char buf[BUFFER_SIZE];
            ssize_t n = recv(server_fd, buf, BUFFER_SIZE, 0);
            
            if (n <= 0) {
                if (n == 0) {
                    printf("[-] Server closed connection (FIN)\n");
                    log_packet(dest_ip_str, client_ip_str, dest_port, client_port, s_seq, c_seq, 0x01, NULL, 0, 1);
                    s_seq++;
                    shutdown(client_fd, SHUT_WR);
                } else if (errno == ECONNRESET) {
                    printf("[-] Server sent RST\n");
                    log_packet(dest_ip_str, client_ip_str, dest_port, client_port, s_seq, c_seq, 0x04, NULL, 0, 1);
                    status = "RST";
                }
                server_closed = 1;
                continue;
            }
            
            send(client_fd, buf, n, MSG_NOSIGNAL);
            log_packet(dest_ip_str, client_ip_str, dest_port, client_port, s_seq, c_seq, 0x10, (uint8_t*)buf, n, 1);
            s_seq += n;
            bytes_s2c += n;
        }
    }
    
    double duration = difftime(time(NULL), start_time);
    log_meta(client_ip_str, client_port, dest_ip_str, dest_port, duration, bytes_c2s, bytes_s2c, status);
    close(client_fd);
    close(server_fd);
    printf("[*] Connection finished\n");
}

int main(int argc, char *argv[]) {
    int listen_port = 0;
    char *dest_host = NULL;
    int dest_port = 0;
    char *output_file = "shadowport.pcap";
    char *log_file = NULL;
    char *listen_host = "127.0.0.1";
    int quiet = 0;
    
    // Show help if no arguments provided
    if (argc < 2) {
#ifdef ENABLE_DNS
        fprintf(stderr, "Usage: %s -l <port> -d <host> -p <port> [-b <bind_ip>] [-o <pcap>] [--log <file>] [-q]\n", argv[0]);
#else
        fprintf(stderr, "Usage: %s -l <port> -d <dest_ip> -p <port> [-b <bind_ip>] [-o <pcap>] [--log <file>] [-q]\n", argv[0]);
#endif
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            dest_host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            dest_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_file = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            listen_host = argv[++i];
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else {
            // Unknown parameter
            fprintf(stderr, "Error: Unknown parameter '%s'\n", argv[i]);
#ifdef ENABLE_DNS
            fprintf(stderr, "Usage: %s -l <port> -d <host> -p <port> [-b <bind_ip>] [-o <pcap>] [--log <file>] [-q]\n", argv[0]);
#else
            fprintf(stderr, "Usage: %s -l <port> -d <dest_ip> -p <port> [-b <bind_ip>] [-o <pcap>] [--log <file>] [-q]\n", argv[0]);
#endif
            return 1;
        }
    }
    
    if (!listen_port || !dest_host || !dest_port) {
        fprintf(stderr, "Error: Missing required arguments (-l, -d, -p)\n");
#ifdef ENABLE_DNS
        fprintf(stderr, "Usage: %s -l <port> -d <host> -p <port> [-b <bind_ip>] [-o <pcap>] [--log <file>] [-q]\n", argv[0]);
#else
        fprintf(stderr, "Usage: %s -l <port> -d <dest_ip> -p <port> [-b <bind_ip>] [-o <pcap>] [--log <file>] [-q]\n", argv[0]);
#endif
        return 1;
    }

#ifndef ENABLE_DNS
    // Validate destination IP format if DNS is disabled
    struct in_addr addr_check;
    if (inet_pton(AF_INET, dest_host, &addr_check) != 1) {
        fprintf(stderr, "Error: Destination must be a valid IPv4 address in this build.\n");
        return 1;
    }
#endif

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    init_pcap(output_file);
    if (log_file) init_meta(log_file);
    
    if (!quiet) {
        printf("[*] shadowport v%s started\n", VERSION);
        printf("[*] Listening on %s:%d -> %s:%d\n", listen_host, listen_port, dest_host, dest_port);
        printf("[*] Press Ctrl+C to stop\n");
    }
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Set listening socket to non-blocking
    fcntl(server_fd, F_SETFL, O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(listen_host);
    addr.sin_port = htons(listen_port);
    
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }
    
    listen(server_fd, 1);
    
    while (running) {
        fd_set readfds;
        struct timeval timeout;
        
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("Select error");
            break;
        }
        
        if (activity > 0 && FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
            
            if (client_fd >= 0) {
                handle_client(client_fd, &client_addr, dest_host, dest_port, output_file, log_file);
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("Accept failed");
                break;
            }
        }
    }
    
    close(server_fd);
    if (pcap_file) fclose(pcap_file);
    if (meta_file) fclose(meta_file);
    if (!quiet) printf("[*] shadowport stopped\n");
    
    return 0;
}