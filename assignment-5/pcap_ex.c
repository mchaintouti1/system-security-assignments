#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <signal.h>

#define MAX_TCP_FLOWS 65536
#define MAX_UDP_FLOWS 65536
#define MAX_TCP_SEQ_TRACKER 65536  // Maximum number for tracking TCP sequence numbers

// Global filter options
unsigned int filter_port = 0;

// Structure to hold statistics
typedef struct {
    unsigned int total_tcp_packets;
    unsigned int total_udp_packets;
    unsigned int total_tcp_bytes;
    unsigned int total_udp_bytes;
    unsigned int total_flows;
    unsigned int total_tcp_flows;
    unsigned int total_udp_flows;
    unsigned int total_packets;
} Stats;

Stats stats = {0};

// Forward declaration of print_stats
void print_stats();

// Structure to define a network flow
typedef struct {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // Protocol (TCP = 6, UDP = 17)
} Flow;

// Structure to track TCP sequence numbers
typedef struct {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
} TcpSeqTracker;

// Arrays to store flows and sequence numbers
Flow tcp_flows[MAX_TCP_FLOWS];
Flow udp_flows[MAX_UDP_FLOWS];
TcpSeqTracker tcp_seq_tracker[MAX_TCP_SEQ_TRACKER];
unsigned int tcp_seq_tracker_count = 0;

// Signal handler to print statistics and exit 
void handle_signal(int signal) {
    // Print statistics when the program is interrupted
    print_stats();
    exit(0); 
}

// Checks if a given flow exists in the array of flows
int flow_exists(Flow *flows, int flow_count, Flow *new_flow) {
    for (int i = 0; i < flow_count; i++) {
        if (strcmp(flows[i].src_ip, new_flow->src_ip) == 0 &&
            strcmp(flows[i].dst_ip, new_flow->dst_ip) == 0 &&
            flows[i].src_port == new_flow->src_port &&
            flows[i].dst_port == new_flow->dst_port &&
            flows[i].protocol == new_flow->protocol) {
            return 1;
        }
    }
    return 0;
}

// Checks if a TCP sequence number has been seen before
int seq_exists(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num) {
    for (int i = 0; i < tcp_seq_tracker_count; i++) {
        if (strcmp(tcp_seq_tracker[i].src_ip, src_ip) == 0 &&
            strcmp(tcp_seq_tracker[i].dst_ip, dst_ip) == 0 &&
            tcp_seq_tracker[i].src_port == src_port &&
            tcp_seq_tracker[i].dst_port == dst_port &&
            tcp_seq_tracker[i].seq_num == seq_num) {
            return 1; // Sequence number found (indicates retransmission)
        }
    }
    return 0; // Sequence number not found
}

// Adds a new TCP sequence number to the tracker
void add_seq(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num) {
    TcpSeqTracker new_seq = {0};
    strcpy(new_seq.src_ip, src_ip);
    strcpy(new_seq.dst_ip, dst_ip);
    new_seq.src_port = src_port;
    new_seq.dst_port = dst_port;
    new_seq.seq_num = seq_num;
    tcp_seq_tracker[tcp_seq_tracker_count++] = new_seq;
}

// Processes a TCP packet and logs its details
void process_tcp_packet(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, 
                        unsigned int payload_size, FILE *log_file, uint8_t is_ipv6, uint32_t seq_num) {

    stats.total_tcp_packets++;
    stats.total_tcp_bytes += payload_size;
    stats.total_packets++;

    if (filter_port && dst_port != filter_port) {
        return;
    }

    Flow new_flow = {0};
    strcpy(new_flow.src_ip, src_ip);
    strcpy(new_flow.dst_ip, dst_ip);
    new_flow.src_port = src_port;
    new_flow.dst_port = dst_port;
    new_flow.protocol = IPPROTO_TCP;

    if (!flow_exists(tcp_flows, stats.total_tcp_flows, &new_flow)) {
        tcp_flows[stats.total_tcp_flows++] = new_flow;
        stats.total_flows++;
    }

    if (seq_exists((char*)src_ip, (char*)dst_ip, src_port, dst_port, seq_num)) {
        fprintf(log_file, "TCP Packet (%s):\n", is_ipv6 ? "IPv6" : "IPv4");
        fprintf(log_file, "  Source IP: %s\n", src_ip);
        fprintf(log_file, "  Destination IP: %s\n", dst_ip);
        fprintf(log_file, "  Source Port: %d\n", src_port);
        fprintf(log_file, "  Destination Port: %d\n", dst_port);
        fprintf(log_file, "  Protocol: TCP\n");
        fprintf(log_file, "  Payload Length: %d bytes\n", payload_size);
        fprintf(log_file, "  Retransmitted: Yes\n\n");
    } else {
        add_seq((char*)src_ip, (char*)dst_ip, src_port, dst_port, seq_num);
        fprintf(log_file, "TCP Packet (%s):\n", is_ipv6 ? "IPv6" : "IPv4");
        fprintf(log_file, "  Source IP: %s\n", src_ip);
        fprintf(log_file, "  Destination IP: %s\n", dst_ip);
        fprintf(log_file, "  Source Port: %d\n", src_port);
        fprintf(log_file, "  Destination Port: %d\n", dst_port);
        fprintf(log_file, "  Protocol: TCP\n");
        fprintf(log_file, "  Payload Length: %d bytes\n", payload_size);
        fprintf(log_file, "  Retransmitted: No\n\n");
    }
}

// Processes a UDP packet and logs its details
void process_udp_packet(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, 
                        unsigned int payload_size, FILE *log_file, uint8_t is_ipv6) {
    
    stats.total_udp_packets++;
    stats.total_udp_bytes += payload_size;
    stats.total_packets++;

    if (filter_port && dst_port != filter_port) {
        return;
    }

    Flow new_flow = {0};
    strcpy(new_flow.src_ip, src_ip);
    strcpy(new_flow.dst_ip, dst_ip);
    new_flow.src_port = src_port;
    new_flow.dst_port = dst_port;
    new_flow.protocol = IPPROTO_UDP;

    if (!flow_exists(udp_flows, stats.total_udp_flows, &new_flow)) {
        udp_flows[stats.total_udp_flows++] = new_flow;
        stats.total_flows++;
    }

    fprintf(log_file, "UDP Packet (%s):\n", is_ipv6 ? "IPv6" : "IPv4");
    fprintf(log_file, "  Source IP: %s\n", src_ip);
    fprintf(log_file, "  Destination IP: %s\n", dst_ip);
    fprintf(log_file, "  Source Port: %d\n", src_port);
    fprintf(log_file, "  Destination Port: %d\n", dst_port);
    fprintf(log_file, "  Protocol: UDP\n");
    fprintf(log_file, "  Payload Length: %d bytes\n\n", payload_size);
}

// Processes an IPv4 packet, extracting TCP/UDP information if present
void process_ipv4_packet(const u_char *packet, struct pcap_pkthdr header, FILE *log_file) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Ethernet header offset
    if (header.len < 14 + sizeof(struct ip)) return;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        unsigned int tcp_header_length = tcp_header->doff * 4;
        unsigned int payload_size = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - tcp_header_length;

        process_tcp_packet(src_ip, dst_ip, ntohs(tcp_header->source), ntohs(tcp_header->dest), payload_size, log_file, 0, ntohl(tcp_header->seq));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        unsigned int payload_size = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - sizeof(struct udphdr);

        process_udp_packet(src_ip, dst_ip, ntohs(udp_header->source), ntohs(udp_header->dest), payload_size, log_file, 0);
    } else {
        stats.total_packets++;
    }
}

// Processes an IPv6 packet, extracting TCP/UDP information if present
void process_ipv6_packet(const u_char *packet, struct pcap_pkthdr header, FILE *log_file) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + 14); // Ethernet header offset
    if (header.len < 14 + sizeof(struct ip6_hdr)) return;

    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

    if (ip6_header->ip6_nxt == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + sizeof(struct ip6_hdr));
        unsigned int payload_size = ntohs(ip6_header->ip6_plen) - (tcp_header->doff * 4);

        process_tcp_packet(src_ip, dst_ip, ntohs(tcp_header->source), ntohs(tcp_header->dest), payload_size, log_file, 1, ntohl(tcp_header->seq));
    } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr));
        unsigned int payload_size = ntohs(ip6_header->ip6_plen) - sizeof(struct udphdr);

        process_udp_packet(src_ip, dst_ip, ntohs(udp_header->source), ntohs(udp_header->dest), payload_size, log_file, 1);
    } else {
        stats.total_packets++;
    }
}

// Function to process packet
void process_packet(const u_char *packet, struct pcap_pkthdr header, FILE *log_file) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Ethernet header offset

    // Check for IPv4
    if (ip_header->ip_v == 4) {
        process_ipv4_packet(packet, header, log_file);
    }
    // Check for IPv6
    else if (ip_header->ip_v == 6) {  
        process_ipv6_packet(packet, header, log_file);
    }
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    FILE *log_file = (FILE *)args; // Transform args to FILE pointer
    process_packet(packet, *header, log_file); // Packet process
}

// Function for online capture
void capture_online(char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        exit(1);
    }

    printf("Listening on device %s...\n", device);

    // Open file log
    FILE *log_file = fopen("online_output.txt", "a");
    if (!log_file) {
        perror("Failed to open online_output.txt");
        exit(1);
    }

    // Use pcap_loop for packet processing 
    pcap_loop(handle, 0, handle_packet, (u_char *)log_file);

    fclose(log_file);
    pcap_close(handle);
}

void capture_offline(char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open file %s: %s\n", filename, errbuf);
        exit(1);
    }

    printf("Reading packets from file %s...\n", filename);
    FILE *log_file = fopen("offline_output.txt", "a");
    if (!log_file) {
        perror("Failed to open offline_output.txt");
        exit(1);
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        process_packet(packet, header, log_file);
    }

    fclose(log_file);
    pcap_close(handle);
}

// Displays the overall statistics
void print_stats() {
    printf("\nStatistics:\n");
    printf("a. Total number of network flows captured: %d\n", stats.total_flows);
    printf("b. Number of TCP network flows captured: %d\n", stats.total_tcp_flows);
    printf("c. Number of UDP network flows captured: %d\n", stats.total_udp_flows);
    printf("d. Total number of packets received: %d\n", stats.total_packets);
    printf("e. Total number of TCP packets received: %d\n", stats.total_tcp_packets);
    printf("f. Total number of UDP packets received: %d\n", stats.total_udp_packets);
    printf("g. Total bytes of TCP packets received: %d\n", stats.total_tcp_bytes);
    printf("h. Total bytes of UDP packets received: %d\n", stats.total_udp_bytes);
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *pcap_file = NULL;
    filter_port = 0;

    // Register signal handler for termination
    signal(SIGINT, handle_signal); 

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            pcap_file = argv[++i];
        }  else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            if (sscanf(argv[++i], "port %u", &filter_port) != 1) {
                fprintf(stderr, "Invalid port filter format. Use: -f \"port <port_number>\"\n");
                exit(1);
            }
        } else {
            fprintf(stderr, "Usage: %s -i <interface> [-f <port>] or -r <pcap_file>\n", argv[0]);
            exit(1);
        }
    }

    if (interface) {
        capture_online(interface);
    } else if (pcap_file) {
        capture_offline(pcap_file);
    } else {
        fprintf(stderr, "You must specify either -i or -r.\n");
        exit(1);
    }

    print_stats(); // Print statistics if the program exits without interruption
    return 0;
}