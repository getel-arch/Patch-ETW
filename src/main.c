#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

// IP header (first part)
typedef struct {
    unsigned char  ihl:4;
    unsigned char  version:4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned long  saddr;
    unsigned long  daddr;
} IPHeader;

// ICMP header
typedef struct {
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
    // followed by data...
} ICMPHeader;

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in src;
    int src_len = sizeof(src);
    char *buffer;
    int buflen;
    
    // Allocate a big enough buffer for IP + ICMP + data
    const int MAX_PACKET = 65536;
    buffer = (char*)malloc(MAX_PACKET);
    if (!buffer) {
        fprintf(stderr, "Unable to allocate buffer\n");
        return 1;
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Create raw socket for ICMP
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Raw socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    printf("Listening for ICMP packets... (press Ctrl+C to quit)\n\n");

    while (1) {
        // Receive packet
        buflen = recvfrom(sock, buffer, MAX_PACKET, 0,
                          (struct sockaddr*)&src, &src_len);
        if (buflen == SOCKET_ERROR) {
            fprintf(stderr, "recvfrom failed: %d\n", WSAGetLastError());
            break;
        }

        // Parse IP header
        IPHeader *ip = (IPHeader*)buffer;
        int ip_header_len = ip->ihl * 4;

        // Only process ICMP
        if (ip->protocol != IPPROTO_ICMP) {
            continue;
        }

        // Parse ICMP header
        ICMPHeader *icmp = (ICMPHeader*)(buffer + ip_header_len);

        // Check for echo request (type 8) or reply (type 0)
        if (icmp->type == 8 || icmp->type == 0) {
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
            printf("UDPate: ICMP %s from %s\n",
                   (icmp->type==8 ? "Echo Request" : "Echo Reply"),
                   src_ip);

            // Payload data starts after ICMP header
            int icmp_header_len = sizeof(ICMPHeader);
            int data_len = buflen - ip_header_len - icmp_header_len;
            if (data_len > 0) {
                unsigned char *data = (unsigned char*)(buffer + ip_header_len + icmp_header_len);
                printf("Payload (%d bytes): ", data_len);
                // Print as ASCII if printable, else hex
                for (int i = 0; i < data_len; i++) {
                    unsigned char c = data[i];
                    if (c >= 32 && c < 127)  // printable ASCII
                        printf("%c", c);
                    else
                        printf("\\x%02x", c);
                }
                printf("\n\n");
            }
        }
    }

    closesocket(sock);
    WSACleanup();
    free(buffer);
    return 0;
}
