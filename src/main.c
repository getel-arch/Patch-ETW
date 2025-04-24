#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

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
    char *buffer = malloc(65536);
    if (!buffer) return 1;

    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // … error checks …

    while (1) {
        int buflen = recvfrom(sock, buffer, 65536, 0,
                              (struct sockaddr*)&src, &src_len);
        if (buflen == SOCKET_ERROR) break;

        IPHeader *ip = (IPHeader*)buffer;
        if (ip->protocol != IPPROTO_ICMP) continue;

        ICMPHeader *icmp = (ICMPHeader*)(buffer + ip->ihl*4);
        if (icmp->type == 8 || icmp->type == 0) {
            struct in_addr addr;
            addr.s_addr = ip->saddr;
            char src_ip[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip)))
                printf("ICMP from %s\n", src_ip);
            // … payload parsing …
        }
    }

    closesocket(sock);
    WSACleanup();
    free(buffer);
    return 0;
}
