#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <zlib.h>

#define ETH_P_ALL 0x0003

/* Configuration */
const char *ingress_iface = "veth-delta-peer";

/* Wire-protocol types (must match sink.py) */
#define TYPE_SYNC        0x00
#define TYPE_DELTA       0x01
#define TYPE_INCREMENTAL 0x02
#define TYPE_HC          0x03

int main(int argc, char **argv) {
    int sock;
    struct sockaddr_ll sll;
    unsigned char buffer[2048];

    printf("[C-Agent] Starting on %s...\n", ingress_iface);
    setbuf(stdout, NULL);

    /* 1. Raw socket to receive redirected packets */
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("Socket error"); return 1; }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ingress_iface, IF_NAMESIZE);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("IOCTL error"); return 1; }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("Bind error"); return 1; }

    /* 2. Standard UDP socket for sending to Sink */
    int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sock < 0) { perror("Send socket error"); return 1; }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(8087);

    /* State for delta encoding */
    unsigned char last_payload[2048];
    int           last_payload_len = 0;
    int           sync_sent = 0;

    /* Scratch buffers */
    unsigned char xor_buf[2048];
    unsigned char zlib_buf[4096];

    int count = 0;
    time_t last_t = time(NULL);
    int last_count = 0;

    while (1) {
        int n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n <= 0) continue;

        /* --- Parse L2/L3/L4 headers --- */
        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        int hdr_len = ip->ihl * 4;

        int payload_offset = sizeof(struct ethhdr) + hdr_len;
        if (ip->protocol == IPPROTO_UDP) {
            payload_offset += sizeof(struct udphdr);
        } else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + payload_offset);
            payload_offset += tcp->doff * 4;
        } else {
            continue;
        }

        if (n <= payload_offset) continue;
        unsigned char *payload = buffer + payload_offset;
        int payload_len = n - payload_offset;

        /* Loop guard: skip anything that looks like our own output */
        if (payload_len > 0 && payload[0] <= TYPE_INCREMENTAL) continue;

        count++;
        time_t now_t = time(NULL);
        if (now_t > last_t) {
            printf("[C-Agent] Throughput: %d pps\n", count - last_count);
            last_t = now_t;
            last_count = count;
        }

        sin.sin_addr.s_addr = ip->daddr;

        /* --- First packet: send SYNC (full payload) --- */
        if (!sync_sent) {
            unsigned char sync_pkt[2048];
            sync_pkt[0] = TYPE_SYNC;
            memcpy(sync_pkt + 1, payload, payload_len);
            sendto(send_sock, sync_pkt, 1 + payload_len, 0,
                   (struct sockaddr *)&sin, sizeof(sin));

            memcpy(last_payload, payload, payload_len);
            last_payload_len = payload_len;
            sync_sent = 1;
            continue;
        }

        /* --- Subsequent packets: XOR delta + zlib --- */
        /* Compute XOR diff against last payload */
        int diff_len = (payload_len < last_payload_len) ? payload_len : last_payload_len;
        for (int i = 0; i < diff_len; i++)
            xor_buf[i] = payload[i] ^ last_payload[i];
        /* If current is longer, copy excess unchanged */
        if (payload_len > last_payload_len)
            memcpy(xor_buf + diff_len, payload + diff_len, payload_len - diff_len);

        /* zlib compress the XOR diff */
        unsigned long zlib_len = sizeof(zlib_buf) - 1; /* leave room for type byte */
        int zret = compress2(zlib_buf + 1, &zlib_len,
                             xor_buf, payload_len, Z_DEFAULT_COMPRESSION);

        /* Choose type based on TOS stamped by eBPF */
        unsigned char type = TYPE_DELTA;  /* default */
        if (ip->tos == 0x28) type = TYPE_HC;
        else if (ip->tos == 0x64) type = TYPE_INCREMENTAL;

        if (zret == Z_OK && (int)zlib_len < payload_len) {
            /* Compressed delta is smaller — send it */
            zlib_buf[0] = type;
            sendto(send_sock, zlib_buf, 1 + zlib_len, 0,
                   (struct sockaddr *)&sin, sizeof(sin));
        } else {
            /* Compression didn't help — send SYNC instead */
            unsigned char sync_pkt[2048];
            sync_pkt[0] = TYPE_SYNC;
            memcpy(sync_pkt + 1, payload, payload_len);
            sendto(send_sock, sync_pkt, 1 + payload_len, 0,
                   (struct sockaddr *)&sin, sizeof(sin));
        }

        /* Update baseline for next delta */
        memcpy(last_payload, payload, payload_len);
        last_payload_len = payload_len;
    }

    close(sock);
    close(send_sock);
    return 0;
}
