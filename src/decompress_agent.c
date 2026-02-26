/*
 * decompress_agent.c — MB2-side Decompression Agent
 * ==================================================
 * Runs on MB2 in the dual-middlebox topology.
 * Captures compressed packets arriving on the tactical link (veth-link2),
 * reconstructs the original payload, and forwards normal UDP packets to H2.
 *
 * This makes compression completely transparent to endpoints — H2's sink
 * receives normal CoT XML packets.
 *
 * Compile: gcc -O3 -o decompress_agent decompress_agent.c -lz -lssl -lcrypto
 */

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
#include "crypto_utils.h"

/* Helper: sendto with optional E2E trailer appended via iovec */
static inline ssize_t send_with_trailer(int sock, const void *buf, size_t len,
                                         const unsigned char *trailer, int has_trailer,
                                         const struct sockaddr *dest, socklen_t dlen) {
    if (!has_trailer)
        return sendto(sock, buf, len, 0, dest, dlen);
    struct iovec iov[2] = {
        { .iov_base = (void *)buf,     .iov_len = len },
        { .iov_base = (void *)trailer, .iov_len = 8   },
    };
    struct msghdr msg = {
        .msg_name    = (void *)dest,
        .msg_namelen = dlen,
        .msg_iov     = iov,
        .msg_iovlen  = 2,
    };
    return sendmsg(sock, &msg, 0);
}

#define ETH_P_ALL 0x0003

/* Wire-protocol types (must match delta_agent_c.c / sink.py) */
#define TYPE_SYNC        0x00
#define TYPE_DELTA       0x01
#define TYPE_INCREMENTAL 0x02
#define TYPE_HC          0x03

/* ---- CoT XML Field-Level Incremental Decoding ---- */
#define MAX_FIELD_VAL 128
#define NUM_COT_FIELDS 13

static const char *field_names[NUM_COT_FIELDS] = {
    "event_version", "event_uid", "event_type",
    "event_time", "event_start", "event_stale",
    "point_lat", "point_lon", "point_hae", "point_ce", "point_le",
    "contact_callsign", "detail_e2e_ts",
};

struct cot_fields {
    char values[NUM_COT_FIELDS][MAX_FIELD_VAL];
    int  valid;
};

/* CoT XML reconstruction template — must match sink.py COT_TEMPLATE */
static const char *COT_TEMPLATE =
    "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
    "<event version=\"%s\" uid=\"%s\" type=\"%s\" time=\"%s\" start=\"%s\" stale=\"%s\">\n"
    "    <point lat=\"%s\" lon=\"%s\" hae=\"%s\" ce=\"%s\" le=\"%s\"/>\n"
    "    <detail%s>\n"
    "        <contact callsign=\"%s\"/>\n"
    "    </detail>\n"
    "</event>";

/*
 * Reconstruct full CoT XML from field values.
 * Returns length of XML, or 0 on failure.
 */
static int reconstruct_xml(const struct cot_fields *f, char *out, int max_out) {
    if (!f->valid) return 0;
    /* Build detail attributes string (e2e_ts if present) */
    char detail_attrs[64] = "";
    if (f->values[12][0] != '\0') {
        snprintf(detail_attrs, sizeof(detail_attrs), " e2e_ts=\"%s\"", f->values[12]);
    }
    int len = snprintf(out, max_out, COT_TEMPLATE,
        f->values[0],  f->values[1],  f->values[2],
        f->values[3],  f->values[4],  f->values[5],
        f->values[6],  f->values[7],  f->values[8],
        f->values[9],  f->values[10],
        detail_attrs,  f->values[11]);
    return (len > 0 && len < max_out) ? len : 0;
}

/*
 * Apply an incremental field diff to stored fields.
 * Wire format: [num_changed (1B)] [field_id (1B)][val_len (1B)][val (N B)]...
 * Returns 1 on success, 0 on failure.
 */
static int apply_incremental_diff(const unsigned char *payload, int payload_len,
                                  struct cot_fields *fields) {
    if (payload_len < 1 || !fields->valid) return 0;

    int num_changed = payload[0];
    int pos = 1;

    for (int i = 0; i < num_changed; i++) {
        if (pos + 2 > payload_len) return 0;
        int field_id = payload[pos];
        int val_len  = payload[pos + 1];
        pos += 2;
        if (pos + val_len > payload_len) return 0;
        if (field_id >= NUM_COT_FIELDS) {
            pos += val_len; /* skip unknown fields */
            continue;
        }
        int copy_len = val_len;
        if (copy_len >= MAX_FIELD_VAL) copy_len = MAX_FIELD_VAL - 1;
        memcpy(fields->values[field_id], payload + pos, copy_len);
        fields->values[field_id][copy_len] = '\0';
        pos += val_len;
    }
    return 1;
}

/*
 * Parse CoT XML to extract field values (same logic as delta_agent_c.c).
 */
static const char *field_attr_names[NUM_COT_FIELDS] = {
    "version", "uid", "type", "time", "start", "stale",
    "lat", "lon", "hae", "ce", "le", "callsign", "e2e_ts",
};

static const char *field_element_tags[NUM_COT_FIELDS] = {
    "<event", "<event", "<event", "<event", "<event", "<event",
    "<point", "<point", "<point", "<point", "<point",
    "<contact", "<detail",
};

static int parse_cot_fields(const unsigned char *payload, int payload_len,
                            struct cot_fields *fields) {
    memset(fields, 0, sizeof(*fields));
    const char *xml = (const char *)payload;
    const char *xml_end = xml + payload_len;

    for (int i = 0; i < NUM_COT_FIELDS; i++) {
        const char *elem = strstr(xml, field_element_tags[i]);
        if (!elem) continue;
        const char *tag_end = memchr(elem, '>', xml_end - elem);
        if (!tag_end) tag_end = xml_end;

        /* Find attr_name=" within element */
        int alen = strlen(field_attr_names[i]);
        const char *p = elem;
        while (p + alen + 2 < tag_end) {
            if (memcmp(p, field_attr_names[i], alen) == 0 &&
                p[alen] == '=' && p[alen+1] == '"') {
                const char *val_start = p + alen + 2;
                const char *val_end = memchr(val_start, '"', tag_end - val_start);
                if (!val_end) break;
                int vlen = val_end - val_start;
                if (vlen >= MAX_FIELD_VAL) vlen = MAX_FIELD_VAL - 1;
                memcpy(fields->values[i], val_start, vlen);
                fields->values[i][vlen] = '\0';
                break;
            }
            p++;
        }
    }
    fields->valid = 1;
    return 1;
}


/* Configuration — default interface, overridable via argv */
static const char *default_iface = "veth-link2";

int main(int argc, char **argv) {
    const char *ingress_iface = (argc > 1) ? argv[1] : default_iface;
    int target_port = (argc > 2) ? atoi(argv[2]) : 8087;
    const char *dest_ip = (argc > 3) ? argv[3] : "10.0.2.1";

    printf("[Decompress] Starting on %s, forwarding to %s:%d\n",
           ingress_iface, dest_ip, target_port);
    setbuf(stdout, NULL);

    /* 1. Raw socket to capture packets on tactical link interface */
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("Socket error"); return 1; }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ingress_iface, IF_NAMESIZE);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("IOCTL error"); return 1; }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Bind error"); return 1;
    }

    /* 2. Standard UDP socket for sending reconstructed packets to H2 */
    int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sock < 0) { perror("Send socket error"); return 1; }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(target_port);
    inet_pton(AF_INET, dest_ip, &sin.sin_addr);

    /* State for Delta decoding: last full payload */
    unsigned char last_payload[4096];
    int           last_payload_len = 0;

    /* State for Incremental decoding: parsed fields */
    struct cot_fields incr_fields;
    memset(&incr_fields, 0, sizeof(incr_fields));

    /* Scratch buffers */
    unsigned char buffer[4096];
    unsigned char xor_buf[4096];
    char xml_buf[4096];

    int total_rx = 0, total_fwd = 0, total_fail = 0;
    time_t last_report = time(NULL);

    /* Derive encryption key from PSK */
    unsigned char aes_key[EFRAC_KEY_LEN];
    int crypto_enabled = 0;
    if (efrac_derive_key("efrac.psk", aes_key) == 0) {
        printf("[Decompress] AES-256-GCM encryption enabled (key from efrac.psk)\n");
        crypto_enabled = 1;
    } else {
        printf("[Decompress] Warning: No encryption key — running without crypto\n");
    }

    /* E2E timestamp trailer: 8-byte send timestamp appended outside encryption */
    int e2e_trailer = (getenv("E2E_TRAILER") != NULL);
    unsigned char trailer_buf[8];
    if (e2e_trailer)
        printf("[Decompress] E2E trailer mode enabled\n");

    /* Crypto scratch buffers */
    unsigned char decrypt_buf[4096];
    unsigned char encrypt_buf[4096];
    int decrypt_len, encrypt_len;

    while (1) {
        int n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n <= 0) continue;

        /* Parse Ethernet header */
        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        /* Parse IP header */
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        int hdr_len = ip->ihl * 4;
        int l4_offset = sizeof(struct ethhdr) + hdr_len;

        /* Only handle UDP to our target port */
        if (ip->protocol != IPPROTO_UDP) continue;
        if (l4_offset + sizeof(struct udphdr) > n) continue;

        struct udphdr *udp = (struct udphdr *)(buffer + l4_offset);
        if (ntohs(udp->dest) != target_port) continue;

        int payload_offset = l4_offset + sizeof(struct udphdr);
        if (n <= payload_offset) continue;
        unsigned char *payload = buffer + payload_offset;
        int payload_len = n - payload_offset;

        if (payload_len < 1) continue;
        total_rx++;

        unsigned char pkt_type = payload[0];
        unsigned char *data = payload + 1;
        int data_len = payload_len - 1;

        /* --- Strip E2E trailer (8B timestamp) before processing --- */
        int has_trailer = 0;
        if (e2e_trailer && data_len > 8) {
            memcpy(trailer_buf, data + data_len - 8, 8);
            data_len -= 8;
            has_trailer = 1;
        }

        if (pkt_type == TYPE_SYNC) {
            /* Full payload — decrypt, store as baseline, forward plaintext to H2 */
            unsigned char *plain = data;
            int plain_len = data_len;
            if (crypto_enabled) {
                if (efrac_decrypt(aes_key, data, data_len, decrypt_buf, &decrypt_len) == 0) {
                    plain = decrypt_buf;
                    plain_len = decrypt_len;
                }
            }
            memcpy(last_payload, plain, plain_len);
            last_payload_len = plain_len;
            parse_cot_fields(plain, plain_len, &incr_fields);

            /* Forward decrypted plaintext to H2 (no re-encrypt) */
            send_with_trailer(send_sock, plain, plain_len,
                       trailer_buf, has_trailer,
                   (struct sockaddr *)&sin, sizeof(sin));
            total_fwd++;

        } else if (pkt_type == TYPE_DELTA) {
            /* zlib-compressed XOR delta — decrypt, decompress, XOR, re-encrypt, forward */
            if (last_payload_len == 0) {
                total_fail++;
                continue;
            }

            /* Decrypt compressed blob first */
            unsigned char *comp_data = data;
            int comp_len = data_len;
            if (crypto_enabled) {
                if (efrac_decrypt(aes_key, data, data_len, decrypt_buf, &decrypt_len) == 0) {
                    comp_data = decrypt_buf;
                    comp_len = decrypt_len;
                }
            }

            unsigned char *xor_diff;
            int xor_len;
            unsigned char zlib_out[4096];
            unsigned long zlib_out_len = sizeof(zlib_out);

            int zret = uncompress(zlib_out, &zlib_out_len, comp_data, comp_len);
            if (zret == Z_OK) {
                xor_diff = zlib_out;
                xor_len = (int)zlib_out_len;
            } else {
                /* Fallback: treat as uncompressed XOR diff */
                xor_diff = comp_data;
                xor_len = comp_len;
            }

            if (xor_len != last_payload_len) {
                total_fail++;
                continue;
            }

            /* XOR reconstruct */
            for (int i = 0; i < xor_len; i++)
                xor_buf[i] = xor_diff[i] ^ last_payload[i];

            /* Update baselines */
            memcpy(last_payload, xor_buf, xor_len);
            last_payload_len = xor_len;
            parse_cot_fields(xor_buf, xor_len, &incr_fields);

            /* Forward decrypted plaintext to H2 (no re-encrypt) */
            send_with_trailer(send_sock, xor_buf, xor_len,
                       trailer_buf, has_trailer,
                   (struct sockaddr *)&sin, sizeof(sin));
            total_fwd++;

        } else if (pkt_type == TYPE_INCREMENTAL) {
            /* Field-level diff — decrypt, apply to stored fields, reconstruct, re-encrypt */
            if (!incr_fields.valid) {
                total_fail++;
                continue;
            }

            /* Decrypt field diff */
            unsigned char *diff_data = data;
            int diff_len = data_len;
            if (crypto_enabled) {
                if (efrac_decrypt(aes_key, data, data_len, decrypt_buf, &decrypt_len) == 0) {
                    diff_data = decrypt_buf;
                    diff_len = decrypt_len;
                }
            }

            if (!apply_incremental_diff(diff_data, diff_len, &incr_fields)) {
                total_fail++;
                continue;
            }

            int xml_len = reconstruct_xml(&incr_fields, xml_buf, sizeof(xml_buf));
            if (xml_len <= 0) {
                total_fail++;
                continue;
            }

            /* Also update delta baseline */
            memcpy(last_payload, xml_buf, xml_len);
            last_payload_len = xml_len;

            /* Forward decrypted plaintext to H2 (no re-encrypt) */
            send_with_trailer(send_sock, xml_buf, xml_len,
                       trailer_buf, has_trailer,
                   (struct sockaddr *)&sin, sizeof(sin));
            total_fwd++;

        } else if (pkt_type == TYPE_HC) {
            /* HC — payload is encrypted from H1, decrypt before forwarding to H2 */
            unsigned char *plain = data;
            int plain_len = data_len;
            if (crypto_enabled) {
                if (efrac_decrypt(aes_key, data, data_len, decrypt_buf, &decrypt_len) == 0) {
                    plain = decrypt_buf;
                    plain_len = decrypt_len;
                }
            }
            send_with_trailer(send_sock, plain, plain_len,
                       trailer_buf, has_trailer,
                   (struct sockaddr *)&sin, sizeof(sin));
            total_fwd++;

        } else {
            /* Unknown type — could be normal traffic, forward as-is */
            send_with_trailer(send_sock, payload, payload_len,
                       trailer_buf, has_trailer,
                   (struct sockaddr *)&sin, sizeof(sin));
            total_fwd++;
        }

        /* Periodic status report */
        time_t now = time(NULL);
        if (now != last_report) {
            printf("[Decompress] rx=%d fwd=%d fail=%d\n",
                   total_rx, total_fwd, total_fail);
            last_report = now;
        }
    }

    close(sock);
    close(send_sock);
    return 0;
}
