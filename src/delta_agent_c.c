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
#include <sys/syscall.h>
#include <time.h>
#include <zlib.h>
#include <linux/bpf.h>
#include <errno.h>
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

/* Wire-protocol types (must match sink.py) */
#define TYPE_SYNC        0x00
#define TYPE_DELTA       0x01
#define TYPE_INCREMENTAL 0x02
#define TYPE_HC          0x03

/* ---- CoT XML Field-Level Incremental Encoding ---- */
#define MAX_FIELD_VAL 128
#define NUM_COT_FIELDS 13

/* Field IDs — must match FIELD_NAMES in sink.py */
enum cot_field_id {
    FID_EVENT_VERSION = 0,
    FID_EVENT_UID,
    FID_EVENT_TYPE,
    FID_EVENT_TIME,
    FID_EVENT_START,
    FID_EVENT_STALE,
    FID_POINT_LAT,
    FID_POINT_LON,
    FID_POINT_HAE,
    FID_POINT_CE,
    FID_POINT_LE,
    FID_CONTACT_CALLSIGN,
    FID_DETAIL_E2E_TS,
};

struct cot_fields {
    char values[NUM_COT_FIELDS][MAX_FIELD_VAL];
    int  valid; /* 1 if fields have been parsed */
};

/* Attribute search patterns: tag prefix to locate the enclosing element,
   then attribute name to extract the value. */
static const char *field_attr_names[NUM_COT_FIELDS] = {
    "version", "uid", "type", "time", "start", "stale",
    "lat", "lon", "hae", "ce", "le", "callsign", "e2e_ts",
};

/* Which XML element contains each attribute */
static const char *field_element_tags[NUM_COT_FIELDS] = {
    "<event", "<event", "<event", "<event", "<event", "<event",
    "<point", "<point", "<point", "<point", "<point",
    "<contact", "<detail",
};

/*
 * Extract the value of attr_name="..." from within xml, starting search
 * from 'start'. Returns pointer past closing quote, or NULL.
 */
static const char *extract_attr(const char *start, const char *end,
                                const char *attr_name, char *out, int max_out) {
    /* Search for attr_name=" */
    int alen = strlen(attr_name);
    const char *p = start;
    while (p + alen + 2 < end) {
        if (memcmp(p, attr_name, alen) == 0 && p[alen] == '=' && p[alen+1] == '"') {
            const char *val_start = p + alen + 2;
            const char *val_end = memchr(val_start, '"', end - val_start);
            if (!val_end) return NULL;
            int vlen = val_end - val_start;
            if (vlen >= max_out) vlen = max_out - 1;
            memcpy(out, val_start, vlen);
            out[vlen] = '\0';
            return val_end + 1;
        }
        p++;
    }
    return NULL;
}

/*
 * Parse CoT XML payload into structured fields.
 * Returns 1 on success, 0 on failure.
 */
static int parse_cot_fields(const unsigned char *payload, int payload_len,
                            struct cot_fields *fields) {
    memset(fields, 0, sizeof(*fields));
    const char *xml = (const char *)payload;
    const char *xml_end = xml + payload_len;

    for (int i = 0; i < NUM_COT_FIELDS; i++) {
        /* Find the element tag */
        const char *elem = strstr(xml, field_element_tags[i]);
        if (!elem) continue;

        /* Find the end of this element's opening tag (> or />) */
        const char *tag_end = memchr(elem, '>', xml_end - elem);
        if (!tag_end) tag_end = xml_end;

        extract_attr(elem, tag_end, field_attr_names[i],
                     fields->values[i], MAX_FIELD_VAL);
    }
    fields->valid = 1;
    return 1;
}

/*
 * Build an incremental diff between prev and curr fields.
 * Format: [num_changed (1B)] [field_id (1B)][val_len (1B)][val (N B)] ...
 * Returns total length of diff in out_buf.
 */
static int build_incremental_diff(const struct cot_fields *prev,
                                  const struct cot_fields *curr,
                                  unsigned char *out_buf, int max_out) {
    int pos = 1; /* reserve byte 0 for count */
    int count = 0;

    for (int i = 0; i < NUM_COT_FIELDS; i++) {
        if (strcmp(prev->values[i], curr->values[i]) != 0) {
            int vlen = strlen(curr->values[i]);
            if (pos + 2 + vlen > max_out) break; /* safety */
            out_buf[pos++] = (unsigned char)i;     /* field_id */
            out_buf[pos++] = (unsigned char)vlen;   /* val_len */
            memcpy(out_buf + pos, curr->values[i], vlen);
            pos += vlen;
            count++;
        }
    }
    out_buf[0] = (unsigned char)count;
    return pos;
}

/* Must match xdp_prog.c exactly (including padding) */
struct packet_key {
    __u32 src_ip[4];
    __u32 dst_ip[4];
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  is_ipv6;
    __u8  padding[2];
};

/* ---- BPF syscall helpers ---- */
static inline int bpf_obj_get(const char *path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (__u64)(unsigned long)path;
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static inline int bpf_map_lookup(int fd, const void *key, void *value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key    = (__u64)(unsigned long)key;
    attr.value  = (__u64)(unsigned long)value;
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static inline int bpf_map_delete(int fd, const void *key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key    = (__u64)(unsigned long)key;
    return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/* Configuration */
const char *ingress_iface = "veth-delta-peer";

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

    /* 3. Open pinned packet_ts map for entry cleanup */
    int ts_map_fd = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        ts_map_fd = bpf_obj_get("/sys/fs/bpf/packet_ts");
        if (ts_map_fd >= 0) break;
        printf("[C-Agent] Waiting for packet_ts map (attempt %d)...\n", attempt + 1);
        sleep(1);
    }
    if (ts_map_fd < 0) {
        printf("[C-Agent] Warning: Could not open packet_ts map.\n");
    } else {
        printf("[C-Agent] Opened packet_ts map (fd=%d)\n", ts_map_fd);
    }

    /* State for delta encoding */
    unsigned char last_payload[2048];
    int           last_payload_len = 0;
    int           sync_sent = 0;

    /* State for incremental encoding */
    struct cot_fields last_fields;
    struct cot_fields curr_fields;
    int incr_baseline_set = 0;
    memset(&last_fields, 0, sizeof(last_fields));

    /* Scratch buffers */
    unsigned char xor_buf[2048];
    unsigned char zlib_buf[4096];
    unsigned char incr_buf[2048];

    int count = 0;
    time_t last_t = time(NULL);
    int last_count = 0;

    /* Derive encryption key from PSK */
    unsigned char aes_key[EFRAC_KEY_LEN];
    int crypto_enabled = 0;
    if (efrac_derive_key("efrac.psk", aes_key) == 0) {
        printf("[C-Agent] AES-256-GCM encryption enabled (key from efrac.psk)\n");
        crypto_enabled = 1;
    } else {
        printf("[C-Agent] Warning: No encryption key — running without crypto\n");
    }

    /* E2E timestamp trailer: 8-byte send timestamp appended outside encryption */
    int e2e_trailer = (getenv("E2E_TRAILER") != NULL);
    unsigned char trailer_buf[8];
    if (e2e_trailer)
        printf("[C-Agent] E2E trailer mode enabled\n");

    /* Decryption/encryption scratch buffers */
    unsigned char decrypt_buf[4096];
    unsigned char encrypt_buf[4096];
    int decrypt_len, encrypt_len;

    while (1) {
        int n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n <= 0) continue;

        /* --- Parse L2/L3/L4 headers --- */
        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;

        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        int hdr_len = ip->ihl * 4;

        int payload_offset = sizeof(struct ethhdr) + hdr_len;
        __u16 sport = 0, dport = 0;

        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(buffer + payload_offset);
            sport = udp->source;
            dport = udp->dest;
            payload_offset += sizeof(struct udphdr);
        } else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + payload_offset);
            sport = tcp->source;
            dport = tcp->dest;
            payload_offset += tcp->doff * 4;
        } else {
            continue;
        }

        if (n <= payload_offset) continue;
        unsigned char *payload = buffer + payload_offset;
        int payload_len = n - payload_offset;

        /* Loop guard: skip anything that looks like our own output */
        if (payload_len > 0 && payload[0] <= TYPE_INCREMENTAL) continue;

        /* --- Strip E2E trailer (8B timestamp) before processing --- */
        int has_trailer = 0;
        if (e2e_trailer && payload_len > 8) {
            memcpy(trailer_buf, payload + payload_len - 8, 8);
            payload_len -= 8;
            has_trailer = 1;
        }

        /* --- Clean up packet_ts entry --- */
        if (ts_map_fd >= 0) {
            struct packet_key pkey;
            memset(&pkey, 0, sizeof(pkey));
            pkey.src_ip[0] = ip->saddr;
            pkey.dst_ip[0] = ip->daddr;
            pkey.src_port  = sport;
            pkey.dst_port  = dport;
            pkey.proto     = ip->protocol;
            pkey.is_ipv6   = 0;
            bpf_map_delete(ts_map_fd, &pkey);
        }

        sin.sin_addr.s_addr = ip->daddr;

        /* --- First packet: send SYNC (full payload) --- */
        if (!sync_sent) {
            unsigned char sync_pkt[4096];
            sync_pkt[0] = TYPE_SYNC;

            /* Decrypt first, store plaintext as baseline */
            unsigned char *first_payload = payload;
            int first_len = payload_len;
            if (crypto_enabled) {
                if (efrac_decrypt(aes_key, payload, payload_len,
                                  decrypt_buf, &decrypt_len) == 0) {
                    first_payload = decrypt_buf;
                    first_len = decrypt_len;
                }
            }

            /* Re-encrypt for wire (or send plaintext if no crypto) */
            if (crypto_enabled) {
                efrac_encrypt(aes_key, first_payload, first_len,
                              sync_pkt + 1, &encrypt_len);
                send_with_trailer(send_sock, sync_pkt, 1 + encrypt_len,
                       trailer_buf, has_trailer,
                       (struct sockaddr *)&sin, sizeof(sin));
            } else {
                memcpy(sync_pkt + 1, first_payload, first_len);
                send_with_trailer(send_sock, sync_pkt, 1 + first_len,
                       trailer_buf, has_trailer,
                       (struct sockaddr *)&sin, sizeof(sin));
            }

            memcpy(last_payload, first_payload, first_len);
            last_payload_len = first_len;
            sync_sent = 1;
            continue;
        }

        /* Choose type based on TOS stamped by eBPF */
        unsigned char type = TYPE_DELTA;
        if (ip->tos == 0x28) type = TYPE_HC;
        else if (ip->tos == 0x64) type = TYPE_INCREMENTAL;

        /* --- Decrypt payload if crypto is enabled --- */
        unsigned char *work_payload = payload;
        int work_len = payload_len;

        if (crypto_enabled && type != TYPE_HC) {
            /* HC passes encrypted payload through unchanged */
            if (efrac_decrypt(aes_key, payload, payload_len,
                              decrypt_buf, &decrypt_len) == 0) {
                work_payload = decrypt_buf;
                work_len = decrypt_len;
            } else {
                /* Decryption failed — might be unencrypted, try as-is */
                work_payload = payload;
                work_len = payload_len;
            }
        }

        if (type == TYPE_HC) {
            /* --- Header Compression: forward payload as-is (stays encrypted) --- */
            unsigned char hc_pkt[4096];
            hc_pkt[0] = TYPE_HC;
            memcpy(hc_pkt + 1, payload, payload_len);
            send_with_trailer(send_sock, hc_pkt, 1 + payload_len,
                       trailer_buf, has_trailer,
                (struct sockaddr *)&sin, sizeof(sin));

        } else if (type == TYPE_INCREMENTAL) {
            /* --- True field-level incremental encoding --- */
            if (!incr_baseline_set || !parse_cot_fields(work_payload, work_len, &curr_fields)) {
                /* First incremental pkt or parse fail: send full SYNC + set baseline */
                unsigned char sync_pkt[4096];
                sync_pkt[0] = TYPE_SYNC;
                if (crypto_enabled) {
                    efrac_encrypt(aes_key, work_payload, work_len, sync_pkt + 1, &encrypt_len);
                    send_with_trailer(send_sock, sync_pkt, 1 + encrypt_len,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                } else {
                    memcpy(sync_pkt + 1, work_payload, work_len);
                    send_with_trailer(send_sock, sync_pkt, 1 + work_len,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                }
                parse_cot_fields(work_payload, work_len, &last_fields);
                incr_baseline_set = 1;
            } else {
                /* Build field-level diff */
                int diff_total = build_incremental_diff(&last_fields, &curr_fields,
                                                       incr_buf + 1, sizeof(incr_buf) - 1);
                /* Re-encrypt the diff */
                if (crypto_enabled) {
                    unsigned char enc_pkt[4096];
                    enc_pkt[0] = TYPE_INCREMENTAL;
                    efrac_encrypt(aes_key, (unsigned char *)(incr_buf + 1), diff_total,
                                  enc_pkt + 1, &encrypt_len);
                    send_with_trailer(send_sock, enc_pkt, 1 + encrypt_len,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                } else {
                    incr_buf[0] = TYPE_INCREMENTAL;
                    send_with_trailer(send_sock, incr_buf, 1 + diff_total,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                }
                memcpy(&last_fields, &curr_fields, sizeof(last_fields));
            }

        } else {
            /* --- Delta: byte-level XOR + zlib --- */
            int diff_len = (work_len < last_payload_len) ? work_len : last_payload_len;
            for (int i = 0; i < diff_len; i++)
                xor_buf[i] = work_payload[i] ^ last_payload[i];
            if (work_len > last_payload_len)
                memcpy(xor_buf + diff_len, work_payload + diff_len, work_len - diff_len);

            unsigned long zlib_len = sizeof(zlib_buf) - 1;
            int zret = compress2(zlib_buf + 1, &zlib_len,
                                 xor_buf, work_len, Z_DEFAULT_COMPRESSION);

            if (zret == Z_OK && (int)zlib_len < work_len) {
                if (crypto_enabled) {
                    unsigned char enc_pkt[4096];
                    enc_pkt[0] = TYPE_DELTA;
                    efrac_encrypt(aes_key, zlib_buf + 1, (int)zlib_len,
                                  enc_pkt + 1, &encrypt_len);
                    send_with_trailer(send_sock, enc_pkt, 1 + encrypt_len,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                } else {
                    zlib_buf[0] = TYPE_DELTA;
                    send_with_trailer(send_sock, zlib_buf, 1 + zlib_len,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                }
            } else {
                unsigned char sync_pkt[4096];
                sync_pkt[0] = TYPE_SYNC;
                if (crypto_enabled) {
                    efrac_encrypt(aes_key, work_payload, work_len,
                                  sync_pkt + 1, &encrypt_len);
                    send_with_trailer(send_sock, sync_pkt, 1 + encrypt_len,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                } else {
                    memcpy(sync_pkt + 1, work_payload, work_len);
                    send_with_trailer(send_sock, sync_pkt, 1 + work_len,
                       trailer_buf, has_trailer,
                        (struct sockaddr *)&sin, sizeof(sin));
                }
            }
        }

        /* Update baseline for next delta (store plaintext) */
        memcpy(last_payload, work_payload, work_len);
        last_payload_len = work_len;
    }

    close(sock);
    close(send_sock);
    if (ts_map_fd >= 0) close(ts_map_fd);
    return 0;
}
