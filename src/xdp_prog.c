#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/ipv6.h>

/* Compressed Packet Protocol */
#define ETH_P_COMP 0x88B5 

/* Compressed Header */
struct compressed_hdr {
    __u8 flow_id;
    __u16 src_port;
};

/* Compressed Header (TCP) */
/* 20 bytes (IP) + 20 bytes (TCP) -> ~13 bytes? 
   No, we need to keep dynamic fields:
   - Seq (4)
   - Ack (4)
   - Window (2)
   - Flags (1) (Actually part of offset/res/flags but let's compress)
   - Checksum (2)? Or recalulate? Let's keep it.
   Total dynamic = 4+4+2+2+2 = 14 bytes + FlowInfo(3) = 17 bytes.
   Savings: 40 - 17 = 23 bytes. Worth it.
*/
struct compressed_tcp_hdr {
    __u8 flow_id;
    __u16 src_port;
    __u32 seq;
    __u32 ack_seq;
    __u16 window;
    __u16 check;
    __u8  flags; // TCP Flags (FIN, SYN, RST, PSH, ACK, URG)
};

/* Context Map (Shared between MB and H2 logic effectively) */
/* In a real system, this would be synced. Here we assume static. */
struct flow_context {
    __u8 is_ipv6;
    struct iphdr ip;
    struct ipv6hdr ipv6;
    struct udphdr udp;
    struct tcphdr tcp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u8); // Flow ID
    __type(value, struct flow_context);
} context_map SEC(".maps");

/* Map to store ingress timestamp */
/* Map to store ingress timestamp */
struct packet_key {
    __u32 src_ip[4];
    __u32 dst_ip[4];
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  is_ipv6;
    __u8  padding[2]; // Explicit padding
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct packet_key);
    __type(value, __u64);
} packet_ts SEC(".maps");

/* Virtual Queue State */
/* State Definitions */
#define STATE_NORMAL      0
#define STATE_COMPRESS    1
#define STATE_DELTA       2
#define STATE_INCREMENTAL 3
#define STATE_DROP        4

struct queue_state {
    __u64 last_update_ns;
    __u64 current_bytes;
    __u32 state;
    __u32 padding;           /* Explicit alignment padding */
    __u64 avg_sojourn_ns;    /* EWMA of latency */
    __u64 link_capacity_bps; /* Physical drain rate estimation */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct queue_state);
} queue_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} remote_state_map SEC(".maps");

/* Remote Queue State Map (Cooperative) */
// Already defined above


/* Performance Stats Map */
struct perf_stats {
    __u64 count;
    __u64 sum_ns;
    __u64 min_ns;
    __u64 max_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); /* 0: Compression, 1: Sojourn */
    __type(key, __u32);
    __type(value, struct perf_stats);
} stats_map SEC(".maps");

static __always_inline void update_stats(__u32 key_idx, __u64 val) {
    struct perf_stats *s = bpf_map_lookup_elem(&stats_map, &key_idx);
    if (!s) return;

    __sync_fetch_and_add(&s->count, 1);
    __sync_fetch_and_add(&s->sum_ns, val);
    
    /* Loose updates for Min/Max */
    if (val < s->min_ns || s->min_ns == 0) s->min_ns = val;
    if (val > s->max_ns) s->max_ns = val;
}

/* Map for TX Port Redirect */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} tx_port SEC(".maps");


/* XDP: Ingress Hook (Now handles Compression + Forwarding) */
SEC("xdp")
int xdp_prog_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* Allow BOTH IPv4 and IPv6 */
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6)) 
        return XDP_PASS;

    __u64 start_ts = bpf_ktime_get_ns();
    struct packet_key key;
    __builtin_memset(&key, 0, sizeof(key));

    /* Branch parsing based on IP version */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;

        key.is_ipv6 = 0;
        key.src_ip[0] = iph->saddr;
        key.dst_ip[0] = iph->daddr;
        key.proto  = iph->protocol;
        
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(iph + 1);
            if ((void *)(udp + 1) <= data_end) {
                key.src_port = udp->source;
                key.dst_port = udp->dest;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(iph + 1);
            if ((void *)(tcp + 1) <= data_end) {
                key.src_port = tcp->source;
                key.dst_port = tcp->dest;
            }
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6h = (void *)(eth + 1);
        if ((void *)(ipv6h + 1) > data_end) return XDP_PASS;

        key.is_ipv6 = 1;
        __builtin_memcpy(key.src_ip, &ipv6h->saddr, sizeof(ipv6h->saddr));
        __builtin_memcpy(key.dst_ip, &ipv6h->daddr, sizeof(ipv6h->daddr));
        key.proto = ipv6h->nexthdr;

        if (key.proto == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ipv6h + 1);
            if ((void *)(udp + 1) <= data_end) {
                key.src_port = udp->source;
                key.dst_port = udp->dest;
            }
        } else if (key.proto == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ipv6h + 1);
            if ((void *)(tcp + 1) <= data_end) {
                key.src_port = tcp->source;
                key.dst_port = tcp->dest;
            }
        }
    }
    
    /* Update Map */
    bpf_map_update_elem(&packet_ts, &key, &start_ts, BPF_ANY);

    /* Queue Drop logic omitted for brevity, but it would go here 
       and also need to check key.proto and key.dst_port rather than hardcoding iph */

    return XDP_PASS;
}

/* TC: Egress Hook (Compressor) */
SEC("tc")
int tc_prog_main(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6)) 
        return TC_ACT_OK;

    struct packet_key key;
    __builtin_memset(&key, 0, sizeof(key));
    
    bool is_target = false;
    __u32 pkt_len = 0;

    /* 1. Protocol Parsing */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

        pkt_len = bpf_ntohs(iph->tot_len);
        key.is_ipv6 = 0;
        key.src_ip[0] = iph->saddr;
        key.dst_ip[0] = iph->daddr;
        key.proto  = iph->protocol;
    
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(iph + 1);
            if ((void *)(udp + 1) <= data_end) {
                key.src_port = udp->source;
                key.dst_port = udp->dest;
                if (udp->dest == bpf_htons(5000) || udp->dest == bpf_htons(8087)) is_target = true;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(iph + 1);
            if ((void *)(tcp + 1) <= data_end) {
                key.src_port = tcp->source;
                key.dst_port = tcp->dest;
                if (tcp->dest == bpf_htons(5000) || tcp->dest == bpf_htons(8087)) is_target = true;
            }
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6h = (void *)(eth + 1);
        if ((void *)(ipv6h + 1) > data_end) return TC_ACT_OK;

        pkt_len = bpf_ntohs(ipv6h->payload_len) + 40;
        key.is_ipv6 = 1;
        __builtin_memcpy(key.src_ip, &ipv6h->saddr, sizeof(ipv6h->saddr));
        __builtin_memcpy(key.dst_ip, &ipv6h->daddr, sizeof(ipv6h->daddr));
        key.proto = ipv6h->nexthdr;

        if (key.proto == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ipv6h + 1);
            if ((void *)(udp + 1) <= data_end) {
                key.src_port = udp->source;
                key.dst_port = udp->dest;
                if (udp->dest == bpf_htons(5000) || udp->dest == bpf_htons(8087)) is_target = true;
            }
        } else if (key.proto == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ipv6h + 1);
            if ((void *)(tcp + 1) <= data_end) {
                key.src_port = tcp->source;
                key.dst_port = tcp->dest;
                if (tcp->dest == bpf_htons(5000) || tcp->dest == bpf_htons(8087)) is_target = true;
            }
        }
    }
    /* Skip locally-generated packets (delta agent output) to prevent redirect loop */
    if (!key.is_ipv6) {
        __be32 mb_ip1 = (__be32)bpf_htonl(0x0A000202); /* 10.0.2.2 = single-MB egress */
        __be32 mb_ip2 = (__be32)bpf_htonl(0x0A000102); /* 10.0.1.2 = dual-MB subnet A */
        __be32 mb_ip3 = (__be32)bpf_htonl(0x0A006401); /* 10.0.100.1 = dual-MB link */
        if (key.src_ip[0] == mb_ip1 || key.src_ip[0] == mb_ip2 || key.src_ip[0] == mb_ip3)
            return TC_ACT_OK;
    }

    /* 2. Measure Sojourn Time */
    __u64 sojourn_ns = 0;
    __u64 *ts = bpf_map_lookup_elem(&packet_ts, &key);
    if (ts) {
        sojourn_ns = bpf_ktime_get_ns() - *ts;
        update_stats(1, sojourn_ns);
        /* Don't delete yet — agent may need it for redirected packets */
    }

    /* 3. Congestion Logic & Action */
    if (is_target) {
        bool compress = false;
        __u32 q_idx = 0;
        struct queue_state *q = bpf_map_lookup_elem(&queue_state_map, &q_idx);
        
        if (q) {
            __u64 now = bpf_ktime_get_ns();

            /* --- Time-varying drain rate (V-shape) --- */
            /* Use link_capacity_bps to store program start time */
            if (q->link_capacity_bps == 0)
                q->link_capacity_bps = now;

            __u64 elapsed_ns = now - q->link_capacity_bps;
            __u64 elapsed_s = elapsed_ns / 1000000000ULL;

            /* V-shape: 5000 ns/byte → 20000 ns/byte → 5000 ns/byte over 40s */
            /* 5000 ns/byte  = 200 KB/s drain (fast, no congestion) */
            /* 20000 ns/byte = 50 KB/s drain  (slow, congestion builds) */
            __u64 ns_per_byte;
            if (elapsed_s < 20) {
                ns_per_byte = 5000 + (elapsed_s * 750);  /* 5000 → 20000 */
            } else if (elapsed_s < 40) {
                __u64 recover = elapsed_s - 20;
                ns_per_byte = 20000 - (recover * 750);   /* 20000 → 5000 */
            } else {
                ns_per_byte = 5000;
            }

            __u64 delta = now - q->last_update_ns;
            __u64 drained = delta / ns_per_byte;

            if (drained > q->current_bytes) q->current_bytes = 0;
            else q->current_bytes -= drained;
            q->last_update_ns = now;

            /* Virtual queue sojourn: estimated queuing delay */
            q->avg_sojourn_ns = q->current_bytes * ns_per_byte;
            
            /* Hysteresis Thresholds (in nanoseconds) */
            /*switch (q->state) {
                case STATE_NORMAL:
                    if (avg_lat > 15000000) q->state = STATE_COMPRESS;
                    break;
                case STATE_COMPRESS:
                    if (avg_lat > 30000000) q->state = STATE_DELTA;
                    else if (avg_lat < 10000000) q->state = STATE_NORMAL;
                    break;
                case STATE_DELTA:
                    if (avg_lat > 60000000) q->state = STATE_INCREMENTAL;
                    else if (avg_lat < 20000000) q->state = STATE_COMPRESS;
                    break;
                case STATE_INCREMENTAL:
                    if (avg_lat > 100000000) q->state = STATE_DROP;
                    else if (avg_lat < 40000000) q->state = STATE_DELTA;
                    break;
                case STATE_DROP:
                    if (avg_lat < 80000000) q->state = STATE_INCREMENTAL;
                    break;
            }*/

            __u32 map_key = 0;
            __u32 *remote_state_ptr = bpf_map_lookup_elem(&remote_state_map, &map_key);
            __u32 remote_state = remote_state_ptr ? *remote_state_ptr : STATE_NORMAL;

            __u32 local_severity = q->state;
            __u32 remote_severity = remote_state;
            __u32 max_severity = (local_severity > remote_severity) ? local_severity : remote_severity;
            
            __u32 operating_state = max_severity;

            /* Set the trigger for the compression engine */
            if (operating_state == STATE_COMPRESS) {
                compress = true;
            }

            __u8 new_tos = 0;
            if (operating_state == STATE_COMPRESS) new_tos = 0x28;
            else if (operating_state == STATE_DELTA) new_tos = 0x50;
            else if (operating_state == STATE_INCREMENTAL) new_tos = 0x64;
            else if (operating_state == STATE_DROP) new_tos = 0x78;
            
            /* Safely apply DSCP signaling only to IPv4 for now */
            if (!key.is_ipv6) {
                struct iphdr *iph_sig = (void *)(eth + 1);
                if ((void *)(iph_sig + 1) <= data_end) {
                    __u16 *ip_start = (void *)iph_sig;
                    __u16 old_val_16 = *ip_start;
                    __u8 old_tos = (old_val_16 >> 8) & 0xFF;
                    
                    if (old_tos != new_tos) {
                        __u16 new_val_16 = (old_val_16 & 0x00FF) | (new_tos << 8);
                        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + 10, old_val_16, new_val_16, 2);
                        bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + 1, &new_tos, 1, 0);
                        
                        data = (void *)(long)skb->data;
                        data_end = (void *)(long)skb->data_end;
                        eth = data;
                    }
                }
            }

            __u32 physical_len = pkt_len;
            if (operating_state == STATE_COMPRESS) physical_len = pkt_len - 22;
            else if (operating_state == STATE_DELTA) physical_len = pkt_len / 2;
            else if (operating_state == STATE_INCREMENTAL) physical_len = pkt_len / 8;

            q->current_bytes += physical_len;
            if (q->current_bytes > 500000) q->current_bytes = 500000;

            if (operating_state == STATE_COMPRESS || operating_state == STATE_DELTA || operating_state == STATE_INCREMENTAL) {
                int key_delta = 1;
                int *delta_if_idx = bpf_map_lookup_elem(&tx_port, &key_delta);
                if (delta_if_idx) {
                    return bpf_redirect(*delta_if_idx, 0);
                }
            }   
        }
    }

    return TC_ACT_OK;
}

/* XDP: Peer Ingress (Cooperative Logic) */
/* Attached to veth2-mb (Peer-facing interface) */
SEC("xdp")
int xdp_peer_ingress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* Only look at IP Packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    /* Extract DSCP */
    __u8 tos = iph->tos;
    

    __u32 state = STATE_NORMAL;
    if (tos == 0x28) state = STATE_COMPRESS;
    else if (tos == 0x50) state = STATE_DELTA;
    else if (tos == 0x64) state = STATE_INCREMENTAL;
    else if (tos == 0x78) state = STATE_DROP;
    
    /* Update Map - LATCH LOGIC (PoC Only) */
    /* Only update if we receive an explicit non-normal signal */
    /* This prevents noise (TOS=0) from resetting the state immediately */
    if (state != STATE_NORMAL) {
        __u32 key = 0;
        bpf_map_update_elem(&remote_state_map, &key, &state, BPF_ANY);

    }
    
    return XDP_PASS;
}
static __always_inline __u16 calc_ip_csum(struct iphdr *iph) {
    __u16 *p = (__u16 *)iph;
    __u32 csum = 0;
    csum += p[0]; csum += p[1]; csum += p[2]; csum += p[3]; csum += p[4];
    csum += p[5]; csum += p[6]; csum += p[7]; csum += p[8]; csum += p[9];
    csum = (csum >> 16) + (csum & 0xffff);
    csum += (csum >> 16);
    return (__u16)~csum;
}
/* XDP: Decompressor Hook (H2 Ingress) */
SEC("xdp")
int xdp_decompress_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* Check for Compressed Packet */
    if (eth->h_proto != bpf_htons(ETH_P_COMP)) return XDP_PASS;

    struct compressed_hdr *ch = (void *)(eth + 1);
    if ((void *)(ch + 1) > data_end) return XDP_PASS;

    __u8 flow_id = ch->flow_id;
    
    if (flow_id == 1) {
        /* UDP Decompression */
        __u16 src_port = ch->src_port;

        unsigned char dst_mac[6], src_mac[6];
        __builtin_memcpy(dst_mac, eth->h_dest,   6);
        __builtin_memcpy(src_mac, eth->h_source,  6);

        /* Lookup Context - For PoC we can hardcode if map fails, but let's try map */
        struct flow_context *ctx_hdr = bpf_map_lookup_elem(&context_map, &flow_id);
        if (!ctx_hdr) {
            /* Fallback */
            return XDP_PASS; 
        }

        /* Calculate sizes */
        int add_len = sizeof(struct iphdr) + sizeof(struct udphdr);
        int strip_len = sizeof(struct compressed_hdr);

        /* Grow packet */
        if (bpf_xdp_adjust_head(ctx, strip_len - add_len))
            return XDP_DROP;

        /* Re-read pointers */
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        
        if ((void *)(eth + 1) > data_end) return XDP_DROP;

        __builtin_memcpy(eth->h_dest,   dst_mac, 6);
        __builtin_memcpy(eth->h_source, src_mac, 6);
        eth->h_proto = bpf_htons(ETH_P_IP);
        

        struct iphdr *iph = (void *)(eth + 1);
        struct udphdr *udp = (void *)(iph + 1);
        
        if ((void *)(udp + 1) > data_end) return XDP_DROP;

        /* Restore Headers */
        __builtin_memcpy(iph, &ctx_hdr->ip, sizeof(struct iphdr));
        __builtin_memcpy(udp, &ctx_hdr->udp, sizeof(struct udphdr));

        /* Update dynamic fields */
        udp->source = src_port;
        
        /* Fix lengths */
        iph->tot_len = bpf_htons((void *)data_end - (void *)iph);
        udp->len = bpf_htons((void *)data_end - (void *)udp);
        
        /* Fix Checksums */
        iph->check = 0;
        iph->check = calc_ip_csum(iph);
        
    } else if (flow_id == 2) {
        unsigned char dst_mac[6], src_mac[6];
        __builtin_memcpy(dst_mac, eth->h_dest,   6);
        __builtin_memcpy(src_mac, eth->h_source,  6);

        /* TCP Decompression */
        struct compressed_tcp_hdr *ctcp = (void *)(eth + 1);
        if ((void *)(ctcp + 1) > data_end) return XDP_DROP;

        __u16 src_port = ctcp->src_port;
        __u32 seq = ctcp->seq;
        __u32 ack_seq = ctcp->ack_seq;
        __u16 window = ctcp->window;
        __u16 check = ctcp->check;
        __u8 flags = ctcp->flags;

        struct flow_context *ctx_hdr = bpf_map_lookup_elem(&context_map, &flow_id);
        if (!ctx_hdr) return XDP_PASS;

        /* Calculate sizes: Assuming base TCP header 20 bytes (no options restored!) */
        int tcp_hdr_len = 20;
        int add_len = sizeof(struct iphdr) + tcp_hdr_len;
        int strip_len = sizeof(struct compressed_tcp_hdr);

        if (bpf_xdp_adjust_head(ctx, strip_len - add_len))
             return XDP_DROP;
        
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        
        if ((void *)(eth + 1) > data_end) return XDP_DROP;
        __builtin_memcpy(eth->h_dest,   dst_mac, 6);
        __builtin_memcpy(eth->h_source, src_mac, 6);
        eth->h_proto = bpf_htons(ETH_P_IP);

        struct iphdr *iph = (void *)(eth + 1);
        struct tcphdr *tcp = (void *)(iph + 1);
        
        if ((void *)(tcp + 1) > data_end) return XDP_DROP;

        /* Restore Headers */
        __builtin_memcpy(iph, &ctx_hdr->ip, sizeof(struct iphdr));
        /* Context TCP likely has ports/proto set, but we usually memcyp template */
        /* Since we added tcp to struct flow_context, we can copy it */
        __builtin_memcpy(tcp, &ctx_hdr->tcp, sizeof(struct tcphdr));

        /* Restore Dynamic Fields */
        tcp->source = src_port;
        tcp->seq = seq;
        tcp->ack_seq = ack_seq;
        tcp->window = window;
        tcp->check = check;
        
        /* Restore Flags */
        /* tcp->res1 = 0; tcp->doff = 5; */
        /* flags byte at offset 13 */
        __u8 *tcp_bytes = (void *)tcp;
        tcp_bytes[12] = 0x50; // Data Offset 5 (20 bytes), Res 0
        tcp_bytes[13] = flags;

        /* Fix Lengths */
        iph->tot_len = bpf_htons((void *)data_end - (void *)iph);
        iph->protocol = IPPROTO_TCP; /* Ensure proto is TCP */
        iph->check = 0;
        iph->check = calc_ip_csum(iph);

        /* Re-calc TCP Checksum? 
           We kept the original checksum from the compressed header.
           However, we stripped Options, so the Length changed, and specific headers changed.
           The checksum is likely INVALID now unless we fix it up.
           But full checksum recalc in XDP is heavy.
           For now, let's keep the old checksum and hope for offload or check failure?
           Actually, if we changed length, check is definitely wrong.
           Let's set to 0. Some stacks verify, some don't.
        */
        tcp->check = 0; 
    }else if(flow_id == 3){
        __u16 src_port = ch->src_port;
        unsigned char dst_mac[6], src_mac[6];
        __builtin_memcpy(dst_mac, eth->h_dest,   6);
        __builtin_memcpy(src_mac, eth->h_source,  6);


        struct flow_context *ctx_hdr = bpf_map_lookup_elem(&context_map, &flow_id);
        if (!ctx_hdr || !ctx_hdr->is_ipv6) return XDP_PASS; 

        int add_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        int strip_len = sizeof(struct compressed_hdr);

        if (bpf_xdp_adjust_head(ctx, strip_len - add_len)) return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_DROP;
        
        __builtin_memcpy(eth->h_dest,   dst_mac, 6);
        __builtin_memcpy(eth->h_source, src_mac, 6);
        eth->h_proto = bpf_htons(ETH_P_IPV6);

        struct ipv6hdr *ipv6h = (void *)(eth + 1);
        struct udphdr *udp = (void *)(ipv6h + 1);
        if ((void *)(udp + 1) > data_end) return XDP_DROP;

        /* Restore Headers */
        __builtin_memcpy(ipv6h, &ctx_hdr->ipv6, sizeof(struct ipv6hdr));
        __builtin_memcpy(udp, &ctx_hdr->udp, sizeof(struct udphdr));

        udp->source = src_port;
        
        /* Fix Payload Length */
        ipv6h->payload_len = bpf_htons((void *)data_end - (void *)udp);
        udp->len = ipv6h->payload_len;
        
    } else if (flow_id == 4) {
        unsigned char dst_mac[6], src_mac[6];
        __builtin_memcpy(dst_mac, eth->h_dest,   6);
        __builtin_memcpy(src_mac, eth->h_source,  6);

        struct compressed_tcp_hdr *ctcp = (void *)(eth + 1);
        if ((void *)(ctcp + 1) > data_end) return XDP_DROP;

        /* Extract ALL fields before adjust_head invalidates the pointer */
        __u16 src_port = ctcp->src_port;
        __u32 seq      = ctcp->seq;
        __u32 ack_seq  = ctcp->ack_seq;
        __u16 window   = ctcp->window;
        __u8 flags     = ctcp->flags;

        struct flow_context *ctx_hdr = bpf_map_lookup_elem(&context_map, &flow_id);
        if (!ctx_hdr || !ctx_hdr->is_ipv6) return XDP_PASS;

        int tcp_hdr_len = 20;
        int add_len = sizeof(struct ipv6hdr) + tcp_hdr_len;
        int strip_len = sizeof(struct compressed_tcp_hdr);

        if (bpf_xdp_adjust_head(ctx, strip_len - add_len)) return XDP_DROP;
        
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_DROP;
        
        __builtin_memcpy(eth->h_dest,   dst_mac, 6);
        __builtin_memcpy(eth->h_source, src_mac, 6);
        eth->h_proto = bpf_htons(ETH_P_IPV6);

        struct ipv6hdr *ipv6h = (void *)(eth + 1);
        struct tcphdr *tcp = (void *)(ipv6h + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_DROP;

        __builtin_memcpy(ipv6h, &ctx_hdr->ipv6, sizeof(struct ipv6hdr));
        __builtin_memcpy(tcp, &ctx_hdr->tcp, sizeof(struct tcphdr));

        /* Restore Dynamic Fields using local variables */
        tcp->source = src_port;
        tcp->seq = seq;
        tcp->ack_seq = ack_seq;
        tcp->window = window;
        
        __u8 *tcp_bytes = (void *)tcp;
        tcp_bytes[12] = 0x50; // Data Offset 5 (20 bytes), Res 0
        tcp_bytes[13] = flags;

        ipv6h->payload_len = bpf_htons((void *)data_end - (void *)tcp);
        tcp->check = 0; 
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
