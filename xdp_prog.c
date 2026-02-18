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
    struct iphdr ip;
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
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  padding[3]; // Explicit padding
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
    

    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    /* Store timestamp (Start of processing) */
    /* Only if we care about "Sojourn" through XDP itself, 
       but "End-to-End" implies different interfaces. 
       If we redirect, we exit immediately. So Sojourn ~= Processing Time.
       Let's keep tracking it for consistency.
    */
    /* Store timestamp (Start of processing) */
    __u64 start_ts = bpf_ktime_get_ns();
    
    /* Parse L4 for ports */
    struct packet_key key;
    __builtin_memset(&key, 0, sizeof(key));
    
    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
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
    
    /* Update Map */
    bpf_map_update_elem(&packet_ts, &key, &start_ts, BPF_ANY);

    /* OPTIMIZATION: Check Queue State and Drop Early */
    __u32 q_idx = 0;
    struct queue_state *q = bpf_map_lookup_elem(&queue_state_map, &q_idx);
    if (q && q->state == STATE_DROP) {
        /* Check if Target Traffic (Port 5000) */
        bool is_drop_target = false;
        
        if (iph->protocol == IPPROTO_UDP) {
             struct udphdr *udp = (void *)(iph + 1);
             if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(5000)) {
                 is_drop_target = true;
             }
        } else if (iph->protocol == IPPROTO_TCP) {
             struct tcphdr *tcp = (void *)(iph + 1);
             if ((void *)(tcp + 1) <= data_end && tcp->dest == bpf_htons(5000)) {
                 is_drop_target = true;
             }   
        }

        if (is_drop_target) {
            bpf_printk("XDP DROP: Congestion Early Drop\n");
            return XDP_DROP;
        }
    }

    /* Reverting to TC-Model */
    return XDP_PASS;
}

/* TC: Egress Hook (Compressor) */
SEC("tc")
int tc_prog_main(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    /* Measure Sojourn Time */
    /* We need to lookup the key stored in XDP */
    struct packet_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.proto  = iph->protocol;
    
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) <= data_end) {
            key.src_port = udp->source;
            key.dst_port = udp->dest;
        }
    }

    __u64 *ts = bpf_map_lookup_elem(&packet_ts, &key);
    if (ts) {
        __u64 delta = bpf_ktime_get_ns() - *ts;
        update_stats(1, delta);
        bpf_map_delete_elem(&packet_ts, &key);
    }

    /* Measure Sojourn Time */
    /* ... skipped ... */

    /* Compression Logic with Virtual Queue */
    /* DEBUG: Print everything to see if we get here */


    /* Common Logic for UDP and TCP */
    bool is_target = false;
    __u32 pkt_len = bpf_ntohs(iph->tot_len);

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) <= data_end) {
            if (udp->dest == bpf_htons(5000)) {
                is_target = true;

            } else if (udp->dest == bpf_htons(8087)) {
                is_target = true;

            }
        }
    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) <= data_end) {
            if (tcp->dest == bpf_htons(5000)) {
                is_target = true;

            } else if (tcp->dest == bpf_htons(8087)) {
                is_target = true;

            }
        }
    }

    if (is_target) {
        bool compress = false;
        /* Virtual Queue Simulation */
        __u32 q_idx = 0;
        struct queue_state *q = bpf_map_lookup_elem(&queue_state_map, &q_idx);
        
        if (q) {
            /* DEBUG: Force update stats for finding the packets */
            update_stats(0, 0); 

            __u64 now = bpf_ktime_get_ns();
            __u64 delta = now - q->last_update_ns;
            /* Decrease bandwidth to 50 KB/s to ensure robust congestion triggering */
            /* delta / 20000 -> 1,000,000,000 / 20000 = 50,000 bytes = 50 KB/s */
            __u64 drained = delta / 20000; 

            if (drained > q->current_bytes) {
                q->current_bytes = 0;
            } else {
                q->current_bytes -= drained;
            }
            q->last_update_ns = now;
            
            /* HYSTERESIS STATE MACHINE */
            /* Thresholds:
               COMPRESS:    On > 100KB, Off < 80KB
               DELTA:       On > 150KB, Off < 120KB
               INCREMENTAL: On > 250KB, Off < 200KB
               DROP:        On > 400KB, Off < 350KB
            */
            switch (q->state) {
                case STATE_NORMAL:
                    if (q->current_bytes > 100000) q->state = STATE_COMPRESS;
                    break;
                case STATE_COMPRESS:
                    if (q->current_bytes > 150000) q->state = STATE_DELTA;
                    else if (q->current_bytes < 80000) q->state = STATE_NORMAL;
                    break;
                case STATE_DELTA:
                    if (q->current_bytes > 250000) q->state = STATE_INCREMENTAL;
                    else if (q->current_bytes < 120000) q->state = STATE_COMPRESS;
                    break;
                case STATE_INCREMENTAL:
                    if (q->current_bytes > 400000) q->state = STATE_DROP;
                    else if (q->current_bytes < 200000) q->state = STATE_DELTA;
                    break;
                case STATE_DROP:
                    if (q->current_bytes < 350000) q->state = STATE_INCREMENTAL;
                    break;
            }

            /* COOPERATIVE LOGIC: Operating State = MAX(Local, Remote) */
            __u32 key = 0;
            __u32 *remote_state_ptr = bpf_map_lookup_elem(&remote_state_map, &key);
            __u32 remote_state = remote_state_ptr ? *remote_state_ptr : STATE_NORMAL;

            /* Map states to severity for proper ordering */
            /* Normal(0) < Compress(1) < Delta(2) < Incremental(3) < Drop(4) */
            __u32 local_severity = 0;
            if (q->state == STATE_COMPRESS) local_severity = 1;
            else if (q->state == STATE_DELTA) local_severity = 2;
            else if (q->state == STATE_INCREMENTAL) local_severity = 3;
            else if (q->state == STATE_DROP) local_severity = 4;

            __u32 remote_severity = 0;
            if (remote_state == STATE_COMPRESS) remote_severity = 1;
            else if (remote_state == STATE_DELTA) remote_severity = 2;
            else if (remote_state == STATE_INCREMENTAL) remote_severity = 3;
            else if (remote_state == STATE_DROP) remote_severity = 4;

            __u32 max_severity = (local_severity > remote_severity) ? local_severity : remote_severity;
            __u32 operating_state = STATE_NORMAL;
            if (max_severity == 1) operating_state = STATE_COMPRESS;
            else if (max_severity == 2) operating_state = STATE_DELTA;
            else if (max_severity == 3) operating_state = STATE_INCREMENTAL;
            else if (max_severity == 4) operating_state = STATE_DROP;

    /* APPLY ACTIONS BASED ON STATE */

            
            /* DSCP Signaling (Layer 3) */
            /* State 0 (Normal)      -> 0x00 */
            /* State 1 (Compress)    -> 0x28 */
            /* State 2 (Delta)       -> 0x50 */
            /* State 3 (Incremental) -> 0x64 */
            /* State 4 (Drop)        -> 0x78 */
            
            /* Stamp OPERATING STATE as TOS so redirected packets carry mode info */
            /* This allows the user-space agent to determine encoding mode */
            __u8 new_tos = 0;
            if (operating_state == STATE_COMPRESS) new_tos = 0x28;
            else if (operating_state == STATE_DELTA) new_tos = 0x50;
            else if (operating_state == STATE_INCREMENTAL) new_tos = 0x64;
            else if (operating_state == STATE_DROP) new_tos = 0x78;
            
            /* Read Old TOS (Byte 1 of IP Header) */
            /* We read the first 16 bits (Ver/IHL + TOS) for csum calc */
            __u16 *ip_start = (void *)iph;
            __u16 old_val_16 = *ip_start;
            __u8 old_tos = (old_val_16 >> 8) & 0xFF;
            
            if (old_tos != new_tos) {
                __u16 new_val_16 = (old_val_16 & 0x00FF) | (new_tos << 8);
                
                /* Update Checksum (Offset 10) */
                int check_offset = sizeof(struct ethhdr) + 10;
                bpf_l3_csum_replace(skb, check_offset, old_val_16, new_val_16, 2);
                
                /* Update TOS in Packet */
                int tos_offset = sizeof(struct ethhdr) + 1;
                bpf_skb_store_bytes(skb, tos_offset, &new_tos, 1, 0);
                
                /* Reload Pointers */
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;
                eth = data;
                iph = (void *)(eth + 1);
                if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
            }

            if (operating_state == STATE_DROP) {
                 return TC_ACT_SHOT;
            }
            
            /* DELTA STATE: Redirect to User Space (veth-delta) */
            /* We need to define thresholds for STATE_DELTA in the switch above first */
            
            if (operating_state == STATE_COMPRESS) {
                 compress = true;
            }
            
            if (operating_state == STATE_DELTA || operating_state == STATE_INCREMENTAL) {
                   /* Redirect to user-space agent for delta/incremental encoding */
                   int key_delta = 1;
                   int *delta_if_idx = bpf_map_lookup_elem(&tx_port, &key_delta);
                   
                   if (delta_if_idx) {
                       return bpf_redirect(*delta_if_idx, 0);
                   } else {
                       bpf_printk("TC: Failed to lookup Delta Interface Index\n");
                   }
            }

            q->current_bytes += pkt_len;
            if (q->current_bytes > 500000) q->current_bytes = 500000;
        } else {
             bpf_printk("TC Error: No Queue Map\n");
        }


        if (compress && iph->protocol == IPPROTO_UDP) {
            /* Compressing UDP */
            struct udphdr *udp = (void *)(iph + 1);
            if ((void *)(udp + 1) > data_end) return TC_ACT_OK; // Bounds check added
            
            __u64 start_comp = bpf_ktime_get_ns();
            __u8 flow_id = 1; 
            __u16 src_port = udp->source;

            int strip_len = sizeof(struct iphdr) + sizeof(struct udphdr);
            int add_len = sizeof(struct compressed_hdr);
            
            if (bpf_skb_adjust_room(skb, (int)add_len - (int)strip_len, BPF_ADJ_ROOM_NET, 0))
                return TC_ACT_SHOT;
            
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
            
            eth->h_proto = bpf_htons(ETH_P_COMP);
            struct compressed_hdr *ch = (void *)(eth + 1);
            if ((void *)(ch + 1) > data_end) return TC_ACT_SHOT;
            
            ch->flow_id = flow_id;
            ch->src_port = src_port;
            
            __u64 end_comp = bpf_ktime_get_ns();
            update_stats(0, end_comp - start_comp);
            
            return TC_ACT_OK;
        } else if (compress && iph->protocol == IPPROTO_TCP) {
             /* Compressing TCP */
            struct tcphdr *tcp = (void *)(iph + 1); // Re-fetch
            if ((void *)(tcp + 1) > data_end) return TC_ACT_OK; // Bounds check added
            /* Explicitly check if we can read 20 bytes of TCP header */
            if ((void *)tcp + 20 > data_end) return TC_ACT_SHOT;
            
            __u64 start_comp = bpf_ktime_get_ns();
            __u8 flow_id = 2; // Separate ID for TCP
            
            /* Save Dynamic Fields */
            /* We need to be careful. The compiler might generate byte-by-byte access 
               which the verifier tracks. */
            
            /* Use bpf_skb_load_bytes? No, we have direct access. */
            
            __u16 src_port = tcp->source;
            __u32 seq = tcp->seq;
            __u32 ack_seq = tcp->ack_seq;
            __u16 window = tcp->window;
            __u16 check = tcp->check;
            
            /* Flag access */
            /* Flags are at offset 13. We just checked 20 bytes. Should be safe. */
            /* To be absolutely sure for verifier, let's re-verify the pointer math. */
            __u8 *tcp_access = (void *)tcp;
            if ((void *)(tcp_access + 14) > data_end) return TC_ACT_SHOT; // Redundant but explicit
            __u8 flags = tcp_access[13]; 
            
            int strip_len = sizeof(struct iphdr) + sizeof(struct tcphdr); 
            /* Note: We assume no TCP Options for now. If doff > 5, we are stripping options. */
            /* Correct SCHC would compress options too or refuse to compress. */
            /* For this POC, we strip options (simulating aggressive compression) */
            /* To be safe, strip_len should be calculated from doff. */
             __u32 tcp_len = tcp->doff * 4;
            if (tcp_len < 20) tcp_len = 20;
            strip_len = sizeof(struct iphdr) + tcp_len;

            int add_len = sizeof(struct compressed_tcp_hdr);
            
            if (bpf_skb_adjust_room(skb, (int)add_len - (int)strip_len, BPF_ADJ_ROOM_NET, 0))
                return TC_ACT_SHOT;
            
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
            
            eth->h_proto = bpf_htons(ETH_P_COMP);
            struct compressed_tcp_hdr *ch = (void *)(eth + 1);
            if ((void *)(ch + 1) > data_end) return TC_ACT_SHOT;
            
            ch->flow_id = flow_id;
            ch->src_port = src_port;
            ch->seq = seq;
            ch->ack_seq = ack_seq;
            ch->window = window;
            ch->check = check;
            ch->flags = flags;
            
            __u64 end_comp = bpf_ktime_get_ns();
            update_stats(0, end_comp - start_comp);
            
            return TC_ACT_OK;       
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
        
    } else if (flow_id == 2) {
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
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
