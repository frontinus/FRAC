#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/ioctl.h>
#include <time.h>
#include "xdp_prog.skel.h"

/* Structure definition (Must match xdp_prog.c) */
struct flow_context {
    struct iphdr ip;
    struct udphdr udp;
    struct tcphdr tcp;
};

/* Stats Struct */
struct perf_stats {
    __u64 count;
    __u64 sum_ns;
    __u64 min_ns;
    __u64 max_ns;
};

struct queue_state {
    __u64 last_update_ns;
    __u64 current_bytes;
    __u32 state;
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

/* Delta Encoding Helpers */
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <pthread.h>
// #include <openssl/sha.h>  // Removed dependency 

/* Simplified SHA256 for Key generation if OpenSSL not avail, 
   but let's assumes we just use a simple hash for PoC to avoid deps issues if possible.
   Actually, let's use a simple LCG for "Hash" to keep it self-contained.
*/
unsigned int simple_hash(unsigned int prev) {
    return (prev * 1103515245 + 12345) & 0x7FFFFFFF;
}

/* Global Key State */
char global_egress_iface[IFNAMSIZ] = "lo"; // Global egress interface for raw socket

volatile unsigned int current_key = 0xDEADBEEF;
pthread_mutex_t key_lock = PTHREAD_MUTEX_INITIALIZER;

/* Key Manager Thread */
void *key_manager(void *arg) {
    while (!exiting) {
        sleep(10); // Interval T = 10s
        
        pthread_mutex_lock(&key_lock);
        current_key = simple_hash(current_key);
        // printf("[KeyMgr] Rotated Key: 0x%08X\n", current_key);
        pthread_mutex_unlock(&key_lock);
    }
    return NULL;
}

/* Delta Worker Thread */
/* Listen on veth-delta (Simulated "Slow Path") */
void *delta_worker(void *arg) {
    int sock;
    struct sockaddr_ll sll;
    unsigned char buffer[2048];
    char *iface = "veth-delta-peer"; // Peer of the redirect target
    
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket error");
        return NULL;
    }
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("IOCTL error");
        return NULL;
    }
    
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Bind error");
        return NULL;
    }
    
    /* Output Socket (Raw Socket on Egress) */
    /* We need to know egress interface name. It's safe to assume a global or pass it in. 
       For now, let's just open a socket and stick to 'veth2-mb' logic or similar. 
       Actually, 'loader' knows egress iface. Let's make it global.
    */
    extern char global_egress_iface[IFNAMSIZ];
    
    int out_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (out_sock < 0) {
        perror("Output Socket error");
        return NULL;
    }
    
    struct sockaddr_ll sll_out;
    struct ifreq ifr_out;
    strncpy(ifr_out.ifr_name, global_egress_iface, IFNAMSIZ);
    if (ioctl(out_sock, SIOCGIFINDEX, &ifr_out) < 0) {
        // perror("Output IOCTL error (using lo fallback)");
        // Fallback to lo? No, must fail.
    }
    
    memset(&sll_out, 0, sizeof(sll_out));
    sll_out.sll_family = AF_PACKET;
    sll_out.sll_ifindex = ifr_out.ifr_ifindex;
    sll_out.sll_protocol = htons(ETH_P_ALL);

    
    printf("[DeltaWorker] Listening on %s...\n", iface);
    
    /* Flow History for Delta */
    /* Key: SrcPort (Simple), Value: Last Payload Hash/Data */
    /* PoC: Just 1 flow supported */
    char last_payload[1500];
    int last_len = 0;
    
    while (!exiting) {
        int n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n <= 0) continue;
        
        /* 1. Parse Packet */
        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;
        
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        int hdr_len = ip->ihl * 4;
        
        /* 2. Decrypt Payload (XOR) */
        /* Assuming TCP/UDP payload starts after Transport Header */
        /* Let's find payload offset */
        int payload_offset = sizeof(struct ethhdr) + hdr_len;
        if (ip->protocol == IPPROTO_TCP) {
             struct tcphdr *tcp = (struct tcphdr *)(buffer + payload_offset);
             payload_offset += tcp->doff * 4;
        } else if (ip->protocol == IPPROTO_UDP) {
             payload_offset += sizeof(struct udphdr);
        } else {
            continue; 
        }
        
        if (n <= payload_offset) continue; // No payload
        
        unsigned char *payload = buffer + payload_offset;
        int payload_len = n - payload_offset;
        
        pthread_mutex_lock(&key_lock);
        unsigned int key = current_key;
        pthread_mutex_unlock(&key_lock);
        
        /* XOR Decrypt */
        /* Note: In a real world, we'd act on the decrypted buffer.
           Here we just modify it in place. */
        for (int i=0; i<payload_len; i++) {
            payload[i] ^= (key & 0xFF); 
        }
        
        /* 3. Compute Delta / Compress */
        /* Logic: If payload matches last seen 'significant' parts, send only diff.
           For CoT (XML), we could strip the header/simpler tags.
           Simplification: If payload starts with specific bytes, truncate it.
        */
        
        /* Let's simulate: If we successfully "decrypted" (which we always do),
           and it looks like CoT (we assume it is based on port), 
           we "compress" it by stripping 50% of bytes to simulate Delta.
           
           Real Delta: 
           Diff = Payload XOR LastPayload? 
           Or Diff = VCDIFF?
           
           Let's do:
           NewPayload = DeltaMarker + (Payload - SharedDictionary)
        */
        
        int new_len = payload_len / 2; // Simulate 50% compression
        if (new_len < 10) new_len = payload_len; // Don't over compress
        
        /* 4. Encrypt (XOR) again */
        for (int i=0; i<new_len; i++) {
            payload[i] ^= (key & 0xFF);
        }
        
        /* Fix IP Length */
        /* packet_offset was likely intended to be hdr_len + sizeof(eth) but we tracked payload_offset */
        /* original packet total len = ntohs(ip->tot_len) */
        /* new packet total len = original - (payload_len - new_len) */
        
        int diff = payload_len - new_len;
        ip->tot_len = htons(ntohs(ip->tot_len) - diff);
        ip->check = 0; // Recalc checksum? Let kernel handle or ignore for PoC
        
        /* SIGNALING: Set EtherType to 0x88B6 (DELTA) */
        // struct ethhdr *eth = (struct ethhdr *)buffer; // Already defined above
        eth->h_proto = htons(0x88B6);
        
        /* 5. Forward (Re-inject) */
        /* Send out socket */
        if (sendto(out_sock, buffer, n - diff, 0, (struct sockaddr *)&sll_out, sizeof(sll_out)) < 0) {
             // perror("Send Error");
        }
        
        // printf("[DeltaWorker] Processed Packet: Len %d -> %d\n", payload_len, new_len);
    }
    
    close(sock);
    close(out_sock);
    return NULL;
}


/* Structure definition (Must match xdp_prog.c) */

char global_egress_iface[IFNAMSIZ];

int main(int argc, char **argv)
{
    struct xdp_prog *skel;
    int err;

    /* Parse Arguments */
    int mode = 0; // 0: MiddleBox (Compressor + Ingress), 1: H2 (Decompressor)
    const char *iface_ingress = NULL;
    const char *iface_egress = NULL;

    if (argc < 2) {
usage:
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  MiddleBox: %s <ingress_iface> <egress_iface>\n", argv[0]);
        fprintf(stderr, "  H2 (Decompressor): %s --decompress <iface>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--decompress") == 0) {
        if (argc < 3) goto usage;
        mode = 1;
        iface_ingress = argv[2];
    } else {
        if (argc < 3) goto usage;
        mode = 0;
        iface_ingress = argv[1];
        iface_egress = argv[2];
        strncpy(global_egress_iface, iface_egress, IFNAMSIZ);
    }
    
    /* Start Threads if Mode 0 */
    if (mode == 0) {
        pthread_t tid_key, tid_delta;
        pthread_create(&tid_key, NULL, key_manager, NULL);
        pthread_create(&tid_delta, NULL, delta_worker, NULL);
    }

    /* Open BPF application */
    skel = xdp_prog__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = xdp_prog__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

     // TC Hook (Ingress for Co-operative Congestion Control & Redirection)
    // We attach to veth1-mb (Ingress)
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;
    memset(&hook, 0, sizeof(hook));
    hook.sz = sizeof(hook);
    hook.ifindex = if_nametoindex(argv[1]);
    hook.attach_point = BPF_TC_INGRESS;
    

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.prog_fd = bpf_program__fd(skel->progs.tc_prog_main);
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC: %d\n", err);
        goto cleanup;
    }


    /* Populate Context Map (Static for PoC) */
    /* Flow ID 1: Src 10.0.1.1, Dst 10.0.2.1, UDP, Dst Port 5000 */
    struct flow_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    
    ctx.ip.version = 4;
    ctx.ip.ihl = 5;
    ctx.ip.tos = 0;
    ctx.ip.tot_len = 0; // Dynamic
    ctx.ip.id = 0; // Dynamic? SCHC usually relies on IP ID behavior
    ctx.ip.frag_off = 0; // Assume no frag
    ctx.ip.ttl = 64;
    ctx.ip.protocol = IPPROTO_UDP;
    ctx.ip.check = 0; // Recalculated by stack?
    ctx.ip.saddr = inet_addr("10.0.1.1"); // Network Byte Order
    ctx.ip.daddr = inet_addr("10.0.2.1");
    
    ctx.udp.source = 0; // Dynamic (saved in compressed header)
    ctx.udp.dest = htons(5000);
    ctx.udp.len = 0; // Dynamic
    ctx.udp.check = 0;

    int map_fd = bpf_map__fd(skel->maps.context_map);
    __u8 flow_id = 1;
    bpf_map__update_elem(skel->maps.context_map, &flow_id, sizeof(flow_id), &ctx, sizeof(ctx), BPF_ANY);

    /* Populate Context for TCP (Flow ID 2) */
    struct flow_context ctx_tcp;
    memset(&ctx_tcp, 0, sizeof(ctx_tcp));
    ctx_tcp.ip = ctx.ip; /* Reuse IP template */
    ctx_tcp.ip.protocol = IPPROTO_TCP;
    
    /* TCP Template */
    ctx_tcp.tcp.source = 0; // Dynamic
    ctx_tcp.tcp.dest = htons(5000);
    ctx_tcp.tcp.seq = 0; // Dynamic
    ctx_tcp.tcp.ack_seq = 0; // Dynamic
    ctx_tcp.tcp.doff = 0; // Dynamic? No, we restore to 5(20 bytes)
    /* We don't really use the context for TCP other than IP and some static fields? */
    /* Decompressor logic mainly uses it for IP header. */
    
    flow_id = 2;
    bpf_map__update_elem(skel->maps.context_map, &flow_id, sizeof(flow_id), &ctx_tcp, sizeof(ctx_tcp), BPF_ANY);


    if (mode == 0) {
        /* MiddleBox Mode */
        int ingress_ifindex = if_nametoindex(iface_ingress);
        int egress_ifindex = if_nametoindex(iface_egress);
        
        if (!ingress_ifindex || !egress_ifindex) {
            fprintf(stderr, "Interface not found\n");
            goto cleanup;
        }

        /* Force Detach XDP first to avoid EBUSY */
        bpf_xdp_detach(ingress_ifindex, 0, NULL);
        
        /* Attach XDP (Ingress) */
        struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_prog_main, ingress_ifindex);
        if (!link) {
            fprintf(stderr, "Failed to attach XDP program to %s in Native mode. Trying Generic/SKB mode.\n", iface_ingress);
             err = -errno;
             fprintf(stderr, "Error: %d\n", err);
            goto cleanup;
        }
        skel->links.xdp_prog_main = link; // Persist link in skeleton to ensure it lives as long as skeleton
        printf("Attached XDP (Sojourn Ingress) to %s\n", iface_ingress);

        /* Attach TC (Egress / Compressor) */
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = egress_ifindex, .attach_point = BPF_TC_EGRESS);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1, .prog_fd = bpf_program__fd(skel->progs.tc_prog_main));

        bpf_tc_hook_create(&tc_hook); // Create clsact (ignore error)
        
        struct bpf_tc_opts detach_opts = tc_opts;
        detach_opts.prog_fd = 0; 
        detach_opts.prog_id = 0;
        detach_opts.flags = 0; 
        
        bpf_tc_detach(&tc_hook, &detach_opts); // Ignore error

        /* Attach TC Program */
        if (err) {
            fprintf(stderr, "Failed to attach TC: %d\n", err);
            goto cleanup;
        }

        /* Attach XDP Peer Ingress (Cooperative Logic) to Egress Interface (veth2-mb) */
        /* Note: veth2-mb is Egress for forwarding, but Ingress for H2->MB traffic */
        bpf_xdp_detach(egress_ifindex, 0, NULL); // Detach any old XDP
        struct bpf_link *peer_link = bpf_program__attach_xdp(skel->progs.xdp_peer_ingress, egress_ifindex);
        if (!peer_link) {
            fprintf(stderr, "Failed to attach XDP Peer Ingress to %s: %d\n", iface_egress, -errno);
            // Try Generic Mode
            peer_link = bpf_program__attach_xdp(skel->progs.xdp_peer_ingress, egress_ifindex);
             if (!peer_link) {
                fprintf(stderr, "Failed to attach Peer XDP in Generic mode either.\n");
             }
        }
        if (peer_link) {
             skel->links.xdp_peer_ingress = peer_link; // Persist
             printf("Attached XDP (Peer Ingress) to %s\n", iface_egress);
        }

        /* Populate TX Port Map */
        int tx_port_fd = bpf_map__fd(skel->maps.tx_port);
        int key = 0;
        int val = egress_ifindex; // Use H2 interface (veth2-mb) as egress
        
        int ret = bpf_map_update_elem(tx_port_fd, &key, &val, BPF_ANY);
        if (ret) {
             printf("Failed to update tx_port map: %d\n", ret);
        } else {
             printf("Configured XDP Redirect to Interface Index %d\n", val);
        }
        
        /* Configure Delta Interface (Key 1) */
        int val_delta = if_nametoindex("veth-delta");
        if (val_delta > 0) {
            int key_delta = 1;
            bpf_map_update_elem(tx_port_fd, &key_delta, &val_delta, BPF_ANY);
             printf("Configured XDP Redirect for Delta to Interface Index %d\n", val_delta);
        } else {
            printf("Warning: veth-delta not found. Delta redirect will fail.\n");
        }
        
    } else {
        /* Decompressor Mode */
        int ifindex = if_nametoindex(iface_ingress);
         if (!ifindex) {
            fprintf(stderr, "Interface %s not found\n", iface_ingress);
            goto cleanup;
        }
        
        /* Force Detach XDP first to avoid EBUSY */
        bpf_xdp_detach(ifindex, 0, NULL);

        /* Attach XDP (Decompressor) */
        struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_decompress_main, ifindex);
        if (!link) {
            fprintf(stderr, "Failed to attach XDP Decompressor to %s: %d\n", iface_ingress, -errno);
            // Try Generic Mode
            link = bpf_program__attach_xdp(skel->progs.xdp_decompress_main, ifindex);
             if (!link) {
                err = -1;
                goto cleanup;
             }
        }
        skel->links.xdp_decompress_main = link; // Persist link
        printf("Attached XDP (Decompressor) to %s\n", iface_ingress);
    }
    
    printf("Successfully attached! Press Ctrl+C to stop.\n");
    printf("Read trace_pipe to see logs: cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Showing Performance Metrics (Ctrl+C to stop):\n");



    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Stats Loop */
    if (mode == 0) {
        int stats_fd = bpf_map__fd(skel->maps.stats_map);
        struct perf_stats stats[2];
        __u32 key = 0;
        
        while (!exiting) {
            printf("\033[H\033[J"); // Clear Screen
            printf("=== Middlebox Performance Metrics ===\n");
            printf("%-20s | %-10s | %-10s | %-10s | %-10s\n", "Metric", "Count", "Min (ns)", "Avg (ns)", "Max (ns)");
            printf("---------------------|------------|------------|------------|------------\n");

            /* Read Queue State (Local) */
            int q_map_fd = bpf_map__fd(skel->maps.queue_state_map);
            struct queue_state qs = {0};
            key = 0;
            bpf_map_lookup_elem(q_map_fd, &key, &qs);
            
            /* Read Remote State */
            int r_map_fd = bpf_map__fd(skel->maps.remote_state_map);
            __u32 remote_state = 0;
            bpf_map_lookup_elem(r_map_fd, &key, &remote_state);
            
            /* Calculate Operating State (Simulate Logic) */
             __u32 local_severity = 0;
            if (qs.state == 1) local_severity = 1; // COMPRESS
            else if (qs.state == 2) local_severity = 2; // DELTA
            else if (qs.state == 3) local_severity = 3; // INCREMENTAL
            else if (qs.state == 4) local_severity = 4; // DROP
            
            __u32 remote_severity = 0;
            if (remote_state == 1) remote_severity = 1;
            else if (remote_state == 2) remote_severity = 2;
            else if (remote_state == 3) remote_severity = 3;
            else if (remote_state == 4) remote_severity = 4;
            
            __u32 max_sev = (local_severity > remote_severity) ? local_severity : remote_severity;
            char *op_state_str = "NORMAL";
            if (max_sev == 1) op_state_str = "COMPRESS";
            else if (max_sev == 2) op_state_str = "DELTA";
            else if (max_sev == 3) op_state_str = "INCREMENTAL";
            else if (max_sev == 4) op_state_str = "DROP";

            char *local_str = "NORMAL";
            if (qs.state == 1) local_str = "COMPRESS";
            else if (qs.state == 2) local_str = "DELTA";
            else if (qs.state == 3) local_str = "INCREMENTAL";
            else if (qs.state == 4) local_str = "DROP";
            
            char *remote_str = "NORMAL";
            if (remote_state == 1) remote_str = "COMPRESS";
            else if (remote_state == 2) remote_str = "DELTA";
            else if (remote_state == 3) remote_str = "INCREMENTAL";
            else if (remote_state == 4) remote_str = "DROP";

            printf("\n=== CONGESTION STATE ===\n");
            printf("Queue Depth: %llu bytes\n", qs.current_bytes);
            printf("Local State: \033[1;36m%s\033[0m (Sev: %d)\n", local_str, local_severity);
            printf("Remote State: \033[1;35m%s\033[0m (Sev: %d)\n", remote_str, remote_severity);
            printf("OPERATING STATE: \033[1;32m%s\033[0m\n", op_state_str);
            printf("========================\n\n");

            __u32 key_stats = 0;
            struct perf_stats val;
            
            /* 1. Compression Stats */
            key = 0;
            if (bpf_map_lookup_elem(stats_fd, &key, &val) == 0) {
                 __u64 avg = val.count ? val.sum_ns / val.count : 0;
                 printf("%-20s | %-10llu | %-10llu | %-10llu | %-10llu\n", "Compression Time", val.count, val.min_ns, avg, val.max_ns);
            }

            /* 2. Sojourn Stats */
            key = 1;
            if (bpf_map_lookup_elem(stats_fd, &key, &val) == 0) {
                 __u64 avg = val.count ? val.sum_ns / val.count : 0;
                 printf("%-20s | %-10llu | %-10llu | %-10llu | %-10llu\n", "End-to-End Sojourn", val.count, val.min_ns, avg, val.max_ns);
            }
            
            /* 3. Queue Depth (Congestion User Interface) */
            struct queue_state q_val;
            __u32 q_key = 0;
            int q_fd = bpf_map__fd(skel->maps.queue_state_map);
            if (q_fd >= 0 && bpf_map_lookup_elem(q_fd, &q_key, &q_val) == 0) {
                 printf("\n=== Congestion Status ===\n");
                 
                 char *state_str = "NORMAL";
                 if (q_val.state == 1) state_str = "COMPRESSING";
                 if (q_val.state == 2) state_str = "DELTA ENCODING";
                 if (q_val.state == 3) state_str = "INCREMENTAL ENCODING";
                 if (q_val.state == 4) state_str = "DROPPING";
                 
                 printf("State: %s\n", state_str);
                 printf("Current Queue: %llu bytes / 500,000 bytes\n", q_val.current_bytes);
                 
                 /* Visual Bar */
                 int percent = (q_val.current_bytes * 100) / 500000;
                 if (percent > 100) percent = 100;

                 printf("Usage: [");
                 for(int i=0; i<50; i++) {
                     if (i < percent/2) printf("#");
                     else printf(" ");
                 }
                 printf("] %d%%\n", percent);

                 /* CSV Logging */
                 FILE *log_fp = fopen("congestion_log.csv", "a");
                 if (log_fp) {
                     fprintf(log_fp, "%llu,%llu,%d,%u\n", (unsigned long long)time(NULL), q_val.current_bytes, percent, q_val.state);
                     fclose(log_fp);
                 }
            }

            printf("\n(Generating traffic in H1 will update these values)\n");
            


            sleep(1);
        }
    } else {
        while (!exiting) {
            sleep(1);
        }
    }

    /* Cleanup handled by destroy, but TC needs explicit detach if MB mode */
    if (mode == 0) {
        int egress_ifindex = if_nametoindex(iface_egress);
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = egress_ifindex, .attach_point = BPF_TC_EGRESS);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1, .prog_fd = 0, .flags = 0, .prog_id = 0);
        bpf_tc_detach(&tc_hook, &tc_opts);
        bpf_tc_hook_destroy(&tc_hook);
    }

cleanup:
    xdp_prog__destroy(skel);
    return err < 0 ? -err : 0;
}
