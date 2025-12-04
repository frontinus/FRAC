#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

/* Map to store ingress timestamp */
struct packet_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct packet_key);
    __type(value, __u64);
} packet_ts SEC(".maps");

/* XDP: Ingress Hook */
SEC("xdp")
int xdp_prog_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    /* Store timestamp */
    struct packet_key key = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .id = iph->id
    };
    __u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&packet_ts, &key, &ts, BPF_ANY);

    return XDP_PASS;
}

/* TC: Egress Hook */
SEC("tc")
int tc_prog_main(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    struct packet_key key = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .id = iph->id
    };

    __u64 *ts = bpf_map_lookup_elem(&packet_ts, &key);
    if (ts) {
        __u64 delta = bpf_ktime_get_ns() - *ts;
        bpf_printk("Sojourn Time: %llu ns (Src: %x, ID: %d)\n", delta, bpf_ntohl(key.src_ip), bpf_ntohs(key.id));
        bpf_map_delete_elem(&packet_ts, &key);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
