#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "xdp_prog.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct xdp_prog *skel;
    int err;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ingress_iface> <egress_iface>\n", argv[0]);
        return 1;
    }

    int ingress_ifindex = if_nametoindex(argv[1]);
    if (!ingress_ifindex) {
        fprintf(stderr, "Ingress interface %s not found\n", argv[1]);
        return 1;
    }

    int egress_ifindex = if_nametoindex(argv[2]);
    if (!egress_ifindex) {
        fprintf(stderr, "Egress interface %s not found\n", argv[2]);
        return 1;
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

    /* Attach XDP (Ingress) */
    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_prog_main, ingress_ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program to %s: %d\n", argv[1], -errno);
        err = -1;
        goto cleanup;
    }
    printf("Attached XDP to %s\n", argv[1]);

    /* Attach TC (Egress) */
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = egress_ifindex, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1, .prog_fd = bpf_program__fd(skel->progs.tc_prog_main));

    /* Create clsact qdisc */
    bpf_tc_hook_create(&tc_hook); // Ignore error if already exists

    /* Attach TC prog */
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC program to %s: %d\n", argv[2], err);
        goto cleanup;
    }
    printf("Attached TC to %s\n", argv[2]);

    printf("Successfully attached! Press Ctrl+C to stop.\n");
    printf("Read trace_pipe to see output: cat /sys/kernel/debug/tracing/trace_pipe\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        sleep(1);
    }

    /* Detach TC */
    tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0; // Clear fields for detach
    tc_opts.flags = 0;
    tc_opts.prog_fd = 0;
    tc_opts.prog_id = 0;
    tc_opts.handle = 1;
    tc_opts.priority = 1;
    bpf_tc_detach(&tc_hook, &tc_opts);
    bpf_tc_hook_destroy(&tc_hook);

cleanup:
    xdp_prog__destroy(skel);
    return err < 0 ? -err : 0;
}
