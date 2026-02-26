#!/usr/bin/env bash
# ===========================================================================
# run_comparative.sh — Unified Comparative Compression Experiment
# ===========================================================================
# Usage:
#   sudo bash run_comparative.sh --topology single    # 3-ns sojourn focus
#   sudo bash run_comparative.sh --topology dual       # 4-ns e2e latency
#   sudo bash run_comparative.sh                       # defaults to single
#
# Single-MB (3 ns):  H1 ── MiddleBox ── H2
#   - Netem on MiddleBox egress, sojourn time measurement
#
# Dual-MB (4 ns):    H1 ── MB1 ═══(netem)═══ MB2 ── H2
#   - Netem on tactical link, e2e latency measurement
#   - MB1 compresses, MB2 decompresses (transparent to endpoints)
# ===========================================================================
set -uo pipefail

# ── Parse Args ──────────────────────────────────────────────────────────────
TOPOLOGY="single"
while [[ $# -gt 0 ]]; do
    case $1 in
        --topology) TOPOLOGY="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; echo "Usage: $0 [--topology single|dual]"; exit 1 ;;
    esac
done

if [[ "$TOPOLOGY" != "single" && "$TOPOLOGY" != "dual" ]]; then
    echo "Error: --topology must be 'single' or 'dual'"
    exit 1
fi

echo "=== Topology: $TOPOLOGY ==="

# ── Tunables ────────────────────────────────────────────────────────────────
DURATION=40
PPS=200
PAYLOAD_SIZE=800
LINK_RATE="200kbit"
LINK_DELAY="50ms"
LINK_JITTER="10ms"
LINK_LOSS="2%"

# ── Cleanup ─────────────────────────────────────────────────────────────────
nuke() {
    echo "  [Nuke] tearing down namespaces..."
    for ns in H1 H2 MiddleBox MB1 MB2; do
        pids=$(ip netns pids $ns 2>/dev/null)
        if [ -n "$pids" ]; then
            echo "    Killing pids in $ns: $pids"
            kill -9 $pids 2>/dev/null || true
        fi
        ip netns del $ns 2>/dev/null || true
    done
    for i in $(seq 1 10); do
        umount /sys/fs/bpf 2>/dev/null || break
    done
    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf/
    rm -f /sys/fs/bpf/queue_state_map \
          /sys/fs/bpf/packet_ts \
          /sys/fs/bpf/context_map \
          /sys/fs/bpf/stats_map \
          /sys/fs/bpf/tx_port \
          /sys/fs/bpf/remote_state_map 2>/dev/null || true
    sleep 0.5
}

# ── Build ─────────────────────────────────────────────────────────────────────────
echo "=== Building ==="
make clean && make
echo "=== Build Done ==="

# ── Ensure PSK exists for encryption ──────────────────────────────────────────────
if [ ! -f efrac.psk ]; then
    python3 -c "import os; print(os.urandom(32).hex())" > efrac.psk
    echo "Generated new efrac.psk"
fi

mkdir -p results/logs

# ── Network Setup ───────────────────────────────────────────────────────────
setup_network_single() {
    echo "  [Setup] Configuring single-MB topology..."
    ip netns add H1
    ip netns add MiddleBox
    ip netns add H2

    # H1 <-> MiddleBox
    ip link add veth1 type veth peer name veth1-mb
    ip link set veth1 netns H1
    ip link set veth1-mb netns MiddleBox

    ip netns exec H1 ip addr add 10.0.1.1/24 dev veth1
    ip netns exec H1 ip link set veth1 up
    ip netns exec H1 ip link set lo up
    ip netns exec H1 ip route add default via 10.0.1.2

    ip netns exec MiddleBox ip addr add 10.0.1.2/24 dev veth1-mb
    ip netns exec MiddleBox ip link set veth1-mb up
    ip netns exec MiddleBox ip link set lo up

    # MiddleBox <-> H2
    ip link add veth2-mb type veth peer name veth2
    ip link set veth2-mb netns MiddleBox
    ip link set veth2 netns H2

    ip netns exec MiddleBox ip addr add 10.0.2.2/24 dev veth2-mb
    ip netns exec MiddleBox ip link set veth2-mb up
    ip netns exec MiddleBox sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ip netns exec H2 ip addr add 10.0.2.1/24 dev veth2
    ip netns exec H2 ip link set veth2 up
    ip netns exec H2 ip link set lo up
    ip netns exec H2 ip route add default via 10.0.2.2

    # Delta agent redirect veth pair inside MiddleBox
    ip link add veth-delta type veth peer name veth-delta-peer
    ip link set veth-delta netns MiddleBox
    ip link set veth-delta-peer netns MiddleBox
    ip netns exec MiddleBox ip link set veth-delta up
    ip netns exec MiddleBox ip link set veth-delta-peer up
    ip netns exec MiddleBox ip addr add 192.168.99.1/24 dev veth-delta
    ip netns exec MiddleBox ip addr add 192.168.99.2/24 dev veth-delta-peer

    # RP filter
    ip netns exec MiddleBox sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    ip netns exec MiddleBox sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
    for dev in veth1-mb veth2-mb veth-delta veth-delta-peer; do
        ip netns exec MiddleBox sysctl -w net.ipv4.conf.$dev.rp_filter=0 >/dev/null 2>&1 || true
    done

    # Disable HW offloading
    for dev in veth1-mb veth2-mb veth-delta veth-delta-peer; do
        ip netns exec MiddleBox ethtool -K $dev tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    done
    ip netns exec H1 ethtool -K veth1 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    ip netns exec H2 ethtool -K veth2 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
}

setup_network_dual() {
    echo "  [Setup] Configuring dual-MB topology..."
    ip netns add H1
    ip netns add MB1
    ip netns add MB2
    ip netns add H2

    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf/
    ip netns exec MB1 mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true
    ip netns exec MB2 mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true
    ip netns exec MB1 rm -f /sys/fs/bpf/queue_state_map /sys/fs/bpf/packet_ts \
          /sys/fs/bpf/context_map /sys/fs/bpf/stats_map /sys/fs/bpf/tx_port \
          /sys/fs/bpf/remote_state_map 2>/dev/null || true
    rm -f /sys/fs/bpf/queue_state_map /sys/fs/bpf/packet_ts \
          /sys/fs/bpf/context_map /sys/fs/bpf/stats_map /sys/fs/bpf/tx_port \
          /sys/fs/bpf/remote_state_map 2>/dev/null || true

    # H1 <-> MB1 (Subnet A: 10.0.1.0/24)
    ip link add veth-h1 type veth peer name veth-mb1
    ip link set veth-h1 netns H1
    ip link set veth-mb1 netns MB1

    ip netns exec H1 ip addr add 10.0.1.1/24 dev veth-h1
    ip netns exec H1 ip link set veth-h1 up
    ip netns exec H1 ip link set lo up
    ip netns exec H1 ip route add default via 10.0.1.2

    ip netns exec MB1 ip addr add 10.0.1.2/24 dev veth-mb1
    ip netns exec MB1 ip link set veth-mb1 up
    ip netns exec MB1 ip link set lo up

    # MB1 <-> MB2 (Tactical Link: 10.0.100.0/24)
    ip link add veth-link1 type veth peer name veth-link2
    ip link set veth-link1 netns MB1
    ip link set veth-link2 netns MB2

    ip netns exec MB1 ip addr add 10.0.100.1/24 dev veth-link1
    ip netns exec MB1 ip link set veth-link1 up

    ip netns exec MB2 ip addr add 10.0.100.2/24 dev veth-link2
    ip netns exec MB2 ip link set veth-link2 up
    ip netns exec MB2 ip link set lo up

    # MB2 <-> H2 (Subnet B: 10.0.2.0/24)
    ip link add veth-mb2 type veth peer name veth-h2
    ip link set veth-mb2 netns MB2
    ip link set veth-h2 netns H2

    ip netns exec MB2 ip addr add 10.0.2.2/24 dev veth-mb2
    ip netns exec MB2 ip link set veth-mb2 up

    ip netns exec H2 ip addr add 10.0.2.1/24 dev veth-h2
    ip netns exec H2 ip link set veth-h2 up
    ip netns exec H2 ip link set lo up
    ip netns exec H2 ip route add default via 10.0.2.2

    # Delta agent redirect veth pair inside MB1
    ip link add veth-delta type veth peer name veth-delta-peer
    ip link set veth-delta netns MB1
    ip link set veth-delta-peer netns MB1
    ip netns exec MB1 ip link set veth-delta up
    ip netns exec MB1 ip link set veth-delta-peer up
    ip netns exec MB1 ip addr add 192.168.99.1/24 dev veth-delta
    ip netns exec MB1 ip addr add 192.168.99.2/24 dev veth-delta-peer

    # Routing
    ip netns exec MB1 sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ip netns exec MB2 sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ip netns exec MB1 ip route add 10.0.2.0/24 via 10.0.100.2
    ip netns exec MB2 ip route add 10.0.1.0/24 via 10.0.100.1

    # RP filter
    for ns in MB1 MB2; do
        ip netns exec $ns sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
        ip netns exec $ns sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
    done
    for dev in veth-mb1 veth-link1 veth-delta veth-delta-peer; do
        ip netns exec MB1 sysctl -w net.ipv4.conf.$dev.rp_filter=0 >/dev/null 2>&1 || true
    done
    for dev in veth-link2 veth-mb2; do
        ip netns exec MB2 sysctl -w net.ipv4.conf.$dev.rp_filter=0 >/dev/null 2>&1 || true
    done

    # Disable HW offloading
    for dev in veth-mb1 veth-link1 veth-delta veth-delta-peer; do
        ip netns exec MB1 ethtool -K $dev tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    done
    for dev in veth-link2 veth-mb2; do
        ip netns exec MB2 ethtool -K $dev tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    done
    ip netns exec H1 ethtool -K veth-h1 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    ip netns exec H2 ethtool -K veth-h2 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
}

# ── Run a single phase ──────────────────────────────────────────────────────
run_phase() {
    PHASE_NAME=$1
    STATE_VAL=$2
    LOG_FILE=$3
    AGENT_ENABLED=$4

    nuke

    if [[ "$TOPOLOGY" == "single" ]]; then
        setup_network_single
    else
        setup_network_dual
    fi

    echo "--- Phase: $PHASE_NAME (State=$STATE_VAL, Topology=$TOPOLOGY) ---"

    # ── Topology-specific variables ──
    if [[ "$TOPOLOGY" == "single" ]]; then
        MB_NS="MiddleBox"
        INGRESS_IFACE="veth1-mb"
        EGRESS_IFACE="veth2-mb"
        NETEM_IFACE="veth2-mb"
        MONITOR_IFACE="veth2-mb"
        DECOMP_IFACE="veth2"
        DECOMP_NS="H2"
    else
        MB_NS="MB1"
        INGRESS_IFACE="veth-mb1"
        EGRESS_IFACE="veth-link1"
        NETEM_IFACE="veth-link1"
        MONITOR_IFACE="veth-link1"
        DECOMP_IFACE="veth-link2"
        DECOMP_NS="MB2"
    fi

    # Apply netem
    ip netns exec $MB_NS tc qdisc add dev $NETEM_IFACE root netem \
       rate ${LINK_RATE} delay ${LINK_DELAY} ${LINK_JITTER} loss ${LINK_LOSS}

    # Dual-MB: block forwarding of compressed traffic (decompress_agent handles it)
    if [[ "$TOPOLOGY" == "dual" && "$AGENT_ENABLED" == "true" ]]; then
        ip netns exec MB2 iptables -A FORWARD -i veth-link2 -p udp --dport 8087 -j DROP
    fi

    rm -f congestion_log.csv

    # Always decrypt: handles encrypted Baseline (no agent) + plaintext from decompress_agent (graceful fallback)
    SINK_CMD="python3 -u src/sink.py --port 8087 --decrypt"
    if [[ "$TOPOLOGY" == "dual" ]]; then
        SINK_CMD="$SINK_CMD --e2e_log results/e2e_latency_${PHASE_NAME}.csv"
    fi
    taskset -c 3 ip netns exec H2 $SINK_CMD > results/logs/sink_${PHASE_NAME}.log 2>&1 &
    SINK_PID=$!

    # ── Start Monitor ──
    echo "Monitoring $MONITOR_IFACE -> results/$LOG_FILE"
    taskset -c 0 ip netns exec $MB_NS python3 src/monitor_general.py $MONITOR_IFACE results/$LOG_FILE &
    MON_PID=$!

    # ── Start Agent on MB if needed ──
    AGENT_PID=""
    if [ "$AGENT_ENABLED" = "true" ]; then
        echo "  > Starting C Agent on $MB_NS (CPU 2)..."
        AGENT_ENV=""
        [[ "$TOPOLOGY" == "dual" ]] && AGENT_ENV="E2E_TRAILER=1"
        taskset -c 2 ip netns exec $MB_NS env $AGENT_ENV ./src/delta_agent_c > results/logs/agent_${PHASE_NAME}.log 2>&1 &
        AGENT_PID=$!
    fi

    # ── Start eBPF Loader on MB ──
    echo "  > Starting Loader on $MB_NS & Forcing State $STATE_VAL..."
    taskset -c 0 ip netns exec $MB_NS ./src/loader $INGRESS_IFACE $EGRESS_IFACE \
        > results/logs/loader_${PHASE_NAME}.log 2>&1 &
    LOADER_PID=$!
    sleep 2

    # ── Start Decompressor ──
    echo "  > Starting Decompressor on $DECOMP_NS..."
    ip netns exec $DECOMP_NS ./src/loader --decompress $DECOMP_IFACE \
        > results/logs/decomp_${PHASE_NAME}.log 2>&1 &
    DECOMP_PID=$!

    # ── Dual-MB: start decompress agent on MB2 ──
    DAGENT_PID=""
    if [[ "$TOPOLOGY" == "dual" && "$AGENT_ENABLED" == "true" ]]; then
        echo "  > Starting Decompress Agent on MB2..."
        ip netns exec MB2 env E2E_TRAILER=1 ./src/decompress_agent veth-link2 8087 10.0.2.1 \
            > results/logs/dagent_${PHASE_NAME}.log 2>&1 &
        DAGENT_PID=$!
    fi
    sleep 1

    # ── Periodic state forcing ──
    (
        while kill -0 $SINK_PID 2>/dev/null; do
            ip netns exec $MB_NS python3 src/force_state.py $STATE_VAL &
            FORCE_PID=$!
            sleep 2.0
            kill $FORCE_PID 2>/dev/null
        done
    ) &
    FORCE_LOOP_PID=$!

    # ── Generate traffic from H1 ──
    echo "  > Sending ${PPS}pps traffic (${PAYLOAD_SIZE}B payload) for ${DURATION}s..."
    TRAFFIC_CMD="python3 -u src/traffic_gen.py 10.0.2.1 \
        --mode cot --port 8087 --rate $PPS --duration $DURATION --udp \
        --payload_size $PAYLOAD_SIZE --encrypt"
    if [[ "$TOPOLOGY" == "dual" ]]; then
        TRAFFIC_CMD="$TRAFFIC_CMD --e2e_timestamp"
    fi
    taskset -c 1 ip netns exec H1 $TRAFFIC_CMD \
        > results/logs/traffic_${PHASE_NAME}.log 2>&1

    sleep 3
    kill $MON_PID $SINK_PID $AGENT_PID $LOADER_PID $DECOMP_PID $DAGENT_PID $FORCE_LOOP_PID 2>/dev/null
    wait $MON_PID $SINK_PID $AGENT_PID $DAGENT_PID 2>/dev/null

    # Preserve sojourn telemetry
    mv congestion_log.csv results/${PHASE_NAME}_sojourn.csv 2>/dev/null

    # Record Sink-side metrics
    SINK_SYNC=$(grep -c "Rx SYNC\|Auto-Sync" results/logs/sink_${PHASE_NAME}.log 2>/dev/null || true)
    SINK_HC=$(grep -c "Rx HC:" results/logs/sink_${PHASE_NAME}.log 2>/dev/null || true)
    SINK_DELTA=$(grep -c "Rx DELTA:" results/logs/sink_${PHASE_NAME}.log 2>/dev/null || true)
    SINK_INCR=$(grep -c "Rx INCREMENTAL:" results/logs/sink_${PHASE_NAME}.log 2>/dev/null || true)
    SINK_FAIL=$(grep -c "FAILED" results/logs/sink_${PHASE_NAME}.log 2>/dev/null || true)
    echo "  > Sink: sync=$SINK_SYNC hc=$SINK_HC delta=$SINK_DELTA incr=$SINK_INCR fail=$SINK_FAIL"
    echo "$PHASE_NAME,$SINK_SYNC,$SINK_HC,$SINK_DELTA,$SINK_INCR,$SINK_FAIL" >> results/sink_summary.csv

    echo "  > Phase $PHASE_NAME Complete."
}

# ── Clean old results ───────────────────────────────────────────────────────
rm -rf results/
mkdir -p results/logs
echo "phase,sync,hc,delta,incr,fail" > results/sink_summary.csv

# ── Run all 4 phases ────────────────────────────────────────────────────────
run_phase "Baseline"    0 baseline_log.csv     false
run_phase "HeaderComp"  1 hc_log.csv           true
run_phase "Delta"       2 delta_log.csv        true
run_phase "Incremental" 3 incremental_log.csv  true

echo "All phases complete. Generating plots..."
cd results/
python3 ../scripts/plot_comparative.py
if [[ "$TOPOLOGY" == "dual" ]]; then
    python3 ../scripts/plot_dual_mb.py
fi
echo ""
cat sink_summary.csv
cd ..
