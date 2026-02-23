#!/bin/bash
# =============================================================================
# run_experiment.sh — eFRAC Real Measurement Runner
#
# Runs four 60-second phases back-to-back:
#   1. Baseline     — no compression, no loader
#   2. HC Only      — header compression active (loader forced to COMPRESS state)
#   3. Delta Only   — delta agent active (loader forced to DELTA state)
#   4. Incremental  — incremental agent active (loader forced to INCREMENTAL state)
#
# Outputs (one CSV per phase, written to ./results/):
#   baseline_monitor.csv      — time, tx_bytes, tx_packets, drops  (from monitor_general.py)
#   hc_monitor.csv
#   delta_monitor.csv
#   incremental_monitor.csv
#
#   baseline_sink.log         — raw sink stdout (parsed by plot_real_results.py)
#   hc_sink.log
#   delta_sink.log
#   incremental_sink.log
#
# Usage:
#   sudo bash run_experiment.sh
#
# Requirements:
#   - Run as root (ip netns, tc, bpftool need root)
#   - Compiled binaries: ./loader, ./delta_agent_c  (make && gcc -O3 -o delta_agent_c delta_agent_c.c -lz)
#   - Python scripts in the same directory: traffic_gen.py, net_conditioner.py,
#                                            sink.py, monitor_general.py, force_state.py
# =============================================================================

set -euo pipefail

RESULTS_DIR="./results"
mkdir -p "$RESULTS_DIR"

# ── Tunables ──────────────────────────────────────────────────────────────────
DURATION=60          # seconds per phase
PPS=100              # packets per second
PAYLOAD_SIZE=800     # bytes (use 0 for natural CoT XML ~230B)
LINK_RATE="200kbit"
LINK_DELAY="50ms"
LINK_JITTER="10ms"
LINK_LOSS="2%"

TARGET_IP="10.0.2.1"
TARGET_PORT=8087

# State values matching xdp_prog.c
STATE_NORMAL=0
STATE_COMPRESS=1   # HC
STATE_DELTA=2
STATE_INCREMENTAL=3

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[$(date '+%H:%M:%S')] $*"; }

nuke_namespaces() {
    log "Tearing down network namespaces..."
    for ns in H1 H2 MiddleBox; do
        local pids
        pids=$(ip netns pids "$ns" 2>/dev/null || true)
        [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    sleep 1
}

setup_network() {
    log "Setting up network topology..."

    ip netns add H1
    ip netns add H2
    ip netns add MiddleBox

    # H1 <-> MiddleBox
    ip link add veth1 type veth peer name veth1-mb
    ip link set veth1 netns H1
    ip link set veth1-mb netns MiddleBox

    # H2 <-> MiddleBox
    ip link add veth2 type veth peer name veth2-mb
    ip link set veth2 netns H2
    ip link set veth2-mb netns MiddleBox

    # H1 addresses
    ip netns exec H1 ip addr add 10.0.1.1/24 dev veth1
    ip netns exec H1 ip link set veth1 up
    ip netns exec H1 ip link set lo up
    ip netns exec H1 ip route add 10.0.2.0/24 via 10.0.1.2

    # MiddleBox addresses
    ip netns exec MiddleBox ip addr add 10.0.1.2/24 dev veth1-mb
    ip netns exec MiddleBox ip addr add 10.0.2.2/24 dev veth2-mb
    ip netns exec MiddleBox ip link set veth1-mb up
    ip netns exec MiddleBox ip link set veth2-mb up
    ip netns exec MiddleBox ip link set lo up
    ip netns exec MiddleBox sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # H2 addresses
    ip netns exec H2 ip addr add 10.0.2.1/24 dev veth2
    ip netns exec H2 ip link set veth2 up
    ip netns exec H2 ip link set lo up
    ip netns exec H2 ip route add 10.0.1.0/24 via 10.0.2.2

    # Delta veth pair (needed for loader even in HC-only mode)
    ip link add veth-delta type veth peer name veth-delta-peer
    ip link set veth-delta netns MiddleBox
    ip link set veth-delta-peer netns MiddleBox
    ip netns exec MiddleBox ip link set veth-delta up
    ip netns exec MiddleBox ip link set veth-delta-peer up
    ip netns exec MiddleBox ip addr add 192.168.99.1/24 dev veth-delta
    ip netns exec MiddleBox ip addr add 192.168.99.2/24 dev veth-delta-peer

    # Disable RP filter (needed for veth redirect)
    for iface in all default veth-delta veth-delta-peer veth1-mb veth2-mb; do
        ip netns exec MiddleBox sysctl -w "net.ipv4.conf.${iface}.rp_filter=0" >/dev/null 2>&1 || true
    done

    # Disable offloading (important for accurate byte counts)
    for dev in veth1-mb veth2-mb veth-delta veth-delta-peer; do
        ip netns exec MiddleBox ethtool -K "$dev" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    done
    ip netns exec H2 ethtool -K veth2 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true

    # Apply link impairment on the MiddleBox egress (tactical link)
    ip netns exec MiddleBox tc qdisc add dev veth2-mb root netem \
        rate "$LINK_RATE" delay "$LINK_DELAY" "$LINK_JITTER" loss "$LINK_LOSS"

    log "Network ready. Link: $LINK_RATE / $LINK_DELAY ±$LINK_JITTER / loss $LINK_LOSS"
}

# ── Phase runner ──────────────────────────────────────────────────────────────
# $1 = phase name (label)
# $2 = state value (0=normal/baseline, 1=HC, 2=delta, 3=incremental)
# $3 = monitor CSV output path
# $4 = sink log output path
# $5 = "true" if delta agent should run
run_phase() {
    local PHASE_NAME="$1"
    local STATE_VAL="$2"
    local MON_CSV="$3"
    local SINK_LOG="$4"
    local RUN_AGENT="$5"

    log "═══════════════════════════════════════════"
    log "Phase: $PHASE_NAME  (state=$STATE_VAL)"
    log "═══════════════════════════════════════════"

    nuke_namespaces
    setup_network

    # Start sink on H2
    ip netns exec H2 python3 -u sink.py --port "$TARGET_PORT" \
        > "$SINK_LOG" 2>&1 &
    SINK_PID=$!
    log "Sink started (PID $SINK_PID)"
    sleep 0.5

    # Start monitor on MiddleBox (watches veth2-mb egress = what hits the tactical link)
    ip netns exec MiddleBox python3 monitor_general.py veth2-mb "$MON_CSV" &
    MON_PID=$!
    log "Monitor started (PID $MON_PID)"

    LOADER_PID=""
    DECOMP_PID=""
    AGENT_PID=""
    FORCE_PID=""

    if [ "$STATE_VAL" -gt 0 ]; then
        # Start loader (eBPF) on MiddleBox
        ip netns exec MiddleBox ./loader veth1-mb veth2-mb \
            > "$RESULTS_DIR/${PHASE_NAME}_loader.log" 2>&1 &
        LOADER_PID=$!
        log "Loader started (PID $LOADER_PID)"
        sleep 2

        # Start decompressor on H2
        ip netns exec H2 ./loader --decompress veth2 \
            > "$RESULTS_DIR/${PHASE_NAME}_decomp.log" 2>&1 &
        DECOMP_PID=$!
        log "Decompressor started (PID $DECOMP_PID)"
        sleep 1

        # Force state via bpftool (runs in a loop for the entire phase duration)
        (
            while kill -0 "$SINK_PID" 2>/dev/null; do
                ip netns exec MiddleBox python3 force_state.py "$STATE_VAL" &
                local FP=$!
                sleep 2
                kill "$FP" 2>/dev/null || true
            done
        ) &
        FORCE_PID=$!
        log "State forcer started (forcing state $STATE_VAL)"
    fi

    # Start delta agent if needed (Delta and Incremental phases)
    if [ "$RUN_AGENT" = "true" ]; then
        ip netns exec MiddleBox ./delta_agent_c \
            > "$RESULTS_DIR/${PHASE_NAME}_agent.log" 2>&1 &
        AGENT_PID=$!
        log "Delta agent started (PID $AGENT_PID)"
        sleep 0.5
    fi

    # Send traffic from H1
    log "Sending traffic for ${DURATION}s..."
    ip netns exec H1 python3 -u traffic_gen.py "$TARGET_IP" \
        --mode cot \
        --port "$TARGET_PORT" \
        --rate "$PPS" \
        --duration "$DURATION" \
        --udp \
        --payload_size "$PAYLOAD_SIZE" \
        > "$RESULTS_DIR/${PHASE_NAME}_traffic.log" 2>&1

    log "Traffic done. Waiting 3s for in-flight packets..."
    sleep 3

    # Tear down
    for pid in $MON_PID $SINK_PID $AGENT_PID $LOADER_PID $DECOMP_PID $FORCE_PID; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    wait "$MON_PID" "$SINK_PID" 2>/dev/null || true

    # Print sink summary
    local SYNC HC DELTA INCR FAIL
    SYNC=$(grep -c "Rx SYNC\|Auto-Sync"     "$SINK_LOG" 2>/dev/null || echo 0)
    HC=$(grep -c   "Rx HC:"                 "$SINK_LOG" 2>/dev/null || echo 0)
    DELTA=$(grep -c "Rx DELTA:"             "$SINK_LOG" 2>/dev/null || echo 0)
    INCR=$(grep -c  "Rx INCREMENTAL:"       "$SINK_LOG" 2>/dev/null || echo 0)
    FAIL=$(grep -c  "FAILED"               "$SINK_LOG" 2>/dev/null || echo 0)
    log "Sink summary → sync=$SYNC  hc=$HC  delta=$DELTA  incr=$INCR  fail=$FAIL"
    echo "$PHASE_NAME,$SYNC,$HC,$DELTA,$INCR,$FAIL" >> "$RESULTS_DIR/sink_summary.csv"

    log "Phase $PHASE_NAME complete. CSV: $MON_CSV"
    sleep 2
}

# ── Compile ───────────────────────────────────────────────────────────────────
log "Compiling..."
make clean && make
gcc -O3 -o delta_agent_c delta_agent_c.c -lz
log "Compilation done."

# ── Clean old results ─────────────────────────────────────────────────────────
rm -f "$RESULTS_DIR"/*.csv "$RESULTS_DIR"/*.log
echo "phase,sync,hc,delta,incr,fail" > "$RESULTS_DIR/sink_summary.csv"

# ── Run phases ────────────────────────────────────────────────────────────────
#                  name            state  monitor_csv                          sink_log                          agent
run_phase "baseline"      0  "$RESULTS_DIR/baseline_monitor.csv"     "$RESULTS_DIR/baseline_sink.log"     "false"
run_phase "hc"            1  "$RESULTS_DIR/hc_monitor.csv"           "$RESULTS_DIR/hc_sink.log"           "false"
run_phase "delta"         2  "$RESULTS_DIR/delta_monitor.csv"        "$RESULTS_DIR/delta_sink.log"        "true"
run_phase "incremental"   3  "$RESULTS_DIR/incremental_monitor.csv"  "$RESULTS_DIR/incremental_sink.log"  "true"

nuke_namespaces

log "All phases complete. Results in $RESULTS_DIR/"
log "Now run:  python3 plot_real_results.py --results $RESULTS_DIR"