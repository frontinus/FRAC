nuke() {
    echo "  [Nuke] tearing down namespaces..."
    for ns in H1 H2 MiddleBox; do
        pids=$(ip netns pids $ns 2>/dev/null)
        if [ -n "$pids" ]; then
            echo "    Killing pids in $ns: $pids"
            kill -9 $pids 2>/dev/null
        fi
        ip netns del $ns 2>/dev/null
    done
    sleep 1
}

setup_network() {
    echo "  [Setup] Configuring topology..."
    ip netns add H1
    ip netns add H2
    ip netns add MiddleBox

    ip link add veth1 type veth peer name veth1-mb
    ip link set veth1 netns H1
    ip link set veth1-mb netns MiddleBox

    ip link add veth2 type veth peer name veth2-mb
    ip link set veth2 netns H2
    ip link set veth2-mb netns MiddleBox

    ip netns exec H1 ip addr add 10.0.1.1/24 dev veth1
    ip netns exec H1 ip link set veth1 up
    ip netns exec H1 ip route add 10.0.2.0/24 via 10.0.1.2

    ip netns exec MiddleBox ip addr add 10.0.1.2/24 dev veth1-mb
    ip netns exec MiddleBox ip link set veth1-mb up
    ip netns exec MiddleBox ip addr add 10.0.2.2/24 dev veth2-mb
    ip netns exec MiddleBox ip link set veth2-mb up
    ip netns exec MiddleBox sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ip netns exec H2 ip addr add 10.0.2.1/24 dev veth2
    ip netns exec H2 ip link set veth2 up
    ip netns exec H2 ip route add 10.0.1.0/24 via 10.0.2.2

    # Agent veth pair (always create for topology consistency)
    ip link add veth-delta type veth peer name veth-delta-peer
    ip link set veth-delta netns MiddleBox
    ip link set veth-delta-peer netns MiddleBox
    ip netns exec MiddleBox ip link set veth-delta up
    ip netns exec MiddleBox ip link set veth-delta-peer up
    ip netns exec MiddleBox ip addr add 192.168.99.1/24 dev veth-delta
    ip netns exec MiddleBox ip addr add 192.168.99.2/24 dev veth-delta-peer

    # Disable RP Filter
    ip netns exec MiddleBox sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
    ip netns exec MiddleBox sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
    ip netns exec MiddleBox sysctl -w net.ipv4.conf.veth-delta.rp_filter=0 >/dev/null
    ip netns exec MiddleBox sysctl -w net.ipv4.conf.veth1-mb.rp_filter=0 >/dev/null
    ip netns exec MiddleBox sysctl -w net.ipv4.conf.veth2-mb.rp_filter=0 >/dev/null

    # Disable Offloading
    for dev in veth1-mb veth2-mb veth-delta veth-delta-peer; do
        ip netns exec MiddleBox ethtool -K $dev tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    done
    ip netns exec H2 ethtool -K veth2 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
}

run_phase() {
    PHASE_NAME=$1
    STATE_VAL=$2
    LOG_FILE=$3
    AGENT_ENABLED=$4

    nuke
    setup_network

    echo "--- Phase: $PHASE_NAME (State=$STATE_VAL) ---"
    # 200kbps link with jitter and loss
    ip netns exec MiddleBox tc qdisc add dev veth2-mb root netem \
       rate 200kbit delay 50ms 10ms loss 2%

    # Clear old telemetry before starting
    rm -f congestion_log.csv

    # Start Sink (CPU 3)
    taskset -c 3 ip netns exec H2 python3 -u sink.py --port 8087 > /tmp/sink_${PHASE_NAME}.log 2>&1 &
    SINK_PID=$!

    # Start Monitor (CPU 0)
    taskset -c 0 ip netns exec MiddleBox python3 monitor_general.py veth2-mb $LOG_FILE &
    MON_PID=$!

    # Start Agent if needed (CPU 2)
    AGENT_PID=""
    if [ "$AGENT_ENABLED" = "true" ]; then
        echo "  > Starting C Agent (CPU 2)..."
        taskset -c 2 ip netns exec MiddleBox ./delta_agent_c > /tmp/agent_${PHASE_NAME}.log 2>&1 &
        AGENT_PID=$!
    fi

    # ALWAYS start the Loader (even in Baseline) to collect eBPF Sojourn Telemetry
    echo "  > Starting Loader & Forcing State $STATE_VAL..."
    taskset -c 0 ip netns exec MiddleBox ./loader veth1-mb veth2-mb > /tmp/loader_${PHASE_NAME}.log 2>&1 &
    LOADER_PID=$!
    sleep 2

    # Start decompressor on H2
    echo "  > Starting Decompressor on H2..."
    ip netns exec H2 ./loader --decompress veth2 > /tmp/decomp_${PHASE_NAME}.log 2>&1 &
    DECOMP_PID=$!
    sleep 1

    # Periodic state forcing
    (
        while kill -0 $SINK_PID 2>/dev/null; do
            ip netns exec MiddleBox python3 force_state.py $STATE_VAL &
            FORCE_PID=$!
            sleep 2.0
            kill $FORCE_PID 2>/dev/null
        done
    ) &
    FORCE_LOOP_PID=$!

    # Traffic (CPU 1)
    echo "  > Sending 100pps traffic (800B payload)..."
    taskset -c 1 ip netns exec H1 python3 -u traffic_gen.py 10.0.2.1 \
        --mode cot --port 8087 --rate 100 --duration 40 --udp --payload_size 800 \
        > /tmp/traffic_${PHASE_NAME}.log 2>&1

    sleep 3
    kill $MON_PID $SINK_PID $AGENT_PID $LOADER_PID $DECOMP_PID $FORCE_LOOP_PID 2>/dev/null
    wait $MON_PID $SINK_PID $AGENT_PID 2>/dev/null

    # Preserve the specific sojourn telemetry for this phase
    mv congestion_log.csv ${PHASE_NAME}_sojourn.csv 2>/dev/null

    # Record Sink-side metrics
    SINK_SYNC=$(grep -c "Rx SYNC\|Auto-Sync" /tmp/sink_${PHASE_NAME}.log 2>/dev/null || echo 0)
    SINK_HC=$(grep -c "Rx HC:" /tmp/sink_${PHASE_NAME}.log 2>/dev/null || echo 0)
    SINK_DELTA=$(grep -c "Rx DELTA:" /tmp/sink_${PHASE_NAME}.log 2>/dev/null || echo 0)
    SINK_INCR=$(grep -c "Rx INCREMENTAL:" /tmp/sink_${PHASE_NAME}.log 2>/dev/null || echo 0)
    SINK_FAIL=$(grep -c "FAILED" /tmp/sink_${PHASE_NAME}.log 2>/dev/null || echo 0)
    echo "  > Sink: sync=$SINK_SYNC hc=$SINK_HC delta=$SINK_DELTA incr=$SINK_INCR fail=$SINK_FAIL"
    echo "$PHASE_NAME,$SINK_SYNC,$SINK_HC,$SINK_DELTA,$SINK_INCR,$SINK_FAIL" >> sink_summary.csv

    echo "  > Phase $PHASE_NAME Complete."
}

# Build
echo "=== Compiling ==="
gcc -O3 -o delta_agent_c delta_agent_c.c -lz
make clean && make
echo "=== Compilation Done ==="

# Clean old data
rm -f baseline_log.csv hc_log.csv delta_log.csv incremental_log.csv sink_summary.csv
echo "phase,sync,hc,delta,incr,fail" > sink_summary.csv

# Execution Sequence
run_phase "Baseline"     "0" "baseline_log.csv"     "false"
run_phase "HeaderComp"   "1" "hc_log.csv"           "true"
run_phase "Delta"        "2" "delta_log.csv"         "true"
run_phase "Incremental"  "3" "incremental_log.csv"   "true"

echo "All phases complete. Generating comparative plot..."
python3 plot_comparative.py
cat sink_summary.csv
