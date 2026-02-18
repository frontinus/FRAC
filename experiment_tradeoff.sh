#!/bin/bash
# experiment_tradeoff.sh

OUTPUT_FILE="tradeoff_results.csv"
echo "Bandwidth_Mbps,Mode,Throughput_Mbps" > $OUTPUT_FILE

# Setup Network
echo "Setting up network..."
sudo ./network.sh > /dev/null 2>&1
sudo ./setup_delta.sh > /dev/null 2>&1

# Setup Loader (SCHC Enabled)
echo "Starting Middlebox Loader..."
sudo killall -9 loader 2>/dev/null
sudo ip netns exec MiddleBox ./loader veth1-mb veth2-mb > /dev/null 2>&1 &
LOADER_PID=$!
sleep 2

# Setup Sinks on H2
echo "Starting Sinks on H2..."
sudo killall -9 python3 2>/dev/null
# Sink for SCHC (8087)
sudo ip netns exec H2 python3 sink.py --port 8087 > /dev/null 2>&1 &
SINK1_PID=$!
# Sink for Baseline (9000)
sudo ip netns exec H2 python3 sink.py --port 9000 > /dev/null 2>&1 &
SINK2_PID=$!
sleep 2

# Test Function
run_test() {
    BW=$1 # e.g., "1mbit"
    MODE=$2 # "Baseline" or "SCHC"
    PORT=$3 # 9000 or 8087
    
    echo "------------------------------------------------"
    echo "Running Test: Bandwidth=$BW, Mode=$MODE"
    
    # Apply TC Limit on H1 Interface (veth1 - egress)
    sudo ip netns exec H1 tc qdisc del dev veth1 root 2>/dev/null
    sudo ip netns exec H1 tc qdisc add dev veth1 root tbf rate $BW burst 32kbit latency 400ms
    
    # Run Traffic Generator (CoT Mode - TCP)
    # Rate 200000 ensures saturation (max sends per sec)
    RESULT=$(sudo ip netns exec H1 python3 traffic_gen.py 10.0.2.1 --mode cot --port $PORT --rate 200000 --duration 15 | grep "Throughput")
    
    # Extract Mbps value
    # Format: "[CoT] Throughput: 12.34 Mbps"
    TPUT=$(echo $RESULT | awk '{print $3}')
    
    if [ -z "$TPUT" ]; then
        TPUT="0.0"
    fi
    
    echo "Result: $TPUT Mbps"
    echo "${BW},${MODE},${TPUT}" >> $OUTPUT_FILE
}

# Run Sweeps
# 1Mbps: Expect SCHC > Baseline
# 10Mbps: Expect SCHC > Baseline
# 100Mbps: Expect SCHC ~= Baseline
# 500Mbps: Expect Baseline > SCHC (CPU Bottleneck)

BWS=("1mbit" "10mbit" "100mbit" "500mbit")

for BW in "${BWS[@]}"; do
    # Baseline (Port 9000 - No Compression)
    run_test $BW "Baseline" 9000
    
    # SCHC (Port 8087 - Compression Enabled)
    run_test $BW "SCHC" 8087
done

# Cleanup
echo "Cleaning up..."
sudo kill $LOADER_PID
sudo kill $SINK1_PID
sudo kill $SINK2_PID
sudo ip netns exec H1 tc qdisc del dev veth1 root 2>/dev/null

echo "Done! Results saved to $OUTPUT_FILE"
cat $OUTPUT_FILE
