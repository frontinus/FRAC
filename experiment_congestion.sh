#!/bin/bash
set -e

# 1. Reset Network (Re-apply basic setup)
./network.sh

# 2. Apply TC Rate Limiting on Middlebox Egress (veth2-mb) -> H2
echo "Applying 5Mbit limit on Middlebox -> H2..."
# Clear existing root qdisc
sudo ip netns exec MiddleBox tc qdisc del dev veth2-mb root 2>/dev/null || true
# Add TBF (Token Bucket Filter) 
# rate 5mbit, burst 10kb, limit 1mb (latency buffer)
sudo ip netns exec MiddleBox tc qdisc add dev veth2-mb root tbf rate 5mbit burst 10kb limit 1mb

# 3. Start Middlebox Loader
echo "Starting Middlebox Loader (Background)..."
# We need to run it in background
# sudo ip netns exec MiddleBox ./loader veth1-mb veth2-mb &
# PID=$!
# But loader needs TTY or might block? Let's assume user runs loader in separate window as usual.
# For this script, we will just prepare the network and run iperf.

echo "PLEASE ENSURE LOADER IS RUNNING IN ANOTHER TERMINAL!"
read -p "Press Enter when Loader is running..."

# 4. Start iperf Server on H2 (Receiver)
# 4. Start iperf Server on H2 (Receiver)
echo "Starting iperf Server on H2 (Port 5000)..."
sudo ip netns exec H2 iperf -s -p 5000 -i 1 > h2_server.log &
IPERF_PID=$!

# 5. Start iperf Client on H1 (Sender) -> 7.5 Mbps
echo "Starting iperf Sender on H1 (7.5 Mbps -> 10.0.2.1:5000)..."
# TCP tries to fill bandwidth, so -b 7.5M is still valid for shaping sender
sudo ip netns exec H1 iperf -c 10.0.2.1 -p 5000 -b 7.5M -t 10 -i 1

echo "Experiment Done. Stopping Server..."
kill $IPERF_PID 2>/dev/null || true

echo "Check h2_server.log for bandwidth results."
echo "Check Middlebox Terminal for 'Q-Depth' logs."
