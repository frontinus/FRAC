#!/bin/bash

# Ensure base topology is up
if ! ip netns list | grep -q "MiddleBox"; then
    echo "MiddleBox namespace not found. Running network.sh..."
    if [ -f "./network.sh" ]; then
        chmod +x ./network.sh
        sudo ./network.sh
    else
        echo "Error: network.sh not found!"
        exit 1
    fi
fi

echo "Setting up Delta Encoding Interfaces in MiddleBox namespace..."

# Check if veth-delta already exists
if ip netns exec MiddleBox ip link show veth-delta >/dev/null 2>&1; then
    echo "veth-delta already exists. Recreating..."
    ip netns exec MiddleBox ip link del veth-delta
fi

# Create veth-delta pair INSIDE MiddleBox namespace
# Note: We create it inside directly to avoid moving
ip netns exec MiddleBox ip link add veth-delta type veth peer name veth-delta-peer

# Bring interfaces up
ip netns exec MiddleBox ip link set veth-delta up
ip netns exec MiddleBox ip link set veth-delta-peer up

# Optional: Assign IPs for debugging (not strictly needed for L2 redirect but good practice)
ip netns exec MiddleBox ip addr add 10.99.0.1/24 dev veth-delta
ip netns exec MiddleBox ip addr add 10.99.0.2/24 dev veth-delta-peer

# Turn off offloading to be safe
ip netns exec MiddleBox ethtool -K veth-delta tx off rx off >/dev/null 2>&1
ip netns exec MiddleBox ethtool -K veth-delta-peer tx off rx off >/dev/null 2>&1

echo "Delta setup complete."
echo ""
echo "To run the loader:"
echo "  sudo ip netns exec MiddleBox ./loader veth1-mb veth2-mb"
