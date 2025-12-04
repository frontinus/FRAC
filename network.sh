#!/bin/bash

# Clean up existing namespaces
ip netns del H1 2>/dev/null
ip netns del MiddleBox 2>/dev/null
ip netns del H2 2>/dev/null

# Create namespaces
ip netns add H1
ip netns add MiddleBox
ip netns add H2

# Create veth pairs
# H1 <-> MiddleBox
ip link add veth1 type veth peer name veth1-mb
# H2 <-> MiddleBox
ip link add veth2 type veth peer name veth2-mb

# Connect H1 <-> MiddleBox
ip link set veth1 netns H1
ip link set veth1-mb netns MiddleBox

# Connect MiddleBox <-> H2
ip link set veth2 netns H2
ip link set veth2-mb netns MiddleBox

# Assign IP addresses
# H1
ip netns exec H1 ip addr add 10.0.1.1/24 dev veth1
ip netns exec H1 ip link set veth1 up
ip netns exec H1 ip link set lo up

# MiddleBox
ip netns exec MiddleBox ip addr add 10.0.1.254/24 dev veth1-mb
ip netns exec MiddleBox ip link set veth1-mb up
ip netns exec MiddleBox ip addr add 10.0.2.254/24 dev veth2-mb
ip netns exec MiddleBox ip link set veth2-mb up
ip netns exec MiddleBox ip link set lo up
# Enable forwarding
ip netns exec MiddleBox sysctl -w net.ipv4.ip_forward=1

# H2
ip netns exec H2 ip addr add 10.0.2.1/24 dev veth2
ip netns exec H2 ip link set veth2 up
ip netns exec H2 ip link set lo up

# Add routes
ip netns exec H1 ip route add default via 10.0.1.254
ip netns exec H2 ip route add default via 10.0.2.254

echo "Topology created: H1 (10.0.1.1) <-> MiddleBox <-> H2 (10.0.2.1)"
