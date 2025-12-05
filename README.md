# Tactical Network Simulation Framework

## Overview
This repository contains a lightweight, modular framework for simulating tactical network environments and generating multi-modal application traffic. The tools are designed to facilitate research into network performance, Quality of Service (QoS), and congestion control mechanisms within bandwidth-constrained and high-latency networks (e.g., SATCOM, tactical radio links).

The framework consists of two primary components:
1.  **`traffic_gen.py`**: A multi-threaded, class-based traffic generator capable of simulating Command & Control (C2), ISR video, voice, and chat traffic patterns.
2.  **`net_conditioner.py`**: A wrapper for Linux Traffic Control (`tc`) to inject deterministic network impairments such as latency, jitter, and bandwidth shaping.

## Components

### 1. Traffic Generator (`traffic_gen.py`)
Provides granular control over traffic generation with support for multiple distinct traffic classes often found in military and emergency response networks.

**Supported Stream Types:**
*   **Cursor on Target (CoT)**: Simulates situational awareness data using XML-based position reports. Sent over TCP with Expedited Forwarding (DSCP 46) marking.
*   **ISR Video**: Simulates Unmanned Aerial System (US) video feeds. Supports UDP streaming of file-based or synthetic video data (DSCP 34/AF41).
*   **Voice over IP (VoIP)**: Simulates RTP-encapsulated voice traffic (G.711 PCMU) over UDP, critical for real-time communications (DSCP 46).
*   **XMPP Chat**: Simulates low-bandwidth text messaging and presence information over TCP (DSCP 0).

**Key Features:**
*   **Interactive TUI**: A terminal-based menu for real-time stream management.
*   **Queue/Playlist System**: Ability to queue sequential file transfers or streams to model specific operational scenarios.
*   **Packet-Level Marking**: Automatic DSCP (DiffServ) tagging for QoS validation.
*   **Zero-Dependency**: Built using standard Python libraries for maximum portability on constrained embedded systems.

### 2. Network Conditioner (`net_conditioner.py`)
A utility script to configure the kernel's network emulator (`netem`) and hierarchical token bucket (`htb`) qdiscs.

**Capabilities:**
*   **Bandwidth Limiting**: Restrict interface throughput (e.g., `5mbit`, `100kbit`).
*   **Latency Injection**: Add fixed delay to packets (e.g., `500ms` for SATCOM simulation).
*   **Jitter**: Introduce variable delay to model realistic channel instability.

## Usage

### Prerequisites
*   Python 3.6+
*   Linux Kernel with `sch_netem` and `sch_htb` modules enabled (for conditioner).
*   Root privileges (required only for `net_conditioner.py`).

### Running the Traffic Generator
To launch the interactive console:
```bash
python3 traffic_gen.py
```
Follow the on-screen menu to add streams or configure a playback queue.

### Applying Network Conditions
To restrict the `veth2-mb` interface to 2 Mbps with 100ms delay and 20ms jitter:
```bash
sudo python3 net_conditioner.py --interface veth2-mb --rate 2mbit --delay 100ms --jitter 20ms
```

To reset all rules:
```bash
sudo python3 net_conditioner.py --reset
```

## Research Context
This toolset supports experiments in:
*   **DSCP-based Priority Scheduling**: Verifying that high-priority C2/Voice traffic preempts bulk video data.
*   **eBPF Traffic Analysis**: Generating known traffic patterns to validate eBPF monitoring hooks.
*   **Protocol Resilience**: Testing application behavior under severe packet loss or latency.

## License
MIT License
