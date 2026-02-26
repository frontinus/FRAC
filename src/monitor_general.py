#!/usr/bin/env python3
import subprocess
import time
import csv
import sys
import re

# monitor_general.py [interface] [output_csv]
# Tracks: Timestamp, TxBytes, QdiscDrops

def get_stats(iface):
    # 1. TX Bytes/Packets from /sys
    try:
        with open(f"/sys/class/net/{iface}/statistics/tx_bytes", "r") as f:
            tx_bytes = int(f.read().strip())
        with open(f"/sys/class/net/{iface}/statistics/tx_packets", "r") as f:
            tx_packets = int(f.read().strip())
    except:
        tx_bytes = 0
        tx_packets = 0

    # 2. Drops from tc -s qdisc
    # Output format:
    # qdisc tbf 1: root refcnt 2 rate 400Kbit burst 2Kb lat 100.0ms 
    #  Sent 246525 bytes 743 pkt (dropped 123, overlimits 456 requeues 0)
    cmd = ["ip", "netns", "exec", "MiddleBox", "tc", "-s", "qdisc", "show", "dev", iface]
    drops = 0
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        # Regex to find "dropped <N>"
        m = re.search(r'dropped\s+(\d+)', res.stdout)
        if m:
            drops = int(m.group(1))
    except:
        pass
        
    return tx_bytes, tx_packets, drops

def main():
    if len(sys.argv) < 3:
        print("Usage: monitor_general.py <iface> <output.csv>")
        sys.exit(1)
        
    iface = sys.argv[1]
    outfile = sys.argv[2]
    
    print(f"Monitoring {iface} -> {outfile}")
    
    with open(outfile, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["time", "tx_bytes", "tx_packets", "drops"])
        
        start_t = time.time()
        
        try:
            while True:
                now = time.time() - start_t
                b, p, d = get_stats(iface)
                writer.writerow([f"{now:.2f}", b, p, d])
                f.flush()
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
