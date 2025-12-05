#!/usr/bin/env python3
import subprocess
import argparse
import sys

def run_command(cmd):
    print(f"Running: {cmd}")
    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")

def reset_tc(interface):
    print(f"Resetting tc on {interface}...")
    # Ignore errors if no qdisc exists
    subprocess.call(f"tc qdisc del dev {interface} root", shell=True, stderr=subprocess.DEVNULL)

def apply_conditions(interface, rate, delay, jitter):
    reset_tc(interface)
    
    cmd = f"tc qdisc add dev {interface} root handle 1: htb default 11"
    run_command(cmd)
    
    cmd = f"tc class add dev {interface} parent 1: classid 1:1 htb rate {rate}"
    run_command(cmd)
    
    cmd = f"tc class add dev {interface} parent 1:1 classid 1:11 htb rate {rate}"
    run_command(cmd)
    
    netem_opts = ""
    if delay:
        netem_opts += f" delay {delay}"
        if jitter:
            netem_opts += f" {jitter}"
            
    if netem_opts:
        cmd = f"tc qdisc add dev {interface} parent 1:11 handle 10: netem {netem_opts}"
        run_command(cmd)

def main():
    parser = argparse.ArgumentParser(description="Network Conditioner (tc wrapper)")
    parser.add_argument("--interface", default="veth2-mb", help="Interface to apply rules to (default: veth2-mb)")
    parser.add_argument("--rate", default="1000mbit", help="Bandwidth limit (e.g., 5mbit, 100kbit)")
    parser.add_argument("--delay", help="Base delay (e.g., 100ms)")
    parser.add_argument("--jitter", help="Jitter (e.g., 20ms). Requires --delay.")
    parser.add_argument("--reset", action="store_true", help="Reset all rules")
    
    args = parser.parse_args()
    
    if args.reset:
        reset_tc(args.interface)
    else:
        apply_conditions(args.interface, args.rate, args.delay, args.jitter)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Print help if no args provided
        sys.argv.append("--help")
    main()
