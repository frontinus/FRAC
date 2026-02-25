#!/usr/bin/env python3
"""
force_state.py — Safely force the eBPF queue state without
disrupting current_bytes / last_update_ns.

Usage:  force_state.py <target_state>
   target_state: 0=NORMAL, 1=COMPRESS, 2=DELTA, 3=INCREMENTAL
"""
import subprocess, json, struct, sys, time

TARGET = int(sys.argv[1])
PINNED_MAP_PATH = "/sys/fs/bpf/queue_state_map"

while True:
    try:
        r = subprocess.run(
            ["bpftool", "-j", "map", "dump", "pinned", PINNED_MAP_PATH],
            capture_output=True, text=True, timeout=5
        )
        
        if not r.stdout.strip():
            time.sleep(1.5)
            continue

        entries = json.loads(r.stdout)
        
        # Catch bpftool system errors (like missing maps)
        if isinstance(entries, dict) and "error" in entries:
            print(f"BPF Map Error: {entries['error']} (Is loader running?)")
            time.sleep(1.5)
            continue
            
        # If it's a valid list, update the state
        if isinstance(entries, list) and len(entries) > 0:
            key_ints = [int(x, 16) for x in entries[0]["key"]]
            val_ints = [int(x, 16) for x in entries[0]["value"]]
            
            raw_val = bytearray(val_ints)
            struct.pack_into("<I", raw_val, 16, TARGET)

            hex_key = " ".join(f"0x{b:02x}" for b in key_ints)
            hex_val = " ".join(f"0x{b:02x}" for b in raw_val)

            subprocess.run(
                ["bpftool", "map", "update", "pinned", PINNED_MAP_PATH,
                 "key"] + hex_key.split() + ["value"] + hex_val.split(),
                capture_output=True, timeout=5
            )
            
    except Exception as e:
        # Expose the actual Python error type and message
        print(f"Python Crash: {type(e).__name__}: {e}")
        
    time.sleep(1.5)