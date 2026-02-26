#!/usr/bin/env python3
"""
force_state.py — Force the eBPF queue state by finding the map by name,
no pinned path required.

Usage:  force_state.py <target_state>
   target_state: 0=NORMAL, 1=COMPRESS, 2=DELTA, 3=INCREMENTAL
"""
import subprocess, json, struct, sys, time

TARGET = int(sys.argv[1])

def find_map_id(name="queue_state_map"):
    """Find a BPF map ID by name using bpftool."""
    try:
        r = subprocess.run(
            ["bpftool", "-j", "map", "show"],
            capture_output=True, text=True, timeout=5
        )
        if not r.stdout.strip():
            return None
        maps = json.loads(r.stdout)
        for m in maps:
            if m.get("name") == name:
                return m["id"]
    except Exception as e:
        print(f"find_map_id error: {e}")
    return None

while True:
    try:
        map_id = find_map_id("queue_state_map")
        if map_id is None:
            print("queue_state_map not found (Is loader running?)")
            time.sleep(1.5)
            continue

        # Dump current value
        r = subprocess.run(
            ["bpftool", "-j", "map", "dump", "id", str(map_id)],
            capture_output=True, text=True, timeout=5
        )
        if not r.stdout.strip():
            time.sleep(1.5)
            continue

        entries = json.loads(r.stdout)
        if isinstance(entries, dict) and "error" in entries:
            print(f"BPF Map Error: {entries['error']}")
            time.sleep(1.5)
            continue

        if isinstance(entries, list) and len(entries) > 0:
            key_ints = [int(x, 16) for x in entries[0]["key"]]
            val_ints = [int(x, 16) for x in entries[0]["value"]]

            raw_val = bytearray(val_ints)
            struct.pack_into("<I", raw_val, 16, TARGET)

            hex_key = " ".join(f"0x{b:02x}" for b in key_ints)
            hex_val = " ".join(f"0x{b:02x}" for b in raw_val)

            result = subprocess.run(
                ["bpftool", "map", "update", "id", str(map_id),
                 "key"] + hex_key.split() + ["value"] + hex_val.split(),
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                print(f"Update failed: {result.stderr.decode().strip()}")
            else:
                print(f"State forced to {TARGET} via map id {map_id}", flush=True)

    except Exception as e:
        print(f"Python Crash: {type(e).__name__}: {e}")

    time.sleep(1.5)