#!/usr/bin/env python3
"""
force_state.py — Safely force the eBPF queue state without
disrupting current_bytes / last_update_ns.

Usage:  force_state.py <target_state>
   target_state: 0=NORMAL, 1=COMPRESS, 2=DELTA, 3=INCREMENTAL

Reads the current queue_state_map value, overwrites ONLY the
state field (offset 16, 4 bytes LE), then writes back.
Repeats every 1.5 s until killed.
"""
import subprocess, json, struct, sys, time

TARGET = int(sys.argv[1])

while True:
    try:
        r = subprocess.run(
            ["bpftool", "-j", "map", "dump", "name", "queue_state_map"],
            capture_output=True, text=True, timeout=5
        )
        entries = json.loads(r.stdout or "[]")
        if entries:
            raw_key = bytes(entries[0]["value"][:4])   # key is 4 bytes
            raw_val = bytearray(entries[0]["value"])    # full value

            # struct queue_state { u64 last_update_ns; u64 current_bytes; u32 state; }
            # state lives at byte offset 16
            struct.pack_into("<I", raw_val, 16, TARGET)

            hex_key = " ".join(f"0x{b:02x}" for b in bytes(entries[0]["key"]))
            hex_val = " ".join(f"0x{b:02x}" for b in raw_val)

            subprocess.run(
                ["bpftool", "map", "update", "name", "queue_state_map",
                 "key"] + hex_key.split() + ["value"] + hex_val.split(),
                capture_output=True, timeout=5
            )
    except Exception:
        pass
    time.sleep(1.5)
