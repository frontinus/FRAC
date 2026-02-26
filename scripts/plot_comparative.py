#!/usr/bin/env python3
"""plot_comparative.py — Generate honest comparative performance plots."""
import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

PLOTS_DIR = "/home/vboxuser/.gemini/antigravity/brain/257313a8-01ca-420d-b20a-ac15dc295cd2"

def read_log(filename):
    if not os.path.exists(filename):
        return [], [], [], []
    t, bytes_out, pkts, drops = [], [], [], []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        t0 = b0 = p0 = d0 = None
        for row in reader:
            ct = float(row['time'])
            cb = int(row['tx_bytes'])
            cp = int(row['tx_packets'])
            cd = int(row['drops'])
            if t0 is None:
                t0, b0, p0, d0 = ct, cb, cp, cd
            t.append(ct - t0)
            bytes_out.append((cb - b0) / 1024.0)   # KB
            pkts.append(cp - p0)
            drops.append(cd - d0)
    return t, bytes_out, pkts, drops

SERIES = [
    ("baseline_log.csv",     "Baseline",       "red",    "-"),
    ("hc_log.csv",           "HC Only",         "blue",   "-"),
    ("delta_log.csv",        "Delta (Agent)",   "green",  "-"),
    ("incremental_log.csv",  "Incr (Agent)",    "orange", "--"),
]

def main():
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    ax_bytes, ax_pkts, ax_drops = axes

    for fn, label, color, ls in SERIES:
        if os.path.exists(fn):
            t, kb, pkts, drops = read_log(fn)
            if t:
                ax_bytes.plot(t, kb,    label=label, color=color, lw=2, ls=ls)
                ax_pkts.plot(t, pkts,   label=label, color=color, lw=2, ls=ls)
                ax_drops.plot(t, drops, label=label, color=color, lw=2, ls=ls)

    ax_bytes.set(title="Wire Throughput (KB out)", xlabel="Time (s)", ylabel="Cumulative KB")
    ax_pkts.set(title="Packets Transmitted", xlabel="Time (s)", ylabel="Cumulative Packets")
    ax_drops.set(title="Cumulative Drops", xlabel="Time (s)", ylabel="Drops")
    for ax in axes:
        ax.grid(True, alpha=0.3)
        ax.legend()

    plt.tight_layout()
    out = os.path.join(PLOTS_DIR, "comparative_plot.png")
    plt.savefig(out, dpi=120)
    print(f"Saved {out}")

if __name__ == "__main__":
    main()
