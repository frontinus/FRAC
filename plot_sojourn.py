#!/usr/bin/env python3
import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

def read_sojourn(filename):
    if not os.path.exists(filename):
        return [], []
    t, lat = [], []
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        t0 = None
        for row in reader:
            try:
                ct = float(row[0])    # Timestamp
                clat = float(row[1])  # Latency in ms
                if t0 is None:
                    t0 = ct
                t.append(ct - t0)
                lat.append(clat)
            except (ValueError, IndexError):
                continue
    return t, lat

SERIES = [
    ("Baseline_sojourn.csv",     "Baseline",       "red",    "-"),
    ("HeaderComp_sojourn.csv",   "HC Only",         "blue",   "-"),
    ("Delta_sojourn.csv",        "Delta (Agent)",   "green",  "-"),
    ("Incremental_sojourn.csv",  "Incr (Agent)",    "orange", "--"),
]

def main():
    plt.figure(figsize=(10, 6))

    for fn, label, color, ls in SERIES:
        t, lat = read_sojourn(fn)
        if t:
            plt.plot(t, lat, label=label, color=color, lw=2, ls=ls)

    plt.title("eBPF Packet Sojourn Time Evolution (Non-Cumulative)")
    plt.xlabel("Time (seconds)")
    plt.ylabel("EWMA Sojourn Time (ms)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()

    out = "sojourn_times_plot.png"
    plt.savefig(out, dpi=120)
    print(f"Saved {out}")

if __name__ == "__main__":
    main()