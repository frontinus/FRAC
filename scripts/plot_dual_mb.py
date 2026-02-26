#!/usr/bin/env python3
"""
plot_dual_mb.py — Generate comparison plots for the dual-middlebox experiment.
Compares Baseline, HC, Delta, and Incremental across multiple metrics.
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import csv
import os
import sys

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 11

PHASES = [
    ('Baseline',    'baseline_log.csv',     'Baseline_sojourn.csv',     '#e74c3c'),
    ('HeaderComp',  'hc_log.csv',           'HeaderComp_sojourn.csv',   '#f39c12'),
    ('Delta',       'delta_log.csv',        'Delta_sojourn.csv',        '#2ecc71'),
    ('Incremental', 'incremental_log.csv',  'Incremental_sojourn.csv',  '#3498db'),
]

def read_csv(path):
    """Read CSV to list of dicts."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows

def read_csv_noheader(path):
    """Read headerless CSV."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 4:
                try:
                    rows.append([float(x) for x in parts])
                except ValueError:
                    pass
    return rows

def read_e2e(path):
    """Read e2e latency CSV."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                rows.append(float(r['latency_ms']))
            except (ValueError, KeyError):
                pass
    return rows

# ─── Parse all data ────────────────────────────────────────────────────────
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Dual-Middlebox Experiment — Compression Comparison', fontsize=15, fontweight='bold')

# Panel 1: Wire Throughput (KB)
ax = axes[0][0]
for name, log_file, _, color in PHASES:
    rows = read_csv(log_file)
    if not rows:
        continue
    times = [float(r['time']) for r in rows]
    bytes_vals = [float(r['tx_bytes']) / 1024 for r in rows]
    base = bytes_vals[0] if bytes_vals else 0
    bytes_vals = [b - base for b in bytes_vals]
    ax.plot(times, bytes_vals, label=name, color=color, linewidth=1.5)
ax.set_xlabel('Time (s)')
ax.set_ylabel('Cumulative Wire Throughput (KB)')
ax.set_title('Wire Throughput on Tactical Link')
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)

# Panel 2: Cumulative Packets
ax = axes[0][1]
for name, log_file, _, color in PHASES:
    rows = read_csv(log_file)
    if not rows:
        continue
    times = [float(r['time']) for r in rows]
    pkts = [float(r['tx_packets']) for r in rows]
    base = pkts[0] if pkts else 0
    pkts = [p - base for p in pkts]
    ax.plot(times, pkts, label=name, color=color, linewidth=1.5)
ax.set_xlabel('Time (s)')
ax.set_ylabel('Cumulative Packets')
ax.set_title('Packets Transmitted on Tactical Link')
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)

# Panel 3: Sojourn Time (virtual queue)
ax = axes[1][0]
for name, _, sojourn_file, color in PHASES:
    rows = read_csv_noheader(sojourn_file)
    if not rows:
        continue
    t0 = rows[0][0] if rows else 0
    times = [r[0] - t0 for r in rows]
    sojourn = [r[1] for r in rows]
    ax.plot(times, sojourn, label=name, color=color, linewidth=1.5, marker='o', markersize=3)
ax.set_xlabel('Time (s)')
ax.set_ylabel('Sojourn Time (ms)')
ax.set_title('Virtual Queue Sojourn Time')
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)

# Panel 4: Summary Bar Chart
ax = axes[1][1]
sink_file = 'sink_summary.csv'
if os.path.exists(sink_file):
    with open(sink_file) as f:
        reader = csv.DictReader(f)
        phases = []
        totals = []
        colors_bar = []
        for r in reader:
            name = r['phase']
            total = sum(int(r.get(k, 0)) for k in ['sync', 'hc', 'delta', 'incr'])
            phases.append(name)
            totals.append(total)
            for pn, _, _, c in PHASES:
                if pn == name:
                    colors_bar.append(c)
                    break
            else:
                colors_bar.append('#999999')
        bars = ax.bar(phases, totals, color=colors_bar, edgecolor='black', linewidth=0.5)
        for bar, t in zip(bars, totals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 50,
                    str(t), ha='center', va='bottom', fontsize=10, fontweight='bold')
ax.set_ylabel('Total Packets Delivered to H2')
ax.set_title('Packet Delivery (Sink)')
ax.grid(True, alpha=0.3, axis='y')

plt.tight_layout(rect=[0, 0, 1, 0.95])
out = 'dual_mb_comparison.png'
plt.savefig(out, dpi=150, bbox_inches='tight')
print(f"Saved {out}")

# ─── Also generate E2E latency box plot if data exists ────────────────────
e2e_data = []
e2e_labels = []
e2e_colors = []
for name, _, _, color in PHASES:
    latencies = read_e2e(f'e2e_latency_{name}.csv')
    if latencies and len(latencies) > 5:
        e2e_data.append(latencies)
        e2e_labels.append(f"{name}\n(n={len(latencies)})")
        e2e_colors.append(color)

if e2e_data:
    fig2, ax2 = plt.subplots(figsize=(8, 5))
    bp = ax2.boxplot(e2e_data, labels=e2e_labels, patch_artist=True, showfliers=False)
    for patch, color in zip(bp['boxes'], e2e_colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
    ax2.set_ylabel('End-to-End Latency (ms)')
    ax2.set_title('E2E Latency by Compression Strategy (Dual-MB)')
    ax2.grid(True, alpha=0.3, axis='y')
    out2 = 'dual_mb_e2e_latency.png'
    fig2.savefig(out2, dpi=150, bbox_inches='tight')
    print(f"Saved {out2}")

print("Done")
