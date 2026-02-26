#!/usr/bin/env python3
"""
plot_real_results.py — eFRAC Thesis Plots from Real Measurements
=================================================================
Reads the CSVs produced by run_experiment.sh and generates
publication-quality figures.

Usage:
    python3 plot_real_results.py --results ./results [--out ./plots]

Input files expected in --results dir:
    baseline_monitor.csv      }
    hc_monitor.csv            }  from monitor_general.py
    delta_monitor.csv         }  columns: time, tx_bytes, tx_packets, drops
    incremental_monitor.csv   }

    baseline_sink.log         }
    hc_sink.log               }  raw stdout from sink.py
    delta_sink.log            }  parsed for Rx SYNC / HC / DELTA / INCREMENTAL
    incremental_sink.log      }

    sink_summary.csv          — phase,sync,hc,delta,incr,fail
"""

import argparse
import csv
import os
import re
import sys
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.lines import Line2D

# ── CLI ───────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--results", default="./results",
                    help="Directory containing experiment CSVs")
parser.add_argument("--out",     default="./plots",
                    help="Output directory for figures")
args = parser.parse_args()

RESULTS = Path(args.results)
OUT     = Path(args.out)
OUT.mkdir(parents=True, exist_ok=True)

# ── Style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family":       "serif",
    "font.serif":        ["Times New Roman", "DejaVu Serif"],
    "font.size":         11,
    "axes.titlesize":    12,
    "axes.labelsize":    11,
    "legend.fontsize":   10,
    "xtick.labelsize":   10,
    "ytick.labelsize":   10,
    "axes.grid":         True,
    "grid.alpha":        0.30,
    "grid.linestyle":    "--",
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "figure.dpi":        150,
})

STYLES = {
    "Baseline":    {"color": "#c0392b", "ls": "-",  "lw": 2.0},
    "Header Comp": {"color": "#e67e22", "ls": "-",  "lw": 2.2},
    "Delta":       {"color": "#2980b9", "ls": "--", "lw": 2.0},
    "Incremental": {"color": "#27ae60", "ls": "--", "lw": 2.0},
}

PHASES = [
    ("baseline",    "Baseline"),
    ("hc",          "Header Comp"),
    ("delta",       "Delta"),
    ("incremental", "Incremental"),
]

# ── Data loaders ──────────────────────────────────────────────────────────────
def load_monitor(csv_path: Path):
    """
    Returns dict with numpy arrays: t, tx_bytes, tx_packets, drops
    All values are zero-based (subtracted from first row).
    Returns None if file missing or empty.
    """
    if not csv_path.exists():
        print(f"  WARNING: {csv_path} not found — skipping", file=sys.stderr)
        return None

    t, tx_bytes, tx_pkts, drops = [], [], [], []
    t0 = b0 = p0 = d0 = None

    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ct = float(row["time"])
                cb = int(row["tx_bytes"])
                cp = int(row["tx_packets"])
                cd = int(row["drops"])
            except (KeyError, ValueError):
                continue
            if t0 is None:
                t0, b0, p0, d0 = ct, cb, cp, cd
            t.append(ct - t0)
            tx_bytes.append(cb - b0)
            tx_pkts.append(cp - p0)
            drops.append(cd - d0)

    if not t:
        print(f"  WARNING: {csv_path} is empty", file=sys.stderr)
        return None

    return {
        "t":        np.array(t),
        "tx_bytes": np.array(tx_bytes),
        "tx_pkts":  np.array(tx_pkts),
        "drops":    np.array(drops),
    }


def parse_sink_log(log_path: Path):
    """
    Parses sink.py stdout to extract per-second goodput
    (count of successfully decoded messages per second).

    Returns dict: t_s (array of integer seconds), msgs_per_sec
    Returns None if file missing.
    """
    if not log_path.exists():
        print(f"  WARNING: {log_path} not found — skipping", file=sys.stderr)
        return None

    # Patterns for successfully decoded packets
    # sink.py prints timestamps only implicitly — we use line count per second
    # Since sink.py doesn't print timestamps, we count Rx lines and assume
    # they arrive at the rate they were sent. A more accurate approach is
    # to add timestamps to sink.py (see NOTE below).
    #
    # NOTE: for a more accurate goodput plot, add this line to process_data()
    # in sink.py right after decoded is set:
    #   print(f"[Sink] OK {time.time():.3f} {len(decoded)}", flush=True)
    # Then this parser extracts real timestamps.

    decoded_times = []
    ts_pattern    = re.compile(r'\[Sink\] OK (\d+\.\d+)')   # if timestamped
    rx_pattern    = re.compile(r'\[Sink\] Rx (SYNC|HC:|DELTA:|INCREMENTAL:)')
    fail_pattern  = re.compile(r'FAILED')

    has_timestamps = False
    total_rx   = 0
    total_fail = 0

    with open(log_path) as f:
        for line in f:
            m = ts_pattern.search(line)
            if m:
                decoded_times.append(float(m.group(1)))
                has_timestamps = True
            elif rx_pattern.search(line):
                total_rx += 1
            if fail_pattern.search(line):
                total_fail += 1

    if has_timestamps and decoded_times:
        decoded_times = np.array(decoded_times)
        t0 = decoded_times[0]
        decoded_times -= t0
        duration = decoded_times[-1] if decoded_times[-1] > 0 else 1
        bins = np.arange(0, duration + 1, 1)
        counts, edges = np.histogram(decoded_times, bins=bins)
        return {
            "t_s":          edges[:-1],
            "msgs_per_sec": counts.astype(float),
            "total_rx":     total_rx,
            "total_fail":   total_fail,
            "has_timestamps": True,
        }
    else:
        # No timestamps in sink — fall back to total count only
        return {
            "t_s":          None,
            "msgs_per_sec": None,
            "total_rx":     total_rx,
            "total_fail":   total_fail,
            "has_timestamps": False,
        }


def load_sink_summary(csv_path: Path):
    if not csv_path.exists():
        return {}
    out = {}
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            out[row["phase"]] = {
                k: int(v) for k, v in row.items()
                if k != "phase" and v is not None and str(v).strip() != ""
            }
    return out


# ── Smoothing ─────────────────────────────────────────────────────────────────
def smooth(arr, window_s=2.0, dt=0.1):
    """Rolling mean. dt = approximate sample interval in seconds."""
    w = max(1, int(window_s / dt))
    kernel = np.ones(w) / w
    return np.convolve(arr, kernel, mode='same')


def goodput_from_bytes(t, tx_bytes, window_s=2.0):
    """
    Derive goodput in messages/second from cumulative byte counter.
    Assumes fixed packet size but gives a real measured derivative.
    Returns t_mid, goodput array.
    """
    dt = np.diff(t)
    db = np.diff(tx_bytes)
    # bytes/s then convert to approx msg/s (we don't know exact pkt size here,
    # so we report bytes/s and label accordingly)
    bps = np.where(dt > 0, db / dt, 0)
    t_mid = 0.5 * (t[:-1] + t[1:])
    return t_mid, bps


# ── Load all data ─────────────────────────────────────────────────────────────
print("Loading data...")
monitor_data = {}
sink_data    = {}

for key, label in PHASES:
    mon = load_monitor(RESULTS / f"{key}_monitor.csv")
    snk = parse_sink_log(RESULTS / f"{key}_sink.log")
    if mon is not None:
        monitor_data[label] = mon
        print(f"  {label}: {len(mon['t'])} monitor samples, "
              f"total_drops={int(mon['drops'][-1])}, "
              f"total_bytes={int(mon['tx_bytes'][-1]/1024)} KB")
    if snk is not None:
        sink_data[label] = snk
        print(f"  {label} sink: rx={snk['total_rx']}, fail={snk['total_fail']}, "
              f"timestamped={'yes' if snk['has_timestamps'] else 'no (add timestamps to sink.py)'}")

sink_summary = load_sink_summary(RESULTS / "sink_summary.csv")

if not monitor_data:
    print("\nERROR: No monitor CSVs found. Run run_experiment.sh first.")
    sys.exit(1)

# ── Infer sample interval ─────────────────────────────────────────────────────
# monitor_general.py polls every 0.1 s
DT = 0.1

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 1 — Throughput on wire (bytes/s) and cumulative drops — side by side
# ═══════════════════════════════════════════════════════════════════════════════
print("\nPlotting Figure 1: Throughput + Drops...")

fig1, (ax_thr, ax_dr) = plt.subplots(1, 2, figsize=(13, 4.8))

for label, d in monitor_data.items():
    st = STYLES[label]
    # Throughput: derivative of cumulative bytes → bytes/s, smoothed
    if len(d["t"]) > 2:
        t_mid, bps = goodput_from_bytes(d["t"], d["tx_bytes"])
        bps_smooth = smooth(bps, window_s=2.0, dt=DT)
        # Convert to kbps for readability
        kbps = bps_smooth / 1000 * 8
        ax_thr.plot(t_mid, kbps, color=st["color"], ls=st["ls"], lw=st["lw"], label=label)

    # Drops
    ax_dr.plot(d["t"], d["drops"], color=st["color"], ls=st["ls"], lw=st["lw"], label=label)

# Link capacity reference
ax_thr.axhline(200, color="black", lw=1.0, ls=":", alpha=0.5, label="_nolegend_")
ax_thr.text(1, 202, "Link capacity (200 kbps)", fontsize=8.5, alpha=0.65)

ax_thr.set_xlabel("Time (s)")
ax_thr.set_ylabel("Throughput on tactical link (kbps)")
ax_thr.set_title("(a) Wire Throughput", fontweight="bold")
ax_thr.set_ylim(bottom=0)

ax_dr.set_xlabel("Time (s)")
ax_dr.set_ylabel("Cumulative Packets Dropped")
ax_dr.set_title("(b) Cumulative Queue Drops", fontweight="bold")
ax_dr.set_ylim(bottom=0)

# Annotate final drop counts
for label, d in monitor_data.items():
    st = STYLES[label]
    final = int(d["drops"][-1])
    t_end = d["t"][-1]
    ax_dr.annotate(
        f"{final:,}",
        xy=(t_end, final),
        xytext=(t_end - 2, final),
        color=st["color"], fontsize=9, fontweight="bold", ha="right", va="center"
    )

handles = [Line2D([0],[0], color=STYLES[l]["color"], ls=STYLES[l]["ls"],
                  lw=STYLES[l]["lw"], label=l)
           for l in STYLES if l in monitor_data]
fig1.legend(handles=handles, loc="lower center", ncol=4,
            framealpha=0.92, bbox_to_anchor=(0.5, -0.04))
fig1.suptitle(
    r"eFRAC: Real Measurements — Throughput and Packet Drops""\n"
    r"(200 kbps link · 50 ms delay · 2% loss · 100 pps · 800 B payload)",
    fontsize=11, fontweight="bold", y=1.01
)
fig1.tight_layout()
out1 = OUT / "real_throughput_drops.png"
fig1.savefig(out1, dpi=180, bbox_inches="tight")
print(f"  Saved {out1}")


# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — Goodput from sink timestamps (if available) OR bar chart from totals
# ═══════════════════════════════════════════════════════════════════════════════
print("Plotting Figure 2: Goodput...")

has_ts = any(d.get("has_timestamps") for d in sink_data.values() if d)

if has_ts:
    # Real per-second goodput time series
    fig2, ax2 = plt.subplots(figsize=(9, 4.5))
    for label, d in sink_data.items():
        if d and d["has_timestamps"] and d["t_s"] is not None:
            st = STYLES.get(label, {"color": "grey", "ls": "-", "lw": 1.8})
            gp_smooth = smooth(d["msgs_per_sec"], window_s=2.0, dt=1.0)
            ax2.plot(d["t_s"], gp_smooth,
                     color=st["color"], ls=st["ls"], lw=st["lw"], label=label)
    ax2.set_xlabel("Time (s)")
    ax2.set_ylabel("Goodput (messages / second)")
    ax2.set_title("Goodput at Receiver — Real Measurements\n"
                  "(2-second rolling average)", fontweight="bold")
    ax2.legend(framealpha=0.92)
    ax2.set_ylim(bottom=0)
    fig2.tight_layout()
    out2 = OUT / "real_goodput_timeseries.png"
    fig2.savefig(out2, dpi=180, bbox_inches="tight")
    print(f"  Saved {out2}")
else:
    print("  NOTE: sink.py has no timestamps — plotting total received counts as bar chart.")
    print("  To get a goodput time series, add this line to process_data() in sink.py:")
    print('    import time; print(f"[Sink] OK {time.time():.3f} {len(decoded)}", flush=True)')

    # Bar chart: total received (rx) vs failed per phase
    labels_bar = []
    rx_counts  = []
    fail_counts = []
    for key, label in PHASES:
        if key in sink_summary:
            s = sink_summary[key]
            total = s.get("sync", 0) + s.get("hc", 0) + s.get("delta", 0) + s.get("incr", 0)
            labels_bar.append(label)
            rx_counts.append(total)
            fail_counts.append(s.get("fail", 0))

    if labels_bar:
        fig2, ax2 = plt.subplots(figsize=(8, 4.5))
        x = np.arange(len(labels_bar))
        w = 0.35
        colors = [STYLES.get(l, {"color": "grey"})["color"] for l in labels_bar]
        bars_rx = ax2.bar(x - w/2, rx_counts, w, color=colors, label="Received OK", alpha=0.85)
        bars_fail = ax2.bar(x + w/2, fail_counts, w, color=colors, label="Decode failures",
                            alpha=0.45, hatch="//")
        ax2.set_xticks(x)
        ax2.set_xticklabels(labels_bar)
        ax2.set_ylabel("Packet count (60 s run)")
        ax2.set_title("Packets Received and Decode Failures by Strategy\n"
                      "(real sink measurements)", fontweight="bold")
        ax2.legend()
        for bar, val in zip(bars_rx, rx_counts):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                     f"{val}", ha="center", va="bottom", fontsize=9, fontweight="bold")
        fig2.tight_layout()
        out2 = OUT / "real_sink_counts.png"
        fig2.savefig(out2, dpi=180, bbox_inches="tight")
        print(f"  Saved {out2}")


# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 3 — Drop rate over time (derivative of cumulative drops)
#            Shows when drops happen, not just the total
# ═══════════════════════════════════════════════════════════════════════════════
print("Plotting Figure 3: Drop rate over time...")

fig3, ax3 = plt.subplots(figsize=(9, 4.5))

for label, d in monitor_data.items():
    st = STYLES[label]
    if len(d["t"]) > 2:
        dt_arr = np.diff(d["t"])
        dd     = np.diff(d["drops"])
        # drops per second
        dps    = np.where(dt_arr > 0, dd / dt_arr, 0)
        t_mid  = 0.5 * (d["t"][:-1] + d["t"][1:])
        dps_sm = smooth(dps, window_s=3.0, dt=DT)
        ax3.plot(t_mid, dps_sm, color=st["color"], ls=st["ls"], lw=st["lw"], label=label)

ax3.set_xlabel("Time (s)")
ax3.set_ylabel("Drop rate (packets / second)")
ax3.set_title("Instantaneous Packet Drop Rate\n"
              "(3-second rolling average — shows congestion dynamics)", fontweight="bold")
ax3.set_ylim(bottom=0)
ax3.legend(framealpha=0.92)
fig3.tight_layout()
out3 = OUT / "real_drop_rate.png"
fig3.savefig(out3, dpi=180, bbox_inches="tight")
print(f"  Saved {out3}")


# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 4 — Summary bar chart: total drops + bytes transmitted
# ═══════════════════════════════════════════════════════════════════════════════
print("Plotting Figure 4: Summary bars...")

fig4, (ax_drops_bar, ax_bytes_bar) = plt.subplots(1, 2, figsize=(11, 4.5))

labels_sum = [l for _, l in PHASES if l in monitor_data]
drops_sum  = [int(monitor_data[l]["drops"][-1]) for l in labels_sum]
bytes_sum  = [int(monitor_data[l]["tx_bytes"][-1] / 1024) for l in labels_sum]   # KB
colors_sum = [STYLES[l]["color"] for l in labels_sum]

baseline_drops = drops_sum[0] if drops_sum else 1
baseline_bytes = bytes_sum[0] if bytes_sum else 1

# Drop bars
bars = ax_drops_bar.bar(labels_sum, drops_sum, color=colors_sum,
                        edgecolor="white", linewidth=1.2)
for bar, val, label in zip(bars, drops_sum, labels_sum):
    pct_red = 100 * (1 - val / baseline_drops) if baseline_drops > 0 else 0
    annotation = f"{val:,}"
    if pct_red > 0:
        annotation += f"\n(−{pct_red:.0f}%)"
    ax_drops_bar.text(
        bar.get_x() + bar.get_width()/2,
        bar.get_height() + baseline_drops * 0.01,
        annotation, ha="center", va="bottom",
        fontsize=9.5, fontweight="bold", color=bar.get_facecolor()
    )

ax_drops_bar.set_ylabel("Total Packets Dropped (60 s run)")
ax_drops_bar.set_title("(a) Total Drops by Strategy", fontweight="bold")
ax_drops_bar.set_ylim(0, max(drops_sum) * 1.22 if drops_sum else 1)
ax_drops_bar.yaxis.grid(True, alpha=0.35, zorder=0)
ax_drops_bar.set_axisbelow(True)

# Bytes transmitted bars
bars2 = ax_bytes_bar.bar(labels_sum, bytes_sum, color=colors_sum,
                         edgecolor="white", linewidth=1.2)
for bar, val, label in zip(bars2, bytes_sum, labels_sum):
    pct_more = 100 * (val / baseline_bytes - 1) if baseline_bytes > 0 else 0
    annotation = f"{val:,} KB"
    if pct_more > 0:
        annotation += f"\n(+{pct_more:.0f}%)"
    ax_bytes_bar.text(
        bar.get_x() + bar.get_width()/2,
        bar.get_height() + baseline_bytes * 0.01,
        annotation, ha="center", va="bottom",
        fontsize=9.5, fontweight="bold", color=bar.get_facecolor()
    )

ax_bytes_bar.set_ylabel("Total Bytes Transmitted on Tactical Link (KB)")
ax_bytes_bar.set_title("(b) Wire Efficiency by Strategy\n"
                       "More bytes delivered = more goodput through the link",
                       fontweight="bold")
ax_bytes_bar.set_ylim(0, max(bytes_sum) * 1.22 if bytes_sum else 1)
ax_bytes_bar.yaxis.grid(True, alpha=0.35, zorder=0)
ax_bytes_bar.set_axisbelow(True)

fig4.suptitle("eFRAC Strategy Comparison — Real Measurements (60 s run)",
              fontsize=12, fontweight="bold")
fig4.tight_layout()
out4 = OUT / "real_summary_bars.png"
fig4.savefig(out4, dpi=180, bbox_inches="tight")
print(f"  Saved {out4}")


# ═══════════════════════════════════════════════════════════════════════════════
# Print summary table to stdout
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "═"*65)
print(f"{'Strategy':15s}  {'Drops':>8s}  {'Drop Δ':>8s}  {'KB sent':>9s}  {'KB Δ':>8s}")
print("─"*65)
for label in labels_sum:
    d = monitor_data[label]
    drops  = int(d["drops"][-1])
    kb     = int(d["tx_bytes"][-1] / 1024)
    d_pct  = f"−{100*(1-drops/baseline_drops):.0f}%" if drops < baseline_drops else "ref"
    kb_pct = f"+{100*(kb/baseline_bytes-1):.0f}%"    if kb    > baseline_bytes  else "ref"
    print(f"{label:15s}  {drops:>8,}  {d_pct:>8s}  {kb:>9,}  {kb_pct:>8s}")
print("═"*65)
print(f"\nPlots saved to: {OUT}/")
print("""
─────────────────────────────────────────────────────────────
IMPORTANT: To get a real goodput time series (not just totals),
add one line to sink.py inside process_data(), after decoded is set:

    import time
    print(f"[Sink] OK {time.time():.3f} {len(decoded)}", flush=True)

Then re-run run_experiment.sh and this script will automatically
produce a per-second goodput plot (Figure 2) from real timestamps.
─────────────────────────────────────────────────────────────
""")