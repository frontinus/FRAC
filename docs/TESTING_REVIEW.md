# eFRAC Testing System Review

## 1. What Is the Test?

The eFRAC experiment evaluates four **packet compression strategies** for bandwidth-constrained tactical networks, all implemented via eBPF hooks on a Linux MiddleBox. The goal is to demonstrate that applying progressively aggressive compression at the network layer reduces congestion (drops, sojourn time) and improves effective goodput.

### 1.1 The Four Phases

| Phase | State | What Happens on the Wire |
|---|---|---|
| **Baseline** | `0` | No compression. Raw CoT XML packets traverse the link unmodified. |
| **Header Compression (HC)** | `1` | The eBPF TC egress hook replaces IP+UDP/TCP headers with a 3–17 byte compressed header (`ETH_P_COMP`). The decompressor on H2 restores them from a pre-shared flow context map. The payload is untouched. |
| **Delta Encoding** | `2` | The C delta agent (`delta_agent_c.c`) receives redirected packets, XOR-diffs them against the previous payload, zlib-compresses the diff, and sends the result to the sink with a `TYPE_DELTA` prefix. |
| **Incremental Encoding** | `3` | Same mechanism as Delta, but the TOS byte is stamped differently (`0x64`), causing the agent to tag output as `TYPE_INCREMENTAL`. The wire encoding is identical to Delta (XOR + zlib). |

### 1.2 Network Topology

A three-namespace virtual topology is created each phase:

```
H1 (10.0.1.1) ──veth1──> MiddleBox ──veth2-mb──> H2 (10.0.2.1)
                              │
                        veth-delta ←→ veth-delta-peer
                        (redirect path for agent)
```

- **H1** runs `traffic_gen.py` (sender)
- **MiddleBox** runs `loader` (eBPF attach + sojourn telemetry), `delta_agent_c` (userspace compressor), `force_state.py` (forces eBPF map state), and `monitor_general.py` (interface stats collector)
- **H2** runs `loader --decompress` (XDP decompressor) and `sink.py` (receiver/decoder)

### 1.3 Link Conditions

Applied via `tc netem` on `veth2-mb` (MiddleBox egress):

| Parameter | `run_clean_comparative.sh` | `run_experiment.sh` |
|---|---|---|
| Rate | 200 kbps | 200 kbps |
| Delay | 50 ms | 50 ms |
| Jitter | 10 ms | 10 ms |
| Loss | 2% | 2% |

### 1.4 Traffic Profile

- **Type**: Cursor on Target (CoT) XML — military situational awareness format
- **Protocol**: UDP
- **Rate**: 200 pps (`run_clean_comparative.sh`) or 100 pps (`run_experiment.sh`)
- **Payload size**: 800 bytes (padded)
- **Duration**: 40s (`run_clean_comparative.sh`) or 60s (`run_experiment.sh`)

### 1.5 Virtual Queue Model (V-Shape)

The eBPF TC hook (`tc_prog_main`) models a **time-varying virtual queue** to simulate evolving congestion:

- **0–20 s**: Drain rate decreases from 200 KB/s → 50 KB/s (congestion builds)
- **20–40 s**: Drain rate increases from 50 KB/s → 200 KB/s (congestion recovers)

This V-shape pattern is the core driver of the sojourn time measurements.

---

## 2. What Is Measured?

### 2.1 Primary Metrics

| Metric | Source | Collection |
|---|---|---|
| **Sojourn time** (EWMA, ms) | eBPF `packet_ts` + `queue_state_map` in `xdp_prog.c` / `loader.c` | Logged to `congestion_log.csv` every 1s by the loader's telemetry loop |
| **Cumulative TX bytes** | `/sys/class/net/<iface>/statistics/tx_bytes` | `monitor_general.py` polls every 100 ms → `*_log.csv` |
| **Cumulative TX packets** | `/sys/class/net/<iface>/statistics/tx_packets` | Same as above |
| **Cumulative drops** | `tc -s qdisc show dev <iface>` (netem drop counter) | Same as above |
| **Sink decode counts** | `sink.py` stdout (SYNC/HC/DELTA/INCREMENTAL/FAIL) | Parsed by experiment script → `sink_summary.csv` |

### 2.2 Derived Metrics (from plotting scripts)

| Metric | Script |
|---|---|
| Wire throughput (kbps) over time | `plot_real_results.py` (Figure 1a) |
| Cumulative drops over time | `plot_real_results.py` (Figure 1b) |
| Drop rate (pps) over time | `plot_real_results.py` (Figure 3) |
| Goodput (messages/sec) at receiver | `plot_real_results.py` (Figure 2, requires timestamped sink) |
| Total drops & bytes summary bars | `plot_real_results.py` (Figure 4) |
| Sojourn time evolution | `plot_sojourn.py` |
| Cumulative bytes/packets/drops comparison | `plot_comparative.py` |

### 2.3 Performance Stats (eBPF)

The `stats_map` in `xdp_prog.c` tracks two kernel-level metrics with count/sum/min/max:

- **Key 0**: Compression processing time (ns) — currently unused in TC hook
- **Key 1**: End-to-end sojourn time (ns) — time from XDP ingress to TC egress

---

## 3. Flaws and Concerns

### 3.1 Critical Flaws

#### 3.1.1 ~~Incremental ≡ Delta — No Real Difference~~ (FIXED)

This flaw has been addressed. The incremental path in `delta_agent_c.c` now implements **true field-level encoding**: the agent parses CoT XML attributes, compares them to the previous packet's fields, and sends only changed key-value pairs in a compact binary format (`[count][field_id, val_len, value]...`). The sink (`sink.py`) decodes these diffs and reconstructs the full XML. Typically only 3 timestamp fields change between CoT packets, producing ~90-byte wire diffs vs. ~400 bytes for Delta's XOR+zlib.

> See the original `TESTING_REVIEW.md` git history for the pre-fix analysis.

#### 3.1.2 State Is Forced, Not Adaptive

The experiment uses `force_state.py` to **override** the eBPF map state every 2 seconds, bypassing the congestion-detection hysteresis logic entirely (which is commented out in `tc_prog_main`). This means:

- The test does **not** validate the system's ability to autonomously detect congestion and select the appropriate strategy.
- Each phase runs under a single fixed state for its entire duration.
- The V-shape virtual queue model computes sojourn times but **never triggers state transitions**.

#### 3.1.3 Virtual Queue ≠ Real Queue

The sojourn time metric is computed from a **virtual queue model**, not from actual kernel qdisc latency:

```c
q->avg_sojourn_ns = q->current_bytes * ns_per_byte;
```

This is a mathematical estimate based on how many bytes are "in the queue" and a time-varying drain rate. It does not measure real packet delay through the netem qdisc. The real latency (netem delay + jitter + queuing) is applied by the kernel but is never directly measured by the eBPF program.

#### 3.1.4 Reduced Physical Length Is an Estimate, Not a Measurement

The virtual queue accounts for compression by plugging in estimated sizes:

```c
if (operating_state == STATE_COMPRESS) physical_len = pkt_len - 22;
else if (operating_state == STATE_DELTA) physical_len = pkt_len / 2;
else if (operating_state == STATE_INCREMENTAL) physical_len = pkt_len / 5;
```

These are hardcoded guesses, not actual compressed sizes. In reality the compressor agent may produce outputs of varying sizes depending on content similarity. The virtual queue's congestion signal is therefore based on assumptions rather than ground truth.

### 3.2 Methodology Flaws

#### 3.2.1 No Baseline Loader Consistency (run_clean_comparative.sh)

In `run_clean_comparative.sh`, the loader is started for **all** phases including Baseline, but the Baseline traffic bypasses the compression path entirely (state 0 → no redirect). The sojourn time is still measured via the virtual queue, which tracks bytes entering with `physical_len = pkt_len` (no compression discount). This is functionally correct but may introduce overhead from the eBPF hooks that pure baseline wouldn't have.

#### 3.2.2 Single Run — No Statistical Significance

Both experiment scripts run each phase **exactly once**. There is:
- No repetition for confidence intervals
- No warm-up / cool-down period isolation
- No randomization of phase ordering to control for temporal effects (Baseline always runs first, Incremental always last)

#### 3.2.3 Phase Ordering Bias

Phases always execute in the same order: Baseline → HC → Delta → Incremental. Later phases may benefit from warmer kernel caches, different memory allocation states, or other system-level effects. A proper experiment would randomize or counterbalance phase ordering.

#### 3.2.4 Monitor Reads Cumulative Counters from /sys

`monitor_general.py` reads `/sys/class/net/<iface>/statistics/tx_bytes`. These counters are maintained since interface creation, but since each phase creates a fresh namespace and veth pair, they start at zero. However, the counters include **all** traffic on the interface (ARP, neighbor discovery, agent traffic, monitoring traffic), not just the experiment's CoT flow.

### 3.3 Implementation Concerns

#### 3.3.1 Loop Guard May Drop Legitimate Packets

In `delta_agent_c.c`:

```c
if (payload_len > 0 && payload[0] <= TYPE_INCREMENTAL) continue;
```

This drops any packet whose first payload byte is 0x00, 0x01, or 0x02 to prevent processing its own output. This is brittle — legitimate CoT XML starts with `<` (0x3C) so it works in practice, but any binary payload starting with these bytes would be silently dropped.

#### 3.3.2 TCP Checksum Set to Zero

The decompressor (`xdp_decompress_main`) sets `tcp->check = 0` after restoring TCP headers. This will cause TCP checksum verification failures on receivers with checksum offload disabled, potentially dropping packets and producing misleading results for TCP flows.

#### 3.3.3 Sink Prints Before Classifying

In `sink.py`, line 131:
```python
print(f"[Sink] OK {time.time():.3f} {len(decoded)}", flush=True)
```
This prints **before** the packet type is determined, with `decoded = b""`. The `len(decoded)` is always 0 at this point. The actual classification happens in the subsequent `if/elif` chain.

#### 3.3.4 Sojourn CSV Has No Header Row

`congestion_log.csv` is written by `loader.c` as raw CSV without a header:
```c
fprintf(log_fp, "%llu,%.6f,%llu,%u\n", time, lat_ms, current_bytes, state);
```

`plot_sojourn.py` handles this gracefully (skipping non-numeric rows), but it makes the data harder to reuse or validate independently.

#### 3.3.5 Hardcoded Plot Output Path

`plot_comparative.py` has a hardcoded output path:
```python
PLOTS_DIR = "/home/vboxuser/.gemini/antigravity/brain/257313a8-..."
```
This is a conversation-specific artifact path that won't work across different sessions.

### 3.4 Measurement Gaps

| Gap | Impact |
|---|---|
| No end-to-end latency measurement (source timestamp → sink timestamp) | Cannot validate real delay benefits of compression |
| No compression ratio measurement per packet | Cannot validate actual wire savings vs. the hardcoded estimates |
| No CPU/memory overhead measurement | Cannot assess practical cost of eBPF + agent processing |
| No packet reordering metric | Compression/decompression may introduce reordering |
| No test with mixed traffic types | Only CoT is tested despite the traffic generator supporting video/voice/XMPP |
| No test under varying link conditions | Single fixed link config (200kbps/50ms/2%) — no sensitivity analysis |

---

## 4. Summary

The testing framework is a well-structured proof-of-concept that demonstrates the eFRAC architecture can produce fewer drops and higher effective throughput when compression is applied. However, it has significant limitations:

1. **Incremental encoding is not actually implemented** — it's a duplicate of Delta
2. **State selection is forced** — the adaptive congestion response is never tested
3. **Sojourn time is modeled, not measured** — the core metric is a virtual queue estimate
4. **No statistical rigor** — single runs with fixed phase ordering
5. **Several implementation bugs** — premature sink logging, hardcoded paths, zeroed checksums

These issues don't invalidate the proof-of-concept but would need to be addressed before the results could be presented as rigorous experimental evidence.
