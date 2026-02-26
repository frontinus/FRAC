# eFRAC — eBPF Flow-Rate Adaptive Compression

## Complete Repository Overview

---

## 1. Project Summary

eFRAC is a research framework that demonstrates **adaptive, congestion-aware packet compression** using eBPF on Linux. It targets **bandwidth-constrained tactical networks** (e.g., SATCOM, tactical radio links) where link capacity is severely limited (200 kbps) and latency is high (50+ ms).

The core idea: when a MiddleBox detects congestion on a tactical link, it progressively applies more aggressive compression to the traffic flowing through it — from doing nothing (Baseline), to stripping redundant headers (Header Compression), to computing byte-level diffs (Delta Encoding), to sending only changed XML fields (Incremental Encoding).

The system is evaluated by running all four strategies under identical link conditions and comparing wire throughput, packet drops, and estimated sojourn times.

---

## 2. Architecture

### 2.1 Two Topologies — Two Measurements

The project supports **two experiment topologies**, each tailored to a different measurement:

| Topology | Script | Namespaces | What It Measures |
|---|---|---|---|
| **Single-MB** (3 ns) | `run_clean_comparative.sh` | H1, MiddleBox, H2 | Virtual queue **sojourn time** — validates eBPF congestion model |
| **Dual-MB** (4 ns) | `run_dual_mb.sh` | H1, MB1, MB2, H2 | Real **end-to-end latency** — validates compression benefit across a tactical link |

The single-MB topology is sufficient for sojourn time because the virtual queue model runs entirely within one middlebox. The dual-MB topology matters when measuring how long it takes a packet to travel from source to destination through two middleboxes and a constrained link.

### 2.2 Single-Middlebox Topology (Sojourn Time)

Three Linux network namespaces connected by virtual ethernet (veth) pairs:

```
┌──────────┐       veth1 / veth1-mb       ┌────────────────────┐       veth2-mb / veth2       ┌──────────┐
│          │ ◄──────────────────────────►  │                    │ ◄──────────────────────────►  │          │
│    H1    │      10.0.1.1 / 10.0.1.2     │     MiddleBox      │      10.0.2.2 / 10.0.2.1     │    H2    │
│ (Sender) │                              │  (eBPF + Agent)    │                              │(Receiver)│
│          │                              │                    │                              │          │
└──────────┘                              │  veth-delta ◄─────►│ veth-delta-peer              └──────────┘
                                          │  192.168.99.1       192.168.99.2                              
                                          │  (redirect path for C agent)                                  
                                          └────────────────────┘                                          
```

- **H1** (`10.0.1.1`): Runs the traffic generator — **userspace only** (no eBPF)
- **MiddleBox** (`10.0.1.2` / `10.0.2.2`): Runs **eBPF programs** (XDP + TC), the C compression agent, state forcing, and interface monitoring
- **H2** (`10.0.2.1`): Runs the **eBPF XDP decompressor** (`xdp_decompress_main`) and the userspace sink receiver

Netem applied to `veth2-mb` (MiddleBox → H2).

### 2.3 Dual-Middlebox Topology (End-to-End Latency)

Four namespaces — each middlebox connects to **one** subnet and the tactical link between them:

```
┌────┐                ┌──────────────────────────┐                       ┌──────────────────────────┐                ┌────┐
│    │  veth-h1       │           MB1             │  veth-link1/link2     │           MB2             │  veth-mb2      │    │
│ H1 │◄─────────────► │  veth-mb1    veth-link1   │◄══════(netem)═══════►│  veth-link2    veth-mb2   │◄─────────────► │ H2 │
│    │  10.0.1.1/.2   │  (eBPF+Agent)             │  10.0.100.1/.2       │  (Decompressor)           │  10.0.2.2/.1   │    │
└────┘  Subnet A      │                           │  Tactical Link       │                           │  Subnet B      └────┘
                      │  veth-delta ◄──► peer     │                       │                           │
                      │  192.168.99.1/.2          │                       │                           │
                      └──────────────────────────┘                       └──────────────────────────┘
```

| Namespace | IP Addresses | Runs | Modality | Role |
|---|---|---|---|---|
| **H1** | `10.0.1.1` | `traffic_gen.py --e2e_timestamp` | Userspace only | Sender — embeds send timestamp in CoT XML |
| **MB1** | `10.0.1.2`, `10.0.100.1` | `loader`, `delta_agent_c`, `force_state.py`, `monitor_general.py` | **eBPF** (XDP + TC) + userspace | Compressor — eBPF timestamps, classifies, redirects; agent compresses |
| **MB2** | `10.0.100.2`, `10.0.2.2` | `loader --decompress veth-link2` | **eBPF** (XDP decompressor) | Decompressor — XDP hook restores headers |
| **H2** | `10.0.2.1` | `sink.py --e2e_log` | Userspace only | Receiver — decodes, extracts send timestamp, computes E2E latency |

Netem applied to `veth-link1` (MB1 → MB2) — the tactical link.

**End-to-end latency measurement**: The traffic generator embeds `e2e_ts="epoch_seconds"` as an attribute on the `<detail>` element in the CoT XML (e.g., `<detail e2e_ts="1740000060.050000">`). The sink extracts this via regex after decoding, computes `recv_time − send_time`, and writes per-packet latency to `e2e_latency_<phase>.csv`.

### 2.4 Link Conditions (Both Topologies)

Applied via `tc netem` on the tactical link:

| Parameter | Value |
|---|---|
| Rate | 200 kbps |
| Delay | 50 ms ± 10 ms jitter |
| Loss | 2% |

### 2.5 Data Flow

```
                                   ┌─────────────────────────────────────────────────┐
                                   │              MB1 (or MiddleBox)                  │
                                   │                                                 │
  ┌────┐    UDP CoT     ┌─────────┤─────┐    XDP ingress     TC egress    ┌────────┐│     netem      ┌────┐
  │ H1 │ ──────────────►│ veth-mb1│     │ ──( timestamp )──►( classify )──│veth-lnk││──(200k/50ms)──►│MB2 │──►H2
  └────┘   800B/pkt     └─────────┤     │                       │         └────────┘│               └────┘
           200 pps                │     │                       │                   │
                                  │     │              ┌────────┴────────┐           │
                                  │     │              │ State 0: pass   │           │
                                  │     │              │ State 1: HC     │──► redirect to veth-delta
                                  │     │              │ State 2: Delta  │           │
                                  │     │              │ State 3: Incr   │           │
                                  │     │              └─────────────────┘           │
                                  │     │                                            │
                                  │     │    veth-delta-peer         veth-delta      │
                                  │     │  ◄─────────────────────────────────────    │
                                  │     │     C Agent receives          │            │
                                  │     │     redirected packets        │            │
                                  │     │     compresses & sends ───────┴──► UDP to H2:8087
                                  │     │                                            │
                                  └─────┤────────────────────────────────────────────┘
```

**State 0 (Baseline)**: Packets pass through unmodified. The TC hook adds them to the virtual queue model but does not redirect.

**State 1 (Header Compression)**: The TC hook stamps TOS=0x28 and redirects to `veth-delta`. The C agent sees TOS=0x28, tags the payload as `TYPE_HC` (0x03), and sends it via UDP to the sink. On H2, the XDP decompressor restores IP+UDP headers from a pre-shared flow context map.

**State 2 (Delta)**: TC stamps TOS=0x50 and redirects. The agent XOR-diffs the payload against the previous packet, zlib-compresses the diff, tags it as `TYPE_DELTA` (0x01), and sends it. The sink decompresses and XOR-recovers the original.

**State 3 (Incremental)**: TC stamps TOS=0x64 and redirects. The agent parses CoT XML fields, compares to the previous packet's fields, and sends only changed key-value pairs as `TYPE_INCREMENTAL` (0x02). The sink applies field diffs to its stored state and reconstructs the XML.

### 2.6 Compression State Machine

The eBPF TC hook maintains a virtual queue model with a time-varying drain rate (V-shape pattern). The state is defined in `queue_state_map`:

| State | Value | TOS Byte | Compression Strategy |
|---|---|---|---|
| `STATE_NORMAL` | 0 | 0x00 | No compression (pass-through) |
| `STATE_COMPRESS` | 1 | 0x28 | Header compression only |
| `STATE_DELTA` | 2 | 0x50 | Byte-level XOR + zlib |
| `STATE_INCREMENTAL` | 3 | 0x64 | Field-level XML diffs |
| `STATE_DROP` | 4 | 0x78 | Emergency drop (not used in experiment) |

> **Note**: In the current experiment, states are force-overridden by `force_state.py` rather than autonomously selected. The adaptive hysteresis logic exists in `xdp_prog.c` but is commented out.

### 2.7 Encryption Architecture

In a real wireless deployment, payloads are encrypted. eFRAC uses **HKDF-derived AES-256-GCM** to implement encryption transparently across the pipeline. All nodes derive the same symmetric key from a pre-shared key file (`efrac.psk`) using HKDF-SHA256.

**Key Derivation (HKDF-SHA256):**

| Parameter | Value |
|---|---|
| IKM | 32-byte hex-encoded PSK from `efrac.psk` |
| Salt | `efrac-salt-v1` (fixed) |
| Info | `efrac-aes256-gcm-key` (context string) |
| Output | 32-byte AES-256 key |

**Encrypted Wire Format:**
```
┌──────────┬──────────────────┬──────────┐
│ Nonce    │ Ciphertext       │ GCM Tag  │
│ (12B)    │ (variable)       │ (16B)    │
└──────────┴──────────────────┴──────────┘
```
Overhead: 28 bytes per encrypted payload. Nonces are randomly generated per packet.

**Per-Node Responsibilities:**

| Node | Encrypt | Decrypt | Notes |
|---|---|---|---|
| **H1** | ✅ Encrypts CoT payload before sending | — | Plaintext → AES-GCM → UDP |
| **MB1** | ✅ Re-encrypts compressed output | ✅ Decrypts payload (Delta/Incr only) | HC passes encrypted payload unchanged |
| **MB2** | ✅ Re-encrypts reconstructed plaintext | ✅ Decrypts compressed data (Delta/Incr only) | HC forwards encrypted payload as-is |
| **H2** | — | ✅ Decrypts all received payloads | Sink `--decrypt` flag |

> **Key insight**: Header Compression **never decrypts** — it operates on L3/L4 headers which sit outside the encryption envelope. The encrypted application payload passes through HC unchanged. Only Delta and Incremental modes require decrypt → compress/decompress → re-encrypt at the middleboxes.

---

## 3. Wire Protocols

### 3.1 Compressed Header Protocol (`ETH_P_COMP` = 0x88B5)

Used by the eBPF TC hook for Header Compression. Replaces the IP + transport headers with a compact structure:

**UDP Compressed Header** (3 bytes):
```
┌──────────┬───────────┐
│ flow_id  │ src_port  │
│  (1B)    │  (2B)     │
└──────────┴───────────┘
```

**TCP Compressed Header** (14 bytes):
```
┌──────────┬───────────┬──────┬──────────┬────────┬───────┬───────┐
│ flow_id  │ src_port  │ seq  │ ack_seq  │ window │ check │ flags │
│  (1B)    │  (2B)     │ (4B) │  (4B)    │  (2B)  │ (2B)  │ (1B)  │
└──────────┴───────────┴──────┴──────────┴────────┴───────┴───────┘
```

Savings: 40 bytes (IP+UDP) → 3 bytes, or 40 bytes (IP+TCP) → 14 bytes.

### 3.2 Agent Wire Protocol (UDP to Sink)

The C agent and sink communicate via standard UDP on port 8087. Each packet has a 1-byte type prefix:

| Byte 0 | Type | Wire Payload |
|---|---|---|
| `0x00` | SYNC | Full original payload (reference frame) |
| `0x01` | DELTA | zlib-compressed XOR diff against previous payload |
| `0x02` | INCREMENTAL | Binary field diff: `[count][field_id, val_len, value]...` |
| `0x03` | HC | Original payload (headers already removed by eBPF) |

### 3.3 Incremental Field Encoding

The field-level diff format for CoT XML:

```
Byte 0:    num_changed (uint8)   ─── number of changed fields
Then for each changed field:
  Byte N:    field_id  (uint8)   ─── index into field table (0–11)
  Byte N+1:  val_len   (uint8)   ─── length of new value string
  Byte N+2…: value     (val_len bytes) ─── UTF-8 field value
```

**Field ID Table:**

| ID | Field Name | XML Location | Typical Change? |
|---|---|---|---|
| 0 | `event_version` | `<event version="...">` | No |
| 1 | `event_uid` | `<event uid="...">` | No |
| 2 | `event_type` | `<event type="...">` | No |
| 3 | `event_time` | `<event time="...">` | **Yes** |
| 4 | `event_start` | `<event start="...">` | **Yes** |
| 5 | `event_stale` | `<event stale="...">` | **Yes** |
| 6 | `point_lat` | `<point lat="...">` | Sometimes |
| 7 | `point_lon` | `<point lon="...">` | Sometimes |
| 8 | `point_hae` | `<point hae="...">` | No |
| 9 | `point_ce` | `<point ce="...">` | No |
| 10 | `point_le` | `<point le="...">` | No |
| 11 | `contact_callsign` | `<contact callsign="...">` | No |
| 12 | `detail_e2e_ts` | `<detail e2e_ts="...">` | **Yes** (dual-MB only) |

---

## 4. File-by-File Documentation

### 4.1 eBPF Dataplane

#### `xdp_prog.c` (723 lines)

The eBPF program containing all kernel-side packet processing logic. Compiled to BPF bytecode by Clang, loaded via the skeleton in `loader.c`.

**Programs (4 eBPF entry points):**

| Section | Function | Attachment Point | Node | Purpose |
|---|---|---|---|---|
| `SEC("xdp")` | `xdp_prog_main` | XDP on `veth1-mb` (ingress) | MB1 / MiddleBox | Timestamps every incoming packet by writing `bpf_ktime_get_ns()` into `packet_ts` map keyed by 5-tuple. |
| `SEC("tc")` | `tc_prog_main` | TC egress on `veth2-mb` | MB1 / MiddleBox | The core logic — reads timestamp from map to compute sojourn time, manages the virtual queue model with V-shape drain rate, applies TOS stamps, and redirects to `veth-delta` when compression is active. |
| `SEC("xdp")` | `xdp_peer_ingress` | XDP on `veth2-mb` (ingress) | MB1 / MiddleBox | Cooperative logic — reads TOS from incoming packets (from peer MiddleBox) and latches the remote congestion state into `remote_state_map`. |
| `SEC("xdp")` | `xdp_decompress_main` | XDP on `veth2` (H2) or `veth-link2` (MB2) | H2 (single-MB) or MB2 (dual-MB) | Decompressor — detects `ETH_P_COMP` packets, looks up flow context, and restores full IP + UDP/TCP headers. Handles flow IDs 1–4 (IPv4 UDP, IPv4 TCP, IPv6 UDP, IPv6 TCP). |

> **Note on eBPF placement**: H1 and H2 are purely userspace (Python traffic generator and sink). All eBPF programs run on the middlebox(es). The one exception is `xdp_decompress_main`, which attaches to H2 in the single-MB topology but moves to MB2 in the dual-MB topology.

**Maps (7 BPF maps):**

| Map | Type | Purpose |
|---|---|---|
| `context_map` | `HASH` (256 entries) | Stores pre-shared `flow_context` structs (template IP/TCP/UDP headers) keyed by flow ID. Used by the decompressor to restore headers. |
| `packet_ts` | `LRU_HASH` (4096 entries) | Per-packet ingress timestamps keyed by 5-tuple (`packet_key`). Written by `xdp_prog_main`, read by `tc_prog_main` to compute sojourn time. |
| `queue_state_map` | `ARRAY` (1 entry) | The virtual queue state: current bytes, state enum, avg sojourn, link capacity, last update timestamp. Pinned to `/sys/fs/bpf/queue_state_map`. |
| `remote_state_map` | `ARRAY` (1 entry) | Cooperative congestion state received from peer MiddleBox via TOS inspection. |
| `stats_map` | `ARRAY` (2 entries) | Performance counters: key 0 = compression processing time, key 1 = sojourn time. Each stores count, sum, min, max in nanoseconds. |
| `tx_port` | `DEVMAP` (64 entries) | Maps logical port index to interface ifindex for XDP redirect. Key 0 = egress iface, key 1 = delta agent veth. |

**Virtual Queue Model (V-Shape):**

The TC hook simulates congestion using a time-varying drain rate:
- `t = 0–20s`: `ns_per_byte` ramps from 5000 → 20000 (drain slows: 200→50 KB/s)
- `t = 20–40s`: `ns_per_byte` ramps from 20000 → 5000 (drain recovers)
- Virtual backlog: `current_bytes += physical_len` on enqueue, drained by `delta_ns / ns_per_byte` each tick
- Virtual sojourn: `avg_sojourn_ns = current_bytes × ns_per_byte`

The physical_len used for the virtual queue depends on the compression state:
- Normal: `pkt_len`
- HC: `pkt_len - 22`
- Delta: `pkt_len / 2`
- Incremental: `pkt_len / 8`

---

#### `loader.c` (578 lines)

Userspace program that loads the eBPF skeleton, attaches programs to interfaces, populates flow context maps, and runs the telemetry display loop. Has two modes:

**Mode 0 — MiddleBox** (`./loader veth1-mb veth2-mb`):
1. Opens and loads the BPF skeleton (`xdp_prog__open`, `xdp_prog__load`)
2. Attaches `xdp_prog_main` (XDP) to `veth1-mb`
3. Attaches `tc_prog_main` (TC egress) to `veth2-mb`
4. Attaches `xdp_peer_ingress` (XDP) to `veth2-mb`
5. Populates `context_map` with 4 flow contexts: IPv4 UDP (flow 1), IPv4 TCP (flow 2), IPv6 UDP (flow 3), IPv6 TCP (flow 4)
6. Configures `tx_port` DEVMAP: key 0 → egress ifindex, key 1 → `veth-delta` ifindex
7. Pins `queue_state_map` and `packet_ts` to `/sys/fs/bpf/`
8. Starts a key manager thread (rotates an XOR key every 10s — legacy feature)
9. Runs a 1-second telemetry loop: reads `stats_map` and `queue_state_map`, displays performance metrics, and appends sojourn data to `congestion_log.csv`

**Mode 1 — Decompressor** (`./loader --decompress veth2`):
1. Loads skeleton, attaches `xdp_decompress_main` to `veth2` on H2
2. Populates the same 4 flow contexts (so the decompressor knows how to restore headers)
3. Sleeps until SIGINT

**Build artifacts**: `loader` (binary), `xdp_prog.o` (BPF object), `xdp_prog.skel.h` (auto-generated skeleton header)

---

#### `Makefile` (26 lines)

```makefile
xdp_prog.o:  clang -O2 -g -target bpf -c xdp_prog.c
skel.h:      bpftool gen skeleton xdp_prog.o > xdp_prog.skel.h
loader:      cc -O2 -g -o loader loader.c -lbpf -lelf -lz
```

Dependencies: `clang`, `bpftool`, `libbpf`, `libelf`, `zlib`.

---

### 4.2 Encryption Utilities

#### `efrac.psk`

Pre-shared key file — a single line of 64 hex characters (32 bytes of input key material). Used by all nodes (H1, MB1, MB2, H2) for HKDF-SHA256 key derivation. Auto-generated by the experiment script if not present.

---

#### `crypto_utils.py` (80 lines)

Python HKDF + AES-256-GCM module. Used by `traffic_gen.py` (encryption) and `sink.py` (decryption).

**Functions:**
- `derive_key(ikm)` — HKDF-SHA256 with fixed salt/info → 32-byte AES key
- `load_key(psk_path)` — Read hex PSK from file → derive key
- `encrypt(key, plaintext)` — AES-256-GCM, returns `nonce + ciphertext + tag`
- `decrypt(key, blob)` — AES-256-GCM, extracts nonce/tag, returns plaintext

---

#### `crypto_utils.h` (170 lines)

C header-only HKDF + AES-256-GCM library using OpenSSL EVP API. Wire-compatible with `crypto_utils.py`. Included by both C agents.

**Functions:**
- `efrac_derive_key(psk_path, out_key)` — Read PSK, HKDF-SHA256 → 32-byte key
- `efrac_encrypt(key, plaintext, pt_len, out, out_len)` — AES-256-GCM encrypt
- `efrac_decrypt(key, blob, blob_len, out, out_len)` — AES-256-GCM decrypt

Requires: `-lssl -lcrypto` (OpenSSL)

---

### 4.3 Userspace Compression Agent

#### `delta_agent_c.c` (465 lines)

The C userspace agent that performs the actual compression for Delta, Incremental, and HC modes. Runs in the MiddleBox namespace.

**How it works:**

1. Opens a raw packet socket on `veth-delta-peer` to receive packets redirected by the eBPF TC hook
2. Opens a standard UDP socket for sending compressed output to the sink on H2
3. Opens the pinned `packet_ts` BPF map via `bpf_obj_get("/sys/fs/bpf/packet_ts")` to clean up timestamp entries after processing
4. For each received packet:
   - Parses Ethernet → IP → UDP/TCP headers to extract the application payload
   - Applies a loop guard: skips packets whose first byte is ≤ 0x02 (to avoid processing its own output)
   - Deletes the corresponding `packet_ts` entry
   - Reads the TOS byte stamped by eBPF to determine which compression mode to use:

| TOS | Mode | Action |
|---|---|---|
| `0x28` | HC | Sends full payload prefixed with `TYPE_HC` (0x03) |
| `0x64` | Incremental | Parses CoT XML fields, diffs against previous, sends compact binary field diff prefixed with `TYPE_INCREMENTAL` (0x02) |
| Other | Delta | XOR-diffs against previous payload, zlib-compresses, sends prefixed with `TYPE_DELTA` (0x01) |

**Incremental encoding pipeline:**
- `parse_cot_fields()` — Scans for `<event`, `<point>`, `<contact>`, `<detail>` elements and extracts 13 attribute values (including `e2e_ts`) using simple string matching
- `build_incremental_diff()` — Compares each field to the stored previous value, emits only changed fields in `[count][id, len, value]` format
- First packet always sent as SYNC (full payload) to establish baseline

---

#### `decompress_agent.c` (407 lines)

The C userspace **decompression** agent — mirror of `delta_agent_c.c`. Runs on **MB2** in the dual-middlebox topology.

**How it works:**

1. Opens a raw packet socket on `veth-link2` (tactical link ingress to MB2)
2. Opens a standard UDP socket for sending reconstructed packets to H2
3. For each UDP packet arriving on port 8087, inspects the first payload byte:

| Type Byte | Action |
|---|---|
| `TYPE_SYNC` (0x00) | Store as Delta baseline + parse as Incremental baseline. Forward payload to H2 |
| `TYPE_DELTA` (0x01) | zlib-decompress, XOR against stored baseline, store result. Forward to H2 |
| `TYPE_INCREMENTAL` (0x02) | Apply binary field diff to stored fields, reconstruct XML from template. Forward to H2 |
| `TYPE_HC` (0x03) | Forward payload as-is (headers already restored by XDP) |

**Interception**: An `iptables FORWARD DROP` rule on MB2 prevents the kernel from forwarding compressed packets directly to H2 — only the decompress_agent's reconstructed output gets through.

**Result**: H2 receives completely normal UDP packets. Compression is transparent to endpoints.

---

### 4.4 Traffic Generator

#### `traffic_gen.py` (535 lines)

Multi-threaded traffic generator supporting four traffic classes typical of tactical/military networks. Can run in CLI mode (automated) or interactive TUI mode.

**Stream Classes:**

| Class | Protocol | DSCP | Default Rate | Payload |
|---|---|---|---|---|
| `CoTStream` | UDP or TCP | EF (46) | Configurable pps | XML position reports with padding |
| `VideoStream` | UDP | AF41 (34) | Configurable Mbps | File-based or synthetic 1400B frames |
| `VoiceStream` | UDP | EF (46) | 50 pps (20ms interval) | RTP-encapsulated G.711 160B frames |
| `XMPPStream` | TCP | CS0 (0) | Configurable msg/s | XML chat messages |

**CLI mode** (used by experiment scripts):
```bash
python3 traffic_gen.py 10.0.2.1 --mode cot --port 8087 --rate 200 \
    --duration 40 --udp --payload_size 800
```

**Key features:**
- Per-stream threading with `threading.Thread`
- DSCP/TOS marking via `IP_TOS` socket option
- Rate ramping: `--ramp_to` linearly changes pps over the duration
- Payload padding: `--payload_size` pads CoT XML to exact size
- Simulated encryption: `--encrypt` replaces payload with `0xAA` bytes
- Queue/playlist system for sequencing file transfers (interactive mode)

**CoT XML format generated:**
```xml
<?xml version="1.0" standalone="yes"?>
<event version="2.0" uid="uuid-XXXX" type="a-f-G-U-C"
       time="..." start="..." stale="...">
    <point lat="34.0" lon="-118.0" hae="0.0" ce="9999999" le="9999999"/>
    <detail e2e_ts="1740000060.050000">   <!-- only when --e2e_timestamp is set -->
        <contact callsign="GroundUnit-XXXX"/>
    </detail>
</event>
```

---

### 4.5 Receiver / Sink

#### `sink.py` (302 lines)

Receives traffic on H2, decodes all compression formats, and prints diagnostic output parsed by the experiment scripts.

**Listeners**: Runs both TCP and UDP listener threads on the configured port (default 8087).

**Decode logic by packet type:**

| Type Byte | Handler | Decode Method |
|---|---|---|
| `0x00` (SYNC) | Store as delta + incremental baseline | Raw passthrough |
| `0x01` (DELTA) | zlib decompress → XOR against stored baseline | Byte-level reconstruction |
| `0x02` (INCREMENTAL) | Parse binary field diff → apply to stored field state → reconstruct XML via template | Field-level reconstruction |
| `0x03` (HC) | Passthrough (eBPF already decompressed headers) | No decode needed |
| Raw XML (`<?xml`) | Auto-detect as SYNC | Store as baseline |

**State dictionaries:**
- `delta_history[addr]` — Last full payload bytes (for XOR reference)
- `incr_history[addr]` — Last parsed field dict (for incremental diffs)

**Output format** (parsed by experiment scripts):
```
[Sink] OK 1740000000.123 0
[Sink] Rx SYNC: b'<?xml ver...' (800B)
[Sink] Rx DELTA: 24B wire -> 800B decoded
[Sink] Rx INCREMENTAL: 88B wire -> 355B decoded (3 fields changed)
[Sink] Rx HC: 800B wire -> 800B reconstructed
```

---

### 4.6 Monitoring & State Control

#### `monitor_general.py` (67 lines)

Polls interface statistics every 100ms and writes to CSV. Runs in the MiddleBox namespace watching `veth2-mb`.

**Data sources:**
- `tx_bytes`, `tx_packets`: Read from `/sys/class/net/<iface>/statistics/`
- `drops`: Parsed from `tc -s qdisc show dev <iface>` (regex for `dropped \d+`)

**Output CSV columns**: `time, tx_bytes, tx_packets, drops`

The `time` column is seconds since monitor start (float). All other columns are cumulative counters since interface creation.

---

#### `force_state.py` (76 lines)

Overrides the eBPF congestion state by directly writing to the `queue_state_map` BPF map.

**How it works:**
1. Uses `bpftool -j map show` to find the map ID for `queue_state_map` by name
2. Dumps the current map entry with `bpftool -j map dump id <N>`
3. Overwrites the `state` field (offset 16 in the struct, `__u32`) with the target value
4. Writes back with `bpftool map update id <N> key ... value ...`
5. Repeats every 1.5 seconds in a loop

**Usage**: `python3 force_state.py <state>` where state is 0–3.

---

### 4.7 Experiment Scripts

#### `run_comparative.sh` (381 lines)

The primary experiment runner. Executes all four phases back-to-back with a clean namespace rebuild between each.

**Sequence:**
1. Compile: `make clean && make` + `gcc delta_agent_c.c`
2. Clean old CSV/log files
3. For each phase (Baseline → HC → Delta → Incremental):
   - `nuke()` — kill processes, delete namespaces, clean BPF pins
   - `setup_network()` — create namespaces, veths, routes, disable offloading
   - Apply netem: `tc qdisc add dev veth2-mb root netem rate 200kbit delay 50ms 10ms loss 2%`
   - Start sink (CPU 3), monitor (CPU 0), agent if needed (CPU 2), loader (CPU 0)
   - Start decompressor on H2
   - Start periodic state forcing loop
   - Send traffic (CPU 1): 200 pps, 800B payload, 40s duration
   - Wait 3s drain, kill processes, save sojourn CSV
   - Parse sink log for SYNC/HC/DELTA/INCR/FAIL counts → append to `sink_summary.csv`
4. Generate comparative plot

**CPU pinning**: Uses `taskset -c N` to isolate components onto specific cores.

**Output files:**
- `baseline_log.csv`, `hc_log.csv`, `delta_log.csv`, `incremental_log.csv` (monitor data)
- `Baseline_sojourn.csv`, `HeaderComp_sojourn.csv`, `Delta_sojourn.csv`, `Incremental_sojourn.csv` (virtual queue telemetry)
- `sink_summary.csv` (per-phase packet counts)
- `/tmp/sink_*.log`, `/tmp/loader_*.log`, `/tmp/agent_*.log`, `/tmp/traffic_*.log` (process logs)

---

#### `run_experiment.sh` (261 lines)

A more polished version of the experiment runner with parameterized tunables and `./results/` output directory.

**Key differences from `run_clean_comparative.sh`:**
- Uses `set -euo pipefail` for stricter error handling
- All tunables at the top: `DURATION=60`, `PPS=100`, `PAYLOAD_SIZE=800`, etc.
- Outputs to `./results/` directory with structured naming
- Loader only starts for non-Baseline phases (State > 0)
- Designed for `plot_real_results.py` as the downstream consumer

---

#### `run_dual_mb.sh` (279 lines)

Dual-middlebox experiment for end-to-end latency measurement. Uses 4 namespaces (H1, MB1, MB2, H2).

**Key differences from `run_clean_comparative.sh`:**
- 4 namespaces instead of 3 — MB1 compresses, MB2 decompresses
- Netem applied to `veth-link1` (inter-MB tactical link) instead of `veth2-mb`
- Traffic generator uses `--e2e_timestamp` to embed send timestamps
- Sink uses `--e2e_log` to write per-packet latency CSVs
- Monitor watches `veth-link1` (MB1's tactical link egress)

**Output files** (in addition to standard monitor/sojourn CSVs):
- `e2e_latency_Baseline.csv`, `e2e_latency_HeaderComp.csv`, etc.

---

#### `run_comparative.sh` (378 lines)

Unified experiment script that combines single-MB and dual-MB topologies into one file, controlled by a `--topology single|dual` flag.

**Key features compared to the separate scripts:**
- Single entry point: `sudo bash run_comparative.sh --topology single` or `--topology dual`
- Parameterized tunables at the top: `DURATION=40`, `PPS=200`, `PAYLOAD_SIZE=800`, link conditions
- Contains `setup_network_single()` and `setup_network_dual()` functions
- A unified `run_phase()` function handles both topologies with conditional logic for agent, sink, monitor, and traffic generator configuration
- Automatically invokes `plot_dual_mb.py` for dual topology runs

---

### 4.8 Plotting Scripts

#### `plot_comparative.py` (64 lines)

Quick plot script used by `run_clean_comparative.sh`. Reads `*_log.csv` files from the working directory and produces a 3-panel figure:
1. **Wire Throughput** (cumulative KB)
2. **Packets Transmitted** (cumulative)
3. **Cumulative Drops**

Output: `comparative_plot.png`

---

#### `plot_sojourn.py` (54 lines)

Plots the sojourn time evolution from the `*_sojourn.csv` files. Shows how the EWMA sojourn time (ms) varies over time for each phase.

**Input CSV format** (no header): `timestamp, latency_ms, current_bytes, state`

Output: `sojourn_times_plot.png`

---

#### `plot_dual_mb.py` (174 lines)

Dual-middlebox experiment plotting script. Reads the same `*_log.csv` and `*_sojourn.csv` files as the single-MB scripts, plus `e2e_latency_*.csv` files. Produces two figures:

1. **4-panel comparison** (`dual_mb_comparison.png`):
   - Wire throughput (KB)
   - Cumulative packets transmitted
   - Virtual queue sojourn time
   - Summary bar chart (total packets delivered to H2)

2. **E2E latency box plot** (`dual_mb_e2e_latency.png`):
   - Box-and-whisker plot comparing end-to-end latency distributions across all four strategies
   - Shows sample counts per strategy

**Usage**: `python3 plot_dual_mb.py` (reads files from the current directory)

---

#### `plot_real_results.py` (511 lines)

Publication-quality plotting script for thesis/paper figures. Uses serif fonts (Times New Roman), proper axis labels, and annotations.

**Generates 4 figures:**

| Figure | Content | Output File |
|---|---|---|
| Fig 1 | Wire throughput (kbps) + cumulative drops (side-by-side) | `real_throughput_drops.png` |
| Fig 2 | Goodput time series (if sink has timestamps) or bar chart of totals | `real_goodput_timeseries.png` or `real_sink_counts.png` |
| Fig 3 | Instantaneous drop rate (3s rolling average) | `real_drop_rate.png` |
| Fig 4 | Summary bars: total drops and total bytes by strategy with % annotations | `real_summary_bars.png` |

**Usage**: `python3 plot_real_results.py --results ./results --out ./plots`

Also prints a formatted summary table to stdout comparing all strategies.

---

### 4.9 Data Files

#### Monitor CSVs (`*_log.csv`)

Format: `time,tx_bytes,tx_packets,drops`

- `time`: Seconds since monitor start (sampled every ~0.1s)
- `tx_bytes`: Cumulative bytes transmitted on `veth2-mb`
- `tx_packets`: Cumulative packets transmitted
- `drops`: Cumulative drops from netem qdisc

Typical file: ~400 rows (40s × 10 samples/s)

---

#### Sojourn CSVs (`*_sojourn.csv`)

Format (no header): `unix_timestamp,sojourn_ms,current_bytes,state`

- `unix_timestamp`: Epoch seconds
- `sojourn_ms`: Virtual queue sojourn time in milliseconds
- `current_bytes`: Virtual queue backlog in bytes
- `state`: Current eBPF state (0–4)

Typical file: ~45 rows (1 sample/s for 40s + startup/drain)

---

#### `sink_summary.csv`

Per-phase packet counts extracted from sink logs:

```
phase,sync,hc,delta,incr,fail
Baseline,1273,0,0,0,0
HeaderComp,1,1066,0,0,0
Delta,1,0,5469,0,0
Incremental,2,0,0,5528,0
```

---

#### E2E Latency CSVs (`e2e_latency_*.csv`)

Generated by `sink.py --e2e_log` in the dual-MB experiment. Per-packet end-to-end latency:

```
recv_time,send_time,latency_ms,pkt_type
1740000060.123456,1740000060.050000,73.456,SYNC
1740000060.223456,1740000060.155000,68.456,DELTA
```

- `recv_time`: Epoch timestamp when sink received the packet
- `send_time`: Epoch timestamp embedded by traffic generator
- `latency_ms`: `(recv_time - send_time) × 1000`
- `pkt_type`: SYNC, DELTA, INCREMENTAL, or HC

---

### 4.10 Generated / Build Artifacts

| File | Description |
|---|---|
| `xdp_prog.o` | Compiled BPF object (Clang output) |
| `xdp_prog.skel.h` | Auto-generated BPF skeleton header (bpftool) — ~183KB |
| `loader` | Compiled loader binary |
| `delta_agent_c` | Compiled compression agent binary |
| `decompress_agent` | Compiled decompression agent binary (MB2) |
| `sojourn_times_plot.png` | Latest sojourn plot |
| `dual_mb_comparison.png` | Latest dual-MB experiment comparison plot |
| `dual_mb_e2e_latency.png` | Latest dual-MB E2E latency box plot |
| `FRAC-5.pdf` | Reference paper / specification document |

---

### 4.11 Configuration & Workflows

#### `.agents/workflows/run_experiment.md`

Workflow definition for running the eBPF experiment via the `/run_experiment` slash command.

---

## 5. Experiment Execution Summary

### Running the Experiments

```bash
# Single-MB: sojourn time measurement (4 phases × 40s each, ~3 minutes)
sudo bash run_comparative.sh --topology single

# Dual-MB: end-to-end latency measurement (4 phases × 40s each, ~3 minutes)
sudo bash run_comparative.sh --topology dual
# Generates: e2e_latency_*.csv, dual_mb_comparison.png, dual_mb_e2e_latency.png
```

All experiments run with **AES-256-GCM encryption enabled** by default. Traffic is encrypted at H1, decrypted/re-encrypted at middleboxes, and decrypted at H2.

### Single-MB Results (Sojourn Time)

| Phase | Sink Packets | Wire Size | Sojourn Peak |
|---|---|---|---|
| Baseline | ~24 (encrypted, uncompressed) | ~828 B/pkt | ~8000–10000 ms |
| HC | ~1036 (header compressed) | ~828 B/pkt (encrypted payload unchanged) | ~10000 ms |
| Delta | ~4113 (XOR+zlib, re-encrypted) | ~52 B/pkt (+28B AES overhead) | ~2300 ms |
| Incremental | ~3854 (field diffs, re-encrypted) | ~116 B/pkt (+28B AES overhead) | ~0 ms |

### Dual-MB Results (End-to-End Latency)

| Phase | Packets Delivered | E2E Samples | Coverage | Median E2E Latency |
|---|---|---|---|---|
| Baseline | ~1221 | ~1221 | 100% | ~18,000 ms |
| HC | ~1023 | ~1023 | 100% | ~15,000 ms |
| Delta | ~5287 | ~5287 | 100% | ~100–200 ms |
| Incremental | ~4826 | ~4826 | 100% | ~3,000 ms |

> **E2E Measurement Technique**: To achieve 100% E2E coverage across all compression modes, the experiment uses an **8-byte timestamp trailer** appended outside the encryption/compression envelope. H1 appends `struct.pack('!d', time.time())` as the last 8 bytes of each UDP datagram (after the encrypted payload). The C agents (`delta_agent_c`, `decompress_agent`) strip this trailer before decryption/compression and re-append it to the outgoing packet via `sendmsg` with scatter-gather iovec. The sink extracts the trailer before processing and computes `recv_time − send_time`. This avoids the prior limitation where byte-level XOR reconstruction could corrupt in-payload timestamps, which had reduced Delta's E2E sample rate to ~9%. The trailer is only active during testing, controlled by `--e2e_timestamp` (traffic gen) and the `E2E_TRAILER` environment variable (C agents).

### Analysis

**Compression effectiveness**: Delta and Incremental deliver 4–5× more packets than Baseline/HC because their compressed output fits within the bandwidth-limited tactical link. Encryption does not measurably affect compression ratios.

**Encryption overhead**: AES-256-GCM adds 28 bytes (12B nonce + 16B tag) per packet — a 3.5% increase on 800B payloads. This overhead is negligible compared to the compression savings.

**Baseline ≈ HC latency**: Both transmit full-size encrypted payloads (~828B). HC saves ~22B on L3/L4 headers, which is insignificant relative to the payload. The encrypted payload passes through HC unchanged (never decrypted).

**Delta vs Incremental**: Delta achieves the lowest E2E latency (~100–200ms vs ~3,000ms) because XOR+zlib diffs are more compact (~24B) than Incremental's field-level diffs (~88B), resulting in less queuing delay. With full-coverage measurement via the timestamp trailer, Delta's near-zero latency is confirmed to be genuine, not a sampling artifact.

---

## 6. Dependencies

| Dependency | Purpose |
|---|---|
| Linux kernel ≥ 5.15 | BPF CO-RE, XDP, TC hooks |
| `clang` | BPF bytecode compilation |
| `bpftool` | Skeleton generation, map inspection |
| `libbpf-dev` | BPF loading library |
| `libelf-dev` | ELF parsing for BPF object |
| `zlib` / `zlib1g-dev` | Delta compression in agent + loader |
| `libssl-dev` | HKDF key derivation + AES-256-GCM encryption (C agents) |
| `iproute2` | `ip`, `tc` commands for namespace/qdisc management |
| `ethtool` | Disable hardware offloading on veth pairs |
| Python 3.6+ | Traffic gen, sink, monitor, plotting, force_state |
| `cryptography` (Python) | HKDF + AES-256-GCM encryption (traffic gen, sink) |
| `matplotlib` | Plotting scripts |
| `numpy` | `plot_real_results.py` |

---

## 7. Key Design Decisions

1. **Virtual queue instead of real measurement**: The sojourn metric is computed from a mathematical model, not from actual qdisc latency. This provides deterministic, reproducible results but doesn't capture real kernel scheduling effects.

2. **Forced state instead of adaptive**: The experiment forces each phase to a fixed compression state for the entire duration. This isolates the effect of each strategy but doesn't test the state-transition logic.

3. **Separate userspace agent**: Compression is done in userspace (C agent) rather than in the eBPF program itself, because eBPF's instruction limits and lack of loops make complex compression (XOR, zlib, XML parsing) impractical in-kernel. The eBPF hooks handle fast-path decisions (redirect or pass) while the agent handles slow-path compression.

4. **Pre-shared flow context**: Header compression relies on both endpoints having identical pre-populated `context_map` entries. In a real deployment, this would require a context synchronization protocol.

5. **CoT-specific incremental encoding**: The field-level encoding is tailored to CoT XML structure. Other application protocols would need their own field parsers.

6. **HKDF-based encryption with trusted middleboxes**: Encryption uses AES-256-GCM with HKDF-derived keys from a pre-shared secret. The middleboxes are trusted nodes that decrypt payloads before compression and re-encrypt after. Header Compression bypasses decryption entirely since it only touches L3/L4 headers. The 28-byte GCM overhead (nonce + auth tag) is a ~3.5% increase on 800B payloads.

7. **E2E timestamp trailer for unbiased measurement**: Rather than embedding send timestamps inside the XML payload (where byte-level XOR reconstruction can corrupt them), an 8-byte IEEE 754 double is appended as a trailer outside the encryption/compression envelope. The C agents strip and re-append it via `sendmsg` scatter-gather. This achieves 100% E2E sample coverage across all compression modes, confirming that Delta's near-zero latency is genuine.
