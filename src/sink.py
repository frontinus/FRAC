#!/usr/bin/env python3
"""
Sink — Receives traffic (normal, delta-encoded, or incrementally-encoded).
Wire Format:
  Byte 0: Type
    0x00 = SYNC  (full payload, used as reference)
    0x01 = DELTA (XOR diff against previous full payload)
    0x02 = INCREMENTAL (JSON diff of changed XML fields)
  Byte 1+: Payload
"""
import socket
import argparse
import signal
import sys
import json
import re
import struct
import threading
import zlib
import time
import crypto_utils

# XML reconstruction template
COT_TEMPLATE = """<?xml version="1.0" standalone="yes"?>
<event version="{event_version}" uid="{event_uid}" type="{event_type}" time="{event_time}" start="{event_start}" stale="{event_stale}">
    <point lat="{point_lat}" lon="{point_lon}" hae="{point_hae}" ce="{point_ce}" le="{point_le}"/>
    <detail>
        <contact callsign="{contact_callsign}"/>
    </detail>
</event>"""

# XML field extraction (mirrors delta_agent.py)
ATTR_RE = re.compile(r'(\w+)="([^"]*)"')
EVENT_RE = re.compile(r'<event\s+([^>]*)>')
POINT_RE = re.compile(r'<point\s+([^/]*)/?>')
CONTACT_RE = re.compile(r'<contact\s+([^/]*)/?>')
E2E_TS_RE = re.compile(r'e2e_ts="(\d+\.\d+)"')

TYPE_SYNC = 0x00
TYPE_DELTA = 0x01
TYPE_INCREMENTAL = 0x02
TYPE_HC = 0x03

def signal_handler(sig, frame):
    print('\nExiting...')
    sys.exit(0)

def xml_to_fields(payload_bytes):
    """Parse CoT XML into a flat dict of field values."""
    try:
        xml_str = payload_bytes.decode('utf-8', errors='replace')
    except:
        return None
    
    fields = {}
    m = EVENT_RE.search(xml_str)
    if m:
        for key, val in ATTR_RE.findall(m.group(1)):
            fields[f"event_{key}"] = val
    m = POINT_RE.search(xml_str)
    if m:
        for key, val in ATTR_RE.findall(m.group(1)):
            fields[f"point_{key}"] = val
    m = CONTACT_RE.search(xml_str)
    if m:
        for key, val in ATTR_RE.findall(m.group(1)):
            fields[f"contact_{key}"] = val
    return fields if fields else None

def fields_to_xml(fields):
    """Reconstruct XML from field dict."""
    try:
        return COT_TEMPLATE.format(**{k: fields.get(k, '?') for k in [
            'event_version', 'event_uid', 'event_type',
            'event_time', 'event_start', 'event_stale',
            'point_lat', 'point_lon', 'point_hae', 'point_ce', 'point_le',
            'contact_callsign'
        ]}).encode('utf-8')
    except Exception as e:
        return f"<reconstruction_error: {e}>".encode('utf-8')

def start_tcp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    print(f"Listening on TCP {port}...")
    
    while True:
        try:
            conn, addr = sock.accept()
            while True:
                try:
                    data = conn.recv(4096)
                    if not data: break
                    process_data(data, addr)
                except ConnectionResetError:
                    break
            conn.close()
        except Exception as e:
            print(f"TCP Error: {e}")

def start_udp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    print(f"Listening on UDP {port}...")
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            process_data(data, addr)
        except Exception as e:
            print(f"UDP Error: {e}")
        
# State for decoding
# Delta: {addr -> last_full_payload (bytes)}
delta_history = {}
# Incremental: {addr -> last_fields (dict)}
incr_history = {}
# E2E latency log file handle (set in main)
e2e_log_fp = None
# Encryption key (set in main if --decrypt is used)
crypto_key = None

def try_decrypt(payload):
    """Decrypt payload if crypto is enabled. Falls back to plaintext on failure."""
    if crypto_key is None:
        return payload
    try:
        return crypto_utils.decrypt(crypto_key, payload)
    except Exception:
        # Might be unencrypted data — return as-is
        return payload

def process_data(data, addr):
    global delta_history, incr_history
    
    if len(data) < 1:
        return

    # --- Extract E2E timestamp trailer (8B, outside encryption envelope) ---
    e2e_send_ts = None
    if e2e_log_fp and len(data) > 8:
        try:
            e2e_send_ts = struct.unpack('!d', data[-8:])[0]
            # Sanity check: valid Unix timestamp (year 2020–2040)
            if 1577836800 < e2e_send_ts < 2208988800:
                data = data[:-8]  # strip trailer before processing
            else:
                e2e_send_ts = None
        except Exception:
            e2e_send_ts = None

    pkt_type = data[0]
    payload = data[1:]
    
    addr_key = addr  # (ip, port)
    decoded = b""
    
    print(f"[Sink] OK {time.time():.3f} {len(decoded)}", flush=True)
    if pkt_type == TYPE_SYNC:
        # Full packet — store as baseline for both modes
        payload = try_decrypt(payload)
        delta_history[addr_key] = payload
        fields = xml_to_fields(payload)
        if fields:
            incr_history[addr_key] = fields
        decoded = payload
        print(f"[Sink] Rx SYNC: {decoded[:20]}... ({len(payload)}B)", flush=True)
        
    elif pkt_type == TYPE_DELTA:
        # zlib-compressed XOR delta — decompress then decode against baseline
        payload = try_decrypt(payload)
        last_payload = delta_history.get(addr_key)
        if last_payload:
            try:
                xor_diff = zlib.decompress(payload)
            except zlib.error:
                # Fallback: treat as uncompressed XOR diff (backward compat)
                xor_diff = payload
            
            if len(last_payload) == len(xor_diff):
                xor_res = bytearray(len(xor_diff))
                for i in range(len(xor_diff)):
                    xor_res[i] = xor_diff[i] ^ last_payload[i]
                decoded = bytes(xor_res)
                delta_history[addr_key] = decoded
                # Also update incremental history
                fields = xml_to_fields(decoded)
                if fields:
                    incr_history[addr_key] = fields
                print(f"[Sink] Rx DELTA: {len(payload)}B wire -> {len(decoded)}B decoded", flush=True)
            else:
                print(f"[Sink] Rx DELTA FAILED (Len Mismatch: diff={len(xor_diff)} vs ref={len(last_payload)})", flush=True)
                decoded = payload
        else:
            print(f"[Sink] Rx DELTA FAILED (Missing History)", flush=True)
            decoded = payload
    
    elif pkt_type == TYPE_INCREMENTAL:
        # --- True field-level incremental decoding ---
        payload = try_decrypt(payload)
        # Wire format: [num_changed (1B)] [field_id (1B)][val_len (1B)][val (N B)] ...
        FIELD_NAMES = [
            'event_version', 'event_uid', 'event_type',
            'event_time', 'event_start', 'event_stale',
            'point_lat', 'point_lon', 'point_hae', 'point_ce', 'point_le',
            'contact_callsign', 'detail_e2e_ts',
        ]
        last_fields = incr_history.get(addr_key)
        if last_fields and len(payload) >= 1:
            try:
                num_changed = payload[0]
                pos = 1
                updated_fields = dict(last_fields)  # copy
                for _ in range(num_changed):
                    if pos + 2 > len(payload):
                        break
                    field_id = payload[pos]
                    val_len = payload[pos + 1]
                    pos += 2
                    if pos + val_len > len(payload):
                        break
                    if field_id < len(FIELD_NAMES):
                        val_str = payload[pos:pos + val_len].decode('utf-8', errors='replace')
                        updated_fields[FIELD_NAMES[field_id]] = val_str
                    pos += val_len
                incr_history[addr_key] = updated_fields
                decoded = fields_to_xml(updated_fields)
                # Also update delta_history so Delta fallback has current state
                delta_history[addr_key] = decoded
                print(f"[Sink] Rx INCREMENTAL: {len(payload)}B wire -> {len(decoded)}B decoded ({num_changed} fields changed)", flush=True)
            except Exception as e:
                print(f"[Sink] Rx INCREMENTAL FAILED (Parse error: {e})", flush=True)
                decoded = payload
        else:
            print(f"[Sink] Rx INCREMENTAL FAILED (No baseline)", flush=True)
            decoded = payload

    elif pkt_type == TYPE_HC:
        # Header Compression only — payload may be encrypted from H1
        payload = try_decrypt(payload)
        decoded = payload
        print(f"[Sink] Rx HC: {len(payload)}B wire -> {len(decoded)}B reconstructed", flush=True)

    else:
        # Unknown type — might be raw encrypted payload (Baseline mode, no type prefix)
        raw = try_decrypt(data)  # Try decrypting the FULL data blob
        if raw.startswith(b'<?xml'):
            # Decrypted to valid XML — treat as auto-sync
            delta_history[addr_key] = raw
            fields = xml_to_fields(raw)
            if fields:
                incr_history[addr_key] = fields
            print(f"[Sink] Auto-Sync (decrypted): {raw[:20]}... ({len(raw)}B)", flush=True)
            decoded = raw
        elif data.startswith(b'<?xml'):
            # Already plaintext XML (unencrypted Baseline or decompress_agent output)
            delta_history[addr_key] = data
            fields = xml_to_fields(data)
            if fields:
                incr_history[addr_key] = fields
            print(f"[Sink] Auto-Sync from Raw XML: {data[:20]}... ({len(data)}B)", flush=True)
            decoded = data
        else:
            # Unknown type and not XML — treat as raw
            decoded = data
            print(f"Rx Unknown [0x{pkt_type:02x}]: {decoded[:20]}...", flush=True)

    # --- E2E Latency extraction ---
    if e2e_log_fp:
        send_ts = None
        # Prefer trailer (outside encryption envelope, always accurate)
        if e2e_send_ts is not None:
            send_ts = e2e_send_ts
        elif decoded:
            # Fallback: regex from decoded XML (may fail for Delta)
            try:
                decoded_str = decoded.decode('utf-8', errors='replace') if isinstance(decoded, bytes) else str(decoded)
                m = E2E_TS_RE.search(decoded_str)
                if m:
                    send_ts = float(m.group(1))
            except Exception:
                pass
        if send_ts is not None:
            recv_ts = time.time()
            latency_ms = (recv_ts - send_ts) * 1000
            pkt_type_str = ['SYNC', 'DELTA', 'INCREMENTAL', 'HC'][pkt_type] if pkt_type <= 3 else 'UNKNOWN'
            e2e_log_fp.write(f"{recv_ts:.6f},{send_ts:.6f},{latency_ms:.3f},{pkt_type_str}\n")
            e2e_log_fp.flush()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8087, help="Port to listen on")
    parser.add_argument("--e2e_log", type=str, default="", help="Path for e2e latency CSV output")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt payloads with AES-256-GCM")
    parser.add_argument("--psk", type=str, default="efrac.psk", help="Path to pre-shared key file")
    args = parser.parse_args()

    if args.decrypt:
        crypto_key = crypto_utils.load_key(args.psk)
        print(f"[Sink] AES-256-GCM decryption enabled (key from {args.psk})")

    if args.e2e_log:
        e2e_log_fp = open(args.e2e_log, 'w')
        e2e_log_fp.write("recv_time,send_time,latency_ms,pkt_type\n")
        e2e_log_fp.flush()
        print(f"[Sink] E2E latency logging to {args.e2e_log}")
    
    # Run both TCP and UDP listeners
    t_tcp = threading.Thread(target=start_tcp, args=(args.port,))
    t_udp = threading.Thread(target=start_udp, args=(args.port,))
    
    t_tcp.daemon = True
    t_udp.daemon = True
    
    t_tcp.start()
    t_udp.start()
    
    t_tcp.join()
    t_udp.join()
