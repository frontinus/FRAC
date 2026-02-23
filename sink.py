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
import threading
import zlib
import time

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
POINT_RE = re.compile(r'<point\s+([^/]*)/>')
CONTACT_RE = re.compile(r'<contact\s+([^/]*)/>')

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

def process_data(data, addr):
    global delta_history, incr_history
    
    if len(data) < 1:
        return

    pkt_type = data[0]
    payload = data[1:]
    
    addr_key = addr  # (ip, port)
    decoded = b""
    
    print(f"[Sink] OK {time.time():.3f} {len(decoded)}", flush=True)
    if pkt_type == TYPE_SYNC:
        # Full packet — store as baseline for both modes
        delta_history[addr_key] = payload
        fields = xml_to_fields(payload)
        if fields:
            incr_history[addr_key] = fields
        decoded = payload
        print(f"[Sink] Rx SYNC: {decoded[:20]}... ({len(payload)}B)", flush=True)
        
    elif pkt_type == TYPE_DELTA:
        # zlib-compressed XOR delta — decompress then decode against baseline
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
        # JSON field diff — apply to stored baseline fields
        old_fields = incr_history.get(addr_key)
        if old_fields:
            try:
                diff = json.loads(payload.decode('utf-8'))
                # Apply diff to baseline
                old_fields.update(diff)
                incr_history[addr_key] = old_fields
                # Reconstruct full XML
                decoded = fields_to_xml(old_fields)
                # Also update delta history with reconstructed payload
                delta_history[addr_key] = decoded
                print(f"[Sink] Rx INCREMENTAL: {len(diff)} fields changed, {len(payload)}B wire -> {len(decoded)}B reconstructed", flush=True)
            except json.JSONDecodeError as e:
                print(f"[Sink] Rx INCREMENTAL FAILED (JSON parse: {e})", flush=True)
                decoded = payload
        else:
            print(f"[Sink] Rx INCREMENTAL FAILED (No baseline)", flush=True)
            decoded = payload

    elif pkt_type == TYPE_HC:
        # Header Compression only
        decoded = payload
        print(f"[Sink] Rx HC: {len(payload)}B wire -> {len(decoded)}B reconstructed", flush=True)

    else:
        # Unknown type — check if it is raw XML (starts with '<?xml')
        if data.startswith(b'<?xml'):
            # Treat as accidental SYNC — update history
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

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8087, help="Port to listen on")
    args = parser.parse_args()
    
    # Run both TCP and UDP listeners
    t_tcp = threading.Thread(target=start_tcp, args=(args.port,))
    t_udp = threading.Thread(target=start_udp, args=(args.port,))
    
    t_tcp.daemon = True
    t_udp.daemon = True
    
    t_tcp.start()
    t_udp.start()
    
    t_tcp.join()
    t_udp.join()
