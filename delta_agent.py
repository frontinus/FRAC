#!/usr/bin/env python3
"""
Delta/Incremental Encoding Agent
Receives redirected packets from eBPF TC hook on veth-delta.
Applies encoding based on the operating state signaled via TOS byte:
  TOS 0x50 -> DELTA (XOR byte-level diff)
  TOS 0x64 -> INCREMENTAL (field-level XML diff as JSON)
Forwards encoded packets to H2 via standard IP routing.
"""
import socket
import struct
import threading
import json
import re
import time
from scapy.all import sniff, IP, TCP, UDP, send, sendp, Ether, Raw

# Configuration
INTERFACE = "veth-delta"
TARGET_IP = "10.0.2.1"

# Wire format type bytes
TYPE_SYNC = 0x00
TYPE_DELTA = 0x01
TYPE_INCREMENTAL = 0x02

# TOS values mapped from eBPF operating state
TOS_DELTA = 0x50
TOS_INCREMENTAL = 0x64

# State: {flow_tuple: last_payload (bytes)}
delta_history = {}
# State: {flow_tuple: last_xml_fields (dict)}
incr_history = {}
history_lock = threading.Lock()

# XML field extraction regex (matches key="value" pairs and self-closing element attributes)
ATTR_RE = re.compile(r'(\w+)="([^"]*)"')
# Extract <point> attributes
POINT_RE = re.compile(r'<point\s+([^/]*)/>')
# Extract <event> attributes
EVENT_RE = re.compile(r'<event\s+([^>]*)>')
# Extract <contact> callsign
CONTACT_RE = re.compile(r'<contact\s+([^/]*)/>')

print(f"[DeltaAgent] Listening on {INTERFACE}...")
print(f"[DeltaAgent] Modes: DELTA (TOS=0x50, XOR), INCREMENTAL (TOS=0x64, JSON diff)")

def xml_to_fields(payload_bytes):
    """Parse CoT XML into a flat dict of field values."""
    try:
        xml_str = payload_bytes.decode('utf-8', errors='replace')
    except:
        return None
    
    fields = {}
    
    # Extract <event> attributes
    m = EVENT_RE.search(xml_str)
    if m:
        for key, val in ATTR_RE.findall(m.group(1)):
            fields[f"event.{key}"] = val
    
    # Extract <point> attributes  
    m = POINT_RE.search(xml_str)
    if m:
        for key, val in ATTR_RE.findall(m.group(1)):
            fields[f"point.{key}"] = val
    
    # Extract <contact> attributes
    m = CONTACT_RE.search(xml_str)
    if m:
        for key, val in ATTR_RE.findall(m.group(1)):
            fields[f"contact.{key}"] = val
    
    return fields if fields else None

def fields_to_diff(old_fields, new_fields):
    """Compute changed fields between old and new."""
    diff = {}
    for k, v in new_fields.items():
        if k not in old_fields or old_fields[k] != v:
            diff[k] = v
    return diff

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    
    # Only care about traffic destined for H2
    if ip.dst != TARGET_IP:
        return

    # Determine encoding mode from TOS byte
    tos = ip.tos
    
    proto = None
    payload = b""
    src_port = 0
    dst_port = 0
    
    if pkt.haslayer(TCP):
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        payload = bytes(pkt[TCP].payload)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        payload = bytes(pkt[UDP].payload)
    
    if not payload:
        return

    flow_key = (ip.src, src_port, ip.dst, dst_port, proto)
    
    header = bytes([TYPE_SYNC])
    new_payload = payload
    
    with history_lock:
        if tos == TOS_INCREMENTAL:
            # === INCREMENTAL ENCODING (Field-Level XML Diff) ===
            new_fields = xml_to_fields(payload)
            
            if new_fields is None:
                # Can't parse XML — fall back to full sync
                new_payload = payload
                header = bytes([TYPE_SYNC])
                print(f"[Sync] XML parse failed -> sending Full")
            else:
                old_fields = incr_history.get(flow_key)
                
                if old_fields:
                    diff = fields_to_diff(old_fields, new_fields)
                    if diff:
                        diff_json = json.dumps(diff, separators=(',', ':')).encode('utf-8')
                        new_payload = diff_json
                        header = bytes([TYPE_INCREMENTAL])
                        print(f"[Incr] {len(payload)}B -> {len(diff_json)}B ({len(diff)} fields changed, {100 - len(diff_json)*100//len(payload)}% saved)")
                    else:
                        # No changes — send minimal empty diff
                        new_payload = b'{}'
                        header = bytes([TYPE_INCREMENTAL])
                        print(f"[Incr] No changes -> 2B")
                else:
                    # First packet for this flow — send full sync
                    new_payload = payload
                    header = bytes([TYPE_SYNC])
                    print(f"[Sync] New Flow -> sending Full ({len(payload)}B)")
                
                # Always update incremental history
                incr_history[flow_key] = new_fields
                # Also update delta history for potential mode switches
                delta_history[flow_key] = payload
        
        else:
            # === DELTA ENCODING (XOR Byte-Level Diff) ===
            last_payload = delta_history.get(flow_key)
            
            if last_payload:
                if len(payload) == len(last_payload):
                    xor_res = bytearray(len(payload))
                    for i in range(len(payload)):
                        xor_res[i] = payload[i] ^ last_payload[i]
                    new_payload = bytes(xor_res)
                    header = bytes([TYPE_DELTA])
                    # Count non-zero bytes as a compression metric
                    nonzero = sum(1 for b in xor_res if b != 0)
                    print(f"[Delta] {len(payload)}B -> XOR diff ({nonzero}/{len(payload)} bytes changed)")
                else:
                    new_payload = payload
                    header = bytes([TYPE_SYNC])
                    print(f"[Sync] Length mismatch ({len(payload)} vs {len(last_payload)}) -> Full")
            else:
                new_payload = payload
                header = bytes([TYPE_SYNC])
                print(f"[Sync] New Flow -> sending Full ({len(payload)}B)")
            
            # Update delta history
            delta_history[flow_key] = payload
            # Also parse and store for potential mode switches
            new_fields = xml_to_fields(payload)
            if new_fields:
                incr_history[flow_key] = new_fields
    
    # Construct new packet
    final_payload = header + new_payload
    
    new_pkt = IP(src=ip.src, dst=ip.dst, tos=tos)
    
    # Use UDP to avoid eBPF redirect loop (TC only redirects target ports)
    new_pkt /= UDP(sport=src_port, dport=dst_port)
    new_pkt = new_pkt / final_payload
    
    # Recalculate checksums
    del new_pkt[IP].len
    del new_pkt[IP].chksum
    del new_pkt[UDP].len
    del new_pkt[UDP].chksum
        
    send(new_pkt, verbose=False)

sniff(iface=INTERFACE, prn=process_packet, store=False)
