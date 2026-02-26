
import socket
import time
import sys
import argparse
import random
import datetime
import threading
import struct
import os
import crypto_utils

# DSCP Values
DSCP_EF = 46 << 2   # Expedited Forwarding (High Priority - CoT/Voice)
DSCP_AF41 = 34 << 2 # Assured Forwarding (Video)
DSCP_CS0 = 0        # Best Effort (XMPP/Chat)

# ==========================================
# Traffic Stream Classes
# ==========================================

class TrafficStream(threading.Thread):
    def __init__(self, target_ip, target_port, duration, loop=False):
        super().__init__()
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.loop = loop
        self.stop_event = threading.Event()
        self.daemon = True
        self.name_type = "Generic"
        self.stats = {'sent_packets': 0, 'errors': 0, 'bytes_sent': 0}

    def run(self):
        print(f"[{self.name_type}] Starting stream to {self.target_ip}:{self.target_port}...")
        start_time = time.time()
        
        while not self.stop_event.is_set():
            if not self.loop and self.duration > 0 and (time.time() - start_time > self.duration):
                break
                
            try:
                if not self.generate_packet():
                    # generate_packet returns False if EOF and no loop
                    break
            except Exception as e:
                self.stats['errors'] += 1
                # print(f"[{self.name_type}] Error: {e}")
                time.sleep(1) # Prevent tight error loop

        duration_actual = time.time() - start_time
        if duration_actual > 0:
            mbps = (self.stats['bytes_sent'] * 8) / (duration_actual * 1000000)
        else:
            mbps = 0.0
            
        print(f"[{self.name_type}] Finished. Stats: {self.stats}")
        print(f"[{self.name_type}] Throughput: {mbps:.2f} Mbps")

    def generate_packet(self):
        raise NotImplementedError

    def stop(self):
        self.stop_event.set()

class CoTStream(TrafficStream):
    def __init__(self, target_ip, target_port, duration, rate=1.0, encrypt=False, dscp=DSCP_EF, udp=False, payload_size=0, ramp_to=0, e2e_timestamp=False):
        super().__init__(target_ip, target_port, duration)
        self.rate = rate
        self.ramp_to = ramp_to  # If > 0, linearly ramp from rate to ramp_to
        self.packet_size = 512 # Standard CoT is smallish
        self.payload_size_target = payload_size
        self.name_type = "CoT"
        self.encrypt = encrypt
        self.udp = udp
        self.e2e_timestamp = e2e_timestamp
        self._start_time = None
        self.uid = f"uuid-{random.randint(1000,9999)}"
        self.lat = 34.0
        self.lon = -118.0
        self._crypto_key = None
        if encrypt:
            try:
                self._crypto_key = crypto_utils.load_key("efrac.psk")
                print(f"[CoT] AES-256-GCM encryption enabled (key derived from efrac.psk)")
            except Exception as e:
                print(f"[CoT] WARNING: Could not load encryption key: {e}")
                print(f"[CoT] Encryption disabled.")
        
        # Setup Socket
        if self.udp:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, dscp) # Set DSCP
        
        if not self.udp:
            try:
                self.sock.connect((self.target_ip, self.target_port))
            except Exception as e:
                print(f"[{self.name_type}] Connection failed: {e}")
                self.stop()
                return

        # Pre-generate XML payload
        self.pregenerated_data = self._create_packet_data()
        
    def run(self):
        print(f"[{self.name_type}] Starting stream to {self.target_ip}:{self.target_port} (DSCP: EF)...")
        
        super().run()
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def _create_packet_data(self):
        now = datetime.datetime.utcnow()
        time_str = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        stale_str = (now + datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        xml = f'''<?xml version="1.0" standalone="yes"?>
<event version="2.0" uid="{self.uid}" type="a-f-G-U-C" time="{time_str}" start="{time_str}" stale="{stale_str}">
    <point lat="{self.lat}" lon="{self.lon}" hae="0.0" ce="9999999" le="9999999"/>
    <detail{f' e2e_ts="{time.time():.6f}"' if self.e2e_timestamp else ""}>
        <contact callsign="GroundUnit-{self.uid[-4:]}"/>
    </detail>
</event>'''
        event_data = xml.encode('utf-8')
        
        # Padding Logic
        if self.payload_size_target > 0:
            current_len = len(event_data)
            if current_len < self.payload_size_target:
                padding_len = self.payload_size_target - current_len
                # Add padding as XML comment or trailing bytes
                # Trailing bytes is safer/easier for simple sizing
                event_data += b' ' * padding_len
        
        if self._crypto_key is not None:
            event_data = crypto_utils.encrypt(self._crypto_key, event_data)
        
        # When e2e_timestamp is set, append an 8-byte trailer (network-order double)
        # outside the encryption envelope so it survives compression losslessly.
        if self.e2e_timestamp:
            event_data += struct.pack('!d', time.time())

        # Batching Optimization: Controlled via batch_size (set to 1 for experiment consistency)
        self.batch_size = 1
        return event_data * self.batch_size
        
    def _current_rate(self):
        """Return the current pps rate, ramping linearly if ramp_to is set."""
        if self.ramp_to <= 0 or self.duration <= 0:
            return self.rate
        if self._start_time is None:
            self._start_time = time.time()
        elapsed = time.time() - self._start_time
        progress = min(elapsed / self.duration, 1.0)
        return self.rate + (self.ramp_to - self.rate) * progress

    def generate_packet(self):
        try:
            data = self._create_packet_data()
            if self.udp:
                self.sock.sendto(data, (self.target_ip, self.target_port))
            else:
                self.sock.sendall(data)
            self.stats['sent_packets'] += self.batch_size
            self.stats['bytes_sent'] += len(data)

        except Exception as e:
            print(f"[{self.name_type}] Send failed: {e}")
            self.stop()

        current_rate = self._current_rate()
        if current_rate < 50000:
            time.sleep(1.0 / current_rate)
        return True

class VideoStream(TrafficStream):
    def __init__(self, target_ip, target_port, duration, bitrate_mbps=1.0, file_path=None, loop=False):
        super().__init__(target_ip, target_port, duration, loop=loop)
        self.bitrate_mbps = bitrate_mbps
        self.file_path = file_path
        self.name_type = "Video"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_AF41)
        self.sock.bind(('0.0.0.0', 5555)) # Fixed Source Port for simplified compression context
        
        self.packet_size = 1400
        packets_per_sec = (self.bitrate_mbps * 1000 * 1000) / (self.packet_size * 8)
        self.interval = 1.0 / packets_per_sec
        self.file_handle = None
        
        if self.file_path and os.path.exists(self.file_path):
            try:
                self.file_handle = open(self.file_path, 'rb')
            except Exception as e:
                print(f"[{self.name_type}] Failed to open file: {e}")

    def generate_packet(self):
        start_gen = time.time()
        
        data = None
        if self.file_handle:
            data = self.file_handle.read(self.packet_size)
            if not data: # EOF
                if self.loop:
                    self.file_handle.seek(0)
                    data = self.file_handle.read(self.packet_size)
                else:
                    return False # Stop stream
        
        if not data:
            data = b'V' * self.packet_size

        self.sock.sendto(data, (self.target_ip, self.target_port))
        self.stats['sent_packets'] += 1
        self.stats['bytes_sent'] += len(data)
        
        elapsed = time.time() - start_gen
        sleep_time = self.interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)
        return True

class VoiceStream(TrafficStream):
    def __init__(self, target_ip, target_port, duration, file_path=None, loop=False):
        super().__init__(target_ip, target_port, duration, loop=loop)
        self.file_path = file_path
        self.name_type = "Voice"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_EF)
        
        self.payload_size = 160
        self.interval = 0.020 
        self.seq_num = 0
        self.timestamp = 0
        self.ssrc = random.randint(0, 0xFFFFFFFF)
        self.file_handle = None
        
        if self.file_path and os.path.exists(self.file_path):
            try:
                self.file_handle = open(self.file_path, 'rb')
            except Exception as e:
                print(f"[{self.name_type}] Failed to open file: {e}")

    def generate_packet(self):
        start_gen = time.time()
        
        header = struct.pack('!BBHII', 0x80, 0x00, self.seq_num, self.timestamp, self.ssrc)
        
        payload = None
        if self.file_handle:
            payload = self.file_handle.read(self.payload_size)
            if not payload: # EOF
                if self.loop:
                    self.file_handle.seek(0)
                    payload = self.file_handle.read(self.payload_size)
                else:
                    return False
        
        if not payload:
            payload = b'\x55' * self.payload_size 

        # Pad payload if short read
        if len(payload) < self.payload_size:
            payload += b'\x00' * (self.payload_size - len(payload))

        packet = header + payload
        
        try:
            self.sock.sendto(packet, (self.target_ip, self.target_port))
            self.stats['sent_packets'] += 1
            self.stats['bytes_sent'] += len(packet)
            if self.stats['sent_packets'] % 100 == 0:
                print(f"[DEBUG] VoiceStream: Sent {self.stats['sent_packets']} packets to {self.target_ip}:{self.target_port}")
        except Exception as e:
            self.stats['errors'] += 1
            print(f"[ERROR] VoiceStream: Send failed: {e}")
            
        self.seq_num = (self.seq_num + 1) & 0xFFFF
        self.timestamp = (self.timestamp + 160) & 0xFFFFFFFF
        
        elapsed = time.time() - start_gen
        sleep_time = self.interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)
        return True

class XMPPStream(TrafficStream):
    def __init__(self, target_ip, target_port, duration, rate=0.5):
        super().__init__(target_ip, target_port, duration)
        self.rate = rate 
        self.name_type = "XMPP"
        self.sock = None
        self.user_jid = f"user{random.randint(100,999)}@chat.mil"

    def run(self):
        print(f"[{self.name_type}] Connecting TCP to {self.target_ip}:{self.target_port} (DSCP: CS0)...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_CS0)
            self.sock.connect((self.target_ip, self.target_port))
            self.sock.sendall(f"<stream:stream to='chat.mil' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>".encode())
        except Exception as e:
            print(f"[{self.name_type}] Connection failed: {e}")
            return

        super().run()
        
        if self.sock:
             try:
                 self.sock.sendall(b"</stream:stream>")
                 self.sock.close()
             except:
                 pass

    def generate_packet(self):
        msg_body = f"Test message {self.stats['sent_packets']} from {self.user_jid}"
        xml = f"""<message from='{self.user_jid}' to='hq@chat.mil' type='chat'>
  <body>{msg_body}</body>
</message>"""
        
        try:
            self.sock.sendall(xml.encode('utf-8'))
            self.stats['sent_packets'] += 1
            self.stats['bytes_sent'] += len(xml.encode('utf-8'))
        except Exception as e:
            print(f"[{self.name_type}] Send failed: {e}")
            self.stop()
            
        time.sleep(1.0 / self.rate)
        return True

# ==========================================
# Main Interface
# ==========================================

def get_input_def(prompt, default):
    val = input(f"{prompt} [{default}]: ")
    return val if val else default

def main_menu():
    active_threads = []
    video_queue = [] # List of config dicts
    queue_state = {'status': 'Idle', 'current_idx': -1, 'running': False}
    
    # Thread to handle queue execution
    def run_queue_thread(q_items, active_threads_ref, state_ref):
        state_ref['running'] = True
        state_ref['status'] = 'Running'
        
        for i, item in enumerate(q_items):
            state_ref['current_idx'] = i
            # state_ref['status'] = f"Playing {os.path.basename(item['file'])}"
            
            if item['type'] == 'video':
                t = VideoStream(item['ip'], item['port'], item['duration'], file_path=item['file'])
            else:
                t = VoiceStream(item['ip'], item['port'], item['duration'], file_path=item['file'])
            
            # Add to active threads so it shows up in the main list
            active_threads_ref.append(t)
            t.start()
            t.join() # Wait for this item to finish before starting next
            
            # Thread is dead now, main loop will clean it up from active_threads
            
        state_ref['running'] = False
        state_ref['status'] = 'Finished'
        state_ref['current_idx'] = -1

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print("=== Traffic Generator Console ===")
        print(f"Active Streams: {len(active_threads)}")
        for i, t in enumerate(active_threads):
            status = "Running" if t.is_alive() else "Finished"
            loop_str = " (Loop)" if t.loop else ""
            print(f"  {i+1}. {t.name_type} -> {t.target_ip}:{t.target_port}{loop_str} ({status}) Stats: {t.stats}")
        
        print(f"\nQueue (Status: {queue_state['status']}):")
        for i, item in enumerate(video_queue):
            marker = " "
            if queue_state['running'] and i == queue_state['current_idx']:
                marker = ">"
            elif queue_state['running'] and i < queue_state['current_idx']:
                marker = "x"
            print(f" {marker} {i+1}. {item['type']} -> {item['file']} ({item['duration']}s)")

        print("\nOptions:")
        print("1. Add CoT Stream (Immediate)")
        print("2. Add Video Stream (Immediate)")
        print("3. Add Voice Stream (Immediate)")
        print("4. Add XMPP Chat Stream (Immediate)")
        print("5. Add File to Queue")
        print("6. Run Queue Sequence")
        print("7. Clear Queue")
        print("8. Stop All & Exit")
        
        print("\n(Press Enter to refresh view)")
        choice = input("Select: ")
        
        # Clean up finished threads strictly before processing new actions to keep list clean
        active_threads = [t for t in active_threads if t.is_alive()]

        if choice == '1':
            ip = get_input_def("Target IP", "127.0.0.1")
            port = int(get_input_def("Port", 8087))
            dur = int(get_input_def("Duration (s)", 30))
            t = CoTStream(ip, port, dur)
            t.start()
            active_threads.append(t)
            
        elif choice == '2':
            ip = get_input_def("Target IP", "127.0.0.1")
            port = int(get_input_def("Port", 5000))
            path = get_input_def("File Path (empty for dummy)", "")
            dur = int(get_input_def("Duration (s)", 30))
            loop = get_input_def("Loop? (y/n)", "n").lower() == 'y'
            t = VideoStream(ip, port, dur, file_path=path, loop=loop)
            t.start()
            active_threads.append(t)
            
        elif choice == '3':
            ip = get_input_def("Target IP", "127.0.0.1")
            port = int(get_input_def("Port", 5060))
            path = get_input_def("File Path (empty for dummy)", "")
            dur = int(get_input_def("Duration (s)", 30))
            loop = get_input_def("Loop? (y/n)", "n").lower() == 'y'
            t = VoiceStream(ip, port, dur, file_path=path, loop=loop)
            t.start()
            active_threads.append(t)

        elif choice == '4':
            ip = get_input_def("Target IP", "127.0.0.1")
            port = int(get_input_def("Port", 5222))
            dur = int(get_input_def("Duration (s)", 30))
            t = XMPPStream(ip, port, dur)
            t.start()
            active_threads.append(t)
            
        elif choice == '5':
            # Add to queue
            q_type = get_input_def("Type (video/voice)", "video")
            default_file = "isr_video.mp4" if q_type == 'video' else "voice.wav"
            path = get_input_def("File Path", default_file)
            dur = int(get_input_def("Duration (s)", 10))
            ip = get_input_def("Target IP", "127.0.0.1")
            port = int(get_input_def("Port", 5000 if q_type == 'video' else 5060))
            
            video_queue.append({
                'type': q_type, 'file': path, 'duration': dur,
                'ip': ip, 'port': port
            })
            
        elif choice == '6':
            if queue_state['running']:
                print("Queue is already running!")
                time.sleep(1)
            elif not video_queue:
                print("Queue is empty!")
                time.sleep(1)
            else:
                t = threading.Thread(target=run_queue_thread, args=(video_queue, active_threads, queue_state))
                t.daemon = True
                t.start()
                
        elif choice == '7':
            if queue_state['running']:
                print("Cannot clear queue while running.")
                time.sleep(1)
            else:
                video_queue = []
                print("Queue cleared.")
                time.sleep(1)
            
        elif choice == '8':
            print("Stopping all threads...")
            for t in active_threads:
                t.stop()
            # Wait a bit
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_ip", nargs="?", help="Target IP address")
    parser.add_argument("--mode", choices=["cot", "video", "voice", "xmpp", "mixed"], help="Traffic mode")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("--rate", type=float, default=1.0, help="Starting packets per second for CoT")
    parser.add_argument("--ramp_to", type=float, default=0, help="Ramp rate linearly to this pps over duration (0=constant)")
    parser.add_argument("--dscp", type=lambda x: int(x,0), default=DSCP_EF, help="DSCP Value (can use hex 0x50)")
    parser.add_argument("--port", type=int, default=8087, help="Target Port (default 8087)")
    
    parser.add_argument("--udp", action="store_true", help="Use UDP for CoT")
    parser.add_argument("--payload_size", type=int, default=0, help="Target payload size (padding)")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt payload with AES-256-GCM (requires efrac.psk)")
    parser.add_argument("--e2e_timestamp", action="store_true", help="Embed send timestamp for e2e latency")
    
    args = parser.parse_args()

    if args.encrypt:
        print("AES-256-GCM Encryption Enabled (HKDF key from efrac.psk)")
        pass

    try:
        if args.target_ip and args.mode:
            # CLI Mode
            threads = []
            if args.mode == "cot" or args.mode == "mixed":
                # CoT Stream
                cot = CoTStream(args.target_ip, args.port, args.duration, rate=args.rate, encrypt=args.encrypt, dscp=args.dscp, udp=args.udp, payload_size=args.payload_size, ramp_to=args.ramp_to, e2e_timestamp=args.e2e_timestamp)
                threads.append(cot)
                if args.mode == "mixed":
                    threads.append(VideoStream(args.target_ip, 5000, args.duration))
            elif args.mode == "video":
                t = VideoStream(args.target_ip, args.port if args.port != 8087 else 5000, args.duration, bitrate_mbps=args.rate)
                threads.append(t)
            elif args.mode == "voice":
                t = VoiceStream(args.target_ip, 5060, args.duration)
                threads.append(t)
            elif args.mode == "mixed":
                threads.append(CoTStream(args.target_ip, 8087, args.duration))
                threads.append(VideoStream(args.target_ip, 5000, args.duration))
                
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        else:
            # Interactive Mode
            main_menu()
    except KeyboardInterrupt:
        print("\nForce Close")
