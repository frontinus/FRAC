
import socket
import time
import sys
import argparse
import random
import datetime
import threading
import struct
import os

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
        self.stats = {'sent_packets': 0, 'errors': 0}

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

        print(f"[{self.name_type}] Finished. Stats: {self.stats}")

    def generate_packet(self):
        raise NotImplementedError

    def stop(self):
        self.stop_event.set()

class CoTStream(TrafficStream):
    def __init__(self, target_ip, target_port, duration, rate=1.0):
        super().__init__(target_ip, target_port, duration)
        self.rate = rate
        self.name_type = "CoT"
        self.sock = None
        self.uid = f"uuid-{random.randint(1000,9999)}"
        self.lat = 34.0
        self.lon = -118.0

    def run(self):
        print(f"[{self.name_type}] Connecting TCP to {self.target_ip}:{self.target_port} (DSCP: EF)...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_EF)
            self.sock.connect((self.target_ip, self.target_port))
        except Exception as e:
            print(f"[{self.name_type}] Connection failed: {e}")
            return

        super().run()
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

    def generate_packet(self):
        self.lat += random.uniform(-0.001, 0.001)
        self.lon += random.uniform(-0.001, 0.001)
        
        now = datetime.datetime.utcnow()
        time_str = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        stale_str = (now + datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        xml = f'''<?xml version="1.0" standalone="yes"?>
<event version="2.0" uid="{self.uid}" type="a-f-G-U-C" time="{time_str}" start="{time_str}" stale="{stale_str}">
    <point lat="{self.lat}" lon="{self.lon}" hae="0.0" ce="9999999" le="9999999"/>
    <detail>
        <contact callsign="GroundUnit-{self.uid[-4:]}"/>
    </detail>
</event>'''
        data = xml.encode('utf-8')
        try:
            self.sock.sendall(data)
            self.stats['sent_packets'] += 1
        except Exception as e:
            print(f"[{self.name_type}] Send failed: {e}")
            self.stop()
            
        time.sleep(1.0 / self.rate)
        return True

class VideoStream(TrafficStream):
    def __init__(self, target_ip, target_port, duration, bitrate_mbps=1.0, file_path=None, loop=False):
        super().__init__(target_ip, target_port, duration, loop=loop)
        self.bitrate_mbps = bitrate_mbps
        self.file_path = file_path
        self.name_type = "Video"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, DSCP_AF41)
        
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
        
        self.sock.sendto(packet, (self.target_ip, self.target_port))
        self.stats['sent_packets'] += 1
        
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
    
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print("=== Traffic Generator Console ===")
        print(f"Active Streams: {len(active_threads)}")
        for i, t in enumerate(active_threads):
            status = "Running" if t.is_alive() else "Finished"
            loop_str = " (Loop)" if t.loop else ""
            print(f"  {i+1}. {t.name_type} -> {t.target_ip}:{t.target_port}{loop_str} ({status}) Stats: {t.stats}")
        
        print("\nQueue (Pending):")
        for i, item in enumerate(video_queue):
            print(f"  {i+1}. {item['type']} -> {item['file']} ({item['duration']}s)")

        print("\nOptions:")
        print("1. Add CoT Stream (Immediate)")
        print("2. Add Video Stream (Immediate)")
        print("3. Add Voice Stream (Immediate)")
        print("4. Add XMPP Chat Stream (Immediate)")
        print("5. Add File to Queue")
        print("6. Run Queue Sequence")
        print("7. Stop All & Exit")
        
        choice = input("\nSelect: ")
        
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
            path = get_input_def("File Path", "video.mp4")
            dur = int(get_input_def("Duration (s)", 10))
            ip = get_input_def("Target IP", "127.0.0.1")
            port = int(get_input_def("Port", 5000 if q_type == 'video' else 5060))
            
            video_queue.append({
                'type': q_type, 'file': path, 'duration': dur,
                'ip': ip, 'port': port
            })
            
        elif choice == '6':
            # Run queue
            # For simplicity, launch them sequentially in a separate thread manager
            def run_queue(q_items):
                print("Starting queue playback...")
                for item in q_items:
                    print(f"Playing {item['file']}...")
                    if item['type'] == 'video':
                        t = VideoStream(item['ip'], item['port'], item['duration'], file_path=item['file'])
                    else:
                        t = VoiceStream(item['ip'], item['port'], item['duration'], file_path=item['file'])
                    t.start()
                    t.join() # Wait for it to finish
                print("Queue finished.")
            
            t = threading.Thread(target=run_queue, args=(video_queue,))
            t.daemon = True
            t.start()
            video_queue = [] # Clear queue? or keep? Let's clear.
            
        elif choice == '7':
            print("Stopping all threads...")
            for t in active_threads:
                t.stop()
            # Wait a bit
            sys.exit(0)
            
        # Clean up finished threads
        active_threads = [t for t in active_threads if t.is_alive()]
        if len(active_threads) > 0:
             time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nForce Close")
