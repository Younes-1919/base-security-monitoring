import subprocess
import time
import sys
import re
import os
from datetime import datetime

LOG_FILE = "security_audit.log"
THRESHOLD = 5 
TIME_WINDOW = 20 
COOLDOWN_PERIOD = 2 
BLOCK_DURATION = 120  

class SecurityMonitor:
    def __init__(self):
        self.failure_timestamps = []
        self.last_processed_line = ""
        self.last_event_time = 0
        self.blocked_ips = {}
        self.dbus_address = os.environ.get('DBUS_SESSION_BUS_ADDRESS', '')

    def send_notification(self, message, critical=False):
        urgency = "critical" if critical else "normal"
        if self.dbus_address:
            cmd = f"sudo -u kali DBUS_SESSION_BUS_ADDRESS={self.dbus_address} notify-send -u {urgency} 'Security Alert' '{message}'"
        else:
            cmd = f"sudo -u kali notify-send -u {urgency} 'Security Alert' '{message}'"
        subprocess.run(cmd, shell=True)

    def log_to_file(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
            f.flush()

    def block_ip(self, ip):
        print(f"[!!!] BLOCKING IP: {ip}")
        subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True)
        self.blocked_ips[ip] = time.time() + BLOCK_DURATION
        self.send_notification(f"IP {ip} BLOCKED!", critical=True)

    def unblock_expired_ips(self):
        now = time.time()
        to_unblock = [ip for ip, expiry in self.blocked_ips.items() if now >= expiry]
        for ip in to_unblock:
            print(f"[*] Unblocking IP: {ip}")
            subprocess.run(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True)
            del self.blocked_ips[ip]

    def extract_ip(self, text):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None

    def check_brute_force(self):
        now = time.time()
        self.failure_timestamps = [t for t in self.failure_timestamps if now - t < TIME_WINDOW]
        return len(self.failure_timestamps) >= THRESHOLD

    def run(self):
        print(f"[*] Monitor Started. Policy: {THRESHOLD} failures / {TIME_WINDOW}s")
        
        cmd = "sudo journalctl -f | grep --line-buffered -i 'fail'"
        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        try:
            while True:
                self.unblock_expired_ips()
                
                line = process.stdout.readline()
                if not line:
                    break
                
                clean_line = line.strip()
                now = time.time()

                if not clean_line or clean_line == self.last_processed_line:
                    continue
                
                if any(x in clean_line.lower() for x in ["password", "authentication failure"]):
                    if now - self.last_event_time < COOLDOWN_PERIOD:
                        continue

                    self.last_processed_line = clean_line
                    self.last_event_time = now
                    self.failure_timestamps.append(now)
                    self.failure_timestamps = [t for t in self.failure_timestamps if now - t < TIME_WINDOW]
                    
                    self.log_to_file(clean_line)
                    attacker_ip = self.extract_ip(clean_line)

                    if self.check_brute_force():
                        print(f"\n[!!!] ATTACK DETECTED")
                        if attacker_ip:
                            self.block_ip(attacker_ip)
                        self.failure_timestamps = [] 
                        self.send_notification("BRUTE FORCE ATTACK DETECTED!", critical=True)
                    else:
                        print(f"[!] Failed attempt ({len(self.failure_timestamps)}/{THRESHOLD})")
                        if len(self.failure_timestamps) == 1:
                             self.send_notification("Failed login attempt detected.")

        except KeyboardInterrupt:
            process.terminate()
            print("\n[!] Stopped.")

if __name__ == "__main__":
    monitor = SecurityMonitor()
    monitor.run()
