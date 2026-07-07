import subprocess
import time
import sys
from datetime import datetime

LOG_FILE = "security_audit.log"
THRESHOLD = 5 
TIME_WINDOW = 10 

class SecurityMonitor:
    def __init__(self):
        self.failure_timestamps = []
        self.last_processed_line = ""

    def send_notification(self, message, critical=False):
        urgency = "critical" if critical else "normal"
        cmd = f"notify-send -u {urgency} 'Security Alert' '{message}'"
        subprocess.run(cmd, shell=True)

    def log_to_file(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
            f.flush()

    def check_brute_force(self):
        now = time.time()
        self.failure_timestamps = [t for t in self.failure_timestamps if now - t < TIME_WINDOW]
        return len(self.failure_timestamps) >= THRESHOLD

    def run(self):
        print(f"[*] Security Monitor Started. Logging to {LOG_FILE}")
        print(f"[*] Policy: {THRESHOLD} failures in {TIME_WINDOW}s triggers alert.")
        
        cmd = "sudo journalctl -f | grep --line-buffered -i 'fail'"
        process = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1
        )

        try:
            for line in process.stdout:
                clean_line = line.strip()
                
                if not clean_line or clean_line == self.last_processed_line:
                    continue
                
                self.last_processed_line = clean_line
                
                if "password" in clean_line.lower() or "authentication failure" in clean_line.lower():
                    now = time.time()
                    self.failure_timestamps.append(now)
                    
                    self.log_to_file(clean_line)
                    
                    if self.check_brute_force():
                        msg = "!!! BRUTE FORCE ATTACK DETECTED !!!"
                        print(f"\n[!!!] {msg}")
                        self.send_notification(msg, critical=True)
                        self.failure_timestamps = [] 
                    else:
                        print(f"[!] Failed login attempt detected. ({len(self.failure_timestamps)}/{THRESHOLD})")
                        sys.stdout.flush() 
                        if len(self.failure_timestamps) == 1:
                             self.send_notification("Failed login attempt detected.")

        except KeyboardInterrupt:
            process.terminate()
            print("\n[!] Monitor stopped.")
            sys.stdout.flush()

if __name__ == "__main__":
    monitor = SecurityMonitor()
    monitor.run()
