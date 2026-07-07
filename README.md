# Brute Force Detection Monitor

A Python-based security tool that monitors system authentication logs in real-time to detect brute-force attack patterns.

## 🛡️ Features
- **Real-time Monitoring:** Uses `journalctl` to capture authentication failures.- **Brute-Force Detection:** Identifies multiple failed login attempts within a specific time window.
- **Instant Alerts:** Triggers desktop notifications using `notify-send`.
- **Security Logging:** Maintains a detailed audit log of all failed attempts.

## 🚀 Installation

1. **Clone the repository:**
bash
   git clone https://github.com/Younes-1919/base-security-monitoring.git
   cd base-securitymonitoring
   
   2. Prerequisites:
        Linux OS (Required for journalctl and notify-send).
        Python 3.x.
        sudo privileges (to read system logs).

🛠️ Usage

Run the monitor with sudo privileges to allow access to system logs:

sudo python3 monitor.py

 Security & Privacy Note

    This tool monitors authentication logs. Ensure you have explicit permission t run this on the target system.
    Sensitive log data is stored locally in security_audit.log (Ensure this file is ignored by git).

📄 License

MIT License
