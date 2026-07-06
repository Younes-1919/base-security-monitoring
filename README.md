# Security Monitor Tool

A Python-based security monitor that detects brute-force attacks by analyzing system logs and automatically blocks malicious IPs using `iptables`.

## Features
- **Brute-Force Detection:** Monitors logs for multiple failed login attempts.
- **Auto-Blocking:** Automatically adds malicious IPs to `iptables` drop rules.
- **Temporary Ban:** Automatically unblocks IPs after a predefined duration.
- **Real-time Notifications:** Sends desktop alerts using `notify-send`.

## Installation & Usage

1. **Clone the repository:**
   bash
   git clone https://github.com/YOUR_USERNAME/security-monitor.git
   cd security-monitor
   
2 Run the script:Since the script interacts with iptables and system logs, it must be run with sudo:

   sudo python3 monitor.py
   
Autostart on Boot (Systemd)

To ensure the security monitor runs automatically every time the system starts, follow these steps:

   1. Create a new service file: 
   sudo nano /etc/systemd/system/security-monitor.service
   	

   2.Paste the following configuration into the editor:(Note: Replace YOUR_USERNAME and /path/to/your/folder with your actual user and project path)

   [Unit]
   Description=Security Monitor Service
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/home/YOUR_USERNAME/security-monitor
   ExecStart=/usr/bin/python3 /home/YOUR_USERNAME/security-monitor/monitor.py
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   
   3.Enable and start the service:

   sudo systemctl daemon-reload
   sudo systemctl enable security-monitor.service
   sudo systemctl start security-monitor.service
   
   4.Verify the status:
   sudo systemctl status security-monitor.service
   
	


 	License

This project is open-source.
