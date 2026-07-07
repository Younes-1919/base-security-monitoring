import platform
import socket
import os

def get_system_info():
    try:
        return {
            "OS": platform.system(),
            "Release": platform.release(),
            "Version": platform.version(),
            "Architecture": platform.machine()
        }
    except Exception as e:
        return {"Error": f"Could not retrieve OS info: {e}"}

def get_network_info():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return {"Hostname": hostname, "IP": ip_address}
    except Exception as e:
        return {"Error": f"Could not retrieve network info: {e}"}

def main():
    print("--- System Security Monitoring ---")
    print(f"[+] System Info: {get_system_info()}")
    print(f"[+] Network Info: {get_network_info()}")
    print("----------------------------------")

if __name__ == "__main__":
    main()
