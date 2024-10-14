import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

THRESHOLD = 40
EXCLUDED_IPS = {"192.168.1.1"}  # Remplacez par l'IP de votre machine
LOG_FILE = "blocked_ips.log"
print(f"THRESHOLD: {THRESHOLD}")

def log_blocked_ip(ip, packet_rate):
    """Journaliser les IP bloquées dans un fichier."""
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.ctime()}: Blocked IP {ip}, packet rate: {packet_rate}\n")

def packet_callback(packet):
    src_ip = packet[IP].src

    if src_ip in EXCLUDED_IPS:
        return  # Ignore le blocage pour cette IP

    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
                log_blocked_ip(ip, packet_rate)  # Journaliser l'IP bloquée
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    # Vérification des privilèges administratifs (simple)
    if os.name == 'nt':
        try:
            if not os.getuid() == 0:
                print("This script requires administrative privileges.")
                sys.exit(1)
        except AttributeError:
            pass  # Ignorer l'erreur sur Windows

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)