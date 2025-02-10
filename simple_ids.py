import os
import time
from scapy.all import *

# Define the network namespace
NAMESPACE = "ns1"
INTERFACE = "veth1"  # Adjust based on your namespace setup

# Threshold for SYN flood detection
SYN_THRESHOLD = 10
syn_counter = {}

def detect_intrusion(packet):
    """Detects basic network threats inside the namespace."""
    global syn_counter

    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags

        # Detect SYN flood (too many SYN packets from the same IP)
        if flags == "S":
            if src_ip not in syn_counter:
                syn_counter[src_ip] = 1
            else:
                syn_counter[src_ip] += 1

            if syn_counter[src_ip] > SYN_THRESHOLD:
                print(f"[ALERT] Possible SYN flood detected from {src_ip} to {dst_ip}")

# Function to sniff packets inside the namespace
def start_sniffing():
    """Starts sniffing traffic inside the namespace."""
    print(f"[*] Monitoring network traffic on {INTERFACE} inside namespace {NAMESPACE}...")
    sniff(iface=INTERFACE, prn=detect_intrusion, store=False)

if __name__ == "__main__":
    # Check if running inside the namespace
    current_ns = os.popen("ip netns identify").read().strip()
    if current_ns != NAMESPACE:
        print(f"[*] Please run this script inside the '{NAMESPACE}' network namespace.")
    else:
        start_sniffing()
