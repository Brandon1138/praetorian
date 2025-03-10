# modules/os_fingerprinting.py
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
from config import CONFIG
from modules.logging_module import log_event

# Load configuration values for OS fingerprinting
KNOWN_TTL_VALUES = set(CONFIG["os_fingerprinting"]["known_ttl_values"])
KNOWN_TCP_WINDOW_SIZES = set(CONFIG["os_fingerprinting"]["known_tcp_window_sizes"])

def os_fingerprint_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet[TCP]
        ip = packet[IP]

        # Analyze SYN packets to detect unusual TTL or TCP window sizes
        if tcp.flags & 0x02:  # SYN flag is set
            if ip.ttl not in KNOWN_TTL_VALUES:
                log_event("warning", f"Suspicious TTL from {ip.src}: {ip.ttl} (expected: {KNOWN_TTL_VALUES})")
            if tcp.window not in KNOWN_TCP_WINDOW_SIZES:
                log_event("warning", f"Suspicious TCP window from {ip.src}: {tcp.window} (expected: {KNOWN_TCP_WINDOW_SIZES})")

        # Detect uncommon flag combinations indicative of fingerprinting probes
        if tcp.flags == 0:  # NULL scan
            log_event("warning", f"NULL TCP flags from {ip.src} may indicate fingerprinting.")
        elif tcp.flags == 0x01:  # FIN-only scan
            log_event("warning", f"FIN TCP flags from {ip.src} may indicate fingerprinting.")

def start_os_fingerprinting(interface=None):
    print("Starting OS fingerprinting detection...")
    sniff(filter="tcp", prn=os_fingerprint_callback, iface=interface, store=False)

if __name__ == "__main__":
    start_os_fingerprinting()
