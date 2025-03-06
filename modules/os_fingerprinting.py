from scapy.all import sniff
from scapy.layers.inet import TCP, IP

# Typical initial values are heuristic. Adjust for your network.
KNOWN_TTL_VALUES = {64, 128, 255}
KNOWN_TCP_WINDOW_SIZES = {5840, 8192, 65535}

def os_fingerprint_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet[TCP]
        ip = packet[IP]

        # Focus on SYN packets to capture connection initiations.
        if tcp.flags & 0x02:  # SYN flag is set.
            if ip.ttl not in KNOWN_TTL_VALUES:
                print(f"Suspicious TTL from {ip.src}: {ip.ttl} (expected: {KNOWN_TTL_VALUES})")
            if tcp.window not in KNOWN_TCP_WINDOW_SIZES:
                print(f"Suspicious TCP window from {ip.src}: {tcp.window} (expected: {KNOWN_TCP_WINDOW_SIZES})")

        # Check for odd flag combinations that may signal fingerprinting probes.
        # A NULL scan (no flags) or FIN-only scan are uncommon in normal traffic.
        if tcp.flags == 0:  # NULL scan
            print(f"NULL TCP flags from {ip.src} may indicate fingerprinting.")
        elif tcp.flags == 0x01:  # FIN-only scan
            print(f"FIN TCP flags from {ip.src} may indicate fingerprinting.")

def start_os_fingerprinting(interface=None):
    print("Starting OS fingerprinting detection...")
    sniff(filter="tcp", prn=os_fingerprint_callback, iface=interface, store=False)

if __name__ == "__main__":
    start_os_fingerprinting()
