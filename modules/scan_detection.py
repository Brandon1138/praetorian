# modules/scan_detection.py
import time
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
from config import CONFIG
from modules.logging_module import log_event

# Global dictionary to track SYN packet timestamps per IP
syn_tracker = {}


def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp_layer = packet.getlayer(TCP)
        ip_layer = packet.getlayer(IP)

        # Check for SYN packets (used to initiate connections)
        if tcp_layer.flags == "S":
            src_ip = ip_layer.src
            current_time = time.time()

            # Update the tracker for the source IP
            if src_ip not in syn_tracker:
                syn_tracker[src_ip] = []
            syn_tracker[src_ip].append(current_time)

            # Purge old timestamps beyond the configured timeframe
            timeframe = CONFIG["scan_detection"]["timeframe_seconds"]
            syn_tracker[src_ip] = [t for t in syn_tracker[src_ip] if current_time - t < timeframe]

            threshold = CONFIG["scan_detection"]["syn_threshold"]
            if len(syn_tracker[src_ip]) > threshold:
                log_event("warning",
                          f"Potential scan detected from {src_ip}: {len(syn_tracker[src_ip])} SYN packets in {timeframe} seconds")
            else:
                log_event("info", f"SYN packet detected from {src_ip}")


def start_sniffing(interface=None):
    print("Starting scan detection...")
    sniff(filter="tcp", prn=packet_callback, iface=interface, store=False)


if __name__ == "__main__":
    start_sniffing()
