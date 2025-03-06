from scapy.all import sniff
from scapy.layers.inet import TCP, IP


def packet_callback(packet):
    # Check if the packet has a TCP layer
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp_layer = packet.getlayer(TCP)
        ip_layer = packet.getlayer(IP)

        # Look for SYN packets which are often used to initiate TCP connections
        if tcp_layer.flags == "S":
            print(f"SYN packet detected: {ip_layer.src} -> {ip_layer.dst}")
            # Here you could add logic to count the number of SYN packets
            # from the same source in a given timeframe as a potential scan.


def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    # The filter "tcp" ensures we only capture TCP packets.
    sniff(filter="tcp", prn=packet_callback, iface=interface, store=False)


if __name__ == "__main__":
    # For Windows, you might need to run PyCharm as an administrator.
    start_sniffing()
