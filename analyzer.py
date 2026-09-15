import sys
from scapy.all import IP, sniff


# Callback function that runs once for every captured packet
def process_packet(packet):
    # Check if this packet has an IP layer
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        # Print source, destination, and Scapy's built-in summary
        print(f"{src} -> {dst} | {packet.summary()}")


def main():
    # Default to capturing 20 packets
    packet_count = 20
    # Accept a custom count from the command line
    if len(sys.argv) > 1:
        packet_count = int(sys.argv[1])

    print(f"Capturing {packet_count} packets... (Ctrl+C to stop early)")
    print("-" * 60)

    # Capture packets, calling process_packet for each one
    try:
        sniff(count=packet_count, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped.")


if __name__ == "__main__":
    main()
