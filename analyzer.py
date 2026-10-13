import sys

from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import (
    ARP,
    DNS,
    ICMP,
    IP,
    Ether,
    Raw,
    TCP,
    UDP,
    sniff,
    wrpcap,
)


class TrafficAnalyzer:

    def __init__(self):

        self.stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "ARP": 0,
            "Other": 0,
        }

        self.dns_queries = []
        self.connections = set()
        self.http_payloads = []

        self.arp_table = {}
        self.arp_spoofing_alerts = []

        self.syn_counter = defaultdict(int)
        self.syn_tracker = defaultdict(set)
        self.packet_counter = Counter()

        self.all_packets = []
        self.start_time = None

    def process_packet(self, packet):

        # Start the timer when the first packet arrives
        if self.start_time is None:
            self.start_time = datetime.now()

        # Save packet for later PCAP export
        self.all_packets.append(packet)

        # --------------------------------------------------
        # ARP
        # --------------------------------------------------

        if packet.haslayer(ARP):

            self.stats["ARP"] += 1

            arp = packet[ARP]

            op_label = "who-has" if arp.op == 1 else "is-at"

            print(f"[ARP]  {arp.psrc} ({arp.hwsrc}) | " f"{op_label} {arp.pdst}")

            # ARP reply
            if arp.op == 2:

                ip = arp.psrc
                mac = arp.hwsrc

                # Check whether this IP previously had another MAC
                if ip in self.arp_table and self.arp_table[ip] != mac:

                    alert = (
                        f"IP {ip} changed MAC from " f"{self.arp_table[ip]} to {mac}"
                    )

                    self.arp_spoofing_alerts.append(alert)

                    print(f"[!!]   ARP SPOOFING: {alert}")

                # Store current IP → MAC mapping
                self.arp_table[ip] = mac

            # ARP packets don't need IP processing
            return

        # --------------------------------------------------
        # Ignore packets without an IP layer
        # --------------------------------------------------

        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst

        # Count packets from each source IP
        self.packet_counter[src] += 1

        # --------------------------------------------------
        # DNS
        # --------------------------------------------------

        if packet.haslayer(DNS) and packet.haslayer(UDP):

            self.stats["DNS"] += 1

            if packet[DNS].qd:

                query = packet[DNS].qd.qname.decode(errors="ignore").rstrip(".")

                self.dns_queries.append(query)

                print(f"[DNS]  {src} -> {dst} | " f"Query: {query}")

        # --------------------------------------------------
        # TCP
        # --------------------------------------------------

        elif packet.haslayer(TCP):

            self.stats["TCP"] += 1

            sport = packet[TCP].sport
            dport = packet[TCP].dport

            flags = str(packet[TCP].flags)

            print(f"[TCP]  {src}:{sport} -> " f"{dst}:{dport} | Flags: {flags}")

            # Store connection information
            self.connections.add((src, sport, dst, dport))

            # SYN without ACK = connection attempt
            if "S" in flags and "A" not in flags:

                self.syn_counter[src] += 1
                self.syn_tracker[src].add(dport)

            # --------------------------------------------------
            # Basic HTTP detection
            # --------------------------------------------------

            if packet.haslayer(Raw):

                payload = packet[Raw].load

                try:
                    text = payload.decode(errors="ignore")

                    if (
                        text.startswith("GET ")
                        or text.startswith("POST ")
                        or text.startswith("PUT ")
                        or text.startswith("DELETE ")
                        or text.startswith("HEAD ")
                    ):

                        self.http_payloads.append(
                            {
                                "src": src,
                                "dst": dst,
                                "preview": text.replace("\r\n", " "),
                            }
                        )

                        print(f"[!!] HTTP: {src} -> {dst}")

                except Exception:
                    pass

        # --------------------------------------------------
        # UDP
        # --------------------------------------------------

        elif packet.haslayer(UDP):

            self.stats["UDP"] += 1

            sport = packet[UDP].sport
            dport = packet[UDP].dport

            print(f"[UDP]  {src}:{sport} -> " f"{dst}:{dport}")

        # --------------------------------------------------
        # ICMP
        # --------------------------------------------------

        elif packet.haslayer(ICMP):

            self.stats["ICMP"] += 1

            icmp_type = packet[ICMP].type

            label = {
                0: "Reply",
                8: "Request",
            }.get(icmp_type, f"Type {icmp_type}")

            print(f"[ICMP] {src} -> {dst} | {label}")

        # --------------------------------------------------
        # Other IP protocols
        # --------------------------------------------------

        else:

            self.stats["Other"] += 1

    def print_report(self):

        end_time = datetime.now()

        duration = (
            (end_time - self.start_time).total_seconds() if self.start_time else 0
        )

        total = sum(self.stats.values())

        if total == 0:

            print("\nNo packets captured.")

            return

        # --------------------------------------------------
        # Save captured packets
        # --------------------------------------------------

        pcap_file = "capture.pcap"

        wrpcap(pcap_file, self.all_packets)

        # --------------------------------------------------
        # Report header
        # --------------------------------------------------

        print("\n" + "=" * 60)

        print("  NETWORK TRAFFIC ANALYSIS REPORT")

        print("=" * 60)

        print(f"\n  Duration: {duration:.1f} seconds")

        print(f"  Total packets analyzed: {total}")

        print(f"  Capture saved to: {pcap_file}")

        # --------------------------------------------------
        # Protocol breakdown
        # --------------------------------------------------

        print("\n  Protocol Breakdown:")

        for proto, count in sorted(self.stats.items(), key=lambda x: -x[1]):

            if count > 0:

                pct = count / total * 100

                bar = "#" * int(pct / 2)

                print(f"    {proto:6s} " f"{count:5d}  " f"({pct:5.1f}%)  " f"{bar}")

        # --------------------------------------------------
        # Top talkers
        # --------------------------------------------------

        if self.packet_counter:

            print("\n  Top Talkers " "(by packet count):")

            for ip, count in self.packet_counter.most_common(5):

                print(f"    {ip:20s} " f"{count} packets")

        # --------------------------------------------------
        # DNS queries
        # --------------------------------------------------

        if self.dns_queries:

            unique = list(dict.fromkeys(self.dns_queries))

            print(
                f"\n  DNS Queries "
                f"({len(self.dns_queries)} total, "
                f"{len(unique)} unique):"
            )

            for domain in unique[:10]:

                count = self.dns_queries.count(domain)

                print(f"    {domain} (x{count})")

        # --------------------------------------------------
        # HTTP traffic
        # --------------------------------------------------

        if self.http_payloads:

            print(
                "\n  !! UNENCRYPTED HTTP "
                "TRAFFIC DETECTED"
                f" ({len(self.http_payloads)} "
                "requests) !!"
            )

            print("  These requests may be visible " "to others on the network:")

            for entry in self.http_payloads[:5]:

                print(
                    f"    {entry['src']} -> "
                    f"{entry['dst']}: "
                    f"{entry['preview'][:60]}"
                )

        # --------------------------------------------------
        # ARP spoofing
        # --------------------------------------------------

        if self.arp_spoofing_alerts:

            print(
                "\n  !! ARP SPOOFING "
                "INDICATION DETECTED"
                f" ({len(self.arp_spoofing_alerts)} "
                "alerts) !!"
            )

            for alert in self.arp_spoofing_alerts:

                print(f"    {alert}")

        # --------------------------------------------------
        # SYN flood heuristic
        # --------------------------------------------------

        syn_flooders = {
            ip: count for ip, count in self.syn_counter.items() if count > 50
        }

        if syn_flooders:

            print("\n  !! HIGH SYN ACTIVITY " "DETECTED !!")

            for ip, count in syn_flooders.items():

                print(f"    {ip} sent " f"{count} SYN packets")

                # Check for port scan: one source hitting many unique ports
        scanners = {
            ip: ports for ip, ports in self.syn_tracker.items() if len(ports) > 10
        }
        if scanners:
            print("\n  !! POTENTIAL PORT SCAN DETECTED !!")
            for ip, ports in scanners.items():
                port_sample = sorted(ports)[:10]
                sample_str = ", ".join(str(p) for p in port_sample)
                print(
                    f"    {ip} sent SYN to {len(ports)} unique ports"
                    f" (e.g. {sample_str})"
                )

        # --------------------------------------------------
        # General information
        # --------------------------------------------------

        print(f"\n  Unique connections: " f"{len(self.connections)}")

        print(f"  ARP table entries: " f"{len(self.arp_table)}")

        # --------------------------------------------------
        # Security summary
        # --------------------------------------------------

        print("\n  Security Summary:")

        if self.http_payloads:

            print(
                f"    [!!] "
                f"{len(self.http_payloads)} "
                "unencrypted HTTP request(s) "
                "detected"
            )

        else:

            print("    [OK] No unencrypted " "HTTP traffic detected")

        if self.arp_spoofing_alerts:

            print(
                f"    [!!] " f"{len(self.arp_spoofing_alerts)} " "ARP spoofing alert(s)"
            )

        else:

            print("    [OK] No ARP spoofing " "indication detected")

        if syn_flooders:

            print(
                f"    [!!] "
                f"{len(syn_flooders)} "
                "high-SYN-activity source(s) "
                "detected"
            )

        else:

            print("    [OK] No high SYN activity " "detected")

        print("\n" + "=" * 60)

        # Port scan status in security summary
        if scanners:
            print(f"    [!!] {len(scanners)} potential port scanner(s)" f" detected")
        else:
            print("    [OK] No port scan activity detected")


def main():

    packet_count = 50

    # Allow custom packet count from command line
    if len(sys.argv) > 1:

        packet_count = int(sys.argv[1])

    analyzer = TrafficAnalyzer()

    print(f"Capturing {packet_count} packets... " "(Ctrl+C to stop early)")

    print("Generate traffic: browse websites, " "run 'ping 8.8.8.8', etc.")

    print("-" * 60)

    try:

        sniff(count=packet_count, prn=analyzer.process_packet, store=0)

    except KeyboardInterrupt:

        print("\nCapture stopped.")

    analyzer.print_report()


if __name__ == "__main__":

    main()
