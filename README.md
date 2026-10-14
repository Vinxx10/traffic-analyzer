# Traffic Analyzer

A lightweight Python tool that captures live network traffic, classifies packets by protocol, and flags common security red flags — ARP spoofing, high SYN activity, port scans, and unencrypted HTTP.

Built with [Scapy](https://scapy.net/).

## What it does

While packets are captured, the analyzer prints a live stream of events (TCP flags, DNS queries, ARP replies, ICMP echo, etc.). When the capture finishes (or you stop it with Ctrl+C), it writes a PCAP file and prints a summary report.

### Protocol analysis

| Protocol | What is logged |
|----------|----------------|
| **TCP** | Source/dest IP and ports, TCP flags, unique connections |
| **UDP** | Source/dest IP and ports |
| **DNS** | Query names (unique domains + counts) |
| **ICMP** | Echo request/reply (and other types) |
| **ARP** | who-has / is-at, and an IP→MAC table |

### Security heuristics

- **Unencrypted HTTP** — detects cleartext `GET`/`POST`/`PUT`/`DELETE`/`HEAD` payloads
- **ARP spoofing** — alerts when the same IP maps to more than one MAC during the capture
- **High SYN activity** — sources that send more than 50 SYN packets (possible SYN flood)
- **Port scan** — sources that SYN to more than 10 unique destination ports

### Report output

The final report includes:

- Capture duration and total packet count
- Protocol breakdown with simple bar charts
- Top talkers (by packet count)
- DNS queries (unique domains)
- HTTP / ARP / SYN / port-scan findings
- A short security summary (`[OK]` / `[!!]`)
- Saved capture: `capture.pcap` (Wireshark / tcpdump compatible)

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- Permission to open a network interface in promiscuous/capture mode (typically **root** / Administrator, or `CAP_NET_RAW`)

## Setup

```bash
git clone https://github.com/Vinxx10/traffic-analyzer.git
cd traffic-analyzer

python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install scapy
```

## Usage

Capture **50 packets** (default):

```bash
sudo python analyzer.py
```

Capture a custom count:

```bash
sudo python analyzer.py 200
```

Stop early anytime with **Ctrl+C** — the report still runs on whatever was captured.

While it runs, generate some traffic so there is something to analyze (browse the web, `ping 8.8.8.8`, open apps that talk to the network, etc.).

### Example session

```text
Capturing 50 packets... (Ctrl+C to stop early)
Generate traffic: browse websites, run 'ping 8.8.8.8', etc.
------------------------------------------------------------
[DNS]  192.168.1.10 -> 8.8.8.8 | Query: example.com
[TCP]  192.168.1.10:54321 -> 93.184.216.34:443 | Flags: S
[ICMP] 192.168.1.10 -> 8.8.8.8 | Request
...

============================================================
  NETWORK TRAFFIC ANALYSIS REPORT
============================================================
  Duration: 12.3 seconds
  Total packets analyzed: 50
  Capture saved to: capture.pcap
  ...
```

Open the saved capture later:

```bash
wireshark capture.pcap
# or
tcpdump -r capture.pcap
```

## General uses

| Use case | How this helps |
|----------|----------------|
| **Learning networking** | See real TCP handshakes, DNS lookups, ARP, and ICMP on your own machine |
| **Lab / coursework** | Quick demos of packet sniffing, protocol mix, and basic threat signals |
| **Home network hygiene** | Spot unexpected DNS names, cleartext HTTP, or odd ARP MAC changes |
| **Incident triage (light)** | Export a PCAP and a human-readable summary before digging in Wireshark |
| **Security awareness** | Show why HTTPS matters and how ARP spoofing can look on the wire |

This is a teaching / diagnostic sniffer, not a full IDS. Thresholds (e.g. 50 SYNs, 10 ports) are simple heuristics meant for short local captures.

## How it works

1. `sniff()` captures packets from the default interface.
2. Each packet is passed to `TrafficAnalyzer.process_packet()`.
3. Layers are inspected with Scapy (`IP`, `TCP`, `UDP`, `DNS`, `ICMP`, `ARP`, `Raw`).
4. Counters, connection sets, DNS lists, and alert lists are updated in memory.
5. On exit, packets are written with `wrpcap("capture.pcap", ...)` and `print_report()` prints the summary.

Main entry point: `analyzer.py` → `TrafficAnalyzer` class → `main()`.

## Notes & limitations

- **Root / elevated privileges** are usually required for live capture.
- Only the **default interface** is used (Scapy’s default); interface selection is not exposed as a CLI flag yet.
- HTTP detection is **cleartext only** — HTTPS payloads are not decrypted.
- ARP “spoofing” here means an IP’s MAC changed during the capture; that can also happen for legitimate reasons (DHCP renewals, VM mobility, etc.).
- SYN-flood and port-scan alerts are **count-based heuristics**, not definitive detections.
- Captures can contain sensitive data (IPs, hostnames, HTTP bodies). Treat `capture.pcap` carefully and do not share captures from networks you do not own or have permission to monitor.

## Project layout

```text
traffic-analyzer/
├── analyzer.py      # Capture, analysis, and reporting
├── capture.pcap     # Written after a run (gitignored if you prefer)
├── venv/            # Local virtualenv (optional)
└── README.md
```

## License

Use and modify freely for personal, educational, and lab purposes. Only capture traffic on networks you own or have explicit permission to monitor.
