# Network Traffic Analysis – Port Scan Detection
This project analyzes a port scan capture (`pcap/portscan.pcap`) using Python to detect suspicious scanning activity.

## Scenario
Detecting suspicious activity (port scans) on a small network by analyzing packet metadata from an offline PCAP file.

## Tech stack

- **Python** 3.x
- **Scapy** for packet-level PCAP parsing and analysis. [web:34]
- **Pyshark** (tshark/Wireshark wrapper) for higher-level packet decoding and filtering. [web:29]
- Standard Python libraries (`collections`, `argparse`, `pandas`).

## Setup

```bash
pip install -r requirements.txt

