import argparse
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP

def load_packets(pcap_path):
    return rdpcap(pcap_path)

def find_suspicious_sources(packets, threshold):
    ports_per_src = defaultdict(set)

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dport = pkt[TCP].dport
            ports_per_src[src].add(dport)

    suspicious = {}
    for src, ports in ports_per_src.items():
        if len(ports) >= threshold:
            suspicious[src] = len(ports)
    return suspicious

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, help="Path to pcap file")
    parser.add_argument("--threshold", type=int, default=50,
                        help="Min number of unique destination ports to flag a source")
    args = parser.parse_args()

    packets = load_packets(args.pcap)
    suspicious = find_suspicious_sources(packets, args.threshold)

    if not suspicious:
        print("No suspicious sources found with current threshold.")
    else:
        print("Suspicious sources (unique destination ports >= {}):".format(args.threshold))
        for src, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
            print(f"- {src}: {count} unique destination ports")

if __name__ == "__main__":
    main()
