from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        payload = ""

        if TCP in packet:
            protocol = "TCP"
            payload = bytes(packet[TCP].payload)[:50]

        elif UDP in packet:
            protocol = "UDP"
            payload = bytes(packet[UDP].payload)[:50]

        elif ICMP in packet:
            protocol = "ICMP"

        print("=" * 60)
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        if payload:
            print(f"Payload (first 50 bytes): {payload}")

def start_sniffing():
    print("[*] Starting packet sniffer...")
    print("[*] Press CTRL+C to stop")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
