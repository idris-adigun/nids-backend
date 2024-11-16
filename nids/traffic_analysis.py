from scapy.all import IP, TCP, sniff

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source: {ip_src} -> Destination: {ip_dst}")
    if TCP in packet:
        print(f"TCP Payload: {packet[TCP].payload}")

sniff(iface="eth0", prn=analyze_packet)