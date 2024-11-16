from scapy.all import ICMP

def detect_ping_flood(packet):
    if ICMP in packet and packet[ICMP].type == 8:  # Echo request
        print("Ping flood detected!")

sniff(iface="eth0", prn=detect_ping_flood, count=100)