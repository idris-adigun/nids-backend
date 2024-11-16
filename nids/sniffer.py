from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff network packets on interface
sniff(iface="eth0", prn=packet_callback, count=10)