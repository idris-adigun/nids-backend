from scapy.all import sniff
import logger as logger
def packet_callback(packet):
    logger.logInfo(f'Packet: {packet.summary()}')
    # logger.logInfo(f'Packet: {packet.show()}')
    
    # Check for suspicious patterns
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        if ip_layer.src == '192.168.1.1':  # Example suspicious IP
            logger.logWarning(f"Suspicious source IP detected: {ip_layer.src}")
        if ip_layer.dst == '192.168.1.255':  # Example suspicious broadcast
            logger.logWarning(f"Suspicious destination IP detected: {ip_layer.dst}")    
    
    if packet.haslayer('TCP'):
        tcp_layer = packet.getlayer('TCP')
        if tcp_layer.dport == 23:  # Example suspicious port (Telnet)
            logger.logWarning(f"Suspicious TCP destination port detected: {tcp_layer.dport}")   
        if tcp_layer.flags == 'S':  # Example suspicious SYN flag
            logger.logWarning(f"Suspicious TCP SYN flag detected: {tcp_layer.flags}")
    
    if packet.haslayer('UDP'):
        udp_layer = packet.getlayer('UDP')
        if udp_layer.dport == 53:  # Example suspicious port (DNS)
            logger.logWarning(f"Suspicious UDP destination port detected: {udp_layer.dport}")
    
    if packet.haslayer('Raw'):
        raw_layer = packet.getlayer('Raw')
        payload = raw_layer.load
        if b'attack' in payload:  # Example suspicious payload content
            logger.logWarning(f"Suspicious payload content detected")

# Sniff network packets on interface
sniff(iface="eth0", prn=packet_callback)