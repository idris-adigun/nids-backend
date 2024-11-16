from scapy.all import sniff
import logger as logger
import config.env as env
def packet_callback(packet):
    logger.logInfo(f'Packet: {packet.summary()}')
    # logger.logInfo(f'Packet: {packet.show()}')
    
    # Check for suspicious patterns
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        suspicious_ips = env.sus_ip
        if ip_layer.src in suspicious_ips:
            logger.logWarning(f"Suspicious source IP detected: {ip_layer.src}")
        if ip_layer.dst == '192.168.1.255':  # Example suspicious broadcast
            logger.logWarning(f"Suspicious destination IP detected: {ip_layer.dst}")    
    
    if packet.haslayer('TCP'):
        tcp_layer = packet.getlayer('TCP')
        suspicious_dst_ports = env.sus_dst_port
        if tcp_layer.dport in suspicious_dst_ports:  # Example suspicious port (Telnet)
            logger.logWarning(f"Suspicious TCP destination port detected: {tcp_layer.dport}")   
        suspicious_flags = env.sus_flag
        if tcp_layer.flags in suspicious_flags:
            logger.logWarning(f"Suspicious TCP SYN flag detected: {tcp_layer.flags}")
    
    if packet.haslayer('UDP'):
        udp_layer = packet.getlayer('UDP')
        suspicious_src_ports = env.sus_src_port
        if udp_layer.dport in suspicious_src_ports:  # Example suspicious port (DNS)
            logger.logWarning(f"Suspicious UDP destination port detected: {udp_layer.dport}")
    
    if packet.haslayer('Raw'):
        raw_layer = packet.getlayer('Raw')
        suspicious_payload = env.sus_payload
        for pattern in suspicious_payload:
            if pattern.encode() in raw_layer.load:
                logger.logWarning(f"Suspicious payload content detected")
                
                
def main():
    interfaces = env.interfaces
    for iface in interfaces:
        sniff(iface=iface, prn=packet_callback)

if __name__ == '__main__':
    main()