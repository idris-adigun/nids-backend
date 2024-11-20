
import logger as logger
import config.env as env

def analyze(packet):
    rule_set = get_rule_set()
    # print(rule_set)
    logger.logInfo(f'Packet: {packet.summary()}')
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        suspicious_ips = rule_set['sus_ip']
        if ip_layer.src in suspicious_ips:
            logger.logWarning(f"Suspicious source IP detected: {ip_layer.src}")
        if ip_layer.dst == '192.168.1.255':
            logger.logWarning(f"Suspicious destination IP detected: {ip_layer.dst}")    
    
    if packet.haslayer('TCP'):
        tcp_layer = packet.getlayer('TCP')
        suspicious_dst_ports = rule_set['sus_dst_port']
        if tcp_layer.dport in suspicious_dst_ports:
            logger.logWarning(f"Suspicious TCP destination port detected: {tcp_layer.dport}")   
        suspicious_flags = rule_set['sus_flag']
        if tcp_layer.flags in suspicious_flags:
            logger.logWarning(f"Suspicious TCP SYN flag detected: {tcp_layer.flags}")
    
    if packet.haslayer('UDP'):
        udp_layer = packet.getlayer('UDP')
        suspicious_src_ports = rule_set['sus_src_port']
        if udp_layer.dport in suspicious_src_ports: 
            logger.logWarning(f"Suspicious UDP destination port detected: {udp_layer.dport}")
    
    if packet.haslayer('Raw'):
        raw_layer = packet.getlayer('Raw')
        suspicious_payload = rule_set['sus_payload']
        for pattern in suspicious_payload:
            if pattern.encode() in raw_layer.load:
                logger.logWarning(f"Suspicious payload content detected")
                
def get_rule_set():
    rule_set = {
        'sus_ip': env.sus_ip,
        'sus_dst_port': env.sus_dst_port,
        'sus_flag': env.sus_flag,
        'sus_src_port': env.sus_src_port,
        'sus_payload': env.sus_payload
    }
    return rule_set