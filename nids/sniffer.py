from scapy.all import sniff
import logger as logger
import analyzer as analyzer
def packet_callback(packet):
    analyzer.analyze(packet)
                
                
def sniff_interface(interface):
        logger.logInfo(f"Sniffing on interface {interface}")
        sniff(iface=interface, prn=lambda x: packet_callback(x))
