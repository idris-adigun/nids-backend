import sniffer as sniffer
import config.env as env

def start_sniffing():
    interfaces = env.interfaces
    for iface in interfaces:
        sniffer.sniff_interface(interface=iface)
    
start_sniffing()