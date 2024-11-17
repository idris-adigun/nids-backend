import sniffer as sniffer
import config.env as env

def analyze():
    interfaces = env.interfaces
    for iface in interfaces:
        sniffer.sniff_interface(interface=iface, rule_set="default")
    
analyze()