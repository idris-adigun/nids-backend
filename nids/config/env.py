import os

# Ports to monitor
ports_env = os.getenv('PORTS', '5432')
sus_ip = os.getenv('SUS_IP', ' ')
sus_port = os.getenv('SUS_PORT', ' ')
sus_payload = os.getenv('SUS_PAYLOAD', ' ')
sus_flag = os.getenv('SUS_FLAG', ' ')
sus_broadcast = os.getenv('SUS_BROADCAST', ' ')
sus_ip = sus_ip.split(',')
sus_port = sus_port.split(',')
sus_payload = sus_payload.split(',')
sus_flag = sus_flag.split(',')
 