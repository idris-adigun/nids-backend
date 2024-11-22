import os


log_level = os.getenv('LOG_LEVEL', 'WARNING')
ports_env = os.getenv('PORTS', '5432')
sus_ip = os.getenv('SUS_IP', '192.168.1.1,10.0.0.1')
sus_dst_port = os.getenv('SUS_PORT', '44206')
sus_src_port = os.getenv('SUS_PORT', '44206')
sus_payload = os.getenv('SUS_PAYLOAD', 'attack,exploit,password')
sus_flag = os.getenv('SUS_FLAG', 'S,A')

sus_ip = sus_ip.split(',')
sus_dst_port = sus_dst_port.split(',')
sus_src_port = sus_src_port.split(',')
sus_payload = sus_payload.split(',')
sus_flag = sus_flag.split(',')
interfaces = os.getenv('INTERFACES', 'eth0')
interfaces = interfaces.split(',')

