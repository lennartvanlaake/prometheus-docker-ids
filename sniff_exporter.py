from scapy.all import sniff, IP
from prometheus_client import start_http_server, Counter
import random
import time

# Count packets
c = Counter('count', 'test', ['port', 'ip'])

def count(p):
    if hasattr(p, 'dport') and IP in p and hasattr(p[IP], 'dst'):
        c.labels(port=p.dport, ip=p[IP].dst).inc()

if __name__ == '__main__':
    start_http_server(8000)
    sniff(prn=count, filter='tcp and !(dst host 192.168.1.103 or dst host 127.0.0.1)')

