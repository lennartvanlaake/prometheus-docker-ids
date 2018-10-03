from scapy.all import sniff, IP, ICMP
from prometheus_client import start_http_server, Counter
import requests
import random
import time

# Count packets
traffic_counter = Counter('count_traffic', 'total calls to legit ports',  ['port'])
nmap_counter = Counter('count_nmap', 'total calls to suspicious ports',  ['ip_city', 'port'])
ssh_counter = Counter('count_ssh', 'total packets to ssh',  ['ip_city', 'port'])
ip_map = {}
def log_or_get_city(ip):
    if ip in ip_map:
        ip_city = ip_map[ip]
    else:
        try:
            ip_city = requests.get('http://ip-api.com/json/' + ip).json()['city']
            ip_map[ip] = ip_city
        except:
            ip_city = "N/A"
        ip_map[ip] = ip_city
    return ip_city

def count(p):
    # if p.dst == p.src:
    #     return
    # if IP in p:
    #     if hasattr(p, 'dport'):
    try:
        if p.dport in [80, 443, 3000, 8080]:
            traffic_counter.labels(port=p.dport).inc()
        elif p.dport == 22:
            ip = p[IP].src
            ssh_counter.labels(ip_city=log_or_get_city(ip), port="22").inc()
        elif p.dport < 1024:
            ip = p[IP].src
            nmap_counter.labels(ip_city=log_or_get_city(ip), port=p.dport).inc()
    except:
        pass

if __name__ == '__main__':
    start_http_server(6789)
    sniff(prn=count, filter='tcp and (dst portrange 1-1023 or dst port 8080 or dst port 3000)', store=0)

