from scapy.all import sniff, IP, ICMP
from prometheus_client import start_http_server, Counter
import requests
import random
import time

# Count packets
legit_counter = Counter('count_legit', 'total calls to legit ports',  ['port'])
suspicious_counter = Counter('count_suspicious', 'total calls to suspicious ports',  ['ip_city', 'port'])
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
    if p.dst == p.src:
        return
    try:
        if p.dport in [80, 3000]:
            legit_counter.labels(port=p.dport).inc()
        else:
            ip = p[IP].src
            suspicious_counter.labels(ip_city=log_or_get_city(ip), port=p.dport).inc()
    except:
        pass

if __name__ == '__main__':
    start_http_server(6789)
    sniff(prn=count, filter='tcp and (dst portrange 1-1023 or dst port 8080 or dst port 3000)', store=0)

