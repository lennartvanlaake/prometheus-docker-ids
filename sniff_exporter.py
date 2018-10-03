from scapy.all import sniff, IP, ICMP
from prometheus_client import start_http_server, Counter
import requests
import random
import time

# Count packets
counter = Counter('traffic', 'total calls to suspicious ports',  ['ip_city', 'port'])
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
    try:
        if p.dport < 10000:
            ip = p[IP].src
            counter.labels(ip_city=log_or_get_city(ip), port=p.dport).inc()
    except:
        pass

if __name__ == '__main__':
    start_http_server(6789)
    sniff(prn=count, filter='tcp', store=0)

