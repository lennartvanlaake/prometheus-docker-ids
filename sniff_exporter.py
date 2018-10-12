from scapy.all import sniff, IP, ICMP
from prometheus_client import start_http_server, Counter
import requests
import random
import time
import threading

# Count packets
ssh_counter = Counter('ssh_counter', 'total calls to suspicious ports',  ['ip_country'])
port_counter = Counter('port_counter', 'total calls to various ports',  ['port'])
ip_map = {}

def set_interval(func, sec):
    def func_wrapper():
        set_interval(func, sec)
        func()
    t = threading.Timer(sec, func_wrapper)
    t.start()
    return t

def clear_map():
    ip_map = {}

set_interval(clear_map, 604800)

def log_or_get_country(ip):
    if ip in ip_map:
        ip_country = ip_map[ip]
    else:
        try:
            ip_country = requests.get('http://ip-api.com/json/' + ip).json()['country']
            ip_map[ip] = ip_country
        except:
            ip_country = "N/A"
        ip_map[ip] = ip_country
    return ip_country

def count(p):
    try:
        if p.dport == 22:
            ip = p[IP].src
            ssh_counter.labels(ip_country=log_or_get_country(ip)).inc()
        elif p.dport < 1000 or p.dport in [8080, 3000, 5000, 1080, 10080, 20080, 30080]:
            port_counter.labels(port=p.dport).inc()
    except:
        pass

if __name__ == '__main__':
    start_http_server(6789)
    sniff(prn=count, filter='tcp', store=0)

