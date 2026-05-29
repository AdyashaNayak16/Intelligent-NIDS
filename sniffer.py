from scapy.all import sniff,ARP
from scapy.layers.inet import IP,TCP,UDP,ICMP
import time
from datetime import datetime
from logger import log_alert
from detectors.syn_detector import detect_syn_flood
from detectors.arp_detector import detect_arp_spoof
from detectors.udp_detector import detect_udp_flood
from detectors.dns_detector import detect_dns_tunneling
from detectors.http_detector import detect_http_attacks
syn_count={}
port_scan_tracker={}

def packet_callback(packet):
    detect_http_attacks(packet)
    detect_dns_tunneling(packet)
    detect_arp_spoof(packet)
    if IP in packet:
        src_ip=packet[IP].src
        dest_ip=packet[IP].dst
        print(f"source ip:{src_ip}")
        print(f"destination ip:{dest_ip}")
        if TCP in packet:
            src_port=packet[TCP].sport
            dest_port=packet[TCP].dport
            flags=packet[TCP].flags
            print(f"source port:{src_port}")
            print(f"destination port:{dest_port}")
            print(f"tcp flags:{flags}")
            detect_syn_flood(src_ip,flags)
            if src_ip not in port_scan_tracker:
                port_scan_tracker[src_ip]=set()
            port_scan_tracker[src_ip].add(dest_port)
            print(f"ports contacted by {src_ip}:{port_scan_tracker[src_ip]}")
            if len(port_scan_tracker[src_ip])>10:
                print(f"ALERT!!!!possible port scan from {src_ip}")
                
                log_alert(f"ALERT!!!!possible port scan from {src_ip}")
            
            print("===================")
        elif UDP in packet:
            src_port=packet[UDP].sport
            dest_port=packet[UDP].dport
            print(f"UDP source port:{src_port}")
            print(f"UDP destination port:{dest_port}")
            detect_udp_flood(src_ip)
        elif ICMP in packet:
            icmp_type=packet[ICMP].type
            print(f"ICMP TYPE:{icmp_type}")
            if icmp_type==8:
                print("ICMP echo request detected ")
sniff(prn=packet_callback,store=False,count=2)