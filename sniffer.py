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
from detectors.beacon_detector import detect_beaconing
from detectors.port_scan import detect_port_scan
from detectors.ip_spoof_detector import detect_ip_spoof
from detectors.botnet_detector import detect_botnet_traffic
from flow_tracker import update_flow
from detectors.ml_detectors import detect_ml_attack

syn_count={}


def packet_callback(packet):
    detect_http_attacks(packet)
    detect_dns_tunneling(packet)
    detect_arp_spoof(packet)
    if IP in packet:
        src_ip=packet[IP].src
        dest_ip=packet[IP].dst
        protocol=packet[IP].proto
        flow=update_flow(
            src_ip,dest_ip,protocol,len(packet)
        )
    
        detect_ip_spoof(src_ip)
        detect_botnet_traffic(src_ip,dest_ip)
        detect_beaconing(src_ip,dest_ip)
        
        print(f"source ip:{src_ip}")
        print(f"destination ip:{dest_ip}")
        
        if TCP in packet:
            src_port=packet[TCP].sport
            dest_port=packet[TCP].dport
            flags=packet[TCP].flags
            flow_features=update_flow(
                src_ip=src_ip,
                dst_ip=dest_ip,
                protocol="TCP",
                packet_len=len(packet),
                dst_port=dest_port,
                tcp_flags=int(flags)
            )
            prediction=detect_ml_attack(flow_features)
            
            print(f"ML PREDICTION:{prediction}")
            if prediction=="BOT":
                print(f"[ML Alert] suspicious bot traffic detected from {src_ip}")
                log_alert("ML BOT DETECTION",src_ip)
            print(f"source port:{src_port}")
            print(f"destination port:{dest_port}")
            print(f"tcp flags:{flags}")
            detect_syn_flood(src_ip,flags)
            detect_port_scan(src_ip,dest_port)
            
            
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
sniff(prn=packet_callback,store=False,count=50)