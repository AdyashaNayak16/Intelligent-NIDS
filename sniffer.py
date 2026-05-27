from scapy.all import *
from scapy.layers.inet import IP,TCP,UDP,ICMP
import time
syn_timestamps={}
syn_count={}
port_scan_tracker={}
log_file="alerts.log"
def log_alert(message):
    with open(log_file,"a")as file:
        file.write(message + "\n")
def packet_callback(packet):
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
            if src_ip not in port_scan_tracker:
                port_scan_tracker[src_ip]=set()
            port_scan_tracker[src_ip].add(dest_port)
            print(f"ports contacted by {src_ip}:{port_scan_tracker[src_ip]}")
            if len(port_scan_tracker[src_ip])>10:
                print(f"ALERT!!!!possible port scan from {src_ip}")
                
                log_alert(f"ALERT!!!!possible port scan from {src_ip}")
            if flags=="S":
                if src_ip not in syn_count:
                    syn_count[src_ip]=0
                ct=time.time()
                if src_ip not in syn_timestamps:
                    syn_timestamps[src_ip]=[]
                syn_timestamps[src_ip].append(ct)
                syn_timestamps[src_ip]=[t for t in syn_timestamps[src_ip]if ct-t<10]
                print(f"SYN count from {src_ip} : {syn_count[src_ip]}")
                if len(syn_timestamps[src_ip])>20:
                    print(f"ALERT!!! possible syn flood from {src_ip}")
                    log_alert(f"ALERT!!! possible syn flood from {src_ip}")
            print("===================")
        elif UDP in packet:
            src_port=packet[UDP].sport
            dest_port=packet[UDP].dport
            print(f"UDP source port:{src_port}")
            print(f"UDP destination port:{dest_port}")
        elif ICMP in packet:
            icmp_type=packet[ICMP].type
            print(f"ICMP TYPE:{icmp_type}")
            if icmp_type==8:
                print("ICMP echo request detected ")
sniff(prn=packet_callback,store=False,count=2)