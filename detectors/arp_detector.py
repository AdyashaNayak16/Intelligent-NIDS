from scapy.all import ARP
from logger import log_alert
arp_table={}
def detect_arp_spoof(packet):
    if ARP in packet:
        src_ip=packet[ARP].psrc
        src_mac=packet[ARP].hwsrc
        print(f"ARP source IP:{src_ip}")
        print(f"ARP SOURCE MAC:{src_mac}")
        if src_ip in arp_table:
            if arp_table[src_ip]!=src_mac:
                print(f"ALERT!!!!possible ARP spoofing from{src_ip}")
                log_alert("ARP spoofing",src_ip)
        else:
            arp_table[src_ip]=src_mac
