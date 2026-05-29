from scapy.layers.dns import DNSQR
from logger import log_alert
def detect_dns_tunneling(packet):
    if packet.haslayer(DNSQR):
        query_name=(
            packet[DNSQR].qname.decode(errors="ignore")
        )
        print(f"DNS Query:{query_name}")
        if len(query_name)>30:
            print("ALERT!!!Possible DNS tunneling detected")
            log_alert("DNS Tunneling",query_name)
