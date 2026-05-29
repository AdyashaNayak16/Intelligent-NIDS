from scapy.all import Raw
from logger import log_alert
suspicisous_patt=["select","union","drop","' or '1'='1","<script>","../"]
def detect_http_attacks(packet):
    if packet.haslayer(Raw):
        payload=(packet[Raw].load.decode(errors="ignore").lower())
        for patt in suspicisous_patt:
            if patt in payload:
                print(f"ALERT!! suspicious payload {patt}")
                log_alert("HTTP payload attack",patt)