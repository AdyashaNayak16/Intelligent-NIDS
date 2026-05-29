import time
from logger import log_alert
udp_timestamps={}
def detect_udp_flood(src_ip):
    
        ct=time.time()
        if src_ip not in udp_timestamps:
            udp_timestamps[src_ip]=[]
            udp_timestamps[src_ip].append(ct)
            udp_timestamps[src_ip]=[t for t in udp_timestamps[src_ip]if ct-t<10]
            print(f"UDP count from {src_ip} : {len(udp_timestamps[src_ip])}")
            if len(udp_timestamps[src_ip])>20:
                print(f"ALERT!!! possible syn flood from {src_ip}")
                log_alert("UDP FLOOD",src_ip)