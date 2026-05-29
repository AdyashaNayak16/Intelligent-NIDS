import time
from logger import log_alert
syn_timestamps={}
def detect_syn_flood(src_ip,flags):
    if flags=="S":
        ct=time.time()
        if src_ip not in syn_timestamps:
            syn_timestamps[src_ip]=[]
            syn_timestamps[src_ip].append(ct)
            syn_timestamps[src_ip]=[t for t in syn_timestamps[src_ip]if ct-t<10]
            print(f"SYN count from {src_ip} : {len(syn_timestamps[src_ip])}")
            if len(syn_timestamps[src_ip])>20:
                print(f"ALERT!!! possible syn flood from {src_ip}")
                log_alert("SYN FLOOD",src_ip)