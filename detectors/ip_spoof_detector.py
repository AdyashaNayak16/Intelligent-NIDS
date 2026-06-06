from logger import log_alert

def detect_ip_spoof(src_ip):

    suspicious_ips = [
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255"
    ]

    if src_ip in suspicious_ips:

        print(
            f"[ALERT] Suspicious Source IP Detected: "
            f"{src_ip}"
        )

        log_alert(
            "IP Spoofing",
            src_ip
        )