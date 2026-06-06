from logger import log_alert

known_bad_ips = {
    "185.220.101.1",
    "45.95.147.236",
    "91.219.236.222"
}

def detect_botnet_traffic(src_ip, dst_ip):

    if src_ip in known_bad_ips:

        print(
            f"[ALERT] Known Malicious Source IP: "
            f"{src_ip}"
        )

        log_alert(
            "Botnet Signature",
            src_ip
        )

    if dst_ip in known_bad_ips:

        print(
            f"[ALERT] Connection To Known Malicious IP: "
            f"{dst_ip}"
        )

        log_alert(
            "Botnet Signature",
            dst_ip
        )