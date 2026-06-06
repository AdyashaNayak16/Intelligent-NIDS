from logger import log_alert

port_scan_tracker = {}

def detect_port_scan(src_ip, dest_port):

    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = set()

    port_scan_tracker[src_ip].add(dest_port)

    print(
        f"Ports contacted by {src_ip}: "
        f"{port_scan_tracker[src_ip]}"
    )

    if len(port_scan_tracker[src_ip]) > 10:

        print(
            f"[ALERT] Possible Port Scan "
            f"from {src_ip}"
        )

        log_alert(
            "Port Scan",
            src_ip
        )