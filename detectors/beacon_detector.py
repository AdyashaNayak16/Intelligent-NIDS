import time
import time

from logger import log_alert

beacon_tracker = {}

def detect_beaconing(src_ip, dst_ip):

    current_time = time.time()

    connection = f"{src_ip}->{dst_ip}"

    if connection not in beacon_tracker:
        beacon_tracker[connection] = []

    beacon_tracker[connection].append(current_time)

    beacon_tracker[connection] = [
        t for t in beacon_tracker[connection]
        if current_time - t < 30
    ]

    print(
        f"Connection Count {connection}: "
        f"{len(beacon_tracker[connection])}"
    )

    if len(beacon_tracker[connection]) > 15:

        print(
            f"[ALERT] Possible Beaconing Detected: "
            f"{connection}"
        )

        log_alert(
            "Beaconing Activity",
            connection
        )
