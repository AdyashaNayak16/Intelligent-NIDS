from datetime import datetime
log_file="alerts.log"
def log_alert(alert_type,src_ip):
    timestamp=datetime.now()
    log_entry=(
        f"{timestamp} |"
        f"{alert_type} |"
        f"{src_ip}\n"
    )
    with open(log_file,"a")as file:
        file.write(log_entry)