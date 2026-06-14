from flask import Flask, render_template


app = Flask(__name__)

def get_recent_alerts():

    alerts = []

    try:

        with open("alerts.log", "r") as file:

            lines = file.readlines()

            for line in lines[-10:]:

                parts = line.strip().split("|")

                if len(parts) == 3:

                    alerts.append({
                    "time": parts[0].strip(),
                    "type": parts[1].strip(),
                    "source": parts[2].strip()
                })

    except FileNotFoundError:
        pass

    return alerts[::-1]

def get_alert_stats():

    try:

        with open("alerts.log", "r") as file:

            lines = file.readlines()

        return len(lines)

    except FileNotFoundError:

        return 0
def get_all_alerts():

    alerts = []

    try:

        with open("alerts.log", "r") as file:

            lines = file.readlines()

            for line in reversed(lines):

                parts = line.strip().split("|")

            if len(parts) == 3:

                alerts.append({
                    "time": parts[0].strip(),
                    "type": parts[1].strip(),
                    "source": parts[2].strip()
                })

    except FileNotFoundError:
        pass

    return alerts

@app.route("/")
def dashboard():

    alerts = get_recent_alerts()

    total_alerts = get_alert_stats()

    return render_template(
    "index.html",
    alerts=alerts,
    total_alerts=total_alerts
)
@app.route("/logs")
def logs():
    alerts=get_all_alerts()
    return render_template("logs.html",alerts=alerts)
@app.route("/ml")
def ml():
    return render_template("ml.html")

if __name__ == "__main__":
    app.run(debug=True)