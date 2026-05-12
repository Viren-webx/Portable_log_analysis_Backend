def generate_alerts(detections):

    alerts = []

    for d in detections:

        alert = {
            "attack_type": d["type"],
            "source_ip": d["ip"],
            "severity": d["severity"],
            "description": f"{d['type']} detected from {d['ip']}",
            "attempts": d["count"]
        }

        alerts.append(alert)

    return alerts