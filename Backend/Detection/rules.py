from collections import defaultdict

#  1. Brute Force Detection
def detect_bruteforce(parsed_logs):

    ip_fail_count = defaultdict(int)

    for log in parsed_logs:

        if log["event_type"] == "FAILED_LOGIN":
            ip = log["source_ip"]
            ip_fail_count[ip] += 1

    detections = []

    for ip, count in ip_fail_count.items():

        if count >= 3:   # lower for testing

            detections.append({
                "type": "Brute Force Attack",
                "ip": ip,
                "severity": "HIGH",
                "count": count
            })

    return detections


#  2. Suspicious IP Activity
def detect_suspicious_ip(parsed_logs):

    ip_count = defaultdict(int)

    for log in parsed_logs:
        ip_count[log["source_ip"]] += 1

    detections = []

    for ip, count in ip_count.items():

        if count >= 10:

            detections.append({
                "type": "Suspicious IP Activity",
                "ip": ip,
                "severity": "MEDIUM",
                "count": count
            })

    return detections


def detect_multiple_users(parsed_logs):

    ip_users = defaultdict(set)

    for log in parsed_logs:

        if "username" in log:
            ip_users[log["source_ip"]].add(log["username"])

    detections = []

    for ip, users in ip_users.items():

        if len(users) >= 3:

            detections.append({
                "type": "Multiple Username Attack",
                "ip": ip,
                "severity": "HIGH",
                "count": len(users)
            })

    return detections