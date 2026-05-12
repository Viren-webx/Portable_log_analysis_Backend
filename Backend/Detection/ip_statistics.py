from collections import defaultdict

def calculate_ip_stats(parsed_logs):

    stats = defaultdict(lambda: {
        "failed_attempts": 0,
        "successful_attempts": 0
    })

    for log in parsed_logs:

        ip = log["source_ip"]

        if log["event_type"] == "FAILED_LOGIN":
            stats[ip]["failed_attempts"] += 1

        elif log["event_type"] == "SUCCESS_LOGIN":
            stats[ip]["successful_attempts"] += 1

    result = []

    for ip, data in stats.items():
        result.append({
            "ip": ip,
            "failed_attempts": data["failed_attempts"],
            "successful_attempts": data["successful_attempts"]
        })

    return result