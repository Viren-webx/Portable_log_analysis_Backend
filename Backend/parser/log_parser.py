import re

def parse_log_line(line):

    ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    ip_match = re.search(ip_pattern, line)

    if not ip_match:
        return None

    ip = ip_match.group()

    # extract username safely
    user_match = re.search(r'for (\w+)', line)
    username = user_match.group(1) if user_match else "unknown"

    if "Failed password" in line:
        event = "FAILED_LOGIN"

    elif "Accepted password" in line:
        event = "SUCCESS_LOGIN"

    else:
        return None

    return {
        "source_ip": ip,
        "event_type": event,
        "username": username
    }