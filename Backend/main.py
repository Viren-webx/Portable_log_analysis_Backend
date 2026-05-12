from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

# Detection imports
from Detection.rules import (
    detect_bruteforce,
    detect_suspicious_ip,
    detect_multiple_users
)
from Detection.ip_statistics import calculate_ip_stats
from parser.log_parser import parse_log_line
from alerts.alert_generator import generate_alerts

app = FastAPI()

# ================= CORS =================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://portablelog.netlify.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= HOME =================
@app.get("/")
def home():
    return {"message": "Log Analyzer Running 🚀 (File Mode Only)"}

# ================= FILE ANALYSIS =================
@app.post("/")
async def analyze_log(file: UploadFile = File(...)):
    try:
        # 📥 Read file
        content = await file.read()
        lines = content.decode(errors="ignore").splitlines()

        parsed_logs = []

        # 🔍 Parse logs
        for line in lines:
            parsed = parse_log_line(line)
            if parsed:
                parsed_logs.append(parsed)

        # 🚨 Run detection rules
        detections = []
        detections.extend(detect_bruteforce(parsed_logs))
        detections.extend(detect_suspicious_ip(parsed_logs))
        detections.extend(detect_multiple_users(parsed_logs))

        # 🔴 Generate alerts
        alerts = generate_alerts(detections)

        # 📊 IP statistics
        ip_stats = calculate_ip_stats(parsed_logs)

        # ✅ Final response
        return {
            "total_logs": len(lines),
            "parsed_logs": len(parsed_logs),
            "alerts": alerts,
            "ip_statistics": ip_stats
        }

    except Exception as e:
        return {"error": str(e)}
