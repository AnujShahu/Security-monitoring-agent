import pandas as pd
import logging
from collections import defaultdict

# ---------------- LOGGING CONFIG ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------- CONFIG ----------------
FAILED_LOGIN_THRESHOLD = 3
SUSPICIOUS_IPS = {"192.168.1.100", "10.0.0.99"}

# ---------------- FUNCTIONS ----------------
def load_logs(file_path: str) -> pd.DataFrame:
    """Load CSV logs"""
    logging.info("Loading log data...")
    return pd.read_csv(file_path)


def detect_failed_logins(df: pd.DataFrame):
    """Detect repeated failed login attempts"""
    logging.info("Analyzing failed logins...")
    failed = df[df["status"] == "failed"]
    attempts = defaultdict(int)

    alerts = []

    for _, row in failed.iterrows():
        key = (row["source_ip"], row["user"])
        attempts[key] += 1

        if attempts[key] == FAILED_LOGIN_THRESHOLD:
            alerts.append(
                f"ALERT: {row['source_ip']} has {FAILED_LOGIN_THRESHOLD} failed logins for user {row['user']}"
            )

    return alerts


def detect_threat_intel(df: pd.DataFrame):
    """Detect known malicious IPs"""
    logging.info("Checking threat intelligence...")
    alerts = []

    for ip in df["source_ip"].unique():
        if ip in SUSPICIOUS_IPS:
            alerts.append(f"THREAT INTEL ALERT: Known malicious IP detected -> {ip}")

    return alerts


def run_agent():
    df = load_logs("data/sample_logs.csv")

    failed_login_alerts = detect_failed_logins(df)
    threat_alerts = detect_threat_intel(df)

    print("\n====== SECURITY ALERTS ======\n")
    for alert in failed_login_alerts + threat_alerts:
        print(alert)

    if not failed_login_alerts and not threat_alerts:
        print("No suspicious activity detected.")


# ---------------- MAIN ----------------
if __name__ == "__main__":
    run_agent()
