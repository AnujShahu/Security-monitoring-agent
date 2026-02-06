import pandas as pd
import logging
import os
from collections import defaultdict
from datetime import datetime

# ======================================================
# LOGGING CONFIGURATION
# ======================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("SecurityMonitoringAgent")

# ======================================================
# PATH HANDLING (ABSOLUTE & SAFE)
# ======================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "sample_logs.csv")

# ======================================================
# SECURITY CONFIGURATION
# ======================================================
FAILED_LOGIN_THRESHOLD = 3
HIGH_ACTIVITY_THRESHOLD = 5

KNOWN_MALICIOUS_IPS = {
    "192.168.1.100",
    "10.0.0.99",
    "203.0.113.45"
}

CRITICAL_USERS = {"admin", "root", "itadmin"}

# ======================================================
# DATA LOADING & NORMALIZATION
# ======================================================
def load_logs(path: str) -> pd.DataFrame:
    logger.info(f"Loading logs from {path}")

    if not os.path.exists(path):
        raise FileNotFoundError(f"Log file not found: {path}")

    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def normalize_logs(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("Normalizing logs")

    df["event"] = df["event"].str.lower()
    df["status"] = df["status"].str.lower()
    df["user"] = df["user"].fillna("unknown")

    return df

# ======================================================
# DETECTION FUNCTIONS
# ======================================================
def detect_bruteforce(df):
    alerts = []
    counter = defaultdict(int)

    for _, row in df.iterrows():
        if row["event"] == "login" and row["status"] == "failed":
            key = (row["source_ip"], row["user"])
            counter[key] += 1

            if counter[key] == FAILED_LOGIN_THRESHOLD:
                alerts.append(
                    f"BRUTE FORCE ALERT: {row['source_ip']} targeting user {row['user']}"
                )
    return alerts


def detect_threat_intel(df):
    alerts = []
    for ip in df["source_ip"].unique():
        if ip in KNOWN_MALICIOUS_IPS:
            alerts.append(
                f"THREAT INTEL ALERT: Known malicious IP detected -> {ip}"
            )
    return alerts


def detect_critical_user_activity(df):
    alerts = []
    critical_df = df[df["user"].isin(CRITICAL_USERS)]

    for _, row in critical_df.iterrows():
        if row["status"] == "failed":
            alerts.append(
                f"CRITICAL ACCOUNT ALERT: Failed activity on {row['user']} from {row['source_ip']}"
            )
    return alerts


def detect_high_activity_ip(df):
    alerts = []
    ip_counts = df["source_ip"].value_counts()

    for ip, count in ip_counts.items():
        if count >= HIGH_ACTIVITY_THRESHOLD:
            alerts.append(
                f"ANOMALY ALERT: High event volume from IP {ip} (events={count})"
            )
    return alerts

# ======================================================
# ALERT DISPLAY
# ======================================================
def show_alerts(alerts):
    print("\n========== SECURITY ALERTS ==========\n")

    if not alerts:
        print("No suspicious activity detected.")
    else:
        for alert in alerts:
            print(alert)

    print("\n====================================\n")

# ======================================================
# MAIN EXECUTION
# ======================================================
def run_agent():
    start = datetime.now()
    logger.info("Security Monitoring Agent started")

    df = load_logs(DATA_PATH)
    df = normalize_logs(df)

    alerts = []
    alerts.extend(detect_bruteforce(df))
    alerts.extend(detect_threat_intel(df))
    alerts.extend(detect_critical_user_activity(df))
    alerts.extend(detect_high_activity_ip(df))

    show_alerts(alerts)

    end = datetime.now()
    logger.info(f"Execution time: {(end - start).seconds} seconds")


if __name__ == "__main__":
    run_agent()
