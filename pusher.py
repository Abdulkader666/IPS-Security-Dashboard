import time
import os
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime

# --- 1. Configuration ---
KEY_PATH = "serviceAccountKey.json" 
APP_ID = "ips_dashboard_v1"

def initialize_firebase():
    try:
        if not firebase_admin._apps:
            if os.path.exists(KEY_PATH):
                cred = credentials.Certificate(KEY_PATH)
                firebase_admin.initialize_app(cred)
                print("Connected to Firebase Cloud successfully")
            else:
                print(f"Error: {KEY_PATH} not found in this directory")
                return None
        return firestore.client()
    except Exception as e:
        print(f"Firebase initialization failed: {e}")
        return None

# --- 2. Data Upload Logic ---
def upload_to_cloud(db, alert_data):
    try:
        collection_path = f"artifacts/{APP_ID}/public/data/snort_alerts"
        alert_data['timestamp'] = firestore.SERVER_TIMESTAMP
        db.collection(collection_path).add(alert_data)
        print("Alert pushed to global dashboard successfully")
    except Exception as e:
        print(f"Cloud upload error: {e}")

# --- 3. Log Monitoring ---
def monitor_snort_logs():
    db = initialize_firebase()
    if not db:
        return

    log_file_path = "/var/log/snort/alert_fast.txt"
    
    if not os.path.exists(log_file_path):
        print(f"Warning: {log_file_path} not found. Ensure Snort is running.")
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        open(log_file_path, 'a').close()

    print(f"Monitoring alerts in {log_file_path}...")
    
    with open(log_file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            if "[**]" in line:
                parts = line.split()
                alert_entry = {
                    "alert_msg": line.split("[**]")[1].split("[**]")[0].strip(),
                    "priority": "High" if "Priority: 1" in line else "Medium",
                    "raw_log": line.strip(),
                    "attacker_ip": parts[-3].split(":")[0] if len(parts) > 3 else "Unknown"
                }
                upload_to_cloud(db, alert_entry)

if __name__ == "__main__":
    try:
        monitor_snort_logs()
    except KeyboardInterrupt:
        print("Pusher service stopped")
