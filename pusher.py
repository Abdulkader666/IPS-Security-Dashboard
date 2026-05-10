import time
import os
import firebase_admin
from firebase_admin import credentials, firestore

KEY_PATH = "serviceAccountKey.json"
APP_ID   = "ips_dashboard_v1"

def initialize_firebase():
    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate(KEY_PATH)
            firebase_admin.initialize_app(cred)
            print("[OORT SEC] ✅ Firebase connected")
        return firestore.client()
    except Exception as e:
        print(f"[OORT SEC] ❌ Firebase error: {e}")
        return None

def parse_line(line):
    try:
        # ── الوقت ──
        timestamp = line.split()[0]

        # ── رسالة الهجوم ──
        # السطر: ... [**] [1:1000002:1] "ICMP Blocked by Snort 3" [**] ...
        msg = line.split('[**]')[1].strip()
        if ']' in msg:
            msg = msg.split(']')[-1].strip().strip('"')

        # ── IP ──
        src_ip = line.split('->')[0].split()[-1].split(':')[0]
        dst_ip = line.split('->')[-1].strip().split(':')[0]

        # ── Protocol ──
        proto = line.split('{')[1].split('}')[0] if '{' in line else 'UNKNOWN'

        # ── Priority ──
        priority = "High" if "Priority: 1" in line else "Medium"

        return {
            "alert_msg":   msg,
            "attacker_ip": src_ip,
            "dst_ip":      dst_ip,
            "proto":       proto,
            "priority":    priority,
            "raw_log":     line.strip(),
        }
    except Exception as e:
        print(f"[OORT SEC] ⚠ Parse error: {e} | line: {line.strip()[:60]}")
        return None

def upload_alert(db, data):
    try:
        path = f"artifacts/{APP_ID}/public/data/snort_alerts"
        data['timestamp'] = firestore.SERVER_TIMESTAMP
        db.collection(path).add(data)
        print(f"[OORT SEC] ✅ Pushed: {data['alert_msg']} from {data['attacker_ip']}")
    except Exception as e:
        print(f"[OORT SEC] ❌ Upload error: {e}")

def monitor():
    db = initialize_firebase()
    if not db:
        return

    log_path = "/var/log/snort/alert_fast.txt"
    while not os.path.exists(log_path):
        print(f"[OORT SEC] ⏳ Waiting for {log_path}...")
        time.sleep(3)

    print(f"[OORT SEC] 👁  Watching: {log_path}")
    with open(log_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            if '[**]' not in line:
                continue

            alert = parse_line(line)
            if alert:
                upload_alert(db, alert)

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[OORT SEC] Pusher stopped.")
