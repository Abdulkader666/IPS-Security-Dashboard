import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
from django.shortcuts import render
from django.http import JsonResponse

def initialize_firebase():
    if not firebase_admin._apps:
        try:
            firebase_key = os.environ.get("FIREBASE_KEY")
            if firebase_key:
                key_dict = json.loads(firebase_key)
                cred = credentials.Certificate(key_dict)
                firebase_admin.initialize_app(cred)
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                cred_path = os.path.join(base_dir, "serviceAccountKey.json")
                if os.path.exists(cred_path):
                    cred = credentials.Certificate(cred_path)
                    firebase_admin.initialize_app(cred)
        except Exception as e:
            print(f"Firebase Init Error: {e}")

def get_alerts_from_cloud():
    try:
        initialize_firebase()
        if not firebase_admin._apps:
            return []
        
        db = firestore.client()
        APP_ID = "ips_dashboard_v1"
        collection_path = f"artifacts/{APP_ID}/public/data/snort_alerts"
        
        # ── Timeout 5 ثوانٍ بدل ما ينتظر للأبد ──
        import concurrent.futures
        def fetch():
            docs = db.collection(collection_path).order_by(
                "timestamp", direction=firestore.Query.DESCENDING
            ).limit(20).stream()
            alerts = []
            for doc in docs:
                data = doc.to_dict()
                display_time = "N/A"
                if data.get('timestamp'):
                    display_time = data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                alerts.append({
                    "timestamp": display_time,
                    "type":     data.get("alert_msg", "Unknown Attack"),
                    "priority": data.get("priority", "High"),
                    "src":      data.get("attacker_ip", "N/A"),
                    "dst":      "192.168.159.128",
                    "status":   "DROPPED",
                })
            return alerts

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(fetch)
            return future.result(timeout=5)  # ← 5 ثوانٍ كحد أقصى

    except concurrent.futures.TimeoutError:
        print("Firebase timeout — returning empty")
        return []
    except Exception as e:
        print(f"Fetch Error: {e}")
        return []

def dashboard(request):
    alerts  = get_alerts_from_cloud()
    unique_ips = len(set([a['src'] for a in alerts if a['src'] != 'N/A']))
    context = {
        "alerts":        alerts,
        "admin_name":    "Abdulkader Maher Salim",
        "engine_status": "ACTIVE (CLOUD MONITORING)",
        "total_alerts":  len(alerts),
        "blocked_ips":   unique_ips,
        "cpu":           12,
        "ram":           45,
        "type_counts":   json.dumps({}),
    }
    return render(request, "monitor/dashboard.html", context)

# ← هذا كان ناقص!
def api_alerts(request):
    alerts = get_alerts_from_cloud()
    unique_ips = len(set([a['src'] for a in alerts if a['src'] != 'N/A']))
    return JsonResponse({
        "alerts":      alerts,
        "total":       len(alerts),
        "blocked_ips": unique_ips,
        "cpu":         12,
        "ram":         45,
        "type_counts": {},
    }, safe=False)
