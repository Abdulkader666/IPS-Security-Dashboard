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
    initialize_firebase()
    alerts = []
    try:
        db = firestore.client()
        APP_ID = "ips_dashboard_v1"
        collection_path = f"artifacts/{APP_ID}/public/data/snort_alerts"
        
        
        docs = db.collection(collection_path).order_by("timestamp", direction=firestore.Query.DESCENDING).limit(20).stream()
        
        for doc in docs:
            data = doc.to_dict()
            
            display_time = "Just Now"
            if 'timestamp' in data and data['timestamp']:
                display_time = data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            
            alerts.append({
                "timestamp": display_time,
                "type": data.get("alert_msg", "Unknown Attack"),
                "priority": data.get("priority", "High"),
                "src": data.get("attacker_ip", "N/A"),
                "dst": "192.168.159.128", 
                "status": "DROPPED"
            })
    except Exception as e:
        print(f"Fetch Error: {e}")
    return alerts

def dashboard(request):
    alerts = get_alerts_from_cloud()
    context = {
        "alerts": alerts,
        "admin_name": "Abdulkader Maher Salim",
        "engine_status": "ACTIVE (CLOUD MONITORING)",
        "total_alerts": len(alerts),
    }
    return render(request, "monitor/dashboard.html", context)
