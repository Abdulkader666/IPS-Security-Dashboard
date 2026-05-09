import os
import json
import requests
import google.auth
import google.auth.transport.requests
from google.oauth2 import service_account
from django.shortcuts import render
from django.http import JsonResponse

# ── توليد Access Token من Service Account ──
def get_access_token():
    firebase_key = os.environ.get("FIREBASE_KEY")
    if not firebase_key:
        # محلياً من الملف
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cred_path = os.path.join(base_dir, "serviceAccountKey.json")
        with open(cred_path) as f:
            firebase_key = f.read()
    
    key_dict = json.loads(firebase_key)
    creds = service_account.Credentials.from_service_account_info(
        key_dict,
        scopes=["https://www.googleapis.com/auth/datastore"]
    )
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token, key_dict["project_id"]

def get_alerts_from_cloud():
    try:
        token, project_id = get_access_token()
        APP_ID = "ips_dashboard_v1"
        
        # ── REST API مباشرة بدل SDK ──
        url = (
            f"https://firestore.googleapis.com/v1/"
            f"projects/{project_id}/databases/(default)/documents/"
            f"artifacts/{APP_ID}/public/data/snort_alerts"
            f"?orderBy=timestamp desc&pageSize=20"
        )
        
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5  # ← 5 ثوانٍ صارمة
        )
        
        if resp.status_code != 200:
            print(f"Firestore error: {resp.text}")
            return []
        
        data = resp.json()
        documents = data.get("documents", [])
        
        alerts = []
        for doc in documents:
            fields = doc.get("fields", {})
            
            # استخراج الحقول من صيغة Firestore REST
            timestamp = fields.get("timestamp", {}).get("timestampValue", "N/A")
            if timestamp != "N/A":
                timestamp = timestamp[:19].replace("T", " ")
            
            alerts.append({
                "timestamp": timestamp,
                "type":     fields.get("alert_msg",    {}).get("stringValue", "Unknown Attack"),
                "priority": fields.get("priority",     {}).get("stringValue", "High"),
                "src":      fields.get("attacker_ip",  {}).get("stringValue", "N/A"),
                "dst":      "192.168.159.128",
                "status":   "DROPPED",
            })
        
        return alerts

    except requests.Timeout:
        print("Firestore REST timeout")
        return []
    except Exception as e:
        print(f"Fetch Error: {e}")
        return []

def dashboard(request):
    alerts     = get_alerts_from_cloud()
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

def api_alerts(request):
    alerts     = get_alerts_from_cloud()
    unique_ips = len(set([a['src'] for a in alerts if a['src'] != 'N/A']))
    return JsonResponse({
        "alerts":      alerts,
        "total":       len(alerts),
        "blocked_ips": unique_ips,
        "cpu":         12,
        "ram":         45,
        "type_counts": {},
    }, safe=False)
