import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
from google.api_core.exceptions import GoogleAPIError
from django.shortcuts import render
from django.http import JsonResponse

# ── Firebase is initialized in apps.py (Singleton Pattern) ──
def get_firestore_client():
    try:
        # Get the already initialized client
        return firestore.client()
    except ValueError:
        print("[ERROR] Firestore client not initialized. Ensure apps.py has run.")
        return None

def get_alerts_from_cloud():
    db = get_firestore_client()
    if not db:
        return []
        
    try:
        COLLECTION_PATH = "artifacts/ips_dashboard_v1/public/data/snort_alerts"
        # ── Memory Optimization ──
        # 1. Use .select() to only retrieve the fields we actually need.
        # 2. Limit to 10 recent documents since dashboard frequently polls and shows limited rows.
        docs = (
            db.collection(COLLECTION_PATH)
            .select(["timestamp", "alert_msg", "priority", "attacker_ip", "dst_ip"])
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(10)
            .stream()
        )
        
        alerts = []
        for doc in docs:
            data = doc.to_dict()
            
            # Timestamp handling: Firestore returns DatetimeWithNanoseconds
            # This must be formatted to string, otherwise JsonResponse will fail (not JSON serializable)
            ts = data.get("timestamp")
            if ts:
                ts_str = ts.strftime('%Y-%m-%d %H:%M:%S')
            else:
                ts_str = "N/A"
                
            alerts.append({
                "timestamp": ts_str,
                "type":      data.get("alert_msg", "Unknown Attack"),
                "priority":  data.get("priority", "High"),
                "src":       data.get("attacker_ip", "N/A"),
                "dst":       data.get("dst_ip", "192.168.159.128"),
                "status":    "DROPPED",
            })
            
        return alerts

    except GoogleAPIError as e:
        print(f"[ERROR] Firestore API error: {e}")
        return []
    except Exception as e:
        print(f"[ERROR] Fetch Error: {e}")
        return []

def dashboard(request):
    alerts     = get_alerts_from_cloud()
    unique_ips = len(set([a['src'] for a in alerts if a['src'] != 'N/A']))
    
    # Calculate type counts for the chart
    type_counts = {}
    for a in alerts:
        t = a['type']
        type_counts[t] = type_counts.get(t, 0) + 1
        
    context = {
        "alerts":        alerts,
        "admin_name":    "Abdulkader Maher Salim",
        "engine_status": "ACTIVE (CLOUD MONITORING)",
        "total_alerts":  len(alerts),
        "blocked_ips":   unique_ips,
        "cpu":           12, # Static placeholder as in original
        "ram":           45, # Static placeholder as in original
        "type_counts":   json.dumps(type_counts),
    }
    return render(request, "monitor/dashboard.html", context)

def api_alerts(request):
    alerts     = get_alerts_from_cloud()
    unique_ips = len(set([a['src'] for a in alerts if a['src'] != 'N/A']))
    
    type_counts = {}
    for a in alerts:
        t = a['type']
        type_counts[t] = type_counts.get(t, 0) + 1
        
    return JsonResponse({
        "alerts":      alerts,
        "total":       len(alerts),
        "blocked_ips": unique_ips,
        "cpu":         12,
        "ram":         45,
        "type_counts": type_counts,
    }, safe=False)
