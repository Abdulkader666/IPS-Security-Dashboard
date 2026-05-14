import os
import json
import zoneinfo
import datetime
import psutil
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
        # 2. Unlimited fetch as per user request (ordered descending)
        docs = (
            db.collection(COLLECTION_PATH)
            .select(["timestamp", "alert_msg", "priority", "attacker_ip", "dst_ip"])
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .stream()
        )
        
        alerts = []
        for doc in docs:
            data = doc.to_dict()
            
            # Timestamp handling: Convert to Egypt/Cairo Timezone
            ts = data.get("timestamp")
            if ts:
                cairo_tz = zoneinfo.ZoneInfo("Africa/Cairo")
                ts_cairo = ts.astimezone(cairo_tz)
                ts_str = ts_cairo.strftime('%Y-%m-%d %H:%M:%S')
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
    
    # ── Real-time System Metrics ──
    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent
    
    # ── Dynamic Threat Level (Last 10 Mins) ──
    recent_alerts_count = 0
    now = datetime.datetime.now(zoneinfo.ZoneInfo("Africa/Cairo"))
    ten_mins_ago = now - datetime.timedelta(minutes=10)
    
    for a in alerts:
        if a['timestamp'] != "N/A":
            try:
                alert_time = datetime.datetime.strptime(a['timestamp'], '%Y-%m-%d %H:%M:%S')
                alert_time = alert_time.replace(tzinfo=zoneinfo.ZoneInfo("Africa/Cairo"))
                if alert_time >= ten_mins_ago:
                    recent_alerts_count += 1
            except Exception:
                pass
                
    if recent_alerts_count == 0:
        t_level = "LOW"
        t_color = "var(--green)"
        t_class = "sc-g"
        t_ic_class = "si-g"
        t_icon = "✅"
    elif 1 <= recent_alerts_count <= 5:
        t_level = "MODERATE"
        t_color = "var(--amber)"
        t_class = "sc-a"
        t_ic_class = "si-a"
        t_icon = "⚠️"
    else:
        t_level = "CRITICAL"
        t_color = "var(--red)"
        t_class = "sc-r"
        t_ic_class = "si-r"
        t_icon = "🚨"

    # Calculate type counts for the chart
    type_counts = {}
    for a in alerts:
        t = a['type']
        type_counts[t] = type_counts.get(t, 0) + 1
        
    latest_alert = alerts[0] if alerts else None
        
    context = {
        "alerts":        alerts,
        "admin_name":    "Abdulkader Maher Salim",
        "engine_status": "ACTIVE (CLOUD MONITORING)",
        "total_alerts":  len(alerts),
        "blocked_ips":   unique_ips,
        "cpu":           cpu_usage,
        "ram":           ram_usage,
        "threat_level":  t_level,
        "threat_color":  t_color,
        "threat_class":  t_class,
        "threat_ic_class": t_ic_class,
        "threat_icon":   t_icon,
        "type_counts":   json.dumps(type_counts),
        "latest_alert":  latest_alert,
    }
    return render(request, "monitor/dashboard.html", context)

def api_alerts(request):
    alerts     = get_alerts_from_cloud()
    unique_ips = len(set([a['src'] for a in alerts if a['src'] != 'N/A']))
    
    # ── Real-time System Metrics ──
    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent
    
    # ── Dynamic Threat Level (Last 10 Mins) ──
    recent_alerts_count = 0
    now = datetime.datetime.now(zoneinfo.ZoneInfo("Africa/Cairo"))
    ten_mins_ago = now - datetime.timedelta(minutes=10)
    
    for a in alerts:
        if a['timestamp'] != "N/A":
            try:
                alert_time = datetime.datetime.strptime(a['timestamp'], '%Y-%m-%d %H:%M:%S')
                alert_time = alert_time.replace(tzinfo=zoneinfo.ZoneInfo("Africa/Cairo"))
                if alert_time >= ten_mins_ago:
                    recent_alerts_count += 1
            except Exception:
                pass
                
    if recent_alerts_count == 0:
        t_level, t_color, t_class, t_ic_class, t_icon = "LOW", "var(--green)", "sc-g", "si-g", "✅"
    elif 1 <= recent_alerts_count <= 5:
        t_level, t_color, t_class, t_ic_class, t_icon = "MODERATE", "var(--amber)", "sc-a", "si-a", "⚠️"
    else:
        t_level, t_color, t_class, t_ic_class, t_icon = "CRITICAL", "var(--red)", "sc-r", "si-r", "🚨"

    type_counts = {}
    for a in alerts:
        t = a['type']
        type_counts[t] = type_counts.get(t, 0) + 1
        
    latest_alert = alerts[0] if alerts else None
        
    return JsonResponse({
        "alerts":      alerts,
        "total":       len(alerts),
        "blocked_ips": unique_ips,
        "cpu":         cpu_usage,
        "ram":         ram_usage,
        "threat_level": t_level,
        "threat_color": t_color,
        "threat_class": t_class,
        "threat_ic_class": t_ic_class,
        "threat_icon": t_icon,
        "type_counts": type_counts,
        "latest_alert": latest_alert,
    }, safe=False)
