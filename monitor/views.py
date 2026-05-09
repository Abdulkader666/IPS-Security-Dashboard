import os
import json
import firebase_admin
from firebase_admin import credentials, firestore
from django.shortcuts import render
from django.http import JsonResponse

# --- 1. إعداد الاتصال بـ Firebase (مرة واحدة فقط) ---
def initialize_firebase():
    if not firebase_admin._apps:
        try:
            # البحث عن الملف في المجلد الرئيسي للمشروع على Vercel
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cred_path = os.path.join(base_dir, "serviceAccountKey.json")
            
            if os.path.exists(cred_path):
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
        except Exception as e:
            print(f"Firebase Init Error: {e}")

# --- 2. جلب البيانات من السحاب ---
def get_alerts_from_cloud():
    initialize_firebase()
    alerts = []
    try:
        db = firestore.client()
        APP_ID = "ips_dashboard_v1"
        # المسار الذي يرسل إليه الـ Pusher في كودك السابق
        collection_path = f"artifacts/{APP_ID}/public/data/snort_alerts"
        
        # جلب آخر 50 تنبيه مرتبة من الأحدث للأقدم
        docs = db.collection(collection_path).order_by("timestamp", direction=firestore.Query.DESCENDING).limit(50).stream()
        
        for doc in docs:
            data = doc.to_dict()
            # تحويل التوقيت السحابي لشكل مقروء
            if 'timestamp' in data and data['timestamp']:
                data['timestamp'] = data['timestamp'].strftime('%m/%d-%H:%M:%S')
            
            # التأكد من وجود الحقول المطلوبة لكي لا ينهار الـ Template
            alerts.append({
                "timestamp": data.get("timestamp", "N/A"),
                "type": data.get("alert_msg", "Unknown Attack"),
                "priority": data.get("priority", "1"),
                "src": data.get("attacker_ip", "N/A"),
                "dst": "192.168.159.128", # IP الكالي الخاص بك
                "status": "DROPPED",
                "proto": "ICMP"
            })
    except Exception as e:
        print(f"Cloud fetch error: {e}")
    
    return alerts

# --- 3. الـ Views الأساسية ---
def dashboard(request):
    alerts = get_alerts_from_cloud()
    
    # حساب الإحصائيات (Summary)
    total_alerts = len(alerts)
    unique_ips = len(set([a['src'] for a in alerts if a['src'] != 'N/A']))
    
    # إحصائيات وهمية للـ CPU/RAM لأن Vercel سيرفر خارجي
    context = {
        "alerts": alerts,
        "admin_name": "Abdulkader Maher Salim",
        "engine_status": "ACTIVE (CLOUD MONITORING)",
        "cpu": 12, # قيم ثابتة لجمال التصميم
        "ram": 45,
        "total_alerts": total_alerts,
        "blocked_ips": unique_ips,
        "type_counts": json.dumps({"ICMP Ping Probe": total_alerts}), # للـ Chart
    }
    return render(request, "monitor/dashboard.html", context)

def api_alerts(request):
    alerts = get_alerts_from_cloud()
    data = {
        "alerts": alerts,
        "total": len(alerts),
        "cpu": 12,
        "ram": 45,
    }
    return JsonResponse(data, safe=False)
