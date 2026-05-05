# monitor/views.py
import re
import os
import json
from django.shortcuts import render
from django.http import JsonResponse

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ======================================================
# مسار ملف لوج Snort — غيّره إذا كان مختلفاً عندك
# ======================================================
LOG_FILE = "/var/log/snort/alert_fast.txt"


def classify_attack(message):
    """تصنيف نوع الهجوم بناءً على رسالة Snort"""
    msg = message.lower()
    if 'icmp' in msg or 'ping' in msg:
        return 'ICMP Ping Probe'
    elif 'nmap' in msg or 'syn scan' in msg or 'portscan' in msg:
        return 'Nmap SYN Scan'
    elif 'ssh' in msg or 'brute' in msg:
        return 'SSH Brute Force'
    elif 'http' in msg or 'web' in msg:
        return 'HTTP Attack'
    else:
        return message[:40]  # أول 40 حرف من الرسالة الأصلية


def get_snort_alerts():
    """
    قراءة ملف Snort وتحويله إلى قائمة من التنبيهات.
    صيغة Snort Fast Alert:
      [**] [1:1000001:1] Message [**]
      [Priority: 1] {TCP} 1.1.1.1:80 -> 2.2.2.2:80
      MM/DD-HH:MM:SS.ffffff
    """
    alerts = []

    if not os.path.exists(LOG_FILE):
        return [{
            "timestamp": "N/A",
            "sid": "N/A",
            "type": "no log _ check it Snort",
            "proto": "N/A",
            "src": "N/A",
            "dst": "N/A",
            "status": "ERROR"
        }]

    # -------------------------------------------------------
    # Regex يستخرج:
    #   group(1) → timestamp   e.g. 01/15-14:23:05.123456
    #   group(2) → SID         e.g. 1:1000001:1
    #   group(3) → message     e.g. ICMP Ping Detected
    #   group(4) → priority    e.g. 1
    #   group(5) → protocol    e.g. TCP
    #   group(6) → src IP      e.g. 192.168.1.5
    #   group(7) → dst IP      e.g. 10.0.0.1
    # -------------------------------------------------------
    pattern = re.compile(
        r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)'   # timestamp
        r'.*?\[\*\*\] \[(\d+:\d+:\d+)\]\s+'         # SID
        r'(.*?)\s+\[\*\*\]'                          # message
        r'.*?\[Priority:\s*(\d+)\]'                  # priority
        r'\s+\{(\w+)\}\s+'                           # protocol
        r'([\d\.]+).*?->\s*([\d\.]+)',               # src -> dst
        re.DOTALL
    )

    try:
        with open(LOG_FILE, "r") as f:
            content = f.read()

        # Snort يفصل التنبيهات بسطر فارغ
        raw_alerts = content.strip().split('\n\n')

        for block in raw_alerts[-50:]:   # آخر 50 تنبيه
            match = pattern.search(block)
            if match:
                alerts.append({
                    "timestamp": match.group(1),     # الوقت الحقيقي
                    "sid":       match.group(2),
                    "type":      classify_attack(match.group(3)),
                    "priority":  match.group(4),
                    "proto":     match.group(5),
                    "src":       match.group(6),
                    "dst":       match.group(7),
                    "status":    "DROPPED"
                })

    except Exception as e:
        print(f"[IPS] خطأ في قراءة اللوج: {e}")

    return alerts[::-1]  # الأحدث أولاً


def get_system_stats():
    """جلب إحصائيات النظام الحقيقية عبر psutil"""
    if PSUTIL_AVAILABLE:
        return {
            "cpu": round(psutil.cpu_percent(interval=0.5)),
            "ram": round(psutil.virtual_memory().percent),
        }
    return {"cpu": 0, "ram": 0}


def get_summary(alerts):
    """حساب ملخص الإحصائيات للداشبورد"""
    blocked_ips = list({a["src"] for a in alerts if a["src"] != "N/A"})
    type_counts = {}
    for a in alerts:
        t = a["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
    return {
        "total":       len(alerts),
        "blocked_ips": len(blocked_ips),
        "ip_list":     blocked_ips[:10],          # أول 10 فقط
        "type_counts": type_counts,               # للـ Chart
    }


# ================================================================
#  View 1 — الصفحة الرئيسية (Django Template)
# ================================================================
def dashboard(request):
    alerts  = get_snort_alerts()
    stats   = get_system_stats()
    summary = get_summary(alerts)

    context = {
        "alerts":       alerts,
        "admin_name":   "Abdulkader Maher Salim",
        "engine_status": "ACTIVE (INLINE MODE)",
        "cpu":          stats["cpu"],
        "ram":          stats["ram"],
        "total_alerts": summary["total"],
        "blocked_ips":  summary["blocked_ips"],
        "type_counts":  json.dumps(summary["type_counts"]),  # للـ Chart.js
    }
    return render(request, "monitor/dashboard.html", context)


# ================================================================
#  View 2 — API endpoint  →  GET /api/alerts/
#  يُعيد JSON — يُستخدم من قِبَل fetch() في الـ Frontend
# ================================================================
def api_alerts(request):
    alerts  = get_snort_alerts()
    stats   = get_system_stats()
    summary = get_summary(alerts)

    data = {
        "alerts":      alerts,
        "total":       summary["total"],
        "blocked_ips": summary["blocked_ips"],
        "cpu":         stats["cpu"],
        "ram":         stats["ram"],
        "type_counts": summary["type_counts"],
    }
    return JsonResponse(data, safe=False)
