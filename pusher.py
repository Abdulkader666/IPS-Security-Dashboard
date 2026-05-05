import time
import re
import os
import firebase_admin
from firebase_admin import credentials, firestore

# --- 1. إعداد الاتصال بـ Firebase ---
# ملاحظة: تأكد من أن ملف المفتاح (serviceAccountKey.json) موجود في نفس المجلد
KEY_FILE = "serviceAccountKey.json"

def initialize_cloud_connection():
    if not os.path.exists(KEY_FILE):
        print(f"❌ خطأ: ملف المفتاح '{KEY_FILE}' غير موجود!")
        print("💡 تأكد من نقل الملف من جهازك الرئيسي إلى مجلد المشروع في Kali.")
        return None
    
    try:
        cred = credentials.Certificate(KEY_FILE)
        firebase_admin.initialize_app(cred)
        print("✅ تم الاتصال بنجاح بقاعدة بيانات Firebase السحابية")
        return firestore.client()
    except Exception as e:
        print(f"❌ فشل الاتصال بالسحاب: {e}")
        return None

# --- 2. إعدادات المراقبة ---
LOG_FILE = "/var/log/snort/alert_fast.txt"
# هذا المعرف سيستخدمه Vercel أيضاً للوصول لنفس البيانات
APP_ID = "ips_dashboard_v1" 

def send_alert_to_cloud(db, alert_data):
    """إرسال التنبيه إلى Firestore في المسار المخصص"""
    try:
        # تحديد المسار في Firebase (نظام المجلدات السحابي)
        collection_path = f"artifacts/{APP_ID}/public/data/snort_alerts"
        # إضافة وثيقة جديدة مع توليد معرف تلقائي
        db.collection(collection_path).add(alert_data)
        print(f"🚀 تم رفع هجوم جديد: {alert_data['type']} من {alert_data['src_ip']}")
    except Exception as e:
        print(f"❌ خطأ أثناء الرفع للسحاب: {e}")

def start_monitoring(db):
    print(f"👀 جاري مراقبة ملف {LOG_FILE} لرصد أي اختراقات...")
    
    # تعبير منتظم (Regex) لتحليل أسطر Snort وتحويلها لبيانات
    # المثال: [**] [1:1000002:1] ICMP Packet Blocked [**] ... 192.168.1.5 -> 192.168.1.10
    pattern = re.compile(r"\[\*\*\] \[(\d+:\d+:\d+)\]\s+(.*?)\s+\[\*\*\]\s+.*?([\d\.]+).*?->\s+([\d\.]+)")

    # فتح الملف والذهاب لآخره لمراقبة الأسطر الجديدة فقط (Tail -f)
    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1) # انتظر ثانية واحدة إذا لم يوجد سطر جديد
                continue
            
            match = pattern.search(line)
            if match:
                alert = {
                    "sid": match.group(1),
                    "type": match.group(2).strip(),
                    "src_ip": match.group(3),
                    "dst_ip": match.group(4),
                    "timestamp": firestore.SERVER_TIMESTAMP, # وقت السيرفر السحابي لضمان الدقة
                    "status": "DROPPED"
                }
                send_alert_to_cloud(db, alert)

if __name__ == "__main__":
    # 1. إعطاء صلاحيات القراءة لملف السجلات
    os.system(f"sudo chmod 644 {LOG_FILE}")
    
    # 2. بدء الاتصال
    db_client = initialize_cloud_connection()
    
    if db_client:
        # 3. بدء المراقبة المستمرة
        try:
            start_monitoring(db_client)
        except KeyboardInterrupt:
            print("\n👋 تم إيقاف ناقل البيانات.")
