import os
import json
import firebase_admin
from firebase_admin import credentials
from django.apps import AppConfig


class MonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitor'

    def ready(self):
        # Singleton pattern: Initialize Firebase once when the Django server starts.
        if not firebase_admin._apps:
            firebase_key = os.environ.get("FIREBASE_KEY")
            cred = None
            
            if firebase_key:
                try:
                    key_dict = json.loads(firebase_key)
                    cred = credentials.Certificate(key_dict)
                except json.JSONDecodeError:
                    cred = credentials.Certificate(firebase_key)
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                cred_path = os.path.join(base_dir, "serviceAccountKey.json")
                if os.path.exists(cred_path):
                    cred = credentials.Certificate(cred_path)
                    
            if cred:
                firebase_admin.initialize_app(cred)
                print("[INFO] Firebase initialized successfully in apps.py (Singleton).")
