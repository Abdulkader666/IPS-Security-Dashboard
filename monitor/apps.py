import os
import json
import firebase_admin
from firebase_admin import credentials
from django.apps import AppConfig


class MonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitor'

    def ready(self):
        # Local Singleton pattern: Initialize Firebase once using the local key.
        if not firebase_admin._apps:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cred_path = os.path.join(base_dir, "serviceAccountKey.json")
            
            if os.path.exists(cred_path):
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
                print(f"[INFO] Local Firebase initialized using {cred_path}")
            else:
                print(f"[ERROR] Local Firebase credentials not found at {cred_path}")
