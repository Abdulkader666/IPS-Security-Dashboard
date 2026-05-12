import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import pandas as pd

# Page Configuration
st.set_page_config(page_title="OortSec IPS Dashboard", layout="wide")

# Firebase Initialization
if not firebase_admin._apps:
    try:
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
    except Exception as e:
        st.error(f"Error connecting to Firebase: {e}")

db = firestore.client()

st.title("🛡️ OortSec - Real-time IPS Security Dashboard")
st.write("Monitoring live attacks blocked by Snort 3")

# Fetch Data
def get_alerts():
    APP_ID = "ips_dashboard_v1"
    collection_path = f"artifacts/{APP_ID}/public/data/snort_alerts"
    docs = db.collection(collection_path).order_by("timestamp", direction=firestore.Query.DESCENDING).limit(20).stream()
    
    data = []
    for doc in docs:
        d = doc.to_dict()
        data.append({
            "Time": d.get("timestamp", "N/A"),
            "Alert Message": d.get("alert_msg", "Unknown"),
            "Priority": d.get("priority", "Medium"),
            "Attacker IP": d.get("attacker_ip", "Unknown")
        })
    return data

# Display Table
alerts_data = get_alerts()
if alerts_data:
    df = pd.DataFrame(alerts_data)
    st.table(df)
else:
    st.info("No attacks detected yet. Waiting for Snort logs...")

# Auto Refresh button
if st.button('Refresh Data'):
    st.rerun()
