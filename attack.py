import streamlit as st
import pandas as pd
import time
import random
import requests  # Backend'e saldırı verisi göndermek için
from datetime import datetime

# --- YAPILANDIRMA ---
RENDER_SERVER_URL = "https://okaf-hackhathon-1.onrender.com"

ATTACK_SCENARIOS = {
    "SQL Injection": {
        "level": "Critical",
        "payloads": ["' OR 1=1 --", "UNION SELECT username, password FROM users", "'; DROP TABLE logs; --"],
        "target_service": "Customer Database",
        "mitre_id": "T1190",
        "cve_score": 9.8
    },
    "Brute Force": {
        "level": "High",
        "payloads": ["Admin/123456", "Root/toor", "User/password123"],
        "target_service": "SSH / Web Login",
        "mitre_id": "T1110",
        "cve_score": 7.5
    },
    "Man-in-the-Middle": {
        "level": "High",
        "payloads": ["ARP Spoofing initiated", "DNS Cache Poisoning", "SSL Stripping active"],
        "target_service": "Gateway / LAN",
        "mitre_id": "T1557",
        "cve_score": 8.1
    }
}

def send_attack_to_server(attack_type, payload, score):
    """Saldırıyı Render üzerindeki gerçek sunucuya iletir."""
    try:
        # Sunucudaki /api/attack endpoint'ini tetikler
        # Bu işlem belediye panelindeki ışıkları bozar
        requests.post(f"{RENDER_SERVER_URL}/api/attack", json={"active": True})
        
        # Ayrıca SOC paneline detaylı log düşmesi için mitigation endpointine de veri yollayabiliriz
        # veya backend'de bu veriyi işleyecek bir yapı kurabiliriz.
        return True
    except Exception as e:
        return False

def main():
    st.set_page_config(page_title="Red Team Attack Panel", layout="wide")
    
    # Koyu Tema (Hacker Modu)
    st.markdown("""<style> .stApp { background-color: #0b0d10; color: #00ff41; } </style>""", unsafe_allow_html=True)
    
    st.title("⚡ Red Team: Multi-Vector Attack Simulator")
    st.caption(f"Hedef Sunucu: {RENDER_SERVER_URL}")

    with st.sidebar:
        st.header("⚙️ Saldırı Kontrol Merkezi")
        selected_attack = st.selectbox("Saldırı Senaryosu Seç", list(ATTACK_SCENARIOS.keys()))
        intensity = st.slider("Saldırı Hızı (Saniye)", 0.5, 5.0, 2.0)
        is_active = st.toggle("SALDIRIYI BAŞLAT", value=False)
        
        if not is_active:
            # Saldırı durduğunda sunucuya normale dön komutu gönder
            try:
                requests.post(f"{RENDER_SERVER_URL}/api/attack", json={"active": False})
            except: pass

    # Oturum geçmişi
    if "attack_history" not in st.session_state:
        st.session_state.attack_history = []

    if is_active:
        payload = random.choice(ATTACK_SCENARIOS[selected_attack]["payloads"])
        cve = ATTACK_SCENARIOS[selected_attack]["cve_score"]
        
        # --- GERÇEK SUNUCUYA GÖNDER ---
        success = send_attack_to_server(selected_attack, payload, cve)
        
        new_event = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "source_ip": f"192.168.1.{random.randint(10, 254)}",
            "attack_type": selected_attack,
            "payload": payload,
            "cve_score": cve,
            "status": "SENT" if success else "FAILED"
        }
        
        st.session_state.attack_history.insert(0, new_event)
        if len(st.session_state.attack_history) > 50:
            st.session_state.attack_history.pop()

    # UI Düzeni
    col1, col2 = st.columns([1, 2])

    with col1:
        if is_active:
            st.error(f"🔥 SALDIRI AKTİF: {selected_attack}")
            st.warning(f"CVE Skoru: {ATTACK_SCENARIOS[selected_attack]['cve_score']}")
        else:
            st.success("Sistem Beklemede (Standby)")
            
        st.json(ATTACK_SCENARIOS[selected_attack])

    with col2:
        st.subheader("📡 Outbound Attack Logs (Giden Saldırı Trafiği)")
        if st.session_state.attack_history:
            df = pd.DataFrame(st.session_state.attack_history)
            st.dataframe(df, use_container_width=True, height=450)
        else:
            st.info("Saldırı paketleri gönderilmek üzere bekleniyor...")

    if is_active:
        time.sleep(intensity)
        st.rerun()

if __name__ == "__main__":
    main()
