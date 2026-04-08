import streamlit as st
import pandas as pd
import socketio
import threading
from datetime import datetime

# --- KONFİGÜRASYON ---
RENDER_SERVER_URL = "https://okaf-hackhathon-1.onrender.com"

# Sayfa Ayarları
st.set_page_config(page_title="SOC Vision Dashboard", layout="wide")

# --- SOCKET.IO İSTEMCİSİ ---
# Streamlit her etkileşimde kodu baştan çalıştırdığı için 
# socket bağlantısını 'session_state' içinde saklıyoruz.
if "socket" not in st.session_state:
    st.session_state.socket = socketio.Client()
    st.session_state.events = [] # Gelen olayları burada biriktireceğiz

def connect_socket():
    sio = st.session_state.socket
    
    @sio.on('traffic-update')
    def on_message(data):
        # Yeni veriyi listenin başına ekle (en güncel en üstte)
        data['received_at'] = datetime.now().strftime("%H:%M:%S")
        st.session_state.events.insert(0, data)
        # Belleği şişirmemek için son 100 kaydı tut
        if len(st.session_state.events) > 100:
            st.session_state.events.pop()

    @sio.on('security-alert')
    def on_alert(data):
        st.toast(f"🚨 GÜVENLİK ALARMI: {data.get('networkSecurity')}", icon="⚠️")

    try:
        if not sio.connected:
            sio.connect(RENDER_SERVER_URL)
    except Exception as e:
        print(f"Bağlantı hatası: {e}")

# Bağlantıyı arka planda başlat
if not st.session_state.socket.connected:
    connect_socket()

# --- DASHBOARD ARAYÜZÜ ---

st.title("SOC Vision: Real-Time Threat Operations")
st.caption(f"📍 Bağlı Sunucu: {RENDER_SERVER_URL}")

# Sidebar - Saldırı Simülasyonu Tetikleme
with st.sidebar:
    st.header("Saldırı Kontrolü")
    if st.button("MITM Saldırısını Başlat", type="primary"):
        try:
            import requests
            requests.post(f"{RENDER_SERVER_URL}/api/attack", json={"active": True})
            st.warning("Saldırı komutu gönderildi!")
        except:
            st.error("Sunucuya ulaşılamadı.")
            
    if st.button("Sistemi Normale Döndür"):
        try:
            import requests
            requests.post(f"{RENDER_SERVER_URL}/api/attack", json={"active": False})
            st.success("Normalleşme komutu gönderildi.")
        except:
            st.error("Sunucuya ulaşılamadı.")

    if st.button("Kayıtları Temizle"):
        st.session_state.events = []
        st.rerun()

# Veri Hazırlama
df = pd.DataFrame(st.session_state.events)

# Metrikler
col1, col2, col3, col4 = st.columns(4)
total_ev = len(df)
critical_ev = len(df[df['light'] == 'glitch']) if not df.empty else 0
mitm_status = "SALDIRI ALTINDA" if critical_ev > 0 else "GÜVENLİ"

col1.metric("Toplam Olay", total_ev)
col2.metric("Kritik Uyarılar", critical_ev, delta_color="inverse")
col3.metric("Ağ Durumu", mitm_status)
col4.metric("Aktif Sensörler", "4")

# Görselleştirmeler
left, right = st.columns([1.5, 1])

with left:
    st.subheader("Canlı Akış (Live Stream)")
    if not df.empty:
        # Görünümü güzelleştirme
        display_df = df[['received_at', 'light', 'timer', 'carCount', 'networkSecurity']]
        st.dataframe(display_df, use_container_width=True, height=400)
    else:
        st.info("Sunucudan veri bekleniyor...")

with right:
    st.subheader("Tehdit Analizi")
    if not df.empty:
        # Işık durumuna göre grafik
        chart_data = df['light'].value_counts()
        st.bar_chart(chart_data)
        
        # Güvenlik Skoru (Simüle edilmiş)
        score = 20 if mitm_status == "SALDIRI ALTINDA" else 95
        st.select_slider("Sistem Güvenlik Skoru", options=range(0, 101), value=score, disabled=True)
    else:
        st.write("Veri yok.")

# Otomatik Yenileme (Streamlit'in canlı kalması için)
if st.session_state.socket.connected:
    st.empty()
    import time
    time.sleep(1)
    st.rerun()
