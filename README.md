# 🚦 TRAFFIC FILTER -- by CYBERFILTER 

![Build Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Tech](https://img.shields.io/badge/Tech-Industrial%20IoT-blue)
![Security](https://img.shields.io/badge/Security-Self--Healing-red)

Bu proje, modern akıllı şehirlerdeki kritik trafik sinyalizasyon altyapısının **Modbus TCP** protokolü üzerinden yönetimini ve bu altyapıya yönelik siber tehditlerin **gerçek zamanlı (Real-time)** tespiti ile **otomatik mitigasyon (Self-Healing)** süreçlerini simüle eden uçtan uca bir ekosistemdir.

---

## 🏛️ Sistem Mimarisi

Proje, birbirine entegre üç ana katmandan ve bir siber saldırı simülatöründen oluşmaktadır:

### 1. Belediye Operatör Paneli (Operational Technology - OT)
*   **Arayüz:** Saha operatörleri için tasarlanmış canlı izleme dashboard'u.
*   **Yetenekler:** Kavşak durumu takibi, araç yoğunluk verileri ve **Yeşil Dalga (40-70 km/s)** hız tavsiye algoritması.
*   **Platform:** Vercel

### 2. Siber Savunma Merkezi (SOC/SOAR)
*   **Arayüz:** Güvenlik analistleri için olay müdahale ve tehdit avcılığı ekranı.
*   **Yetenekler:** Canlı log akışı, **CVE-2026** veritabanı eşleştirmesi, otomatik IP karantinası ve mitigasyon animasyonları.
*   **Platform:** Vercel

### 3. Merkezi Backend & Haberleşme
*   **Motor:** Express.js ve Socket.io tabanlı yüksek hızlı veri dağıtım katmanı.
*   **Protokol:** Modbus TCP simülasyonu ve anomali tespit motoru.
*   **Platform:** Render

### 4. Red Team Saldırı Simülatörü
*   **Teknoloji:** Streamlit (Python)
*   **İşlev:** MITM (Man-in-the-Middle), SQL Injection ve Paket Manipülasyonu saldırılarını başlatır.

---

## 🛡️ Siber Güvenlik Akışı (SOAR Playbook)

Sistem bir saldırı algıladığında aşağıdaki **otomatik savunma** adımlarını izler:

| Faz | İşlem | Teknik Detay |
| :--- | :--- | :--- |
| 🔍 **Tespit** | Anomali Analizi | Modbus paketindeki geçersiz yazma (Write Single Coil) istekleri yakalanır. |
| 📊 **Analiz** | CVE Eşleştirme | Tespit edilen tehdit, CVSS 9.8 skoruyla veritabanında sınıflandırılır. |
| 🚫 **Müdahale** | Otomatik Ban | Saldırgan IP adresi firewall katmanında (Software Defined) engellenir. |
| ✨ **Onarım** | Self-Healing | Sistem, manipüle edilen verileri temizleyerek trafik akışını güvenli moda döndürür. |

---

## 🛠️ Kullanılan Teknolojiler

*   **Frontend:** HTML5, CSS3 (Modern Siber Panel Tasarımı), JavaScript (ES6+)
*   **Backend:** Node.js, Socket.io (Real-time WebSockets), JsModbus
*   **Simulator:** Python, Streamlit, Requests
*   **Deployment:** Vercel (Frontend), Render (Backend)

---

## 📂 Proje Dosya Yapısı

```text
├── server.js           # Ana sunucu, WebSocket ve API yönetimi (Render)
├── index.html          # Belediye Trafik İzleme Dashboard'u (Vercel)
├── socserver.html      # Siber Savunma (SOC/SOAR) Dashboard'u (Vercel)
├── attack.py           # Red Team Saldırı Paneli (Python/Streamlit)
├── package.json        # Node.js bağımlılıkları ve konfigürasyonu
└── README.md           # Proje dökümantasyonu
