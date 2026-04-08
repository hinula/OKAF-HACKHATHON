# CYBERFİLTER Akıllı trafik ışıkları SOAR system

## 🎯 Proje Özeti

CYBERFİLTER tarafından yapılan akıllı trafik ışıkları için geliştirilmiş profesyonel bir siber savunma platformudur.

## ✨ Özellikler

### 🛡️ Otomatik Savunma Merkezi
- **Gerçek Zamanlı Saldırı Tespiti**: CVE skorlarına dayalı otomatik tehdit analizi
- **Otomatik IP Banlama**: 7.0+ CVE skorunda otomatik engelleme
- **Manuel Müdahale**: Admin panelinden IP ban/unban işlemleri
- **Kendini Onarma**: Saldırı sonrası otomatik sistem kurtarma

### 📊 CVE Veritabanı & Raporlama
- **5 Kritik CVE** kategorize edilmiş ve puanlandırılmış
- **MITRE ATT&CK** framework entegrasyonu
- **Detaylı CVE Kartları**: Servis, saldırı tipi, exploitability bilgileri
- **Renk Kodlu Skorlama**: 9.0+ Kritik (Kırmızı), 7.0-8.9 Yüksek (Turuncu), 4.0-6.9 Orta (Sarı)

### 📟 Canlı Log Akışı
- **Gerçek Zamanlı Log Streaming**: Socket.IO ile anlık log görüntüleme
- **500 Log Buffer**: Otomatik sıralama ve yönetim
- **7 Kolon Detay**: Timestamp, Severity, Category, Message, IP, Action, CVE
- **Renk Kodlu Severity**: CRITICAL (Kırmızı), HIGH (Turuncu), MEDIUM (Sarı), LOW (Yeşil)

### ⚡ Rate Limiting & Cooldown
- **100 İstek/Saniye Limiti**: Aşım durumunda 5 dakika cooldown
- **Görsel İlerleme Çubukları**: IP bazında trafik izleme
- **Otomatik Throttling**: DDoS koruması

### 🚨 Kritik Durum Pop-up
- **Trafik Işığı Alarm Sistemi**: 9.0+ CVE skorunda otomatik popup
- **Acil Müdahale Butonu**: Tek tıkla saldırıyı engelleme
- **Görsel Alarm**: Yanıp sönen polis ışığı animasyonu

### 🚦 Tehdit Seviye Göstergesi
- **4 Seviye Monitoring**: SECURE, ELEVATED, HIGH, CRITICAL
- **Dinamik Banner**: Gerçek zamanlı durum güncellemesi
- **Renk Kodlu Uyarılar**: Görsel tehdit seviyelendirme

## 📁 Dosya Yapısı

```
OKAF-HACKHATHON/
│
├── server-fixed.js          
├── socserver-fixed.html     
├── index.html               
│
├── package.json             
├── attack.py                
└── README-SETUP.md          
```

## 🚀 Kurulum

### 1. Gereksinimler

```bash
- Node.js 
- npm 
- (Opsiyonel) Python 3 (Saldırı testleri için)
```

### 2. Backend Kurulumu

```bash
# Bağımlılıkları yükle
npm install

# Server'ı başlat
node server.js

# veya
npm start
```
##Şu sitelerden ulaşabilirsiniz
````
https://okaf-hackhathon.vercel.app/socserver.html = soc panel
https://okaf-hackhathon.vercel.app/= Belediyedeki bir çalışanın gördüğü trafik ışığı paneli
https://okaf-hackhathon-pzdvnr4d58peadaatbanhy.streamlit.app/ = Red team panel (saldırı başlatma)
````
### ✅ Çözümler

#### 1. Backend (server-fixed.js)

**Eklenen API Endpoint'leri:**
- ✅ `GET /api/logs` - Log geçmişi
- ✅ `GET /api/banned-ips` - Banlı IP listesi
- ✅ `POST /api/unban` - IP ban kaldırma
- ✅ `GET /api/rate-status` - Rate limit durumu
- ✅ `GET /api/cve-database` - CVE veritabanı
- ✅ `GET /api/stats` - Sistem istatistikleri
- ✅ `POST /api/clear-bans` - Tüm banları temizle
- ✅ `POST /api/clear-logs` - Log geçmişini temizle

**Özellikler:**
  - IP ban kontrolü
  - Rate limiting (100 req/s)
  - 5 dakika cooldown mekanizması
  - IP spoofing koruması
  
- 📊 Log Sistemi
  - 500 log buffer
  - Gerçek zamanlı Socket.IO streaming
  - 7 log kategorisi: severity, category, source, message, ip, action, cveId
  
- 🗄️ CVE Database
  - 5 pre-loaded CVE (CRITICAL to MEDIUM)
  - MITRE ATT&CK ID'leri
  - Vector ve exploitability bilgileri
  
- ⚡ Rate Limiting
  - Per-IP tracking
  - Cooldown sistemi
  - Görsel progress bar verisi

**Yeni Özellikler:**
- 🎨 Geliştirilmiş UI/UX
- 🔄 Gerçek zamanlı Socket.IO event handlers
- 📱 Responsive tasarım
- 🚨 Kritik saldırı popup (police-popup)
- 📊 CVE kartları (tıkla-genişlet)
- ⚡ Rate limiting görselleştirmesi
- 🍞 Toast bildirimleri

## 🎮 Kullanım Senaryoları

### Senaryo 1: Manuel IP Banlama

1. SOC Dashboard'u aç
2. "Otomatik Savunma Merkezi" kartında IP gir
3. "BAN" butonuna tıkla
4. IP anında banlanır ve tabloda görünür

### Senaryo 2: Saldırı Simülasyonu

attack.py ile

**Beklenen Sonuçlar:**
- ✅ Trafik ışıkları "glitch" moduna geçer
- ✅ Tehdit seviyesi "CRITICAL" olur
- ✅ Pop-up görünür (CVE >= 9.0)
- ✅ Logda "ATTACK_DETECTED" kaydı oluşur



## 📊 API Endpoint'leri

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/attack` | Saldırı simülasyonu tetikle |
| POST | `/api/mitigate` | Saldırıyı engelle/IP banla |
| POST | `/api/unban` | IP ban'ı kaldır |
| GET | `/api/banned-ips` | Banlı IP listesi |
| GET | `/api/rate-status` | Rate limit durumları |
| GET | `/api/cve-database` | CVE veritabanı |
| GET | `/api/logs` | Log geçmişi |
| GET | `/api/stats` | Sistem istatistikleri |
| POST | `/api/clear-bans` | Tüm banları temizle |
| POST | `/api/clear-logs` | Logları temizle |

## 🔌 Socket.IO Events

### Server → Client

| Event | Payload | Açıklama |
|-------|---------|----------|
| `traffic-update` | `{light, timer, isMitmAttack, ...}` | Trafik durumu |
| `new-log` | `{timestamp, severity, message, ...}` | Yeni log kaydı |
| `critical-alert` | `{attackType, sourceIP, cveScore}` | Kritik saldırı uyarısı |
| `ip-banned` | `{ip, reason, cveScore, bannedAt}` | IP ban bildirimi |
| `ip-unbanned` | `{ip, timestamp}` | Ban kaldırma bildirimi |
| `system-recovered` | `{timestamp}` | Sistem onarım tamamlandı |
| `initial-data` | `{bannedIPs, logs, cveDatabase, stats}` | İlk bağlantı verisi |

## 🎨 Tehdit Seviye Renk Kodları

| Seviye | Renk | CVE Skoru | Açıklama |
|--------|------|-----------|----------|
| SECURE | 🟢 Yeşil | - | Sistem güvenli |
| ELEVATED | 🟡 Sarı | 4.0-6.9 | Banlı IP var |
| HIGH | 🟠 Turuncu | 7.0-8.9 | Aktif saldırı |
| CRITICAL | 🔴 Kırmızı | 9.0+ | Kritik tehdit! |

## 🐛 Sorun Giderme

### Sorun 1: "API bağlantı hatası: Unexpected token '<'"
**Çözüm:** `server-fixed.js` kullanıldığından emin olun. Eski `server.js` dosyası bazı endpoint'leri eksik.

### Sorun 2: Loglar görünmüyor
**Çözüm:** 
1. Backend çalışıyor mu? `node server-fixed.js`
2. Socket.IO bağlantısı kuruldu mu? (Header'da yeşil nokta)
3. Browser console'u kontrol edin

### Sorun 3: Pop-up açılmıyor
**Çözüm:** CVE skoru 9.0'dan büyük mü? Popup sadece kritik saldırılarda açılır.

## 📝 Örnek CVE'ler

| CVE ID | Skor | Severity | Açıklama |
|--------|------|----------|----------|
| CVE-2024-9801 | 9.8 | CRITICAL | ModBus TCP Write Manipulation |
| CVE-2024-8734 | 8.6 | HIGH | SCADA Traffic Injection |
| CVE-2024-7621 | 7.5 | HIGH | Real-time Protocol Tampering |
| CVE-2024-6509 | 6.8 | MEDIUM | Rate Limit Bypass |
| CVE-2024-5432 | 5.3 | MEDIUM | Log Injection |

## 🚀 Deployment (Render/Vercel)

### Render.com

1. Repository'i GitHub'a push edin
2. Render.com'da "New Web Service" oluşturun
3. Build Command: `npm install`
4. Start Command: `node server-fixed.js`
5. Port: 3000 (AUTO)

### Vercel

```bash
# vercel.json oluşturun
{
  "version": 2,
  "builds": [
    { "src": "server-fixed.js", "use": "@vercel/node" }
  ],
  "routes": [
    { "src": "/(.*)", "dest": "server-fixed.js" }
  ]
}
```

## 🔐 Güvenlik Notları

- ⚠️ Bu proje **demo/eğitim amaçlıdır**
- 🔒 Production'da mutlaka environment variables kullanın
- 🛡️ HTTPS zorunlu tutun
- 🔑 API key/token implementasyonu ekleyin
- 📊 Log rotation implementasyonu ekleyin (production)

## 👨‍💻 Geliştirici Notları

### Rate Limit Değiştirme
```javascript
// server-fixed.js, satır 19
const RATE_LIMIT_THRESHOLD = 100; // İstek/saniye
const COOLDOWN_DURATION = 300000; // 5 dakika (ms)
```

### Log Buffer Boyutu
```javascript
// server-fixed.js, satır 18
const MAX_LOGS = 500; // Maksimum log sayısı
```

### CVE Ekleme
```javascript
// server-fixed.js, satır 23-62
const CVE_DATABASE = [
  {
    id: "CVE-2024-XXXX",
    score: 8.5,
    severity: "HIGH",
    description: "...",
    service: "...",
    attackType: "...",
    mitreId: "T1XXX.XXX",
    vector: "NETWORK",
    exploitability: "HIGH"
  }
];
```
**Made with ❤️ for OKAF Hackathon**
