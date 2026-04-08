const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const net = require('net');
const modbus = require('jsmodbus');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// --- GÜVENLİK VERİLERİ ---
const blacklistedIPs = new Set();
const requestCounts = {};
const THRESHOLD = 20;

// --- SİSTEM DURUMU ---
let trafficStatus = {
    light: "red",
    timer: 15,
    carCount: 45,
    mode: "AUTO",
    isMitmAttack: false,
    networkSecurity: "Safe",
    lastMitigation: "None"
};

// --- MODBUS YAPILANDIRMASI ---
const holdingRegisters = Buffer.alloc(100);
const netServer = new net.Server();
const modbusServer = new modbus.server.TCP(netServer);

function getLightCode(light) {
    if (trafficStatus.isMitmAttack) return 99;
    const codes = { red: 0, yellow: 1, green: 2, glitch: 99 };
    return codes[light] || 0;
}

// Modbus Register Güncelleme Döngüsü
setInterval(() => {
    try {
        holdingRegisters.writeUInt16BE(getLightCode(trafficStatus.light), 0); // Register 0: Işık
        holdingRegisters.writeUInt16BE(trafficStatus.timer, 2);               // Register 1: Timer
        holdingRegisters.writeUInt16BE(trafficStatus.carCount, 4);           // Register 2: Araç
    } catch (err) {
        // Hata durumunda sessiz kal
    }
}, 1000);

// --- KENDİ KENDİNİ ONARMA FONKSİYONU ---
const recoverSystem = () => {
    console.log("🛠️ Sistem Onarma Protokolü Başlatıldı...");
    trafficStatus.isMitmAttack = false;
    trafficStatus.light = "red"; // Güvenlik için kırmızıdan başla
    trafficStatus.timer = 10;
    trafficStatus.networkSecurity = "Safe (Recovered)";
    trafficStatus.lastMitigation = "Auto-Recovery Triggered";
    
    io.emit('traffic-update', trafficStatus);
    console.log("✅ Sistem başarıyla fabrika ayarlarına döndü.");
};

// --- GÜVENLİK KALKANI (MIDDLEWARE) ---
const securityShield = (req, res, next) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (blacklistedIPs.has(clientIP)) {
        return res.status(403).json({
            status: "BLOCKED",
            message: "Güvenlik protokolleri gereği erişiminiz engellendi.",
            reason: "CVE-Based Auto-Mitigation"
        });
    }

    requestCounts[clientIP] = (requestCounts[clientIP] || 0) + 1;
    if (requestCounts[clientIP] > THRESHOLD) {
        blacklistedIPs.add(clientIP);
        console.log(`[SAVUNMA] ${clientIP} çok fazla istek attığı için banlandı.`);
    }

    next();
};

app.use(securityShield);

// --- API ENDPOINTLERI ---

// MODİFİYE EDİLMİŞ MİTİGASYON (SAVUNMA)
app.post('/api/mitigate', (req, res) => {
    const { targetIP, cveScore, attackType } = req.body;

    if (parseFloat(cveScore) >= 7.0) {
        blacklistedIPs.add(targetIP);
        console.log(`[SAVUNMA] ${targetIP} OTOMATİK banlandı. Tehdit: ${attackType || 'Bilinmiyor'}`);
        
        // Saldırı bayrağını indir ve onarma fonksiyonunu çağır
        recoverSystem(); 

        return res.json({ 
            success: true, 
            action: "AUTO_RECOVER", 
            message: "Saldırgan banlandı ve sistem onarıldı." 
        });
    }
    res.json({ success: false, message: "Risk puanı onarma için yetersiz." });
});

// Manuel Saldırı Simülasyonu
app.post('/api/attack', (req, res) => {
    trafficStatus.isMitmAttack = req.body.active;
    trafficStatus.networkSecurity = req.body.active ? "Under Attack" : "Safe";
    
    io.emit('traffic-update', trafficStatus);
    res.json({ status: "OK", attackStatus: trafficStatus.isMitmAttack });
});

// --- TRAFİK DÖNGÜSÜ ---
setInterval(() => {
    if (!trafficStatus.isMitmAttack) {
        if (trafficStatus.timer > 0) {
            trafficStatus.timer--;
        } else {
            const next = { red: "green", green: "yellow", yellow: "red" };
            trafficStatus.light = next[trafficStatus.light];
            trafficStatus.timer = trafficStatus.light === "yellow" ? 3 : 15;
        }
    } else {
        trafficStatus.light = "glitch";
        trafficStatus.timer = Math.floor(Math.random() * 99);
    }
    io.emit('traffic-update', trafficStatus);
}, 1000);

// Watchdog: Her 10 saniyede bir kontrol et
setInterval(() => {
    if (trafficStatus.light === "glitch" && !trafficStatus.isMitmAttack) {
        console.log("🚨 Tutarsızlık Tespit Edildi: Işık bozuk ama aktif saldırı yok. Onarılıyor...");
        recoverSystem();
    }
}, 10000);

// --- SUNUCULARI BAŞLAT ---
const API_PORT = process.env.PORT || 3000;
server.listen(API_PORT, () => {
    console.log(`🚀 API ve Webhook Sunucusu: ${API_PORT} portunda aktif.`);
});

const MODBUS_PORT = 502; // Render'da 502 hata verirse 5020 yapın
netServer.listen(MODBUS_PORT, () => {
    console.log(`📟 Modbus TCP Sunucusu: ${MODBUS_PORT} portunda aktif.`);
});

modbusServer.on('postReadHoldingRegisters', (request, cb) => {
    cb(holdingRegisters);
});
