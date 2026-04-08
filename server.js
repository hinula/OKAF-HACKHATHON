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
        console.error("Modbus Register Yazma Hatası");
    }
}, 1000);

// --- GÜVENLİK KALKANI (MIDDLEWARE) ---
const securityShield = (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;

    // 1. Kontrol: IP Banlı mı?
    if (blacklistedIPs.has(clientIP)) {
        return res.status(403).json({
            status: "BLOCKED",
            message: "Güvenlik protokolleri gereği erişiminiz engellendi.",
            reason: "CVE-Based Auto-Mitigation"
        });
    }

    // 2. Kontrol: Rate Limiting (Basit Brute Force Koruması)
    requestCounts[clientIP] = (requestCounts[clientIP] || 0) + 1;
    if (requestCounts[clientIP] > THRESHOLD) {
        blacklistedIPs.add(clientIP);
        console.log(`[SAVUNMA] ${clientIP} çok fazla istek attığı için banlandı.`);
    }

    next();
};

app.use(securityShield);

// --- API ENDPOINTLERI ---

// SOC'dan gelen müdahale isteği
app.post('/api/mitigate', (req, res) => {
    const { targetIP, attackType, cveScore } = req.body;

    if (parseFloat(cveScore) >= 7.0) {
        blacklistedIPs.add(targetIP);
        trafficStatus.lastMitigation = `IP ${targetIP} BANNED (CVE: ${cveScore})`;
        trafficStatus.isMitmAttack = false; // Saldırıyı durdur
        trafficStatus.networkSecurity = "Safe (Threat Neutralized)";
        
        console.log(`[SAVUNMA] ${targetIP} OTOMATİK banlandı. Tehdit: ${attackType}`);

        return res.json({ 
            success: true, 
            action: "AUTO_BAN", 
            message: `Kritik tehdit (${cveScore}) bertaraf edildi.` 
        });
    }

    res.json({ success: true, action: "LOGGED", message: "Düşük risk kaydedildi." });
});

// Manuel Saldırı Simülasyonu (Test için)
app.post('/api/attack', (req, res) => {
    trafficStatus.isMitmAttack = req.body.active;
    trafficStatus.networkSecurity = req.body.active ? "Under Attack" : "Safe";
    io.emit('traffic-update', trafficStatus);
    res.json({ status: "OK" });
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

// --- SUNUCULARI BAŞLAT ---
const API_PORT = 3000;
server.listen(API_PORT, () => {
    console.log(`🚀 API ve Webhook Sunucusu: http://localhost:${API_PORT}`);
});

const MODBUS_PORT = 502; // Hata alırsan 5020 yap
netServer.listen(MODBUS_PORT, () => {
    console.log(`📟 Modbus TCP Sunucusu: ${MODBUS_PORT} portunda aktif.`);
});

modbusServer.on('postReadHoldingRegisters', (request, cb) => {
    cb(holdingRegisters);
});
