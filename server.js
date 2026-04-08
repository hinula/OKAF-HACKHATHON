const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" }
});

// --- SİSTEM DURUMU ---
let trafficStatus = {
    light: "red",
    timer: 15,
    carCount: 45,
    isMitmAttack: false, // MITM Saldırı Bayrağı
    networkSecurity: "Safe"
};

// --- API ENDPOINTLERİ ---

// 1. Genel Durum Sorgulama (Belediye Paneli İçin)
app.get('/api/status', (req, res) => {
    res.json(trafficStatus);
});

// 2. Saldırı Simülasyonu (Hackathon Gösterisi İçin)
// SOC panelinden bu endpoint'e istek atarak belediye panelini bozacağız
app.post('/api/attack', (req, res) => {
    const { active } = req.body;
    trafficStatus.isMitmAttack = active;
    
    if (active) {
        trafficStatus.networkSecurity = "Compromised (MITM Detected)";
        console.log("⚠️ UYARI: Paket manipülasyonu başladı!");
    } else {
        trafficStatus.networkSecurity = "Safe";
        console.log("✅ Sistem normale döndü.");
    }

    io.emit('security-alert', trafficStatus); // SOC paneline anlık uyarı
    res.json({ status: "ok", attackActive: active });
});

// --- TRAFİK DÖNGÜSÜ ---
setInterval(() => {
    if (!trafficStatus.isMitmAttack) {
        // Normal Çalışma Mantığı
        if (trafficStatus.timer > 0) {
            trafficStatus.timer--;
        } else {
            const next = { red: "green", green: "yellow", yellow: "red" };
            trafficStatus.light = next[trafficStatus.light];
            trafficStatus.timer = trafficStatus.light === "yellow" ? 3 : 15;
        }
    } else {
        // SALDIRI ANI: Veriler saçmalıyor
        trafficStatus.timer = Math.floor(Math.random() * 99);
        trafficStatus.light = "glitch"; // Frontend'de tüm ışıkların yanıp sönmesini sağlar
    }

    // Soket üzerinden tüm bağlı panelleri (Belediye & SOC) güncelle
    io.emit('traffic-update', trafficStatus);
}, 1000);

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`
    🚦 AKILLI TRAFİK SUNUCUSU BAŞLATILDI
    ------------------------------------
    Sunucu Adresi: http://localhost:${PORT}
    Saldırı Testi: POST http://localhost:${PORT}/api/attack
    ------------------------------------
    `);
});