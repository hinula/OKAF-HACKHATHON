const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

// --- MIDDLEWARE ---
app.use(cors({ origin: "*" })); // Vercel'den gelen isteklere izin ver
app.use(express.json());

const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// --- SİSTEM DEĞİŞKENLERİ ---
let trafficStatus = {
    light: 'red',
    timer: 30,
    carCount: 45,
    mode: 'AUTO',
    isMitmAttack: false,
    activeAttackType: null,
    activeSourceIP: null,
    activeCveScore: null,
    lastMitigation: 'None'
};

let attackLogs = []; 
let blacklistedIPs = new Set();

// --- API ENDPOINTLERİ (SOC PANELI İÇİN) ---

// 1. Canlı Logları Getir
app.get('/api/logs', (req, res) => {
    res.json(attackLogs.slice(0, 50));
});

// 2. Banlı IP Listesini Getir
app.get('/api/blocked-ips', (req, res) => {
    const list = Array.from(blacklistedIPs).map(ip => ({
        ip: ip,
        reason: "CVE-Based Siber Tehdit",
        cveScore: 9.8,
        bannedAt: new Date()
    }));
    res.json(list);
});

// 3. Sabit CVE Listesi
app.get('/api/cve-list', (req, res) => {
    res.json([
        { id: "CVE-2026-TRF-01", score: 9.8, severity: "CRITICAL", description: "Modbus TCP Paket Manipülasyonu ile Sinyalizasyon Ele Geçirme" },
        { id: "CVE-2026-TRF-02", score: 7.5, severity: "HIGH", description: "Admin Panel Brute Force Giriş Denemesi" },
        { id: "CVE-2026-TRF-03", score: 8.1, severity: "HIGH", description: "Sensör Verisi Sahteciliği (Data Spoofing)" }
    ]);
});

// 4. Mevcut Sistem Durumu
app.get('/api/status', (req, res) => {
    res.json(trafficStatus);
});

// 5. Saldırı Başlatma / Durdurma (Attack Simulator'dan gelir)
app.post('/api/attack', (req, res) => {
    const { active, type, sourceIP } = req.body;
    
    trafficStatus.isMitmAttack = active;
    
    if (active) {
        trafficStatus.activeAttackType = type || "Man-in-the-Middle";
        trafficStatus.activeSourceIP = sourceIP || "192.168.1.105";
        trafficStatus.activeCveScore = 9.8;
        
        // SOC Paneli için Log Oluştur
        const newLog = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            sourceIP: trafficStatus.activeSourceIP,
            attackType: trafficStatus.activeAttackType,
            payload: "Modbus Write Single Coil (0x05) - Illegal Address",
            cveScore: 9.8,
            action: "DETECTED"
        };
        attackLogs.unshift(newLog);
        io.emit('new-log', newLog);
    } else {
        trafficStatus.activeAttackType = null;
        trafficStatus.activeSourceIP = null;
    }

    io.emit('traffic-update', trafficStatus);
    res.json({ success: true, status: trafficStatus });
});

// 6. Tehdit Bertaraf Etme (Mitigate / Ban)
app.post('/api/mitigate', (req, res) => {
    const { targetIP, attackType } = req.body;
    
    if (targetIP) {
        blacklistedIPs.add(targetIP);
        trafficStatus.lastMitigation = new Date().toLocaleTimeString();
        
        // Ban Logu Oluştur
        const banLog = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            sourceIP: targetIP,
            attackType: attackType || "Mitigation Action",
            payload: "IP address added to firewall blacklist",
            cveScore: 9.8,
            action: "AUTO_BANNED"
        };
        attackLogs.unshift(banLog);
        io.emit('new-log', banLog);
        io.emit('ip-banned', { ip: targetIP, reason: "Security Threat" });
    }

    // Sistemi normale döndür
    trafficStatus.isMitmAttack = false;
    trafficStatus.activeAttackType = null;
    io.emit('traffic-update', trafficStatus);
    
    res.json({ success: true, message: `IP ${targetIP} başarıyla banlandı.` });
});

// 7. IP Ban Kaldırma (Unban)
app.post('/api/unban', (req, res) => {
    const { ip } = req.body;
    if (blacklistedIPs.has(ip)) {
        blacklistedIPs.delete(ip);
        io.emit('ip-unbanned', { ip }); 
        return res.json({ success: true, message: `IP ${ip} banı kaldırıldı.` });
    }
    res.json({ success: false, message: "IP bulunamadı." });
});

// --- TRAFİK DÖNGÜSÜ (Simülasyon) ---
setInterval(() => {
    if (!trafficStatus.isMitmAttack) {
        trafficStatus.timer--;
        if (trafficStatus.timer <= 0) {
            if (trafficStatus.light === 'red') trafficStatus.light = 'green';
            else if (trafficStatus.light === 'green') trafficStatus.light = 'yellow';
            else trafficStatus.light = 'red';
            trafficStatus.timer = 30;
        }
        io.emit('traffic-update', trafficStatus);
    }
}, 1000);

// --- SUNUCUYU BAŞLAT ---
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
