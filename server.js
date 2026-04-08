const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const net = require('net');
const modbus = require('jsmodbus');
const path = require('path');

const app = express();
app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// ============================================================
// GÜVENLİK VERİLERİ & LOGLAR
// ============================================================
const blockedIPs = new Map();
const requestCounts = {};
const cooldowns = new Map();
const attackLogs = [];
const MAX_LOGS = 200;

// SİSTEM DURUMU (Dinamik hale getirildi)
let trafficStatus = {
    light: "red",
    timer: 15,
    carCount: 45,
    mode: "AUTO",
    isMitmAttack: false,
    networkSecurity: "Safe",
    lastMitigation: "None",
    criticalAlert: false,
    activeAttackType: null,
    activeCveScore: null,
    activeSourceIP: null
};

// IP Yakalama Fonksiyonu (Render/Proxy Uyumlu)
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const raw = (forwarded || realIp || req.ip || req.connection.remoteAddress || '127.0.0.1').toString();
    return raw.split(',')[0].trim().replace('::ffff:', '');
}

// ============================================================
// API: SALDIRI RAPORU (attack.py'den gelen veri)
// ============================================================
app.post('/api/attack', (req, res) => {
    const { active, attackType, sourceIP, payload, cveScore, mitreId } = req.body;

    const sIP = sourceIP || "85.105.x.x"; // Boşsa dummy IP
    const score = parseFloat(cveScore) || 0;

    // Durumu Güncelle
    trafficStatus.isMitmAttack = !!active;
    trafficStatus.activeAttackType = active ? attackType : null;
    trafficStatus.activeCveScore = active ? score : null;
    trafficStatus.activeSourceIP = active ? sIP : null;

    if (active) {
        trafficStatus.networkSecurity = "Under Attack";
        const isCritical = score >= 9.0;
        trafficStatus.criticalAlert = isCritical;

        // 1. Log Ekle
        addLog({
            sourceIP: sIP,
            attackType: attackType || "Sızma Girişimi",
            payload: payload || "Zararlı paket algılandı",
            cveScore: score,
            action: isCritical ? "CRITICAL_ALERT" : "DETECTED",
            severity: isCritical ? "CRITICAL" : "HIGH"
        });

        // 2. OTOMATİK SAVUNMA (CVE >= 9.0 ise)
        if (isCritical && !blockedIPs.has(sIP)) {
            executeBan(sIP, `Otomatik Savunma (CVE ${score})`, score);
        }

        // 3. POP-UP TETİKLE (Kritikse zorla gönder)
        if (isCritical) {
            io.emit('critical-alert', { attackType, sourceIP: sIP, cveScore: score });
        }
    } else {
        // Saldırı Durduğunda Temizlik
        trafficStatus.criticalAlert = false;
        trafficStatus.networkSecurity = "Safe";
        addLog({ attackType: "ATTACK_STOPPED", severity: "INFO", action: "CLEARED" });
    }

    // Tüm SOC'a durumu yay
    io.emit('traffic-update', trafficStatus);
    res.json({ success: true, status: trafficStatus.networkSecurity });
});

// ============================================================
// API: MANUEL/SOAR MİTİGASYON (Pop-up butonu burayı çağırır)
// ============================================================
app.post('/api/mitigate', (req, res) => {
    const { targetIP, attackType, cveScore } = req.body;
    const ip = targetIP || trafficStatus.activeSourceIP;

    if (!ip) return res.status(400).json({ success: false, message: "IP bulunamadı." });

    // Ban işlemini gerçekleştir
    executeBan(ip, `Manuel Müdahale: ${attackType}`, cveScore || 9.0);

    // Saldırıyı sistemden temizle (Saldırı Durdurma)
    trafficStatus.isMitmAttack = false;
    trafficStatus.criticalAlert = false;
    trafficStatus.networkSecurity = "Safe (Threat Neutralized)";
    
    io.emit('traffic-update', trafficStatus);
    res.json({ success: true, message: `${ip} engellendi ve saldırı durduruldu.` });
});

// Yardımcı Fonksiyon: Ban Uygula
function executeBan(ip, reason, score) {
    const banInfo = { ip, reason, cveScore: score, bannedAt: new Date().toISOString() };
    blockedIPs.set(ip, banInfo);
    trafficStatus.lastMitigation = `BAN: ${ip} (${score})`;
    
    io.emit('ip-banned', banInfo);
    addLog({
        sourceIP: ip,
        attackType: "IP_BAN",
        payload: reason,
        cveScore: score,
        action: "BANNED",
        severity: "CRITICAL"
    });
}

// Log Ekleme Fonksiyonu
function addLog(data) {
    const log = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        sourceIP: data.sourceIP || "SYSTEM",
        attackType: data.attackType || "INFO",
        payload: data.payload || "-",
        cveScore: data.cveScore || 0,
        action: data.action || "LOGGED",
        severity: data.severity || "INFO"
    };
    attackLogs.unshift(log);
    if (attackLogs.length > MAX_LOGS) attackLogs.pop();
    io.emit('new-log', log);
}

// ============================================================
// DİĞER STANDART ROUTE'LAR (Log çekme, Unban vs.)
// ============================================================
app.get('/api/logs', (req, res) => res.json(attackLogs));
app.get('/api/blocked-ips', (req, res) => res.json(Array.from(blockedIPs.values())));
app.get('/api/status', (req, res) => res.json(trafficStatus));
app.post('/api/unban', (req, res) => {
    const { ip } = req.body;
    if(blockedIPs.has(ip)) {
        blockedIPs.delete(ip);
        io.emit('ip-unbanned', { ip });
        return res.json({ success: true });
    }
    res.status(404).send();
});

// Trafik Döngüsü (Işıklar)
setInterval(() => {
    if (!trafficStatus.isMitmAttack) {
        if (trafficStatus.timer > 0) trafficStatus.timer--;
        else {
            const cycle = { red: "green", green: "yellow", yellow: "red" };
            trafficStatus.light = cycle[trafficStatus.light];
            trafficStatus.timer = trafficStatus.light === "yellow" ? 3 : 15;
        }
    } else {
        trafficStatus.light = "glitch"; // Saldırı varken ışıklar sapıtır
    }
    io.emit('traffic-update', trafficStatus);
}, 1000);

// Sunucuyu Başlat
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`SOC Server running on port ${PORT}`));
