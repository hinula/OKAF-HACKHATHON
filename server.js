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
// GÜVENLİK VERİLERİ
// ============================================================
const blockedIPs = new Map();   // IP -> { reason, cveScore, bannedAt }
const requestCounts = {};        // IP -> { count, windowStart }
const cooldowns = new Map();     // IP -> { until, reason }

const RATE_LIMIT_THRESHOLD = 100;           // saniyede max istek
const COOLDOWN_DURATION = 5 * 60 * 1000;   // 5 dakika (ms)

// ============================================================
// LOG DEPOSU
// ============================================================
const attackLogs = [];
const MAX_LOGS = 200;

// ============================================================
// CVE VERİTABANI (Simüle)
// ============================================================
const CVE_DATABASE = [
    {
        id: "CVE-2024-4577",
        score: 9.8,
        severity: "CRITICAL",
        mitreId: "T1190",
        description: "PHP CGI Argument Injection — Uzaktan Kod Çalıştırma",
        service: "PHP/Apache",
        attackType: "SQL Injection",
        published: "2024-06-09"
    },
    {
        id: "CVE-2024-3400",
        score: 10.0,
        severity: "CRITICAL",
        mitreId: "T1210",
        description: "PAN-OS GlobalProtect OS Command Injection RCE",
        service: "VPN Gateway",
        attackType: "Man-in-the-Middle",
        published: "2024-04-12"
    },
    {
        id: "CVE-2023-44487",
        score: 7.5,
        severity: "HIGH",
        mitreId: "T1499",
        description: "HTTP/2 Rapid Reset Attack — Dağıtık Servis Engelleme",
        service: "HTTP/2 Web Server",
        attackType: "Brute Force",
        published: "2023-10-10"
    },
    {
        id: "CVE-2024-21887",
        score: 9.1,
        severity: "CRITICAL",
        mitreId: "T1059",
        description: "Ivanti Connect Secure Komut Enjeksiyonu RCE",
        service: "VPN / ICS",
        attackType: "Brute Force",
        published: "2024-01-10"
    },
    {
        id: "CVE-2024-23897",
        score: 9.8,
        severity: "CRITICAL",
        mitreId: "T1213",
        description: "Jenkins CLI Arbitrary File Read / Uzaktan Kod Çalıştırma",
        service: "CI/CD Pipeline",
        attackType: "SQL Injection",
        published: "2024-01-24"
    }
];

// ============================================================
// SİSTEM DURUMU
// ============================================================
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

// ============================================================
// MODBUS YAPILANDIRMASI
// ============================================================
const holdingRegisters = Buffer.alloc(100);
const netServer = new net.Server();
const modbusServer = new modbus.server.TCP(netServer);

function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const raw = (forwarded || realIp || req.ip || req.connection.remoteAddress || 'unknown').toString();
    const first = raw.split(',')[0].trim();
    return first.replace('::ffff:', '');
}

function getLightCode(light) {
    if (trafficStatus.isMitmAttack) return 99;
    const codes = { red: 0, yellow: 1, green: 2, glitch: 99 };
    return codes[light] || 0;
}

setInterval(() => {
    try {
        holdingRegisters.writeUInt16BE(getLightCode(trafficStatus.light), 0);
        holdingRegisters.writeUInt16BE(trafficStatus.timer, 2);
        holdingRegisters.writeUInt16BE(trafficStatus.carCount, 4);
    } catch (err) {
        console.error("[MODBUS] Register yazma hatası");
    }
}, 1000);

// ============================================================
// HELPER: LOG EKLE & YAYINLA
// ============================================================
function addLog(logData) {
    const log = {
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp: new Date().toISOString(),
        sourceIP: "Unknown",
        attackType: "Unknown",
        payload: "-",
        cveScore: 0,
        mitreId: "-",
        action: "LOGGED",
        severity: "INFO",
        ...logData
    };
    attackLogs.unshift(log);
    if (attackLogs.length > MAX_LOGS) attackLogs.pop();
    io.emit('new-log', log);
    console.log(`[LOG][${log.severity}] ${log.sourceIP} | ${log.attackType} | CVE:${log.cveScore} | ${log.action}`);
    return log;
}

// ============================================================
// GÜVENLİK KALKANI MIDDLEWARE
// ============================================================
const securityShield = (req, res, next) => {
    const clientIP = getClientIP(req);
    const now = Date.now();

    // 1. IP Banlı mı?
    if (blockedIPs.has(clientIP)) {
        const banInfo = blockedIPs.get(clientIP);
        addLog({
            sourceIP: clientIP,
            attackType: "BLOCKED_REQUEST",
            payload: `${req.method} ${req.originalUrl}`,
            cveScore: Number(banInfo.cveScore || 0),
            action: "BLOCKED",
            severity: "HIGH"
        });
        return res.status(403).json({
            status: "BLOCKED",
            message: "Güvenlik protokolleri gereği erişiminiz engellendi.",
            reason: banInfo.reason || "CVE-Based Auto-Mitigation"
        });
    }

    // 2. Cooldown'da mı?
    if (cooldowns.has(clientIP)) {
        const cd = cooldowns.get(clientIP);
        if (now < cd.until) {
            const remaining = Math.ceil((cd.until - now) / 1000);
            addLog({
                sourceIP: clientIP,
                attackType: "COOLDOWN_BLOCK",
                payload: `${req.method} ${req.originalUrl} (${remaining}s kaldı)`,
                cveScore: 5.3,
                action: "BLOCKED",
                severity: "MEDIUM"
            });
            return res.status(429).json({
                status: "RATE_LIMITED",
                message: `Rate limit aşıldı. ${remaining} saniye bekleyin.`,
                cooldownRemaining: remaining
            });
        } else {
            cooldowns.delete(clientIP);
            requestCounts[clientIP] = { count: 0, windowStart: now };
        }
    }

    // 3. Rate Limit Kontrolü (saniyede RATE_LIMIT_THRESHOLD istek)
    if (!requestCounts[clientIP] || (now - requestCounts[clientIP].windowStart) > 1000) {
        requestCounts[clientIP] = { count: 1, windowStart: now };
    } else {
        requestCounts[clientIP].count++;
    }

    if (requestCounts[clientIP].count > RATE_LIMIT_THRESHOLD) {
        const cooldownUntil = now + COOLDOWN_DURATION;
        cooldowns.set(clientIP, { until: cooldownUntil, reason: "Rate Limit Aşıldı" });
        requestCounts[clientIP] = { count: 0, windowStart: now };

        addLog({
            sourceIP: clientIP,
            attackType: "RATE_LIMIT_EXCEEDED",
            payload: `${RATE_LIMIT_THRESHOLD}+ req/s tespit edildi — 5 dakika soğuma`,
            cveScore: 5.3,
            action: "COOLDOWN_5MIN",
            severity: "HIGH"
        });

        io.emit('rate-limit-triggered', {
            ip: clientIP,
            cooldownUntil,
            cooldownSeconds: 300
        });

        return res.status(429).json({
            status: "RATE_LIMITED",
            message: "Çok fazla istek. 5 dakika soğuma süresine alındınız.",
            cooldownSeconds: 300
        });
    }

    next();
};

app.use(securityShield);

// ============================================================
// STATIC FILE ROUTES
// ============================================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/soc', (req, res) => res.sendFile(path.join(__dirname, 'soc.html')));

// ============================================================
// API: SALDIRI RAPORU (attack.py'den gelir — gerçek saldırı verisi)
// ============================================================
app.post('/api/attack', (req, res) => {
    const {
        active,
        attackType,
        sourceIP,
        payload,
        cveScore,
        mitreId
    } = req.body;

    trafficStatus.isMitmAttack = !!active;
    trafficStatus.networkSecurity = active ? "Under Attack" : "Safe";
    trafficStatus.activeAttackType = active ? (attackType || null) : null;
    trafficStatus.activeCveScore = active ? (cveScore || null) : null;
    trafficStatus.activeSourceIP = active ? (sourceIP || null) : null;

    if (active) {
        const isCritical = parseFloat(cveScore) >= 9.0;
        trafficStatus.criticalAlert = isCritical;

        // Log kaydı
        addLog({
            sourceIP: sourceIP || "Unknown",
            attackType: attackType || "Unknown",
            payload: payload || "-",
            cveScore: cveScore || 0,
            mitreId: mitreId || "-",
            action: isCritical ? "CRITICAL_ALERT" : "DETECTED",
            severity: isCritical ? "CRITICAL" : "HIGH"
        });

        // Otomatik Ban: CVE >= 9.0 ise
        if (isCritical && sourceIP && !blockedIPs.has(sourceIP)) {
            const banInfo = {
                reason: `Auto-Ban: ${attackType} (CVE ${cveScore})`,
                cveScore,
                bannedAt: new Date().toISOString()
            };
            blockedIPs.set(sourceIP, banInfo);
            trafficStatus.lastMitigation = `AUTO-BAN: ${sourceIP} (CVE: ${cveScore})`;

            io.emit('ip-banned', { ip: sourceIP, ...banInfo });

            addLog({
                sourceIP,
                attackType: "AUTO_BAN",
                payload: `CVE ${cveScore} eşiği aşıldı — Otomatik ban uygulandı`,
                cveScore,
                mitreId: mitreId || "-",
                action: "IP_BANNED",
                severity: "CRITICAL"
            });
        }

        // Kritik uyarı yayınla
        if (isCritical) {
            io.emit('critical-alert', {
                attackType,
                sourceIP,
                cveScore,
                mitreId
            });
        }
    } else {
        trafficStatus.criticalAlert = false;
        addLog({
            sourceIP: sourceIP || "System",
            attackType: "ATTACK_STOPPED",
            payload: "Saldırı durduruldu — Sistem normale döndü",
            cveScore: 0,
            action: "CLEARED",
            severity: "INFO"
        });
    }

    io.emit('traffic-update', trafficStatus);
    res.json({ status: "OK", criticalAlert: trafficStatus.criticalAlert });
});

// ============================================================
// API: MANUEL MİTİGASYON (SOC panelinden)
// ============================================================
app.post('/api/mitigate', (req, res) => {
    const { targetIP, attackType, cveScore } = req.body;

    if (!targetIP) return res.status(400).json({ success: false, message: "targetIP gerekli." });

    const score = parseFloat(cveScore) || 0;

    if (score >= 7.0) {
        const banInfo = {
            reason: `Manuel Mitigate: ${attackType || 'Unknown'} (CVE ${cveScore})`,
            cveScore: score,
            bannedAt: new Date().toISOString()
        };
        blockedIPs.set(targetIP, banInfo);
        trafficStatus.lastMitigation = `MANUAL-BAN: ${targetIP} (CVE: ${cveScore})`;
        trafficStatus.isMitmAttack = false;
        trafficStatus.networkSecurity = "Safe (Threat Neutralized)";
        trafficStatus.criticalAlert = false;

        io.emit('traffic-update', trafficStatus);
        io.emit('ip-banned', { ip: targetIP, ...banInfo });

        addLog({
            sourceIP: targetIP,
            attackType: "MANUAL_BAN",
            payload: `SOC operatörü tarafından manuel ban uygulandı`,
            cveScore: score,
            action: "IP_BANNED",
            severity: "INFO"
        });

        return res.json({ success: true, action: "MANUAL_BAN", message: `${targetIP} başarıyla banlandı.` });
    }

    addLog({
        sourceIP: targetIP,
        attackType: attackType || "Unknown",
        payload: "Düşük risk kaydedildi",
        cveScore: score,
        action: "LOGGED",
        severity: "LOW"
    });

    res.json({ success: true, action: "LOGGED", message: "Düşük risk — Kayıt altına alındı." });
});

// ============================================================
// API: IP UNBAN
// ============================================================
app.post('/api/unban', (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP adresi gerekli." });

    if (blockedIPs.has(ip)) {
        blockedIPs.delete(ip);
        cooldowns.delete(ip);
        io.emit('ip-unbanned', { ip });
        addLog({
            sourceIP: ip,
            attackType: "UNBAN",
            payload: "SOC operatörü ban kaldırdı",
            cveScore: 0,
            action: "UNBANNED",
            severity: "INFO"
        });
        return res.json({ success: true, message: `${ip} banı kaldırıldı.` });
    }

    res.status(404).json({ success: false, message: "Bu IP ban listesinde değil." });
});

// ============================================================
// API: LOG LİSTESİ
// ============================================================
app.get('/api/logs', (req, res) => {
    res.json(attackLogs);
});

app.get('/api/cve-report', (req, res) => {
    const summary = attackLogs.reduce((acc, log) => {
        const key = log.attackType || "Unknown";
        if (!acc[key]) {
            acc[key] = {
                attackType: key,
                count: 0,
                highestCve: 0,
                lastSeen: null,
                lastAction: null
            };
        }
        acc[key].count += 1;
        acc[key].highestCve = Math.max(acc[key].highestCve, Number(log.cveScore || 0));
        acc[key].lastSeen = log.timestamp;
        acc[key].lastAction = log.action || "LOGGED";
        return acc;
    }, {});
    res.json(Object.values(summary).sort((a, b) => b.highestCve - a.highestCve || b.count - a.count));
});

// ============================================================
// API: BANLI IP LİSTESİ
// ============================================================
app.get('/api/blocked-ips', (req, res) => {
    const list = [];
    blockedIPs.forEach((info, ip) => list.push({ ip, ...info }));
    res.json(list);
});

// ============================================================
// API: CVE LİSTESİ
// ============================================================
app.get('/api/cve-list', (req, res) => {
    res.json(CVE_DATABASE);
});

// ============================================================
// API: RATE LIMIT DURUMU
// ============================================================
app.get('/api/rate-status', (req, res) => {
    const status = {};
    Object.entries(requestCounts).forEach(([ip, data]) => {
        status[ip] = {
            count: data.count,
            windowStart: data.windowStart,
            inCooldown: cooldowns.has(ip),
            cooldownUntil: cooldowns.has(ip) ? cooldowns.get(ip).until : null,
            cooldownRemaining: cooldowns.has(ip) ? Math.max(0, Math.ceil((cooldowns.get(ip).until - Date.now()) / 1000)) : 0
        };
    });
    res.json(status);
});

// ============================================================
// API: SİSTEM DURUMU
// ============================================================
app.get('/api/status', (req, res) => {
    res.json({
        ...trafficStatus,
        blockedIPCount: blockedIPs.size,
        logCount: attackLogs.length
    });
});

// ============================================================
// TRAFİK DÖNGÜSÜ
// ============================================================
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

// ============================================================
// SUNUCULARI BAŞLAT
// ============================================================
const API_PORT = process.env.PORT || 3000;
server.listen(API_PORT, () => {
    addLog({
        sourceIP: "SYSTEM",
        attackType: "SOC_BOOT",
        payload: "SOC/SOAR servisi ayakta ve log akışı aktif",
        cveScore: 0,
        action: "LOGGED",
        severity: "INFO"
    });
    console.log(`🚀 API Sunucusu     : http://localhost:${API_PORT}`);
    console.log(`🏙️  Trafik Paneli   : http://localhost:${API_PORT}/`);
    console.log(`🛡️  SOC/SOAR Paneli : http://localhost:${API_PORT}/soc`);
});

const MODBUS_PORT = process.env.MODBUS_PORT || 5020;
netServer.listen(MODBUS_PORT, () => {
    console.log(`📟 Modbus TCP       : port ${MODBUS_PORT}`);
});

modbusServer.on('postReadHoldingRegisters', (request, cb) => {
    cb(holdingRegisters);
});
