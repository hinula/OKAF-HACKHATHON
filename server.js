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

// ============================================================
// 🛡️ GÜVENLİK VERİLERİ - ENHANCED
// ============================================================
const blacklistedIPs = new Map(); // IP -> { reason, bannedAt, cveScore, attackType }
const requestCounts = new Map(); // IP -> { count, lastReset, inCooldown, cooldownUntil }
const logBuffer = []; // Canlı log akışı için buffer
const MAX_LOGS = 500;
const RATE_LIMIT_THRESHOLD = 100; // İstek/saniye
const COOLDOWN_DURATION = 300000; // 5 dakika (ms)

// CVE Database (Simulated)
const CVE_DATABASE = [
    {
        id: "CVE-2024-9801",
        score: 9.8,
        severity: "CRITICAL",
        description: "ModBus TCP Write Manipulation - Unauthorized PLC Control",
        service: "ModBus TCP",
        attackType: "MITM Write Attack",
        mitreId: "T1557.002",
        vector: "NETWORK",
        exploitability: "HIGH"
    },
    {
        id: "CVE-2024-8734",
        score: 8.6,
        severity: "HIGH",
        description: "SCADA Traffic Injection - Packet Forgery",
        service: "SCADA/ICS",
        attackType: "Packet Injection",
        mitreId: "T1071.001",
        vector: "NETWORK",
        exploitability: "MEDIUM"
    },
    {
        id: "CVE-2024-7621",
        score: 7.5,
        severity: "HIGH",
        description: "Real-time Protocol Tampering",
        service: "WebSocket/Socket.io",
        attackType: "Protocol Exploit",
        mitreId: "T1499.004",
        vector: "NETWORK",
        exploitability: "HIGH"
    },
    {
        id: "CVE-2024-6509",
        score: 6.8,
        severity: "MEDIUM",
        description: "Rate Limit Bypass via IP Spoofing",
        service: "API Gateway",
        attackType: "DDoS/Flood",
        mitreId: "T1498.001",
        vector: "NETWORK",
        exploitability: "MEDIUM"
    },
    {
        id: "CVE-2024-5432",
        score: 5.3,
        severity: "MEDIUM",
        description: "Information Disclosure via Log Injection",
        service: "Logging System",
        attackType: "Log Poisoning",
        mitreId: "T1565.002",
        vector: "LOCAL",
        exploitability: "LOW"
    }
];

// ============================================================
// 🚦 SİSTEM DURUMU
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
    activeCveScore: null
};

// ============================================================
// 📟 MODBUS YAPILANDIRMASI
// ============================================================
const holdingRegisters = Buffer.alloc(100);
const netServer = new net.Server();
const modbusServer = new modbus.server.TCP(netServer);

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
        // Silent error handling
    }
}, 1000);

// ============================================================
// 📊 LOGLARİ YÖNET
// ============================================================
function addLog(severity, category, source, message, ip = 'SYSTEM', action = 'INFO', cveId = null) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        severity,
        category,
        source,
        message,
        ip,
        action,
        cveId,
        id: Date.now() + Math.random()
    };
    
    logBuffer.unshift(logEntry);
    if (logBuffer.length > MAX_LOGS) {
        logBuffer.pop();
    }
    
    // Socket.io ile gerçek zamanlı gönder
    io.emit('new-log', logEntry);
    
    // Console'a da yazdır
    console.log(`[${severity}] ${category} | ${source} | ${message}`);
    
    return logEntry;
}

// ============================================================
// 🛡️ GÜVENLİK KALKANI (ENHANCED MIDDLEWARE)
// ============================================================
const securityShield = (req, res, next) => {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0].trim() || 
                     req.socket.remoteAddress || 
                     'unknown';

    // 1. IP BAN Kontrolü
    if (blacklistedIPs.has(clientIP)) {
        const banInfo = blacklistedIPs.get(clientIP);
        addLog('CRITICAL', 'SECURITY', 'FIREWALL', 
               `Blocked request from banned IP: ${clientIP}`, 
               clientIP, 'BLOCKED', banInfo.cveId);
        
        return res.status(403).json({
            status: "BLOCKED",
            message: "Erişim engellendi - IP blacklist'te",
            reason: banInfo.reason,
            cveScore: banInfo.cveScore,
            bannedAt: banInfo.bannedAt
        });
    }

    // 2. Rate Limiting & Cooldown
    const now = Date.now();
    let ipData = requestCounts.get(clientIP) || {
        count: 0,
        lastReset: now,
        inCooldown: false,
        cooldownUntil: 0
    };

    // Cooldown kontrolü
    if (ipData.inCooldown) {
        if (now < ipData.cooldownUntil) {
            const remainingSeconds = Math.ceil((ipData.cooldownUntil - now) / 1000);
            addLog('HIGH', 'RATE_LIMIT', 'THROTTLE', 
                   `Request during cooldown period - ${remainingSeconds}s remaining`, 
                   clientIP, 'THROTTLED');
            
            return res.status(429).json({
                status: "THROTTLED",
                message: `Çok fazla istek - Soğuma süresi: ${remainingSeconds} saniye`,
                cooldownRemaining: remainingSeconds
            });
        } else {
            // Cooldown bitti, sıfırla
            ipData.inCooldown = false;
            ipData.count = 0;
            ipData.lastReset = now;
        }
    }

    // Her saniye sayacı sıfırla
    if (now - ipData.lastReset > 1000) {
        ipData.count = 0;
        ipData.lastReset = now;
    }

    ipData.count++;
    requestCounts.set(clientIP, ipData);

    // Rate limit aşımı kontrolü
    if (ipData.count > RATE_LIMIT_THRESHOLD) {
        ipData.inCooldown = true;
        ipData.cooldownUntil = now + COOLDOWN_DURATION;
        requestCounts.set(clientIP, ipData);

        addLog('CRITICAL', 'RATE_LIMIT', 'AUTO_DEFENSE', 
               `Rate limit exceeded: ${ipData.count} req/s - Cooldown activated (5min)`, 
               clientIP, 'COOLDOWN', 'CVE-2024-6509');

        // Otomatik ban (opsiyonel - şimdilik sadece cooldown)
        // blacklistedIPs.set(clientIP, {
        //     reason: 'Rate Limit Exceeded',
        //     bannedAt: new Date().toISOString(),
        //     cveScore: 6.8,
        //     attackType: 'DDoS/Flood',
        //     cveId: 'CVE-2024-6509'
        // });

        return res.status(429).json({
            status: "COOLDOWN_ACTIVATED",
            message: "Aşırı istek tespit edildi - 5 dakika soğuma periyodu başlatıldı",
            cooldownDuration: COOLDOWN_DURATION / 1000
        });
    }

    next();
};

app.use(securityShield);

// ============================================================
// 🔄 KENDİNİ ONARMA FONKSİYONU
// ============================================================
const recoverSystem = () => {
    addLog('MEDIUM', 'SYSTEM', 'AUTO_RECOVERY', 'Sistem onarma protokolü başlatıldı', 'SYSTEM', 'RECOVERY');
    
    trafficStatus.isMitmAttack = false;
    trafficStatus.light = "red";
    trafficStatus.timer = 10;
    trafficStatus.networkSecurity = "Safe (Recovered)";
    trafficStatus.lastMitigation = "Auto-Recovery Triggered";
    trafficStatus.criticalAlert = false;
    trafficStatus.activeAttackType = null;
    trafficStatus.activeCveScore = null;
    
    io.emit('traffic-update', trafficStatus);
    io.emit('system-recovered', { timestamp: new Date().toISOString() });
    
    addLog('LOW', 'SYSTEM', 'AUTO_RECOVERY', 'Sistem başarıyla fabrika ayarlarına döndü', 'SYSTEM', 'RECOVERED');
};

// ============================================================
// 🚨 API ENDPOINTS
// ============================================================

// 1. SALDIRI TETİKLEME (Manuel Test)
app.post('/api/attack', (req, res) => {
    const { active, attackType, cveScore, sourceIP } = req.body;
    
    trafficStatus.isMitmAttack = active;
    trafficStatus.networkSecurity = active ? "Under Attack" : "Safe";
    
    if (active) {
        trafficStatus.criticalAlert = parseFloat(cveScore || 0) >= 9.0;
        trafficStatus.activeAttackType = attackType || "Unknown Attack";
        trafficStatus.activeCveScore = cveScore || "N/A";
        
        const severity = parseFloat(cveScore || 0) >= 9.0 ? 'CRITICAL' : 'HIGH';
        addLog(severity, 'ATTACK', 'THREAT_INTEL', 
               `Saldırı tespit edildi: ${attackType}`, 
               sourceIP || 'Unknown', 
               'ATTACK_DETECTED', 
               `CVE-2024-${Math.floor(Math.random() * 9999)}`);
        
        // Kritik saldırılarda otomatik popup tetikle
        if (trafficStatus.criticalAlert) {
            io.emit('critical-alert', {
                attackType: trafficStatus.activeAttackType,
                sourceIP: sourceIP || 'Unknown',
                cveScore: trafficStatus.activeCveScore,
                timestamp: new Date().toISOString()
            });
        }
    } else {
        addLog('LOW', 'SYSTEM', 'MITIGATION', 'Saldırı sona erdi veya engellendi', 'SYSTEM', 'MITIGATED');
    }
    
    io.emit('traffic-update', trafficStatus);
    res.json({ status: "OK", attackStatus: trafficStatus.isMitmAttack });
});

// 2. SAVUNMA / MİTİGASYON
app.post('/api/mitigate', (req, res) => {
    const { targetIP, cveScore, attackType } = req.body;
    
    if (!targetIP) {
        return res.status(400).json({ success: false, message: "IP adresi gerekli" });
    }

    const score = parseFloat(cveScore) || 0;
    
    if (score >= 7.0) {
        blacklistedIPs.set(targetIP, {
            reason: attackType || 'CVE-Based Auto-Mitigation',
            bannedAt: new Date().toISOString(),
            cveScore: score,
            attackType: attackType || 'Unknown',
            cveId: `CVE-2024-${Math.floor(Math.random() * 9999)}`
        });
        
        addLog('CRITICAL', 'MITIGATION', 'AUTO_BAN', 
               `IP otomatik banlandı: ${targetIP} | CVE Score: ${score}`, 
               targetIP, 
               'BANNED', 
               `CVE-SCORE-${score}`);
        
        // Saldırı bayrağını indir ve onar
        recoverSystem();
        
        // Realtime bildirim
        io.emit('ip-banned', {
            ip: targetIP,
            reason: attackType || 'Auto-mitigation',
            cveScore: score,
            bannedAt: new Date().toISOString()
        });

        return res.json({ 
            success: true, 
            action: "AUTO_RECOVER", 
            message: `${targetIP} banlandı ve sistem onarıldı`
        });
    }
    
    res.json({ success: false, message: "CVE skoru otomatik ban için yetersiz (min: 7.0)" });
});

// 3. IP UNBAN
app.post('/api/unban', (req, res) => {
    const { ip } = req.body;
    
    if (!ip) {
        return res.status(400).json({ success: false, message: "IP adresi gerekli" });
    }
    
    if (blacklistedIPs.has(ip)) {
        blacklistedIPs.delete(ip);
        addLog('MEDIUM', 'ADMIN', 'UNBAN', `IP ban kaldırıldı: ${ip}`, ip, 'UNBANNED');
        
        io.emit('ip-unbanned', { ip, timestamp: new Date().toISOString() });
        
        return res.json({ success: true, message: `${ip} ban listesinden çıkarıldı` });
    }
    
    res.json({ success: false, message: "IP zaten ban listesinde değil" });
});

// 4. BANLI IP'LERİ LİSTELE
app.get('/api/banned-ips', (req, res) => {
    const bannedList = Array.from(blacklistedIPs.entries()).map(([ip, data]) => ({
        ip,
        ...data
    }));
    
    res.json(bannedList);
});

// 5. RATE LIMITING DURUMU
app.get('/api/rate-status', (req, res) => {
    const now = Date.now();
    const statusMap = {};
    
    requestCounts.forEach((data, ip) => {
        statusMap[ip] = {
            count: data.count,
            inCooldown: data.inCooldown,
            cooldownRemaining: data.inCooldown ? Math.ceil((data.cooldownUntil - now) / 1000) : 0
        };
    });
    
    res.json(statusMap);
});

// 6. CVE VERİTABANI
app.get('/api/cve-database', (req, res) => {
    res.json(CVE_DATABASE);
});

// 7. LOG AKIŞI
app.get('/api/logs', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    res.json({
        logs: logBuffer.slice(0, limit),
        total: logBuffer.length,
        timestamp: new Date().toISOString()
    });
});

// 8. SİSTEM İSTATİSTİKLERİ
app.get('/api/stats', (req, res) => {
    const now = Date.now();
    let activeCooldowns = 0;
    
    requestCounts.forEach((data) => {
        if (data.inCooldown && now < data.cooldownUntil) {
            activeCooldowns++;
        }
    });
    
    res.json({
        bannedIPs: blacklistedIPs.size,
        activeCooldowns,
        totalRequests: Array.from(requestCounts.values()).reduce((sum, d) => sum + d.count, 0),
        logsCount: logBuffer.length,
        systemStatus: trafficStatus.networkSecurity,
        underAttack: trafficStatus.isMitmAttack,
        criticalAlert: trafficStatus.criticalAlert
    });
});

// 9. TÜM BANLARI TEMİZLE (Admin)
app.post('/api/clear-bans', (req, res) => {
    const count = blacklistedIPs.size;
    blacklistedIPs.clear();
    
    addLog('MEDIUM', 'ADMIN', 'CLEAR_BANS', `Tüm ban listesi temizlendi (${count} IP)`, 'ADMIN', 'CLEARED');
    io.emit('bans-cleared', { count, timestamp: new Date().toISOString() });
    
    res.json({ success: true, message: `${count} IP ban'ı kaldırıldı` });
});

// 10. LOGLAR TEMİZLE
app.post('/api/clear-logs', (req, res) => {
    const count = logBuffer.length;
    logBuffer.length = 0;
    
    addLog('LOW', 'ADMIN', 'CLEAR_LOGS', `Log geçmişi temizlendi (${count} kayıt)`, 'ADMIN', 'CLEARED');
    
    res.json({ success: true, message: `${count} log kaydı silindi` });
});

// ============================================================
// 🚦 TRAFİK DÖNGÜSÜ
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
// 🔍 WATCHDOG: Tutarsızlık Tespiti
// ============================================================
setInterval(() => {
    if (trafficStatus.light === "glitch" && !trafficStatus.isMitmAttack) {
        addLog('HIGH', 'WATCHDOG', 'ANOMALY', 
               'Tutarsızlık tespit edildi: Işık bozuk ama aktif saldırı yok', 
               'SYSTEM', 'ANOMALY_DETECTED');
        recoverSystem();
    }
}, 10000);

// ============================================================
// 🔗 SOCKET.IO EVENT HANDLER
// ============================================================
io.on('connection', (socket) => {
    addLog('LOW', 'CONNECTION', 'SOCKET', 'Yeni client bağlandı', socket.handshake.address, 'CONNECTED');
    
    // İlk bağlantıda mevcut durumu gönder
    socket.emit('traffic-update', trafficStatus);
    socket.emit('initial-data', {
        bannedIPs: Array.from(blacklistedIPs.entries()).map(([ip, data]) => ({ ip, ...data })),
        logs: logBuffer.slice(0, 50),
        cveDatabase: CVE_DATABASE,
        stats: {
            bannedIPs: blacklistedIPs.size,
            logsCount: logBuffer.length
        }
    });
    
    socket.on('disconnect', () => {
        addLog('LOW', 'CONNECTION', 'SOCKET', 'Client bağlantısı kesildi', socket.handshake.address, 'DISCONNECTED');
    });
});

// ============================================================
// 🚀 SUNUCULARI BAŞLAT
// ============================================================
const API_PORT = process.env.PORT || 3000;
server.listen(API_PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║  🚀 OKAF SOAR SYSTEM - ACTIVATED                         ║
║  📡 API & WebSocket Server: PORT ${API_PORT}             ║
║  🛡️  Security Shield: ENABLED                            ║
║  📊 Log Buffer: ${MAX_LOGS} entries                       ║
║  ⚡ Rate Limit: ${RATE_LIMIT_THRESHOLD} req/s            ║
║  🔒 Cooldown: ${COOLDOWN_DURATION / 1000}s                ║
╚═══════════════════════════════════════════════════════════╝
    `);
    
    addLog('LOW', 'SYSTEM', 'STARTUP', 'OKAF SOAR Sistemi başlatıldı', 'SYSTEM', 'STARTED');
});

const MODBUS_PORT = process.env.MODBUS_PORT || 502;
netServer.listen(MODBUS_PORT, () => {
    console.log(`📟 Modbus TCP Sunucusu: ${MODBUS_PORT} portunda aktif.`);
    addLog('LOW', 'SYSTEM', 'STARTUP', `Modbus TCP server başlatıldı - Port: ${MODBUS_PORT}`, 'SYSTEM', 'STARTED');
});

modbusServer.on('postReadHoldingRegisters', (request, cb) => {
    cb(holdingRegisters);
});
