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
const blockedIPs = new Map();
const requestCounts = {};
const cooldowns = new Map();
const RATE_LIMIT_THRESHOLD = 100;
const COOLDOWN_DURATION = 5 * 60 * 1000;

// ============================================================
// DİNAMİK VERİ AKIŞI - GERÇEK ZAMANLI SİMÜLASYON
// ============================================================
const trafficMetrics = {
    totalRequests: 0,
    blockedRequests: 0,
    avgResponseTime: 0,
    activeConnections: 0,
    throughput: 0, // req/s
    bandwidth: 0, // MB/s
    cpuUsage: 0,
    memoryUsage: 0
};

const geoAttackSources = [
    { country: 'Rusya', flag: '🇷🇺', code: 'RU', ips: [] },
    { country: 'Çin', flag: '🇨🇳', code: 'CN', ips: [] },
    { country: 'Kuzey Kore', flag: '🇰🇵', code: 'KP', ips: [] },
    { country: 'İran', flag: '🇮🇷', code: 'IR', ips: [] },
    { country: 'ABD', flag: '🇺🇸', code: 'US', ips: [] },
    { country: 'Almanya', flag: '🇩🇪', code: 'DE', ips: [] }
];

// ============================================================
// LOG DEPOSU
// ============================================================
const attackLogs = [];
const MAX_LOGS = 200;

// ============================================================
// CVE VERİTABANI (Genişletilmiş)
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
        published: "2024-06-09",
        affected: "PHP 8.1.x - 8.3.x",
        patch: "PHP 8.3.8+"
    },
    {
        id: "CVE-2024-3400",
        score: 10.0,
        severity: "CRITICAL",
        mitreId: "T1210",
        description: "PAN-OS GlobalProtect OS Command Injection RCE",
        service: "VPN Gateway",
        attackType: "Man-in-the-Middle",
        published: "2024-04-12",
        affected: "PAN-OS 10.x, 11.x",
        patch: "PAN-OS 11.1.2-h3"
    },
    {
        id: "CVE-2023-44487",
        score: 7.5,
        severity: "HIGH",
        mitreId: "T1499",
        description: "HTTP/2 Rapid Reset Attack — Dağıtık Servis Engelleme",
        service: "HTTP/2 Web Server",
        attackType: "DDoS",
        published: "2023-10-10",
        affected: "HTTP/2 All Versions",
        patch: "Server Configuration"
    },
    {
        id: "CVE-2024-21887",
        score: 9.1,
        severity: "CRITICAL",
        mitreId: "T1059",
        description: "Ivanti Connect Secure Komut Enjeksiyonu RCE",
        service: "VPN / ICS",
        attackType: "Brute Force",
        published: "2024-01-10",
        affected: "Ivanti Connect 9.x, 22.x",
        patch: "Ivanti Connect 22.7R2.1"
    },
    {
        id: "CVE-2024-23897",
        score: 9.8,
        severity: "CRITICAL",
        mitreId: "T1213",
        description: "Jenkins CLI Arbitrary File Read / Uzaktan Kod Çalıştırma",
        service: "CI/CD Pipeline",
        attackType: "SQL Injection",
        published: "2024-01-24",
        affected: "Jenkins < 2.442",
        patch: "Jenkins 2.442+"
    },
    {
        id: "CVE-2024-6387",
        score: 8.1,
        severity: "HIGH",
        mitreId: "T1021",
        description: "OpenSSH RegreSSHion - Race Condition RCE",
        service: "SSH Server",
        attackType: "Remote Code Execution",
        published: "2024-07-01",
        affected: "OpenSSH 8.5p1 - 9.7p1",
        patch: "OpenSSH 9.8p1"
    },
    {
        id: "CVE-2024-1086",
        score: 7.8,
        severity: "HIGH",
        mitreId: "T1068",
        description: "Linux Kernel Use-After-Free Privilege Escalation",
        service: "Linux Kernel",
        attackType: "Privilege Escalation",
        published: "2024-01-31",
        affected: "Linux Kernel 5.14 - 6.6",
        patch: "Kernel 6.7+"
    }
];

// ============================================================
// SALDIRI TİPLERİ VE SİMÜLASYON VERİLERİ
// ============================================================
const attackPatterns = [
    { 
        type: 'SQL Injection', 
        icon: '💉', 
        probability: 0.25,
        payloads: [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM credentials--",
            "admin'--",
            "' OR 1=1--"
        ],
        ports: [80, 443, 8080, 3306]
    },
    { 
        type: 'DDoS Attack', 
        icon: '⚡', 
        probability: 0.20,
        payloads: [
            "SYN Flood",
            "UDP Flood",
            "HTTP Flood",
            "Slowloris Attack"
        ],
        ports: [80, 443, 53, 8080]
    },
    { 
        type: 'XSS Attempt', 
        icon: '🎭', 
        probability: 0.15,
        payloads: [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert('XSS')>",
            "javascript:alert(document.cookie)"
        ],
        ports: [80, 443, 8080]
    },
    { 
        type: 'Brute Force', 
        icon: '🔨', 
        probability: 0.15,
        payloads: [
            "SSH Login Attempt",
            "RDP Brute Force",
            "FTP Password Guess",
            "Admin Panel Attack"
        ],
        ports: [22, 3389, 21, 80]
    },
    { 
        type: 'Port Scan', 
        icon: '🔍', 
        probability: 0.10,
        payloads: [
            "Nmap SYN Scan",
            "Full Connect Scan",
            "Service Enumeration",
            "OS Fingerprinting"
        ],
        ports: [1, 22, 80, 443, 3389, 8080]
    },
    { 
        type: 'Malware Upload', 
        icon: '🦠', 
        probability: 0.08,
        payloads: [
            "ransomware.exe",
            "trojan.sh",
            "backdoor.php",
            "cryptominer.js"
        ],
        ports: [80, 443, 21]
    },
    { 
        type: 'CSRF Attack', 
        icon: '🎪', 
        probability: 0.05,
        payloads: [
            "Unauthorized Fund Transfer",
            "Profile Modification",
            "Password Change Request",
            "Admin Action Forgery"
        ],
        ports: [80, 443]
    },
    { 
        type: 'Directory Traversal', 
        icon: '📁', 
        probability: 0.02,
        payloads: [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/shadow",
            "file:///etc/passwd"
        ],
        ports: [80, 443, 8080]
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
    activeSourceIP: null,
    greenWaveActive: false,
    greenWaveProgress: 0
};

// ============================================================
// MODBUS YAPILANDIRMASI (GENİŞLETİLMİŞ)
// ============================================================
const holdingRegisters = Buffer.alloc(200);
const netServer = new net.Server();
const modbusServer = new modbus.server.TCP(netServer);

// Register mapping
const REGISTER_MAP = {
    LIGHT_STATUS: 0,      // 0=red, 1=yellow, 2=green, 99=glitch
    TIMER: 2,             // Countdown timer
    CAR_COUNT: 4,         // Vehicles waiting
    ATTACK_STATUS: 6,     // 0=safe, 1=attack
    CVE_SCORE: 8,         // CVE score * 10
    BLOCKED_IPS: 10,      // Count of blocked IPs
    TOTAL_LOGS: 12,       // Total log entries
    THROUGHPUT: 14,       // Requests per second
    CPU_USAGE: 16,        // CPU percentage
    MEMORY_USAGE: 18,     // Memory percentage
    BANDWIDTH: 20,        // Bandwidth in KB/s
    GREEN_WAVE: 22        // Green wave status (0-100)
};

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

function generateRandomIP(countryCode) {
    const ipRanges = {
        'RU': () => `${Math.floor(Math.random() * 30) + 185}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        'CN': () => `${Math.floor(Math.random() * 10) + 115}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        'KP': () => `175.45.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        'IR': () => `${Math.floor(Math.random() * 5) + 5}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        'US': () => `${Math.floor(Math.random() * 50) + 50}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        'DE': () => `${Math.floor(Math.random() * 10) + 80}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
    };
    return (ipRanges[countryCode] || ipRanges['US'])();
}

// Modbus register güncelleyici
function updateModbusRegisters() {
    try {
        holdingRegisters.writeUInt16BE(getLightCode(trafficStatus.light), REGISTER_MAP.LIGHT_STATUS);
        holdingRegisters.writeUInt16BE(trafficStatus.timer, REGISTER_MAP.TIMER);
        holdingRegisters.writeUInt16BE(trafficStatus.carCount, REGISTER_MAP.CAR_COUNT);
        holdingRegisters.writeUInt16BE(trafficStatus.isMitmAttack ? 1 : 0, REGISTER_MAP.ATTACK_STATUS);
        holdingRegisters.writeUInt16BE(Math.floor((trafficStatus.activeCveScore || 0) * 10), REGISTER_MAP.CVE_SCORE);
        holdingRegisters.writeUInt16BE(blockedIPs.size, REGISTER_MAP.BLOCKED_IPS);
        holdingRegisters.writeUInt16BE(attackLogs.length, REGISTER_MAP.TOTAL_LOGS);
        holdingRegisters.writeUInt16BE(Math.floor(trafficMetrics.throughput), REGISTER_MAP.THROUGHPUT);
        holdingRegisters.writeUInt16BE(Math.floor(trafficMetrics.cpuUsage), REGISTER_MAP.CPU_USAGE);
        holdingRegisters.writeUInt16BE(Math.floor(trafficMetrics.memoryUsage), REGISTER_MAP.MEMORY_USAGE);
        holdingRegisters.writeUInt16BE(Math.floor(trafficMetrics.bandwidth * 1024), REGISTER_MAP.BANDWIDTH);
        holdingRegisters.writeUInt16BE(trafficStatus.greenWaveProgress, REGISTER_MAP.GREEN_WAVE);
    } catch (err) {
        console.error("[MODBUS] Register yazma hatası:", err.message);
    }
}

setInterval(updateModbusRegisters, 1000);

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
        targetPort: 80,
        country: "Unknown",
        ...logData
    };
    
    attackLogs.unshift(log);
    if (attackLogs.length > MAX_LOGS) attackLogs.pop();
    
    io.emit('new-log', log);
    
    console.log(`[LOG][${log.severity}] ${log.sourceIP} | ${log.attackType} | CVE:${log.cveScore} | ${log.action}`);
    
    return log;
}

// ============================================================
// DİNAMİK VERİ SİMÜLATÖRÜ
// ============================================================
function simulateTrafficMetrics() {
    trafficMetrics.totalRequests += Math.floor(Math.random() * 50) + 10;
    trafficMetrics.blockedRequests += Math.floor(Math.random() * 5);
    trafficMetrics.avgResponseTime = Math.floor(Math.random() * 150) + 50;
    trafficMetrics.activeConnections = Math.floor(Math.random() * 100) + 20;
    trafficMetrics.throughput = Math.floor(Math.random() * 1000) + 200;
    trafficMetrics.bandwidth = (Math.random() * 10 + 2).toFixed(2);
    trafficMetrics.cpuUsage = Math.floor(Math.random() * 40) + 30;
    trafficMetrics.memoryUsage = Math.floor(Math.random() * 30) + 50;
    
    io.emit('metrics-update', trafficMetrics);
}

// Simüle saldırı üreteci
function generateSimulatedAttack() {
    const rand = Math.random();
    let cumulativeProbability = 0;
    let selectedPattern = attackPatterns[0];
    
    for (const pattern of attackPatterns) {
        cumulativeProbability += pattern.probability;
        if (rand <= cumulativeProbability) {
            selectedPattern = pattern;
            break;
        }
    }
    
    const countryIndex = Math.floor(Math.random() * geoAttackSources.length);
    const country = geoAttackSources[countryIndex];
    const sourceIP = generateRandomIP(country.code);
    
    const cve = CVE_DATABASE.find(c => c.attackType === selectedPattern.type) || CVE_DATABASE[0];
    const payload = selectedPattern.payloads[Math.floor(Math.random() * selectedPattern.payloads.length)];
    const targetPort = selectedPattern.ports[Math.floor(Math.random() * selectedPattern.ports.length)];
    
    addLog({
        sourceIP,
        attackType: selectedPattern.type,
        payload,
        cveScore: cve.score,
        mitreId: cve.mitreId,
        action: "DETECTED",
        severity: cve.severity,
        targetPort,
        country: country.country
    });
    
    // Coğrafi kaynak güncelleme
    country.ips.push(sourceIP);
    if (country.ips.length > 100) country.ips.shift();
    
    io.emit('geo-update', {
        country: country.country,
        flag: country.flag,
        count: country.ips.length,
        latestIP: sourceIP
    });
}

// ============================================================
// GÜVENLİK KALKANI MIDDLEWARE
// ============================================================
const securityShield = (req, res, next) => {
    const clientIP = getClientIP(req);
    const now = Date.now();
    
    trafficMetrics.totalRequests++;
    
    if (blockedIPs.has(clientIP)) {
        const banInfo = blockedIPs.get(clientIP);
        trafficMetrics.blockedRequests++;
        
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
    
    if (cooldowns.has(clientIP)) {
        const cd = cooldowns.get(clientIP);
        if (now < cd.until) {
            const remaining = Math.ceil((cd.until - now) / 1000);
            trafficMetrics.blockedRequests++;
            
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
// API: SALDIRI RAPORU
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
        
        addLog({
            sourceIP: sourceIP || "Unknown",
            attackType: attackType || "Unknown",
            payload: payload || "-",
            cveScore: cveScore || 0,
            mitreId: mitreId || "-",
            action: isCritical ? "CRITICAL_ALERT" : "DETECTED",
            severity: isCritical ? "CRITICAL" : "HIGH"
        });
        
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
// API: MANUEL MİTİGASYON
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
// API: YEŞIL IŞIK DALGASI KONTROLÜ
// ============================================================
app.post('/api/greenwave', (req, res) => {
    const { enable } = req.body;
    
    trafficStatus.greenWaveActive = !!enable;
    trafficStatus.greenWaveProgress = enable ? 0 : 0;
    
    addLog({
        sourceIP: "SYSTEM",
        attackType: "GREEN_WAVE",
        payload: `Yeşil ışık dalgası ${enable ? 'başlatıldı' : 'durduruldu'}`,
        cveScore: 0,
        action: enable ? "ACTIVATED" : "DEACTIVATED",
        severity: "INFO"
    });
    
    io.emit('greenwave-update', {
        active: trafficStatus.greenWaveActive,
        progress: trafficStatus.greenWaveProgress
    });
    
    res.json({ success: true, greenWaveActive: trafficStatus.greenWaveActive });
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
// API: COĞRAFİ SALDIRI İSTATİSTİKLERİ
// ============================================================
app.get('/api/geo-stats', (req, res) => {
    const stats = geoAttackSources.map(country => ({
        country: country.country,
        flag: country.flag,
        count: country.ips.length,
        percentage: Math.round((country.ips.length / Math.max(1, attackLogs.length)) * 100)
    })).sort((a, b) => b.count - a.count);
    
    res.json(stats);
});

// ============================================================
// API: TRAFİK METRİKLERİ
// ============================================================
app.get('/api/metrics', (req, res) => {
    res.json(trafficMetrics);
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
        logCount: attackLogs.length,
        metrics: trafficMetrics
    });
});

// ============================================================
// API: MODBUS REGİSTER OKUMA
// ============================================================
app.get('/api/modbus/registers', (req, res) => {
    const registers = {};
    Object.entries(REGISTER_MAP).forEach(([key, address]) => {
        registers[key] = holdingRegisters.readUInt16BE(address);
    });
    res.json(registers);
});

// ============================================================
// TRAFİK DÖNGÜSÜ
// ============================================================
setInterval(() => {
    if (!trafficStatus.isMitmAttack) {
        if (trafficStatus.greenWaveActive) {
            // Yeşil ışık dalgası modu
            trafficStatus.light = "green";
            trafficStatus.greenWaveProgress = (trafficStatus.greenWaveProgress + 5) % 100;
            trafficStatus.timer = 30;
        } else {
            if (trafficStatus.timer > 0) {
                trafficStatus.timer--;
            } else {
                const next = { red: "green", green: "yellow", yellow: "red" };
                trafficStatus.light = next[trafficStatus.light];
                trafficStatus.timer = trafficStatus.light === "yellow" ? 3 : 15;
            }
        }
        
        // Araç sayısı simülasyonu
        if (trafficStatus.light === "green") {
            trafficStatus.carCount = Math.max(0, trafficStatus.carCount - Math.floor(Math.random() * 5));
        } else {
            trafficStatus.carCount = Math.min(100, trafficStatus.carCount + Math.floor(Math.random() * 3));
        }
    } else {
        trafficStatus.light = "glitch";
        trafficStatus.timer = Math.floor(Math.random() * 99);
        trafficStatus.carCount = Math.min(100, trafficStatus.carCount + Math.floor(Math.random() * 5));
    }
    
    io.emit('traffic-update', trafficStatus);
}, 1000);

// ============================================================
// DİNAMİK VERİ SİMÜLASYONU
// ============================================================
setInterval(simulateTrafficMetrics, 2000);
setInterval(generateSimulatedAttack, 5000);

// ============================================================
// SOCKET.IO BAĞLANTILARI
// ============================================================
io.on('connection', (socket) => {
    console.log(`[SOCKET] Yeni bağlantı: ${socket.id}`);
    
    // İlk bağlantıda mevcut durumu gönder
    socket.emit('traffic-update', trafficStatus);
    socket.emit('metrics-update', trafficMetrics);
    
    socket.on('disconnect', () => {
        console.log(`[SOCKET] Bağlantı kesildi: ${socket.id}`);
    });
});

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
    
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                    🛡️  SOC/SOAR SİSTEMİ BAŞLATILDI            ║
╠═══════════════════════════════════════════════════════════════╣
║  🚀 API Sunucusu        : http://localhost:${API_PORT}                ║
║  🏙️  Trafik Paneli      : http://localhost:${API_PORT}/             ║
║  🛡️  SOC/SOAR Paneli    : http://localhost:${API_PORT}/soc          ║
║  📊 Dinamik Veri Akışı  : ✅ AKTİF                            ║
║  🔄 Simüle Saldırılar   : ✅ AKTİF (5 saniyede bir)           ║
║  📈 Metrik Güncellemesi : ✅ AKTİF (2 saniyede bir)           ║
╚═══════════════════════════════════════════════════════════════╝
    `);
});

const MODBUS_PORT = process.env.MODBUS_PORT || 5020;
netServer.listen(MODBUS_PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  📟 Modbus TCP Sunucusu : port ${MODBUS_PORT}                         ║
║  📊 Register Haritası   :                                     ║
║     - LIGHT_STATUS      : Reg 0  (0=red,1=yellow,2=green)     ║
║     - TIMER             : Reg 2  (Geri sayım)                 ║
║     - CAR_COUNT         : Reg 4  (Bekleyen araç)              ║
║     - ATTACK_STATUS     : Reg 6  (0=safe, 1=attack)           ║
║     - CVE_SCORE         : Reg 8  (CVE skoru x10)              ║
║     - BLOCKED_IPS       : Reg 10 (Ban sayısı)                 ║
║     - THROUGHPUT        : Reg 14 (İstek/saniye)               ║
║     - GREEN_WAVE        : Reg 22 (Yeşil dalga %)              ║
╚═══════════════════════════════════════════════════════════════╝
    `);
});

modbusServer.on('postReadHoldingRegisters', (request, cb) => {
    cb(holdingRegisters);
});

// ============================================================
// HATA YÖNETİMİ
// ============================================================
process.on('uncaughtException', (err) => {
    console.error('[HATA] Yakalanmamış istisna:', err);
    addLog({
        sourceIP: "SYSTEM",
        attackType: "SYSTEM_ERROR",
        payload: err.message,
        cveScore: 0,
        action: "ERROR",
        severity: "HIGH"
    });
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[HATA] İşlenmeyen Promise reddi:', reason);
    addLog({
        sourceIP: "SYSTEM",
        attackType: "PROMISE_ERROR",
        payload: String(reason),
        cveScore: 0,
        action: "ERROR",
        severity: "MEDIUM"
    });
});
