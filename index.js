// ============================================================
// 🛡️ ROBLOX SCRIPT PROTECTOR - BACKEND SERVER
// ============================================================

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto-js');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 📦 DATABASE IN-MEMORY (Bisa diganti dengan MongoDB/Redis)
// ============================================================

const database = {
    // Valid Keys dengan expiry dan HWID
    keys: {
        "TEST-KEY-0001-FREE": {
            hwid: null,           // null = belum terdaftar
            maxHwid: 1,           // maksimal 1 device
            expiry: null,         // null = lifetime
            createdAt: Date.now(),
            usageCount: 0,
            tier: "free"
        },
        "PREM-KEY-1234-XXXX": {
            hwid: null,
            maxHwid: 2,
            expiry: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 hari
            createdAt: Date.now(),
            usageCount: 0,
            tier: "premium"
        }
    },
    
    // Blacklist IP dan HWID
    blacklist: {
        ips: [],
        hwids: []
    },
    
    // Log akses
    logs: [],
    
    // Failed attempts untuk auto-blacklist
    failedAttempts: {}
};

// ============================================================
// 🔧 KONFIGURASI
// ============================================================

const CONFIG = {
    ORIGINAL_SCRIPT_URL: process.env.ORIGINAL_SCRIPT_URL || "https://api.junkie-development.de/api/v1/luascripts/public/8a56151af71ed4b56c346b2bef75d232f22d3ffb242e31d5ef79d12f69d974d6/download",
    SECRET_KEY: process.env.SECRET_KEY || "super-secret-key-change-this",
    ADMIN_KEY: process.env.ADMIN_KEY || "admin-secret-key",
    MAX_FAILED_ATTEMPTS: 5,
    RATE_LIMIT_WINDOW: 60 * 1000,  // 1 menit
    RATE_LIMIT_MAX: 10,            // 10 request per window
    ENABLE_OBFUSCATION: true,
    ENABLE_ANTI_TAMPER: true,
    ENABLE_HEARTBEAT: true
};

// ============================================================
// 🛡️ MIDDLEWARE SETUP
// ============================================================

// Security Headers
app.use(helmet());

// CORS
app.use(cors());

// JSON Parser
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
    windowMs: CONFIG.RATE_LIMIT_WINDOW,
    max: CONFIG.RATE_LIMIT_MAX,
    message: { 
        success: false, 
        error: "Too many requests. Please wait before trying again.",
        code: "RATE_LIMITED"
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logAccess(req, 'RATE_LIMITED', false);
        res.status(429).json({
            success: false,
            error: "Rate limit exceeded",
            code: "RATE_LIMITED"
        });
    }
});

app.use('/api/', limiter);

// ============================================================
// 📝 LOGGING FUNCTIONS
// ============================================================

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.ip || 
           'unknown';
}

function logAccess(req, action, success, details = {}) {
    const log = {
        timestamp: new Date().toISOString(),
        ip: getClientIP(req),
        userAgent: req.headers['user-agent'] || 'unknown',
        action: action,
        success: success,
        key: req.query.key || req.body?.key || 'none',
        hwid: req.query.hwid || req.body?.hwid || 'none',
        ...details
    };
    
    database.logs.push(log);
    
    // Keep only last 1000 logs
    if (database.logs.length > 1000) {
        database.logs = database.logs.slice(-1000);
    }
    
    console.log(`[${log.timestamp}] ${success ? '✅' : '❌'} ${action} - IP: ${log.ip} - Key: ${log.key}`);
    
    return log;
}

// ============================================================
// 🔐 SECURITY FUNCTIONS
// ============================================================

// Check if IP/HWID is blacklisted
function isBlacklisted(ip, hwid) {
    return database.blacklist.ips.includes(ip) || 
           database.blacklist.hwids.includes(hwid);
}

// Add to blacklist
function addToBlacklist(ip, hwid, reason) {
    if (ip && !database.blacklist.ips.includes(ip)) {
        database.blacklist.ips.push(ip);
    }
    if (hwid && !database.blacklist.hwids.includes(hwid)) {
        database.blacklist.hwids.push(hwid);
    }
    console.log(`🚫 Blacklisted - IP: ${ip}, HWID: ${hwid}, Reason: ${reason}`);
}

// Track failed attempts
function trackFailedAttempt(ip) {
    if (!database.failedAttempts[ip]) {
        database.failedAttempts[ip] = { count: 0, firstAttempt: Date.now() };
    }
    
    database.failedAttempts[ip].count++;
    
    // Auto-blacklist after too many failed attempts
    if (database.failedAttempts[ip].count >= CONFIG.MAX_FAILED_ATTEMPTS) {
        addToBlacklist(ip, null, "Too many failed attempts");
        return true;
    }
    
    return false;
}

// Validate key
function validateKey(key, hwid) {
    const keyData = database.keys[key];
    
    if (!keyData) {
        return { valid: false, error: "Invalid key", code: "INVALID_KEY" };
    }
    
    // Check expiry
    if (keyData.expiry && Date.now() > keyData.expiry) {
        return { valid: false, error: "Key has expired", code: "KEY_EXPIRED" };
    }
    
    // Check HWID
    if (keyData.hwid === null) {
        // First time use - register HWID
        keyData.hwid = hwid;
        console.log(`🔗 HWID registered for key ${key}: ${hwid}`);
    } else if (keyData.hwid !== hwid) {
        return { valid: false, error: "HWID mismatch. This key is locked to another device.", code: "HWID_MISMATCH" };
    }
    
    // Increment usage
    keyData.usageCount++;
    
    return { valid: true, keyData };
}

// ============================================================
// 🔒 OBFUSCATION ENGINE
// ============================================================

function generateRandomString(length) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return '_' + result;
}

function encryptString(str) {
    // Convert string to byte codes
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        bytes.push(str.charCodeAt(i));
    }
    return `(function() local t={${bytes.join(',')}} local s="" for i=1,#t do s=s..string.char(t[i]) end return s end)()`;
}

function obfuscateScript(script) {
    if (!CONFIG.ENABLE_OBFUSCATION) return script;
    
    let obfuscated = script;
    
    // 1. Encrypt strings (basic)
    const stringPattern = /"([^"\\]|\\.)*"|'([^'\\]|\\.)*'/g;
    const strings = obfuscated.match(stringPattern) || [];
    
    strings.forEach((str, index) => {
        const content = str.slice(1, -1);
        if (content.length > 2 && content.length < 50) {
            const encrypted = encryptString(content);
            obfuscated = obfuscated.replace(str, encrypted);
        }
    });
    
    // 2. Add junk code
    const junkCode = `
-- ${generateRandomString(20)}
local ${generateRandomString(8)} = (function()
    local ${generateRandomString(6)} = {}
    for ${generateRandomString(4)}=1,math.random(1,10) do
        ${generateRandomString(6)}[${generateRandomString(4)}] = math.random()
    end
    return ${generateRandomString(6)}
end)()
`;
    
    // 3. Wrap in protected call
    obfuscated = `
--[[ 
    Protected by Script Protector
    Generated: ${new Date().toISOString()}
    ID: ${uuidv4()}
]]

${junkCode}

local ${generateRandomString(10)} = function()
${obfuscated}
end

${generateRandomString(10)}()
`;
    
    return obfuscated;
}

// ============================================================
// 🛡️ ANTI-TAMPER CODE INJECTION
// ============================================================

function generateAntiTamperCode(key, hwid, sessionToken) {
    if (!CONFIG.ENABLE_ANTI_TAMPER) return "";
    
    return `
-- ============================================================
-- 🛡️ ANTI-TAMPER PROTECTION
-- ============================================================

local _PROTECTED = true
local _SESSION_TOKEN = "${sessionToken}"
local _VALID_KEY = "${key}"
local _VALID_HWID = "${hwid}"
local _SERVER_URL = "${process.env.RENDER_EXTERNAL_URL || 'http://localhost:' + PORT}"
local _START_TIME = tick()

-- Environment Check
local function _checkEnvironment()
    local checks = {
        {getfenv, "getfenv"},
        {setfenv, "setfenv"},
        {getmetatable, "getmetatable"},
        {setmetatable, "setmetatable"},
        {rawget, "rawget"},
        {rawset, "rawset"}
    }
    
    for _, check in ipairs(checks) do
        if type(check[1]) ~= "function" then
            return false, "Environment tampered: " .. check[2]
        end
    end
    
    return true
end

-- Debug Detection
local function _checkDebug()
    local info = debug and debug.info or nil
    if info then
        local status, result = pcall(function()
            return debug.info(1, "f")
        end)
        if not status then
            return false, "Debug hooks detected"
        end
    end
    return true
end

-- Self-Destruct Function
local function _selfDestruct(reason)
    warn("[SECURITY] Script terminated: " .. tostring(reason))
    
    -- Report to server
    pcall(function()
        local http = game:GetService("HttpService")
        http:PostAsync(_SERVER_URL .. "/api/report", http:JSONEncode({
            key = _VALID_KEY,
            hwid = _VALID_HWID,
            reason = reason,
            timestamp = os.time()
        }))
    end)
    
    -- Crash the script
    while true do
        wait(0.1)
        error("Security violation detected")
    end
end

-- Run checks
local envOk, envErr = _checkEnvironment()
if not envOk then
    _selfDestruct(envErr)
end

local debugOk, debugErr = _checkDebug()
if not debugOk then
    _selfDestruct(debugErr)
end

-- Heartbeat System
${CONFIG.ENABLE_HEARTBEAT ? `
spawn(function()
    local http = game:GetService("HttpService")
    while _PROTECTED do
        wait(30) -- Every 30 seconds
        
        local success, response = pcall(function()
            return http:PostAsync(_SERVER_URL .. "/api/heartbeat", http:JSONEncode({
                token = _SESSION_TOKEN,
                key = _VALID_KEY,
                hwid = _VALID_HWID,
                uptime = tick() - _START_TIME
            }))
        end)
        
        if not success then
            warn("[HEARTBEAT] Failed to connect to server")
        else
            local data = http:JSONDecode(response)
            if not data.valid then
                _selfDestruct("Heartbeat validation failed")
            end
        end
    end
end)
` : '-- Heartbeat disabled'}

print("[SECURITY] Protection initialized successfully")

-- ============================================================
-- 📜 PROTECTED SCRIPT BELOW
-- ============================================================

`;
}

// ============================================================
// 🌐 API ROUTES
// ============================================================

// Health Check
app.get('/', (req, res) => {
    res.json({
        status: "online",
        message: "🛡️ Roblox Script Protector API",
        version: "1.0.0",
        endpoints: {
            script: "GET /api/script?key=YOUR_KEY&hwid=YOUR_HWID",
            validate: "POST /api/validate",
            heartbeat: "POST /api/heartbeat",
            admin: "POST /api/admin/* (requires admin key)"
        }
    });
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: "healthy", 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ============================================================
// 📜 MAIN SCRIPT ENDPOINT
// ============================================================

app.get('/api/script', async (req, res) => {
    const { key, hwid } = req.query;
    const clientIP = getClientIP(req);
    
    try {
        // 1. Check required params
        if (!key || !hwid) {
            logAccess(req, 'SCRIPT_ACCESS', false, { error: 'Missing parameters' });
            return res.status(400).send('-- Error: Missing key or hwid parameter');
        }
        
        // 2. Check blacklist
        if (isBlacklisted(clientIP, hwid)) {
            logAccess(req, 'SCRIPT_ACCESS', false, { error: 'Blacklisted' });
            return res.status(403).send('-- Error: Access denied. You have been blacklisted.');
        }
        
        // 3. Validate key
        const validation = validateKey(key, hwid);
        if (!validation.valid) {
            const wasBlacklisted = trackFailedAttempt(clientIP);
            logAccess(req, 'SCRIPT_ACCESS', false, { error: validation.error });
            
            if (wasBlacklisted) {
                return res.status(403).send('-- Error: Too many failed attempts. You have been blacklisted.');
            }
            
            return res.status(401).send(`-- Error: ${validation.error}`);
        }
        
        // 4. Fetch original script
        console.log(`📥 Fetching script from: ${CONFIG.ORIGINAL_SCRIPT_URL}`);
        
        const response = await axios.get(CONFIG.ORIGINAL_SCRIPT_URL, {
            timeout: 10000,
            headers: {
                'User-Agent': 'ScriptProtector/1.0'
            }
        });
        
        let originalScript = response.data;
        
        // 5. Generate session token
        const sessionToken = crypto.SHA256(key + hwid + Date.now()).toString().substring(0, 32);
        
        // 6. Add anti-tamper code
        const antiTamperCode = generateAntiTamperCode(key, hwid, sessionToken);
        
        // 7. Combine and obfuscate
        let finalScript = antiTamperCode + originalScript;
        finalScript = obfuscateScript(finalScript);
        
        // 8. Log success
        logAccess(req, 'SCRIPT_ACCESS', true, { 
            tier: validation.keyData.tier,
            sessionToken: sessionToken.substring(0, 8) + '...'
        });
        
        // 9. Return script
        res.setHeader('Content-Type', 'text/plain');
        res.send(finalScript);
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        logAccess(req, 'SCRIPT_ACCESS', false, { error: error.message });
        res.status(500).send(`-- Error: Failed to load script. Please try again later.`);
    }
});

// ============================================================
// 🔐 VALIDATION ENDPOINT
// ============================================================

app.post('/api/validate', (req, res) => {
    const { key, hwid } = req.body;
    const clientIP = getClientIP(req);
    
    if (!key || !hwid) {
        return res.status(400).json({ valid: false, error: "Missing key or hwid" });
    }
    
    if (isBlacklisted(clientIP, hwid)) {
        return res.status(403).json({ valid: false, error: "Blacklisted" });
    }
    
    const validation = validateKey(key, hwid);
    
    logAccess(req, 'VALIDATE', validation.valid);
    
    if (validation.valid) {
        res.json({
            valid: true,
            tier: validation.keyData.tier,
            expiry: validation.keyData.expiry,
            usageCount: validation.keyData.usageCount
        });
    } else {
        trackFailedAttempt(clientIP);
        res.status(401).json({ valid: false, error: validation.error });
    }
});

// ============================================================
// 💓 HEARTBEAT ENDPOINT
// ============================================================

app.post('/api/heartbeat', (req, res) => {
    const { token, key, hwid, uptime } = req.body;
    
    if (!token || !key || !hwid) {
        return res.status(400).json({ valid: false, error: "Missing parameters" });
    }
    
    // Validate the key is still valid
    const validation = validateKey(key, hwid);
    
    if (!validation.valid) {
        return res.json({ valid: false, error: validation.error, action: "terminate" });
    }
    
    console.log(`💓 Heartbeat from ${key.substring(0, 10)}... - Uptime: ${Math.round(uptime)}s`);
    
    res.json({ 
        valid: true, 
        message: "Heartbeat received",
        serverTime: Date.now()
    });
});

// ============================================================
// 🚨 REPORT ENDPOINT
// ============================================================

app.post('/api/report', (req, res) => {
    const { key, hwid, reason, timestamp } = req.body;
    const clientIP = getClientIP(req);
    
    console.log(`🚨 Security Report - Key: ${key}, HWID: ${hwid}, Reason: ${reason}`);
    
    logAccess(req, 'SECURITY_REPORT', false, { reason });
    
    // Optionally blacklist on certain reasons
    if (reason && reason.includes("tampered")) {
        addToBlacklist(clientIP, hwid, reason);
    }
    
    res.json({ received: true });
});

// ============================================================
// 👑 ADMIN ENDPOINTS
// ============================================================

// Admin middleware
function adminAuth(req, res, next) {
    const adminKey = req.headers['x-admin-key'] || req.body.adminKey;
    
    if (adminKey !== CONFIG.ADMIN_KEY) {
        logAccess(req, 'ADMIN_ACCESS', false, { error: 'Invalid admin key' });
        return res.status(403).json({ error: "Invalid admin key" });
    }
    
    next();
}

// Generate new key
app.post('/api/admin/keys/generate', adminAuth, (req, res) => {
    const { tier = "free", expiryDays = null, maxHwid = 1 } = req.body;
    
    // Generate new key
    const newKey = `${tier.toUpperCase().substring(0, 4)}-${uuidv4().substring(0, 4).toUpperCase()}-${uuidv4().substring(0, 4).toUpperCase()}-${uuidv4().substring(0, 4).toUpperCase()}`;
    
    database.keys[newKey] = {
        hwid: null,
        maxHwid: maxHwid,
        expiry: expiryDays ? Date.now() + (expiryDays * 24 * 60 * 60 * 1000) : null,
        createdAt: Date.now(),
        usageCount: 0,
        tier: tier
    };
    
    logAccess(req, 'KEY_GENERATED', true, { newKey, tier });
    
    res.json({
        success: true,
        key: newKey,
        tier: tier,
        expiry: database.keys[newKey].expiry ? new Date(database.keys[newKey].expiry).toISOString() : "lifetime",
        maxHwid: maxHwid
    });
});

// List all keys
app.get('/api/admin/keys', adminAuth, (req, res) => {
    const keys = Object.entries(database.keys).map(([key, data]) => ({
        key: key,
        ...data,
        expiryFormatted: data.expiry ? new Date(data.expiry).toISOString() : "lifetime",
        isExpired: data.expiry ? Date.now() > data.expiry : false
    }));
    
    res.json({ success: true, count: keys.length, keys });
});

// Delete key
app.delete('/api/admin/keys/:key', adminAuth, (req, res) => {
    const { key } = req.params;
    
    if (!database.keys[key]) {
        return res.status(404).json({ error: "Key not found" });
    }
    
    delete database.keys[key];
    logAccess(req, 'KEY_DELETED', true, { deletedKey: key });
    
    res.json({ success: true, message: `Key ${key} deleted` });
});

// Reset HWID for a key
app.post('/api/admin/keys/:key/reset-hwid', adminAuth, (req, res) => {
    const { key } = req.params;
    
    if (!database.keys[key]) {
        return res.status(404).json({ error: "Key not found" });
    }
    
    database.keys[key].hwid = null;
    logAccess(req, 'HWID_RESET', true, { key });
    
    res.json({ success: true, message: `HWID reset for key ${key}` });
});

// View logs
app.get('/api/admin/logs', adminAuth, (req, res) => {
    const { limit = 100 } = req.query;
    const logs = database.logs.slice(-parseInt(limit));
    
    res.json({ success: true, count: logs.length, logs });
});

// Blacklist management
app.get('/api/admin/blacklist', adminAuth, (req, res) => {
    res.json({ success: true, blacklist: database.blacklist });
});

app.post('/api/admin/blacklist/add', adminAuth, (req, res) => {
    const { ip, hwid, reason } = req.body;
    
    addToBlacklist(ip, hwid, reason || "Manual blacklist");
    
    res.json({ success: true, message: "Added to blacklist" });
});

app.post('/api/admin/blacklist/remove', adminAuth, (req, res) => {
    const { ip, hwid } = req.body;
    
    if (ip) {
        database.blacklist.ips = database.blacklist.ips.filter(i => i !== ip);
    }
    if (hwid) {
        database.blacklist.hwids = database.blacklist.hwids.filter(h => h !== hwid);
    }
    
    res.json({ success: true, message: "Removed from blacklist" });
});

// Stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
    const totalKeys = Object.keys(database.keys).length;
    const activeKeys = Object.values(database.keys).filter(k => k.hwid !== null).length;
    const expiredKeys = Object.values(database.keys).filter(k => k.expiry && Date.now() > k.expiry).length;
    const totalLogs = database.logs.length;
    const blacklistedIPs = database.blacklist.ips.length;
    const blacklistedHWIDs = database.blacklist.hwids.length;
    
    res.json({
        success: true,
        stats: {
            totalKeys,
            activeKeys,
            expiredKeys,
            unusedKeys: totalKeys - activeKeys,
            totalLogs,
            blacklistedIPs,
            blacklistedHWIDs,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        }
    });
});

// ============================================================
// 🚀 START SERVER
// ============================================================

app.listen(PORT, () => {
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════╗');
    console.log('║     🛡️  ROBLOX SCRIPT PROTECTOR - SERVER STARTED      ║');
    console.log('╠═══════════════════════════════════════════════════════╣');
    console.log(`║  🌐 Server running on port: ${PORT}                       ║`);
    console.log(`║  📅 Started at: ${new Date().toISOString()}   ║`);
    console.log('║                                                       ║');
    console.log('║  📍 Endpoints:                                        ║');
    console.log('║     GET  /api/script?key=XXX&hwid=YYY                 ║');
    console.log('║     POST /api/validate                                ║');
    console.log('║     POST /api/heartbeat                               ║');
    console.log('║     POST /api/admin/*                                 ║');
    console.log('╚═══════════════════════════════════════════════════════╝');
    console.log('');
});
