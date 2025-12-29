// ============================================================
// 🛡️ ROBLOX SCRIPT PROTECTOR - SECURE SERVER v2.1.0
// ============================================================

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const config = require('./config');
const { db, scriptCache } = require('./database');
const cryptoLayer = require('./crypto-layer');
const validator = require('./validator');

const app = express();

// ============================================================
// 🌐 UNAUTHORIZED HTML PAGE (ORIGINAL - TIDAK BERUBAH)
// ============================================================

const UNAUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unauthorized | Premium Protect</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body, html {
            width: 100%; height: 100%; overflow: hidden;
            background-color: #000000;
            font-family: 'Inter', -apple-system, sans-serif;
            color: #ffffff;
        }
        .bg-layer {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(270deg, #000000, #0f172a, #000000);
            background-size: 600% 600%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }
        .container {
            position: relative; z-index: 10; height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px; user-select: none;
        }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #ffffff; font-size: 1.1rem; font-weight: 600;
            letter-spacing: 3px; text-transform: uppercase;
            margin-bottom: 25px;
        }
        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800; max-width: 700px;
            margin: 0 0 20px 0; line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p { color: rgba(255, 255, 255, 0.4); font-size: 1.1rem; margin: 0; }
        .icon { font-size: 1.4rem; }
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>
    <div class="container">
        <div class="auth-label">
            <span class="icon">⛔</span>
            Not Authorized
            <span class="icon">⛔</span>
        </div>
        <h1>You are not allowed to view these files.</h1>
        <p>Close this page & proceed.</p>
    </div>
</body>
</html>`;

// ============================================================
// 🔧 MIDDLEWARE SETUP
// ============================================================

app.use(helmet({ 
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({ 
    origin: (origin, callback) => {
        // Allow requests tanpa origin (executor)
        if (!origin) return callback(null, true);
        // Block browser origins
        callback(new Error('Not allowed'));
    },
    methods: ['GET', 'POST', 'DELETE', 'PUT'],
    allowedHeaders: ['Content-Type', 'x-admin-key', 'x-session', 'x-protection', 'Authorization']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

// ============================================================
// 🚦 RATE LIMITING
// ============================================================

const scriptLimiter = rateLimit({
    windowMs: 60000,
    max: 20, // 20 requests per menit (lebih longgar)
    message: { success: false, error: "Too many requests", code: "RATE_LIMITED" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getClientIP(req),
    handler: (req, res) => {
        logAccess(req, 'RATE_LIMITED', false);
        validator.trackSuspicious(getClientIP(req), 'RATE_LIMITED');
        res.status(429).json({ success: false, error: "Rate limit exceeded" });
    }
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "Too many admin attempts" },
    keyGenerator: (req) => getClientIP(req)
});

app.use('/api/', scriptLimiter);

// ============================================================
// 🔧 HELPER FUNCTIONS
// ============================================================

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress ||
           req.ip || 
           'unknown';
}

function logAccess(req, action, success, details = {}) {
    const log = { 
        ip: getClientIP(req), 
        userAgent: req.headers['user-agent'] || 'unknown', 
        action, 
        success, 
        method: req.method, 
        path: req.path,
        timestamp: new Date().toISOString(),
        ...details 
    };
    db.addLog(log);
    console.log(`[${log.timestamp}] ${success ? '✅' : '❌'} ${action} | IP: ${log.ip}`);
    return log;
}

function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

// ============================================================
// 🛡️ SECURITY MIDDLEWARE (Updated - Executor Friendly)
// ============================================================

function securityCheck(req, res, next) {
    const ip = getClientIP(req);
    
    // Check if IP is blocked
    if (validator.isBlocked(ip)) {
        logAccess(req, 'IP_BLOCKED', false);
        return res.status(403).send('');
    }
    
    // Check if valid executor
    const executorCheck = validator.isValidExecutor(req);
    if (!executorCheck.valid) {
        validator.trackSuspicious(ip, executorCheck.reason);
        logAccess(req, executorCheck.reason, false);
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    // Log executor type jika terdeteksi
    if (executorCheck.type) {
        req.executorType = executorCheck.type;
    }
    
    next();
}

// ============================================================
// 🎫 SESSION SYSTEM
// ============================================================

const activeSessions = new Map();

function createSession(ip, userAgent) {
    const sessionId = uuidv4();
    const session = {
        id: sessionId,
        ip: ip,
        userAgent: userAgent,
        created: Date.now(),
        uses: 0,
        maxUses: 10 // Naikkan limit
    };
    activeSessions.set(sessionId, session);
    
    // Auto cleanup after 15 menit
    setTimeout(() => activeSessions.delete(sessionId), 15 * 60 * 1000);
    
    return sessionId;
}

function validateSession(sessionId, ip) {
    const session = activeSessions.get(sessionId);
    if (!session) return { valid: false, reason: 'SESSION_NOT_FOUND' };
    if (session.ip !== ip) return { valid: false, reason: 'IP_MISMATCH' };
    if (session.uses >= session.maxUses) return { valid: false, reason: 'SESSION_EXHAUSTED' };
    if (Date.now() - session.created > 15 * 60 * 1000) return { valid: false, reason: 'SESSION_EXPIRED' };
    
    session.uses++;
    return { valid: true, session };
}

// ============================================================
// 🎫 ENDPOINT: Initialize Session
// ============================================================

app.get('/init', securityCheck, (req, res) => {
    const ip = getClientIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
    const sessionId = createSession(ip, userAgent);
    const token = cryptoLayer.generateToken();
    
    logAccess(req, 'SESSION_CREATED', true, { 
        sessionId: sessionId.substring(0, 8),
        executorType: req.executorType || 'unknown'
    });
    
    res.type('text/plain').send(`return "${sessionId}","${token}"`);
});

// ============================================================
// 🚀 MAIN ENDPOINT - /script (PROTECTED)
// ============================================================

app.get('/script', securityCheck, async (req, res) => {
    const ip = getClientIP(req);
    const sessionId = req.headers['x-session'];
    const protectionLevel = req.headers['x-protection'] || 'standard';

    try {
        // Validate session jika ada
        if (sessionId) {
            const sessionCheck = validateSession(sessionId, ip);
            if (!sessionCheck.valid) {
                logAccess(req, sessionCheck.reason, false);
                // Jangan block, hanya log
            }
        }

        console.log(`📥 [SCRIPT] Request from: ${ip} | Protection: ${protectionLevel}`);

        // Cek cache
        let script = scriptCache.get('main_script');
        let cacheHit = true;
        
        if (!script) {
            cacheHit = false;
            
            if (!config.SCRIPT_SOURCE_URL) {
                throw new Error('Script source not configured');
            }
            
            console.log(`🔄 Fetching from source...`);
            
            const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                timeout: 15000,
                headers: {
                    'User-Agent': 'Roblox/WinInet',
                    'Accept': '*/*'
                },
                maxRedirects: 2
            });

            script = response.data;

            if (typeof script !== 'string' || script.length < 10) {
                throw new Error('Invalid script response');
            }

            scriptCache.set('main_script', script);
            console.log(`✅ Script cached (${script.length} bytes)`);
        } else {
            console.log(`📦 Using cached script`);
        }

        // ============================================================
        // 🛡️ PROTECTION LEVELS
        // ============================================================
        let protectedScript;
        
        switch(protectionLevel) {
            case 'advanced':
                // Protection lebih kuat
                protectedScript = cryptoLayer.createAdvancedPayload(script);
                break;
            case 'minimal':
                // Minimal wrapper (untuk debugging)
                protectedScript = cryptoLayer.lightObfuscate(script);
                break;
            case 'standard':
            default:
                // Standard protection
                protectedScript = cryptoLayer.createProtectedPayload(script);
                break;
        }

        logAccess(req, 'SCRIPT_SERVED', true, { 
            size: protectedScript.length,
            cached: cacheHit,
            hasSession: !!sessionId,
            protection: protectionLevel,
            executorType: req.executorType || 'unknown'
        });
        
        res.type('text/plain').send(protectedScript);

    } catch (error) {
        console.error('❌ Error:', error.message);
        logAccess(req, 'SCRIPT_ERROR', false, { error: error.message });
        
        const errorScript = `
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "❌ Error",
    Text = "Failed to load script. Try again.",
    Duration = 5
})
warn("[LOADER] Connection error")
`;
        res.status(500).type('text/plain').send(errorScript);
    }
});

// ============================================================
// 🌐 ROOT & HEALTH ENDPOINTS
// ============================================================

app.get('/', (req, res) => {
    const check = validator.isValidExecutor(req);
    if (!check.valid) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.json({
        status: "online",
        name: "Premium Loader",
        version: "2.1.0"
    });
});

app.get('/api/health', (req, res) => {
    const check = validator.isValidExecutor(req);
    if (!check.valid) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.json({ 
        status: "healthy", 
        timestamp: new Date().toISOString(), 
        uptime: Math.floor(process.uptime()) + "s"
    });
});

// ============================================================
// 👑 ADMIN ROUTES
// ============================================================

function adminAuth(req, res, next) {
    const adminKey = req.headers['x-admin-key'] || req.body?.adminKey;
    
    if (!adminKey || !secureCompare(adminKey, config.ADMIN_KEY)) {
        logAccess(req, 'ADMIN_AUTH_FAILED', false);
        validator.trackSuspicious(getClientIP(req), 'ADMIN_BRUTEFORCE');
        return res.status(403).json({ error: "Invalid admin key" });
    }
    
    next();
}

app.post('/api/admin/cache/clear', adminLimiter, adminAuth, (req, res) => {
    scriptCache.clear();
    console.log('🗑️ Cache cleared by admin');
    logAccess(req, 'CACHE_CLEARED', true);
    res.json({ success: true, message: "Cache cleared" });
});

app.get('/api/admin/stats', adminLimiter, adminAuth, (req, res) => {
    res.json({ 
        success: true, 
        stats: db.getStats(),
        security: validator.getStats(),
        sessions: activeSessions.size,
        cacheStatus: scriptCache.has('main_script') ? 'cached' : 'empty'
    });
});

app.get('/api/admin/logs', adminLimiter, adminAuth, (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    res.json({ success: true, logs: db.getLogs(limit) });
});

app.post('/api/admin/refresh', adminLimiter, adminAuth, async (req, res) => {
    try {
        scriptCache.clear();
        
        const response = await axios.get(config.SCRIPT_SOURCE_URL, {
            timeout: 15000,
            headers: { 'User-Agent': 'Roblox/WinInet' }
        });
        
        if (typeof response.data === 'string' && response.data.length > 10) {
            scriptCache.set('main_script', response.data);
            logAccess(req, 'SCRIPT_REFRESHED', true, { size: response.data.length });
            res.json({ success: true, size: response.data.length });
        } else {
            throw new Error('Invalid response');
        }
    } catch (error) {
        logAccess(req, 'REFRESH_FAILED', false);
        res.status(500).json({ success: false, error: 'Refresh failed' });
    }
});

// Unblock IP
app.post('/api/admin/unblock', adminLimiter, adminAuth, (req, res) => {
    const { ip } = req.body;
    if (ip && validator.suspiciousIPs) {
        validator.suspiciousIPs.delete(ip);
        logAccess(req, 'IP_UNBLOCKED', true, { unblockedIP: ip });
        res.json({ success: true, message: `IP ${ip} unblocked` });
    } else {
        res.status(400).json({ success: false, error: 'IP required' });
    }
});

// ============================================================
// 🚫 CATCH-ALL ROUTE
// ============================================================

app.use('*', (req, res) => {
    const check = validator.isValidExecutor(req);
    if (!check.valid) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.status(404).json({ error: "Not found" });
});

// ============================================================
// 🚀 START SERVER
// ============================================================

app.listen(config.PORT, () => {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║      🛡️  PREMIUM LOADER v2.1.0 - SECURE MODE             ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
    console.log(`║  Port: ${config.PORT}                                            ║`);
    console.log(`║  Environment: ${(config.NODE_ENV || 'development').padEnd(40)}║`);
    console.log('║                                                          ║');
    console.log('║  ✅ Script Source: HIDDEN (env variable)                 ║');
    console.log('║  ✅ Protection Layer: ACTIVE                             ║');
    console.log('║  ✅ Session System: ACTIVE                               ║');
    console.log('║  ✅ Executor Detection: IMPROVED                         ║');
    console.log('║  ✅ Anti-Tamper: LIGHT (executor safe)                   ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
    console.log('║  Protection Levels:                                      ║');
    console.log('║  • standard (default) - Balanced protection              ║');
    console.log('║  • advanced - Stronger protection                        ║');
    console.log('║  • minimal - Light wrapper                               ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
});

module.exports = app;
