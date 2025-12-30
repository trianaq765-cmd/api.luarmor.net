// ============================================================
// 🛡️ PREMIUM LOADER v2.2.0 - SIMPLE & CLEAN
// ============================================================

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const config = require('./config');
const { db, scriptCache } = require('./database');

const app = express();

// ============================================================
// 🌐 UNAUTHORIZED HTML (ORIGINAL)
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
// 🔧 MIDDLEWARE
// ============================================================

app.use(helmet({ 
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false 
}));

app.use(cors({ 
    origin: '*', 
    methods: ['GET', 'POST', 'DELETE', 'PUT'], 
    allowedHeaders: ['Content-Type', 'x-admin-key', 'Authorization'] 
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

// Rate Limiting
const limiter = rateLimit({
    windowMs: config.RATE_LIMIT.WINDOW_MS,
    max: config.RATE_LIMIT.MAX_REQUESTS,
    message: { success: false, error: "Too many requests" },
    keyGenerator: (req) => getClientIP(req),
    handler: (req, res) => {
        logAccess(req, 'RATE_LIMITED', false);
        res.status(429).json({ success: false, error: "Rate limit exceeded" });
    }
});

app.use('/api/', limiter);

// ============================================================
// 🔧 HELPER FUNCTIONS
// ============================================================

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
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
        ...details 
    };
    db.addLog(log);
    console.log(`[${new Date().toISOString()}] ${success ? '✅' : '❌'} ${action} | IP: ${log.ip}`);
    return log;
}

function isBrowserRequest(req) {
    const accept = req.headers['accept'] || '';
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    
    // Executor whitelist - langsung izinkan
    const executorKeywords = [
        'roblox', 'synapse', 'krnl', 'fluxus', 'delta', 
        'electron', 'script-ware', 'sentinel', 'coco', 
        'oxygen', 'evon', 'arceus', 'hydrogen', 'vegax',
        'trigon', 'comet', 'jjsploit', 'wearedevs', 
        'executor', 'exploit', 'wininet'
    ];
    
    if (executorKeywords.some(keyword => userAgent.includes(keyword))) {
        return false; // Ini executor, bukan browser
    }
    
    // Cek apakah browser
    if (accept.includes('text/html')) {
        const hasBrowserUA = userAgent.includes('mozilla') || 
                             userAgent.includes('chrome') || 
                             userAgent.includes('safari') ||
                             userAgent.includes('firefox') ||
                             userAgent.includes('edge');
        
        const hasAcceptLanguage = !!req.headers['accept-language'];
        
        if (hasBrowserUA && hasAcceptLanguage) {
            return true; // Ini browser
        }
    }
    
    return false; // Default: bukan browser (izinkan)
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
// 🚀 MAIN ENDPOINT - /script
// ============================================================

app.get('/script', async (req, res) => {
    // Block browsers
    if (isBrowserRequest(req)) {
        logAccess(req, 'BROWSER_BLOCKED', false);
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    try {
        console.log(`📥 [SCRIPT] Request from: ${getClientIP(req)}`);

        // Cek cache dulu
        let script = scriptCache.get('main_script');
        
        if (!script) {
            // Cek apakah URL sudah di-set
            if (!config.SCRIPT_SOURCE_URL) {
                console.error('❌ SCRIPT_SOURCE_URL not configured!');
                throw new Error('Script source not configured');
            }
            
            console.log(`🔄 Fetching from source...`);
            
            const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                timeout: 15000,
                headers: {
                    'User-Agent': 'Roblox/WinInet',
                    'Accept': '*/*'
                }
            });

            script = response.data;

            if (typeof script !== 'string' || script.length < 10) {
                throw new Error('Invalid script response');
            }

            // Cache script
            scriptCache.set('main_script', script);
            console.log(`✅ Script cached (${script.length} bytes)`);
        } else {
            console.log(`📦 Using cached script`);
        }

        logAccess(req, 'SCRIPT_SERVED', true, { size: script.length });
        
        // Langsung kirim script tanpa wrapper
        res.type('text/plain').send(script);

    } catch (error) {
        console.error('❌ Error:', error.message);
        logAccess(req, 'SCRIPT_ERROR', false, { error: error.message });
        
        const errorScript = `
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "❌ Error",
    Text = "Failed to load script. Try again.",
    Duration = 5
})
warn("[LOADER] Error: Connection failed")
`;
        res.status(500).type('text/plain').send(errorScript);
    }
});

// ============================================================
// 🌐 ROOT & HEALTH
// ============================================================

app.get('/', (req, res) => {
    if (isBrowserRequest(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.json({
        status: "online",
        name: "Premium Loader",
        version: "2.2.0"
    });
});

app.get('/api/health', (req, res) => {
    if (isBrowserRequest(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.json({ 
        status: "healthy", 
        timestamp: new Date().toISOString(), 
        uptime: Math.floor(process.uptime()) + "s",
        cached: scriptCache.has('main_script')
    });
});

// ============================================================
// 👑 ADMIN ROUTES
// ============================================================

function adminAuth(req, res, next) {
    const adminKey = req.headers['x-admin-key'] || req.body?.adminKey;
    
    if (!adminKey || !secureCompare(adminKey, config.ADMIN_KEY)) {
        logAccess(req, 'ADMIN_AUTH_FAILED', false);
        return res.status(403).json({ error: "Invalid admin key" });
    }
    
    next();
}

// Clear cache
app.post('/api/admin/cache/clear', adminAuth, (req, res) => {
    scriptCache.flushAll();
    console.log('🗑️ Cache cleared by admin');
    logAccess(req, 'CACHE_CLEARED', true);
    res.json({ success: true, message: "Cache cleared" });
});

// Get stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
    res.json({ 
        success: true, 
        stats: db.getStats(),
        cacheStatus: scriptCache.has('main_script') ? 'cached' : 'empty',
        cacheKeys: scriptCache.keys()
    });
});

// Get logs
app.get('/api/admin/logs', adminAuth, (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    res.json({ success: true, logs: db.getLogs(limit) });
});

// Force refresh script
app.post('/api/admin/refresh', adminAuth, async (req, res) => {
    try {
        scriptCache.flushAll();
        
        if (!config.SCRIPT_SOURCE_URL) {
            throw new Error('SCRIPT_SOURCE_URL not configured');
        }
        
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
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================
// 🚫 CATCH-ALL
// ============================================================

app.use('*', (req, res) => {
    if (isBrowserRequest(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.status(404).json({ error: "Not found" });
});

// ============================================================
// 🚀 START SERVER
// ============================================================

app.listen(config.PORT, () => {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║      🛡️  PREMIUM LOADER v2.2.0 - SIMPLE & CLEAN         ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
    console.log(`║  Port: ${config.PORT}                                            ║`);
    console.log('║                                                          ║');
    console.log('║  ✅ Script Source: ' + (config.SCRIPT_SOURCE_URL ? 'CONFIGURED' : '❌ NOT SET') + '                       ║');
    console.log('║  ✅ Admin Key: ' + (config.ADMIN_KEY ? 'CONFIGURED' : '❌ NOT SET') + '                           ║');
    console.log('║                                                          ║');
    console.log('║  Endpoints:                                              ║');
    console.log('║  • GET /script - Main script                             ║');
    console.log('║  • GET /api/health - Health check                        ║');
    console.log('║  • POST /api/admin/cache/clear - Clear cache             ║');
    console.log('║  • POST /api/admin/refresh - Refresh script              ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
});

module.exports = app;
