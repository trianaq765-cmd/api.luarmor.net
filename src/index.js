// ============================================================
// 🛡️ ROBLOX SCRIPT PROTECTOR - MAIN SERVER v1.3.0
// ============================================================
// Features:
// - Key System + HWID Lock + Expiry
// - Anti-Tamper + Obfuscation
// - Admin Detection (10s scan - memory optimized)
// - Browser Protection (Unauthorized HTML)
// - Heartbeat System (30s)
// - Universal Executor Support (PC & Mobile)
// ============================================================

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto-js');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');
const { db, scriptCache } = require('./database');

const app = express();

// ============================================================
// 🌐 UNAUTHORIZED HTML PAGE (Browser Protection)
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
    message: { success: false, error: "Too many requests", code: "RATE_LIMITED" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getClientIP(req),
    handler: (req, res) => {
        logAccess(req, 'RATE_LIMITED', false);
        res.status(429).json({ success: false, error: "Rate limit exceeded", code: "RATE_LIMITED" });
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
        key: req.query.key || req.body?.key || 'none', 
        hwid: req.query.hwid || req.body?.hwid || 'none', 
        method: req.method, 
        path: req.path, 
        ...details 
    };
    db.addLog(log);
    const keyDisplay = String(log.key).substring(0, 15);
    console.log(`[${new Date().toISOString()}] ${success ? '✅' : '❌'} ${action} | IP: ${log.ip} | Key: ${keyDisplay}...`);
    return log;
}

function generateSessionToken(key, hwid) {
    return crypto.SHA256(key + hwid + Date.now() + Math.random()).toString().substring(0, 32);
}

function generateRandomVar(len = 8) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let r = '_';
    for (let i = 0; i < len; i++) r += chars.charAt(Math.floor(Math.random() * chars.length));
    return r;
}

// ============================================================
// 🔍 BROWSER DETECTION - Universal Executor Support
// ============================================================

function isBrowserRequest(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const acceptHeader = req.headers['accept'] || '';
    
    // ========================================================
    // EXECUTOR PATTERNS - All supported executors
    // ========================================================
    const executorPatterns = [
        // PC Executors
        'synapse', 'synapsex', 'synapse x',
        'scriptware', 'script-ware', 'script ware',
        'krnl',
        'fluxus',
        'jjsploit', 'jj sploit',
        'oxygen', 'oxygenu', 'oxygen u',
        'electron',
        'cefsharp',
        'evon',
        'trigon', 'trigon evo',
        'solara',
        'wave',
        'comet',
        'sirhurt', 'sir hurt',
        'temple',
        'aspect',
        'valyse',
        'celery',
        
        // Mobile Executors (Android/iOS)
        'delta', 'deltax', 'delta x',
        'arceus', 'arceusx', 'arceus x',
        'hydrogen',
        'codex',
        'vegax', 'vega x',
        'nihon',
        'fluxus android',
        'zorara',
        'cryptic',
        'hoho hub',
        'mobile',
        
        // Roblox Related
        'roblox',
        'robloxapp',
        'roblox studio',
        
        // Generic executor indicators
        'executor',
        'exploit',
        'inject',
        'cheat',
        'httpservice'
    ];
    
    // Check if user agent matches any executor
    const isExecutor = executorPatterns.some(pattern => userAgent.includes(pattern));
    if (isExecutor) return false;
    
    // Empty or very short user agent (likely executor with no UA)
    if (!userAgent || userAgent.length < 10) return false;
    
    // Some executors send specific headers
    const executorHeaders = [
        'x-executor',
        'x-exploit', 
        'x-delta',
        'x-synapse',
        'x-fluxus',
        'x-script',
        'x-roblox'
    ];
    
    const hasExecutorHeader = executorHeaders.some(h => req.headers[h]);
    if (hasExecutorHeader) return false;
    
    // Check for browser patterns
    const browserPatterns = [
        'mozilla/',
        'chrome/',
        'safari/',
        'firefox/',
        'edge/',
        'opera/',
        'msie',
        'trident/',
        'webkit'
    ];
    
    const isBrowserUA = browserPatterns.some(pattern => userAgent.includes(pattern));
    const acceptsHTML = acceptHeader.includes('text/html');
    
    // Only block if BOTH: has browser UA AND accepts HTML
    return isBrowserUA && acceptsHTML;
}

// ============================================================
// 🔐 KEY VALIDATION
// ============================================================

function validateKey(key, hwid) {
    if (!key || !hwid) {
        return { valid: false, error: "Missing key or hwid", code: "MISSING_PARAMS" };
    }
    
    const keyData = db.getKey(key);
    if (!keyData) {
        return { valid: false, error: "Invalid key", code: "INVALID_KEY" };
    }
    
    // Check expiry
    if (keyData.expiry && Date.now() > keyData.expiry) {
        return { valid: false, error: "Key expired", code: "KEY_EXPIRED" };
    }
    
    // Check HWID
    if (keyData.hwid === null) {
        // First use - bind HWID
        db.updateKey(key, { hwid });
        console.log(`🔗 HWID bound: ${key.substring(0, 15)}... -> ${hwid.substring(0, 15)}...`);
    } else if (keyData.hwid !== hwid) {
        return { valid: false, error: "HWID mismatch - Key bound to another device", code: "HWID_MISMATCH" };
    }
    
    // Update usage count
    db.updateKey(key, { usageCount: (keyData.usageCount || 0) + 1, lastUsed: Date.now() });
    
    return { valid: true, keyData: db.getKey(key) };
}

// ============================================================
// 🔒 OBFUSCATION ENGINE
// ============================================================

function generateJunkCode() {
    const v1 = generateRandomVar(8), v2 = generateRandomVar(6), v3 = generateRandomVar(4);
    const patterns = [
        `local ${v1}=(function() local ${v2}={} for ${v3}=1,math.random(1,5) do ${v2}[${v3}]=math.random() end return ${v2} end)()`,
        `local ${v1}=tick()*0+(function() return 0 end)()`,
        `local ${v1}=(true and false) or nil`,
        `do local ${v1}=nil for ${v2}=1,0 do ${v1}=${v2} end end`,
        `local ${v1}=type(nil)=="nil" and nil or nil`
    ];
    return patterns[Math.floor(Math.random() * patterns.length)];
}

function obfuscateScript(script) {
    if (!config.SECURITY.ENABLE_OBFUSCATION) return script;
    
    const scriptId = uuidv4().substring(0, 8);
    let junkCode = '';
    for (let i = 0; i < 3; i++) junkCode += generateJunkCode() + '\n';
    
    const mainFunc = generateRandomVar(12);
    const errorHandler = generateRandomVar(10);
    
    return `
--[[ ${generateRandomVar(30)} | ID: ${scriptId} | ${Date.now()} ]]

${junkCode}

local ${mainFunc} = function()
${script}
end

local ${errorHandler} = function(err) 
    return nil 
end

local _success_, _result_ = pcall(${mainFunc})
`;
}

// ============================================================
// 👑 ADMIN DETECTION CODE - Universal Executor Support
// Memory Optimized (10s scan interval)
// ============================================================

function generateAdminDetectionCode() {
    if (!config.SECURITY.ENABLE_ADMIN_DETECTION) return "";
    
    const adminUserIds = config.ADMIN_DETECTION.USER_IDS;
    const adminUsernames = config.ADMIN_DETECTION.USERNAMES;
    
    if (adminUserIds.length === 0 && adminUsernames.length === 0) return "";
    
    const v = {
        adminIds: generateRandomVar(12),
        adminNames: generateRandomVar(12),
        players: generateRandomVar(10),
        checkAdmin: generateRandomVar(14),
        destroyScript: generateRandomVar(15),
        isDestroyed: generateRandomVar(13),
        connection: generateRandomVar(11),
        localPlayer: generateRandomVar(12),
        scanInterval: generateRandomVar(10),
        runScan: generateRandomVar(11),
        safeWait: generateRandomVar(9),
        safeSpawn: generateRandomVar(10),
        safeGC: generateRandomVar(8)
    };

    return `
-- ============================================================
-- 👑 ADMIN DETECTION SYSTEM
-- Universal Executor Support (PC & Mobile)
-- Memory Optimized (10s scan interval)
-- ============================================================

local ${v.isDestroyed} = false
local ${v.players} = game:GetService("Players")
local ${v.localPlayer} = ${v.players}.LocalPlayer
local ${v.connection} = nil
local ${v.scanInterval} = 10

-- Safe wait function (works on all executors: Delta, Arceus, Synapse, etc.)
local ${v.safeWait} = function(t)
    local waitFunc = (task and task.wait) or wait
    return waitFunc(t)
end

-- Safe spawn function (works on all executors)
local ${v.safeSpawn} = function(f)
    local spawnFunc = (task and task.spawn) or spawn
    return spawnFunc(f)
end

-- Safe garbage collection (some executors don't have this)
local ${v.safeGC} = function()
    pcall(function()
        if collectgarbage then
            collectgarbage("step", 100)
        end
    end)
end

-- Admin User IDs
local ${v.adminIds} = {${adminUserIds.length > 0 ? adminUserIds.map(id => `[${id}]=true`).join(',') : '[0]=false'}}

-- Admin Usernames (lowercase)
local ${v.adminNames} = {${adminUsernames.length > 0 ? adminUsernames.map(name => `["${name.toLowerCase()}"]=true`).join(',') : '["_"]=false'}}

-- Destroy Script Function (Silent & Clean)
local ${v.destroyScript} = function()
    if ${v.isDestroyed} then return end
    ${v.isDestroyed} = true
    
    -- Disconnect listener
    pcall(function()
        if ${v.connection} then 
            ${v.connection}:Disconnect() 
            ${v.connection} = nil
        end
    end)
    
    -- Clear environment
    pcall(function()
        local env = getfenv and getfenv() or {}
        for k, _ in pairs(env) do
            if k ~= "_G" and k ~= "game" and k ~= "workspace" and k ~= "script" then
                pcall(function() env[k] = nil end)
            end
        end
    end)
    
    -- Garbage collection
    ${v.safeGC}()
    
    -- Silent infinite yield
    while true do
        ${v.safeWait}(9999)
    end
end

-- Check if player is admin
local ${v.checkAdmin} = function(player)
    if not player then return false end
    
    local success, result = pcall(function()
        local uid = player.UserId
        local name = string.lower(tostring(player.Name))
        local display = string.lower(tostring(player.DisplayName))
        
        if ${v.adminIds}[uid] then return true end
        if ${v.adminNames}[name] then return true end
        if ${v.adminNames}[display] then return true end
        return false
    end)
    
    return success and result or false
end

-- Run scan on all players
local ${v.runScan} = function()
    local success, result = pcall(function()
        for _, p in ipairs(${v.players}:GetPlayers()) do
            if ${v.checkAdmin}(p) then return true end
        end
        return false
    end)
    return success and result or false
end

-- Skip detection if local player is admin (allow admin to use script normally)
if not ${v.checkAdmin}(${v.localPlayer}) then
    
    -- ========================================================
    -- PRE-EXECUTE CHECK: Scan all current players
    -- ========================================================
    if ${v.runScan}() then
        ${v.destroyScript}()
        return
    end
    
    -- ========================================================
    -- RUNTIME DETECTION: Listen for admin joining
    -- ========================================================
    pcall(function()
        ${v.connection} = ${v.players}.PlayerAdded:Connect(function(p)
            if ${v.isDestroyed} then return end
            ${v.safeWait}(0.5)
            if ${v.checkAdmin}(p) then
                ${v.destroyScript}()
            end
        end)
    end)
    
    -- ========================================================
    -- PERIODIC SCAN: Every 10 seconds (memory optimized)
    -- ========================================================
    ${v.safeSpawn}(function()
        while not ${v.isDestroyed} do
            ${v.safeWait}(${v.scanInterval})
            if ${v.isDestroyed} then break end
            
            if ${v.runScan}() then
                ${v.destroyScript}()
                break
            end
            
            -- Periodic garbage collection to prevent memory leak
            ${v.safeGC}()
        end
    end)
end

-- Check if destroyed before continuing
if ${v.isDestroyed} then return end

`;
}

// ============================================================
// 🛡️ ANTI-TAMPER CODE - Universal Executor Support
// ============================================================

function generateAntiTamperCode(key, hwid, sessionToken) {
    if (!config.SECURITY.ENABLE_ANTI_TAMPER) return "";
    
    const serverURL = config.getServerURL();
    const v = {
        p: generateRandomVar(10), 
        st: generateRandomVar(12), 
        vk: generateRandomVar(11),
        vh: generateRandomVar(11), 
        su: generateRandomVar(10), 
        ti: generateRandomVar(9),
        ce: generateRandomVar(14), 
        cd: generateRandomVar(13), 
        sd: generateRandomVar(15),
        hs: generateRandomVar(12),
        pl: generateRandomVar(10),
        sw: generateRandomVar(9),
        ss: generateRandomVar(10),
        sg: generateRandomVar(8)
    };

    const heartbeatCode = config.SECURITY.ENABLE_HEARTBEAT ? `
-- ============================================================
-- 💓 HEARTBEAT SYSTEM (30 second interval)
-- ============================================================
${v.ss}(function()
    local fails = 0
    while ${v.p} do
        ${v.sw}(30)
        if not ${v.p} then break end
        
        -- Collect player data for server-side admin check
        local playerIds = {}
        local playerNames = {}
        
        pcall(function()
            for _, p in ipairs(${v.pl}:GetPlayers()) do
                table.insert(playerIds, p.UserId)
                table.insert(playerNames, p.Name)
            end
        end)
        
        local ok, res = pcall(function() 
            return ${v.hs}:PostAsync(
                ${v.su}.."/api/heartbeat",
                ${v.hs}:JSONEncode({
                    token = ${v.st},
                    key = ${v.vk},
                    hwid = ${v.vh},
                    uptime = tick() - ${v.ti},
                    playerIds = playerIds,
                    playerNames = playerNames
                }),
                Enum.HttpContentType.ApplicationJson
            ) 
        end)
        
        if ok and res then
            local success, data = pcall(function() 
                return ${v.hs}:JSONDecode(res) 
            end)
            
            if success and data then
                if data.valid then 
                    fails = 0 
                elseif data.action == "destroy" or data.action == "terminate" then 
                    ${v.sd}("Server:destroy") 
                else 
                    fails = fails + 1 
                end
            else
                fails = fails + 1
            end
        else 
            fails = fails + 1 
        end
        
        -- Only warn after 5 consecutive failures
        if fails >= 5 then 
            warn("[Security] Connection issues detected")
        end
    end
end)` : '-- Heartbeat disabled';

    return `
-- ============================================================
-- 🛡️ ANTI-TAMPER PROTECTION
-- Universal Executor Support (PC & Mobile)
-- ============================================================

local ${v.p} = true
local ${v.st} = "${sessionToken}"
local ${v.vk} = "${key}"
local ${v.vh} = "${hwid}"
local ${v.su} = "${serverURL}"
local ${v.ti} = tick()

-- Services (with pcall for safety)
local ${v.hs} = game:GetService("HttpService")
local ${v.pl} = game:GetService("Players")

-- Safe wait (universal - works on Delta, Arceus, Synapse, KRNL, etc.)
local ${v.sw} = function(t)
    local waitFunc = (task and task.wait) or wait
    return waitFunc(t or 0)
end

-- Safe spawn (universal)
local ${v.ss} = function(f)
    local spawnFunc = (task and task.spawn) or spawn
    return spawnFunc(f)
end

-- Safe garbage collection
local ${v.sg} = function()
    pcall(function()
        if collectgarbage then
            collectgarbage("step", 50)
        end
    end)
end

-- Environment check (validates core Lua functions)
local ${v.ce} = function()
    -- Required functions (must exist on all executors)
    local requiredFuncs = {
        {"pcall", pcall},
        {"type", type},
        {"tostring", tostring},
        {"tonumber", tonumber},
        {"pairs", pairs},
        {"ipairs", ipairs},
        {"error", error},
        {"select", select}
    }
    
    for _, f in ipairs(requiredFuncs) do 
        if type(f[2]) ~= "function" then 
            return false, "ENV:" .. f[1] 
        end 
    end
    
    -- Optional functions (some executors may not have these)
    local optionalFuncs = {
        {"getfenv", getfenv},
        {"setfenv", setfenv},
        {"getmetatable", getmetatable},
        {"setmetatable", setmetatable},
        {"rawget", rawget},
        {"rawset", rawset}
    }
    
    for _, f in ipairs(optionalFuncs) do
        if f[2] ~= nil and type(f[2]) ~= "function" then
            return false, "ENV:" .. f[1] .. ":modified"
        end
    end
    
    return true, nil
end

-- Debug detection
local ${v.cd} = function()
    if debug and type(debug) == "table" then
        if debug.traceback and type(debug.traceback) == "function" then
            local ok, _ = pcall(debug.traceback)
            if not ok then return false, "DBG:traceback:hooked" end
        end
    end
    return true, nil
end

-- Self destruct function
local ${v.sd} = function(reason)
    ${v.p} = false
    
    -- Report to server
    pcall(function() 
        ${v.hs}:PostAsync(
            ${v.su}.."/api/report",
            ${v.hs}:JSONEncode({
                key = ${v.vk},
                hwid = ${v.vh},
                reason = reason,
                uptime = tick() - ${v.ti},
                timestamp = os.time()
            }),
            Enum.HttpContentType.ApplicationJson
        ) 
    end)
    
    -- Silent infinite yield
    while true do 
        ${v.sw}(9999) 
    end
end

-- ============================================================
-- INITIAL SECURITY CHECKS
-- ============================================================
do
    local eOk, eErr = ${v.ce}()
    if not eOk then 
        ${v.sd}(eErr) 
        return 
    end
    
    local dOk, dErr = ${v.cd}()
    if not dOk then 
        ${v.sd}(dErr) 
        return 
    end
end

${heartbeatCode}

-- ============================================================
-- CONTINUOUS PROTECTION (15 second check interval)
-- ============================================================
${v.ss}(function() 
    while ${v.p} do 
        ${v.sw}(15)
        if not ${v.p} then break end
        
        local ok, err = ${v.ce}()
        if not ok then 
            ${v.sd}(err) 
            break 
        end 
        
        -- Periodic garbage collection
        ${v.sg}()
    end 
end)

`;
}

// ============================================================
// 🌐 ROUTES - PUBLIC
// ============================================================

// Root endpoint
app.get('/', (req, res) => {
    if (isBrowserRequest(req)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(UNAUTHORIZED_HTML);
    }
    
    res.json({
        status: "online",
        name: "Roblox Script Protector",
        version: "1.3.0",
        features: [
            "Key System + HWID Lock",
            "Anti-Tamper",
            "Obfuscation",
            "Heartbeat",
            "Admin Detection",
            "Browser Protection",
            "Universal Executor Support"
        ]
    });
});

// Health check
app.get('/api/health', (req, res) => {
    if (isBrowserRequest(req)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(UNAUTHORIZED_HTML);
    }
    
    res.json({ 
        status: "healthy", 
        timestamp: new Date().toISOString(), 
        uptime: Math.floor(process.uptime()) + "s",
        memory: Math.floor(process.memoryUsage().heapUsed / 1024 / 1024) + "MB"
    });
});

// ============================================================
// 📜 MAIN SCRIPT ENDPOINT
// ============================================================

app.get('/api/script', async (req, res) => {
    // Browser protection
    if (isBrowserRequest(req)) {
        logAccess(req, 'BROWSER_BLOCKED', false);
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(UNAUTHORIZED_HTML);
    }
    
    const { key, hwid } = req.query;
    const clientIP = getClientIP(req);

    try {
        // Validate params
        if (!key || !hwid) {
            logAccess(req, 'SCRIPT_ACCESS', false, { error: 'Missing params' });
            return res.status(400).type('text/plain').send('-- Error: Missing key or hwid parameter');
        }

        // Check blacklist
        if (db.isBlacklisted(clientIP, hwid)) {
            logAccess(req, 'SCRIPT_ACCESS', false, { error: 'Blacklisted' });
            return res.status(403).type('text/plain').send('-- Error: Access denied - Blacklisted');
        }

        // Validate key
        const validation = validateKey(key, hwid);
        if (!validation.valid) {
            const shouldBlacklist = db.trackFailedAttempt(clientIP, config.SECURITY.MAX_FAILED_ATTEMPTS);
            logAccess(req, 'SCRIPT_ACCESS', false, { error: validation.error });
            
            if (shouldBlacklist) {
                db.addToBlacklist(clientIP, hwid, "Too many failed attempts");
            }
            
            return res.status(401).type('text/plain').send(`-- Error: ${validation.error}`);
        }

        // Fetch original script (with cache)
        let originalScript = scriptCache.get('main_script');
        if (!originalScript) {
            console.log(`📥 Fetching script from: ${config.ORIGINAL_SCRIPT_URL}`);
            
            const response = await axios.get(config.ORIGINAL_SCRIPT_URL, { 
                timeout: 15000, 
                headers: { 'User-Agent': 'ScriptProtector/1.3.0' },
                validateStatus: (status) => status === 200
            });
            
            originalScript = response.data;
            
            if (typeof originalScript !== 'string' || originalScript.length < 10) {
                throw new Error('Invalid script response from source');
            }
            
            scriptCache.set('main_script', originalScript);
            console.log(`✅ Script cached (${originalScript.length} bytes)`);
        }

        // Generate session
        const sessionToken = generateSessionToken(key, hwid);
        db.createSession(sessionToken, key, hwid);

        // ========================================================
        // BUILD PROTECTED SCRIPT (Order matters!)
        // ========================================================
        let finalScript = '';
        
        // 1. Admin Detection (FIRST - can stop execution immediately)
        finalScript += generateAdminDetectionCode();
        
        // 2. Anti-Tamper (SECOND - validates environment before main script)
        finalScript += generateAntiTamperCode(key, hwid, sessionToken);
        
        // 3. Original Script
        finalScript += '\n-- ============================================================\n';
        finalScript += '-- MAIN SCRIPT\n';
        finalScript += '-- ============================================================\n\n';
        finalScript += originalScript;
        
        // 4. Obfuscation (wrap everything)
        finalScript = obfuscateScript(finalScript);

        // Log success
        logAccess(req, 'SCRIPT_ACCESS', true, { 
            tier: validation.keyData.tier,
            session: sessionToken.substring(0, 8) + '...'
        });

        // Send script
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'no-store, no-cache');
        res.send(finalScript);

    } catch (error) {
        console.error('❌ Script Error:', error.message);
        logAccess(req, 'SCRIPT_ACCESS', false, { error: error.message });
        res.status(500).type('text/plain').send('-- Error: Failed to load script. Please try again.');
    }
});

// ============================================================
// 🔐 VALIDATION ENDPOINT
// ============================================================

app.post('/api/validate', (req, res) => {
    if (isBrowserRequest(req)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(UNAUTHORIZED_HTML);
    }
    
    const { key, hwid } = req.body;
    const clientIP = getClientIP(req);

    if (!key || !hwid) {
        return res.status(400).json({ valid: false, error: "Missing key or hwid" });
    }
    
    if (db.isBlacklisted(clientIP, hwid)) {
        return res.status(403).json({ valid: false, error: "Blacklisted" });
    }

    const validation = validateKey(key, hwid);
    logAccess(req, 'VALIDATE', validation.valid, { code: validation.code });

    if (validation.valid) {
        const kd = validation.keyData;
        res.json({ 
            valid: true, 
            tier: kd.tier,
            expiry: kd.expiry ? new Date(kd.expiry).toISOString() : null,
            expiresIn: kd.expiry ? Math.max(0, Math.floor((kd.expiry - Date.now()) / 1000 / 60 / 60 / 24)) + " days" : "lifetime",
            usage: kd.usageCount 
        });
    } else {
        db.trackFailedAttempt(clientIP, config.SECURITY.MAX_FAILED_ATTEMPTS);
        res.status(401).json({ valid: false, error: validation.error, code: validation.code });
    }
});

// ============================================================
// 👑 ADMIN CHECK ENDPOINT (Live check from client)
// ============================================================

app.post('/api/admin-check', (req, res) => {
    const { playerIds, playerNames } = req.body;
    
    if (!config.SECURITY.ENABLE_ADMIN_DETECTION) {
        return res.json({ hasAdmin: false, enabled: false });
    }
    
    const adminUserIds = config.ADMIN_DETECTION.USER_IDS;
    const adminUsernames = config.ADMIN_DETECTION.USERNAMES;
    
    let hasAdmin = false;
    let adminInfo = null;
    
    // Check by User ID
    if (playerIds && Array.isArray(playerIds)) {
        for (const id of playerIds) {
            if (adminUserIds.includes(String(id))) {
                hasAdmin = true;
                adminInfo = { type: 'userId', id };
                break;
            }
        }
    }
    
    // Check by Username
    if (!hasAdmin && playerNames && Array.isArray(playerNames)) {
        for (const name of playerNames) {
            if (adminUsernames.includes(String(name).toLowerCase())) {
                hasAdmin = true;
                adminInfo = { type: 'username', name };
                break;
            }
        }
    }
    
    if (hasAdmin) {
        logAccess(req, 'ADMIN_CHECK_POSITIVE', true, adminInfo);
    }
    
    res.json({ 
        hasAdmin,
        action: hasAdmin ? "destroy" : "continue",
        timestamp: Date.now()
    });
});

// ============================================================
// 💓 HEARTBEAT ENDPOINT
// ============================================================

app.post('/api/heartbeat', (req, res) => {
    const { token, key, hwid, uptime, playerIds, playerNames } = req.body;
    
    if (!token || !key || !hwid) {
        return res.status(400).json({ valid: false, error: "Missing params" });
    }

    // Validate session
    const session = db.getSession(token);
    if (!session || session.key !== key || session.hwid !== hwid) {
        return res.json({ valid: false, error: "Invalid session", action: "terminate" });
    }

    // Validate key still valid
    const keyData = db.getKey(key);
    if (!keyData) {
        return res.json({ valid: false, error: "Key not found", action: "terminate" });
    }
    
    if (keyData.expiry && Date.now() > keyData.expiry) {
        return res.json({ valid: false, error: "Key expired", action: "terminate" });
    }

    // Server-side admin detection (double check)
    if (config.SECURITY.ENABLE_ADMIN_DETECTION) {
        const adminUserIds = config.ADMIN_DETECTION.USER_IDS;
        const adminUsernames = config.ADMIN_DETECTION.USERNAMES;
        
        let hasAdmin = false;
        
        if (playerIds && Array.isArray(playerIds)) {
            hasAdmin = playerIds.some(id => adminUserIds.includes(String(id)));
        }
        
        if (!hasAdmin && playerNames && Array.isArray(playerNames)) {
            hasAdmin = playerNames.some(name => adminUsernames.includes(String(name).toLowerCase()));
        }
        
        if (hasAdmin) {
            logAccess(req, 'ADMIN_IN_HEARTBEAT', true, { key, hwid });
            return res.json({ valid: false, error: "Admin detected", action: "destroy" });
        }
    }

    // Update heartbeat timestamp
    db.updateSessionHeartbeat(token);
    
    const uptimeDisplay = typeof uptime === 'number' ? Math.round(uptime) : 0;
    console.log(`💓 HB: ${key.substring(0, 12)}... | Uptime: ${uptimeDisplay}s`);
    
    res.json({ 
        valid: true, 
        serverTime: Date.now(),
        message: "OK"
    });
});

// ============================================================
// 🚨 SECURITY REPORT ENDPOINT
// ============================================================

app.post('/api/report', (req, res) => {
    const { key, hwid, reason, uptime } = req.body;
    const clientIP = getClientIP(req);
    
    console.log(`🚨 Security Report | Reason: ${reason} | Key: ${key?.substring(0, 12)}... | HWID: ${hwid?.substring(0, 12)}...`);
    
    logAccess(req, 'SECURITY_REPORT', false, { reason, uptime });
    
    // Auto-blacklist on certain violations
    const blacklistReasons = ['ENV:', 'DBG:', 'tamper', 'hook', 'inject', 'modified'];
    if (reason && blacklistReasons.some(r => reason.toLowerCase().includes(r.toLowerCase()))) {
        db.addToBlacklist(clientIP, hwid, reason);
        console.log(`🚫 Auto-blacklisted: ${clientIP} / ${hwid?.substring(0, 12)}...`);
    }
    
    res.json({ received: true });
});

// ============================================================
// 👑 ADMIN API ROUTES
// ============================================================

function adminAuth(req, res, next) {
    const adminKey = req.headers['x-admin-key'] || req.body?.adminKey;
    
    if (!adminKey || adminKey !== config.ADMIN_KEY) {
        logAccess(req, 'ADMIN_AUTH_FAILED', false);
        return res.status(403).json({ success: false, error: "Invalid admin key" });
    }
    
    next();
}

// --- Key Management ---

app.post('/api/admin/keys/generate', adminAuth, (req, res) => {
    const { tier = "free", expiryDays = null, maxHwid = 1, note = "" } = req.body;
    
    const prefix = tier.toUpperCase().substring(0, 4);
    const newKey = `${prefix}-${uuidv4().substring(0, 4).toUpperCase()}-${uuidv4().substring(0, 4).toUpperCase()}-${uuidv4().substring(0, 4).toUpperCase()}`;
    
    db.createKey(newKey, { tier, expiryDays, maxHwid, note });
    
    const keyData = db.getKey(newKey);
    logAccess(req, 'KEY_GENERATED', true, { key: newKey, tier });
    
    res.json({ 
        success: true, 
        key: newKey, 
        tier,
        expiry: keyData.expiry ? new Date(keyData.expiry).toISOString() : "lifetime",
        maxHwid 
    });
});

app.get('/api/admin/keys', adminAuth, (req, res) => {
    const keys = db.getAllKeys();
    res.json({ success: true, count: keys.length, keys });
});

app.get('/api/admin/keys/:key', adminAuth, (req, res) => {
    const keyData = db.getKey(req.params.key);
    if (!keyData) {
        return res.status(404).json({ success: false, error: "Key not found" });
    }
    res.json({ success: true, key: req.params.key, ...keyData });
});

app.delete('/api/admin/keys/:key', adminAuth, (req, res) => {
    const { key } = req.params;
    if (!db.getKey(key)) {
        return res.status(404).json({ success: false, error: "Key not found" });
    }
    db.deleteKey(key);
    logAccess(req, 'KEY_DELETED', true, { key });
    res.json({ success: true, message: `Key ${key} deleted` });
});

app.post('/api/admin/keys/:key/reset-hwid', adminAuth, (req, res) => {
    const { key } = req.params;
    if (!db.getKey(key)) {
        return res.status(404).json({ success: false, error: "Key not found" });
    }
    db.updateKey(key, { hwid: null });
    logAccess(req, 'HWID_RESET', true, { key });
    res.json({ success: true, message: `HWID reset for ${key}` });
});

// --- Logs ---

app.get('/api/admin/logs', adminAuth, (req, res) => {
    const { limit = 100, success, action, ip } = req.query;
    const filter = {};
    if (success !== undefined) filter.success = success === 'true';
    if (action) filter.action = action;
    if (ip) filter.ip = ip;
    
    const logs = db.getLogs(parseInt(limit), filter);
    res.json({ success: true, count: logs.length, logs });
});

// --- Blacklist ---

app.get('/api/admin/blacklist', adminAuth, (req, res) => {
    res.json({ success: true, blacklist: db.getBlacklist() });
});

app.post('/api/admin/blacklist/add', adminAuth, (req, res) => {
    const { ip, hwid, reason = "Manual" } = req.body;
    if (!ip && !hwid) {
        return res.status(400).json({ success: false, error: "Provide ip or hwid" });
    }
    db.addToBlacklist(ip || null, hwid || null, reason);
    logAccess(req, 'BLACKLIST_ADD', true, { ip, hwid, reason });
    res.json({ success: true, message: "Added to blacklist" });
});

app.post('/api/admin/blacklist/remove', adminAuth, (req, res) => {
    const { ip, hwid } = req.body;
    db.removeFromBlacklist(ip || null, hwid || null);
    logAccess(req, 'BLACKLIST_REMOVE', true, { ip, hwid });
    res.json({ success: true, message: "Removed from blacklist" });
});

// --- Admin Detection Management ---

app.get('/api/admin/detection/list', adminAuth, (req, res) => {
    res.json({ 
        success: true,
        enabled: config.SECURITY.ENABLE_ADMIN_DETECTION, 
        userIds: config.ADMIN_DETECTION.USER_IDS, 
        usernames: config.ADMIN_DETECTION.USERNAMES 
    });
});

app.post('/api/admin/detection/update', adminAuth, (req, res) => {
    const { userIds, usernames, enabled } = req.body;
    
    if (typeof enabled === 'boolean') {
        config.SECURITY.ENABLE_ADMIN_DETECTION = enabled;
    }
    if (userIds && Array.isArray(userIds)) {
        config.ADMIN_DETECTION.USER_IDS = userIds.map(id => String(id).trim()).filter(Boolean);
    }
    if (usernames && Array.isArray(usernames)) {
        config.ADMIN_DETECTION.USERNAMES = usernames.map(n => String(n).trim().toLowerCase()).filter(Boolean);
    }
    
    logAccess(req, 'DETECTION_UPDATED', true);
    
    res.json({ 
        success: true, 
        enabled: config.SECURITY.ENABLE_ADMIN_DETECTION,
        userIds: config.ADMIN_DETECTION.USER_IDS, 
        usernames: config.ADMIN_DETECTION.USERNAMES 
    });
});

// --- Stats ---

app.get('/api/admin/stats', adminAuth, (req, res) => {
    const stats = db.getStats();
    
    res.json({ 
        success: true, 
        stats: { 
            ...stats,
            server: {
                uptime: Math.floor(process.uptime()) + "s",
                memory: Math.floor(process.memoryUsage().heapUsed / 1024 / 1024) + "MB",
                nodeVersion: process.version
            },
            security: {
                obfuscation: config.SECURITY.ENABLE_OBFUSCATION,
                antiTamper: config.SECURITY.ENABLE_ANTI_TAMPER,
                heartbeat: config.SECURITY.ENABLE_HEARTBEAT,
                adminDetection: config.SECURITY.ENABLE_ADMIN_DETECTION,
                adminUserIds: config.ADMIN_DETECTION.USER_IDS.length,
                adminUsernames: config.ADMIN_DETECTION.USERNAMES.length
            }
        } 
    });
});

// --- Cache Management ---

app.post('/api/admin/cache/clear', adminAuth, (req, res) => {
    scriptCache.flushAll();
    logAccess(req, 'CACHE_CLEARED', true);
    res.json({ success: true, message: "Script cache cleared" });
});

// ============================================================
// 🚫 CATCH-ALL: Block unknown routes + Browser protection
// ============================================================

app.use('*', (req, res) => {
    if (isBrowserRequest(req)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(UNAUTHORIZED_HTML);
    }
    res.status(404).json({ success: false, error: "Endpoint not found" });
});

// ============================================================
// ❌ GLOBAL ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.message);
    logAccess(req, 'SERVER_ERROR', false, { error: err.message });
    
    if (isBrowserRequest(req)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(UNAUTHORIZED_HTML);
    }
    
    res.status(500).json({ success: false, error: "Internal server error" });
});

// ============================================================
// 🚀 START SERVER
// ============================================================

const PORT = config.PORT;

app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════════════╗');
    console.log('║          🛡️  ROBLOX SCRIPT PROTECTOR v1.3.0 - STARTED            ║');
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log(`║  🌐 Port: ${PORT}                                                     ║`);
    console.log(`║  📅 ${new Date().toISOString()}                            ║`);
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log(`║  🔒 Obfuscation:       ${config.SECURITY.ENABLE_OBFUSCATION ? '✅ ON ' : '❌ OFF'}                                 ║`);
    console.log(`║  🛡️  Anti-Tamper:       ${config.SECURITY.ENABLE_ANTI_TAMPER ? '✅ ON ' : '❌ OFF'}                                 ║`);
    console.log(`║  💓 Heartbeat:         ${config.SECURITY.ENABLE_HEARTBEAT ? '✅ ON ' : '❌ OFF'} (30s interval)                    ║`);
    console.log(`║  👑 Admin Detection:   ${config.SECURITY.ENABLE_ADMIN_DETECTION ? '✅ ON ' : '❌ OFF'} (10s scan)                      ║`);
    console.log(`║  🌐 Browser Block:     ✅ ON                                      ║`);
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log('║  📱 Supported Executors:                                         ║');
    console.log('║     PC: Synapse, KRNL, Fluxus, Script-Ware, Evon, Solara, etc.   ║');
    console.log('║     Mobile: Delta, Arceus X, Hydrogen, Codex, Vegax, etc.        ║');
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log('║  📍 Endpoints:                                                   ║');
    console.log('║     GET  /api/script?key=XXX&hwid=YYY                            ║');
    console.log('║     POST /api/validate                                           ║');
    console.log('║     POST /api/heartbeat                                          ║');
    console.log('║     POST /api/admin-check                                        ║');
    console.log('║     POST /api/admin/* (x-admin-key required)                     ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('');
});

module.exports = app;
