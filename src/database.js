// ============================================================
// 💾 IN-MEMORY DATABASE
// ============================================================

const NodeCache = require('node-cache');

// Cache untuk script (TTL dalam detik)
const scriptCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// Database in-memory
const database = {
    // ========================================================
    // 🔑 KEYS DATABASE
    // ========================================================
    keys: {
        // Key gratis untuk testing
        "TEST-FREE-0001-XXXX": {
            hwid: null,
            maxHwid: 1,
            expiry: null,  // lifetime
            createdAt: Date.now(),
            usageCount: 0,
            tier: "free",
            note: "Test key untuk development"
        },
        // Key premium contoh
        "PREM-DEMO-1234-ABCD": {
            hwid: null,
            maxHwid: 2,
            expiry: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 hari
            createdAt: Date.now(),
            usageCount: 0,
            tier: "premium",
            note: "Demo premium key"
        },
        // Key VIP contoh
        "VIPS-DEMO-5678-EFGH": {
            hwid: null,
            maxHwid: 3,
            expiry: null,  // lifetime
            createdAt: Date.now(),
            usageCount: 0,
            tier: "vip",
            note: "Demo VIP key"
        }
    },
    
    // ========================================================
    // 🚫 BLACKLIST DATABASE
    // ========================================================
    blacklist: {
        ips: [],
        hwids: [],
        reasons: {}  // Menyimpan alasan blacklist
    },
    
    // ========================================================
    // ✅ WHITELIST DATABASE (Optional)
    // ========================================================
    whitelist: {
        enabled: false,  // Jika true, hanya HWID di whitelist yang bisa akses
        hwids: []
    },
    
    // ========================================================
    // 📝 LOGS DATABASE
    // ========================================================
    logs: [],
    maxLogs: 1000,
    
    // ========================================================
    // 🔒 SESSIONS DATABASE
    // ========================================================
    sessions: {},  // token -> { key, hwid, createdAt, lastHeartbeat }
    
    // ========================================================
    // ❌ FAILED ATTEMPTS TRACKER
    // ========================================================
    failedAttempts: {}  // ip -> { count, firstAttempt, lastAttempt }
};

// ============================================================
// 📦 DATABASE HELPER FUNCTIONS
// ============================================================

const db = {
    // ========================================================
    // 🔑 KEY OPERATIONS
    // ========================================================
    
    getKey: (key) => {
        return database.keys[key] || null;
    },
    
    createKey: (key, data) => {
        database.keys[key] = {
            hwid: null,
            maxHwid: data.maxHwid || 1,
            expiry: data.expiryDays 
                ? Date.now() + (data.expiryDays * 24 * 60 * 60 * 1000) 
                : null,
            createdAt: Date.now(),
            usageCount: 0,
            tier: data.tier || 'free',
            note: data.note || ''
        };
        return database.keys[key];
    },
    
    updateKey: (key, updates) => {
        if (database.keys[key]) {
            Object.assign(database.keys[key], updates);
            return true;
        }
        return false;
    },
    
    deleteKey: (key) => {
        if (database.keys[key]) {
            delete database.keys[key];
            return true;
        }
        return false;
    },
    
    getAllKeys: () => {
        return Object.entries(database.keys).map(([key, data]) => ({
            key,
            ...data,
            isExpired: data.expiry ? Date.now() > data.expiry : false,
            isActive: data.hwid !== null
        }));
    },
    
    // ========================================================
    // 🚫 BLACKLIST OPERATIONS
    // ========================================================
    
    isBlacklisted: (ip, hwid) => {
        return database.blacklist.ips.includes(ip) || 
               database.blacklist.hwids.includes(hwid);
    },
    
    addToBlacklist: (ip, hwid, reason) => {
        if (ip && !database.blacklist.ips.includes(ip)) {
            database.blacklist.ips.push(ip);
            database.blacklist.reasons[`ip:${ip}`] = reason;
        }
        if (hwid && !database.blacklist.hwids.includes(hwid)) {
            database.blacklist.hwids.push(hwid);
            database.blacklist.reasons[`hwid:${hwid}`] = reason;
        }
    },
    
    removeFromBlacklist: (ip, hwid) => {
        if (ip) {
            database.blacklist.ips = database.blacklist.ips.filter(i => i !== ip);
            delete database.blacklist.reasons[`ip:${ip}`];
        }
        if (hwid) {
            database.blacklist.hwids = database.blacklist.hwids.filter(h => h !== hwid);
            delete database.blacklist.reasons[`hwid:${hwid}`];
        }
    },
    
    getBlacklist: () => {
        return {
            ips: database.blacklist.ips.map(ip => ({
                ip,
                reason: database.blacklist.reasons[`ip:${ip}`] || 'Unknown'
            })),
            hwids: database.blacklist.hwids.map(hwid => ({
                hwid,
                reason: database.blacklist.reasons[`hwid:${hwid}`] || 'Unknown'
            }))
        };
    },
    
    // ========================================================
    // ❌ FAILED ATTEMPTS OPERATIONS
    // ========================================================
    
    trackFailedAttempt: (ip, maxAttempts) => {
        if (!database.failedAttempts[ip]) {
            database.failedAttempts[ip] = {
                count: 0,
                firstAttempt: Date.now(),
                lastAttempt: Date.now()
            };
        }
        
        const tracker = database.failedAttempts[ip];
        tracker.count++;
        tracker.lastAttempt = Date.now();
        
        // Reset jika sudah lebih dari 1 jam
        if (Date.now() - tracker.firstAttempt > 60 * 60 * 1000) {
            tracker.count = 1;
            tracker.firstAttempt = Date.now();
        }
        
        return tracker.count >= maxAttempts;
    },
    
    resetFailedAttempts: (ip) => {
        delete database.failedAttempts[ip];
    },
    
    // ========================================================
    // 📝 LOG OPERATIONS
    // ========================================================
    
    addLog: (log) => {
        database.logs.push({
            ...log,
            id: database.logs.length + 1,
            timestamp: new Date().toISOString()
        });
        
        // Trim logs jika melebihi batas
        if (database.logs.length > database.maxLogs) {
            database.logs = database.logs.slice(-database.maxLogs);
        }
    },
    
    getLogs: (limit = 100, filter = {}) => {
        let logs = [...database.logs];
        
        // Apply filters
        if (filter.success !== undefined) {
            logs = logs.filter(l => l.success === filter.success);
        }
        if (filter.action) {
            logs = logs.filter(l => l.action === filter.action);
        }
        if (filter.ip) {
            logs = logs.filter(l => l.ip === filter.ip);
        }
        
        return logs.slice(-limit).reverse();
    },
    
    // ========================================================
    // 🔒 SESSION OPERATIONS
    // ========================================================
    
    createSession: (token, key, hwid) => {
        database.sessions[token] = {
            key,
            hwid,
            createdAt: Date.now(),
            lastHeartbeat: Date.now()
        };
    },
    
    getSession: (token) => {
        return database.sessions[token] || null;
    },
    
    updateSessionHeartbeat: (token) => {
        if (database.sessions[token]) {
            database.sessions[token].lastHeartbeat = Date.now();
            return true;
        }
        return false;
    },
    
    deleteSession: (token) => {
        delete database.sessions[token];
    },
    
    cleanExpiredSessions: (maxAge = 3600000) => { // Default 1 jam
        const now = Date.now();
        Object.keys(database.sessions).forEach(token => {
            if (now - database.sessions[token].lastHeartbeat > maxAge) {
                delete database.sessions[token];
            }
        });
    },
    
    // ========================================================
    // 📊 STATS OPERATIONS
    // ========================================================
    
    getStats: () => {
        const keys = Object.values(database.keys);
        return {
            totalKeys: keys.length,
            activeKeys: keys.filter(k => k.hwid !== null).length,
            expiredKeys: keys.filter(k => k.expiry && Date.now() > k.expiry).length,
            freeKeys: keys.filter(k => k.tier === 'free').length,
            premiumKeys: keys.filter(k => k.tier === 'premium').length,
            vipKeys: keys.filter(k => k.tier === 'vip').length,
            totalLogs: database.logs.length,
            blacklistedIPs: database.blacklist.ips.length,
            blacklistedHWIDs: database.blacklist.hwids.length,
            activeSessions: Object.keys(database.sessions).length
        };
    }
};

// Export
module.exports = {
    db,
    scriptCache,
    database  // Export raw database untuk debugging
};
