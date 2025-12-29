// ============================================================
// 🔍 VALIDATOR - Request Validation Layer (FIXED)
// ============================================================

const CryptoJS = require('crypto-js');
const config = require('./config');

class RequestValidator {
    constructor() {
        this.usedTokens = new Map();
        this.suspiciousIPs = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    }

    // ============================================================
    // 🎮 Detect Valid Executor - LEBIH AKURAT
    // ============================================================
    isValidExecutor(req) {
        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const accept = req.headers['accept'] || '';
        const contentType = req.headers['content-type'] || '';
        
        // ============================================================
        // ✅ EXECUTOR WHITELIST - Langsung izinkan
        // ============================================================
        const executorPatterns = [
            'roblox',           // Roblox client
            'synapse',          // Synapse X
            'krnl',             // KRNL
            'fluxus',           // Fluxus
            'delta',            // Delta
            'electron',         // Electron-based executors
            'script-ware',      // Script-Ware
            'scriptware',       // Script-Ware (no dash)
            'sentinel',         // Sentinel
            'coco',             // Coco Z
            'oxygen',           // Oxygen U
            'evon',             // Evon
            'arceus',           // Arceus X
            'hydrogen',         // Hydrogen
            'vegax',            // VegaX
            'trigon',           // Trigon
            'comet',            // Comet
            'nihon',            // Nihon
            'jjsploit',         // JJSploit
            'wearedevs',        // WeAreDevs
            'exploit',          // Generic exploit
            'executor',         // Generic executor
            'wininet',          // WinInet (Roblox HTTP)
            'robloxstudio'      // Roblox Studio
        ];
        
        // Jika User-Agent mengandung kata executor, IZINKAN
        const isExecutorUA = executorPatterns.some(pattern => userAgent.includes(pattern));
        if (isExecutorUA) {
            return { valid: true, type: 'EXECUTOR_DETECTED' };
        }
        
        // ============================================================
        // ✅ EXECUTOR BEHAVIOR - Ciri khas executor
        // ============================================================
        
        // Executor biasanya:
        // 1. Tidak kirim Accept: text/html (atau kirim */*)
        // 2. User-Agent kosong atau sederhana
        // 3. Tidak ada Referer
        // 4. Tidak ada Cookie
        // 5. Tidak ada Accept-Language yang kompleks
        
        const hasNoReferer = !req.headers['referer'];
        const hasNoCookie = !req.headers['cookie'];
        const simpleAccept = accept === '*/*' || accept === '' || !accept.includes('text/html');
        const noAcceptLanguage = !req.headers['accept-language'];
        const simpleUA = userAgent.length < 50 || userAgent === '';
        
        // Jika memenuhi 3+ ciri executor, izinkan
        const executorScore = [
            hasNoReferer,
            hasNoCookie, 
            simpleAccept,
            noAcceptLanguage,
            simpleUA
        ].filter(Boolean).length;
        
        if (executorScore >= 3) {
            return { valid: true, type: 'EXECUTOR_BEHAVIOR' };
        }
        
        // ============================================================
        // 🌐 BROWSER DETECTION - Ciri khas browser
        // ============================================================
        
        const browserPatterns = [
            // Browser harus punya kombinasi ini
            { ua: 'mozilla', accept: 'text/html' },
            { ua: 'chrome', accept: 'text/html' },
            { ua: 'safari', accept: 'text/html' },
            { ua: 'firefox', accept: 'text/html' },
            { ua: 'edge', accept: 'text/html' },
            { ua: 'opera', accept: 'text/html' }
        ];
        
        const isBrowser = browserPatterns.some(pattern => 
            userAgent.includes(pattern.ua) && accept.includes(pattern.accept)
        );
        
        // Extra check: Browser biasanya punya Accept-Language
        const hasAcceptLanguage = !!req.headers['accept-language'];
        const hasSecFetchHeaders = !!req.headers['sec-fetch-mode'] || !!req.headers['sec-fetch-site'];
        
        // Jika terdeteksi sebagai browser DAN punya ciri browser
        if (isBrowser && (hasAcceptLanguage || hasSecFetchHeaders)) {
            return { valid: false, reason: 'BROWSER_DETECTED' };
        }
        
        // ============================================================
        // ✅ DEFAULT: Izinkan jika tidak yakin browser
        // ============================================================
        // Lebih baik izinkan executor yang tidak terdeteksi
        // daripada block user yang legitimate
        
        return { valid: true, type: 'UNKNOWN_ALLOWED' };
    }

    // ============================================================
    // 🚨 Track Suspicious Activity
    // ============================================================
    trackSuspicious(ip, reason) {
        const current = this.suspiciousIPs.get(ip) || { count: 0, reasons: [] };
        current.count++;
        current.reasons.push({ reason, time: Date.now() });
        current.lastSeen = Date.now();
        this.suspiciousIPs.set(ip, current);
        
        return current.count >= 15; // Naikkan threshold
    }

    // ============================================================
    // 🚫 Check if IP is Blocked
    // ============================================================
    isBlocked(ip) {
        const record = this.suspiciousIPs.get(ip);
        if (!record) return false;
        
        if (record.count >= 15) { // Naikkan threshold
            const blockDuration = 30 * 60 * 1000; // 30 menit (turunkan)
            if (Date.now() - record.lastSeen < blockDuration) {
                return true;
            }
            this.suspiciousIPs.delete(ip);
        }
        
        return false;
    }

    // ============================================================
    // 🧹 Cleanup Old Data
    // ============================================================
    cleanup() {
        const now = Date.now();
        
        for (const [nonce, time] of this.usedTokens) {
            if (now - time > 60000) {
                this.usedTokens.delete(nonce);
            }
        }
        
        for (const [ip, record] of this.suspiciousIPs) {
            if (now - record.lastSeen > 1800000) { // 30 menit
                this.suspiciousIPs.delete(ip);
            }
        }
    }

    // ============================================================
    // 📊 Get Security Stats
    // ============================================================
    getStats() {
        return {
            usedTokens: this.usedTokens.size,
            suspiciousIPs: this.suspiciousIPs.size,
            blockedIPs: Array.from(this.suspiciousIPs.entries())
                .filter(([_, r]) => r.count >= 15)
                .map(([ip, _]) => ip)
        };
    }
}

module.exports = new RequestValidator();
