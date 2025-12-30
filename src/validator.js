// ============================================================
// 🔍 VALIDATOR - src/validator.js
// ============================================================

const config = require('./config');

class RequestValidator {
    constructor() {
        this.usedTokens = new Map();
        this.suspiciousIPs = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    }

    // 🎮 Detect Valid Executor
    isValidExecutor(req) {
        const userAgent = (req.headers['user-agent'] || '').toLowerCase();
        const accept = req.headers['accept'] || '';
        
        // ✅ Executor whitelist
        const executorPatterns = [
            'roblox', 'synapse', 'krnl', 'fluxus', 'delta', 'electron',
            'script-ware', 'scriptware', 'sentinel', 'coco', 'oxygen',
            'evon', 'arceus', 'hydrogen', 'vegax', 'trigon', 'comet',
            'nihon', 'jjsploit', 'wearedevs', 'exploit', 'executor',
            'wininet', 'robloxstudio'
        ];
        
        if (executorPatterns.some(p => userAgent.includes(p))) {
            return { valid: true, type: 'EXECUTOR_DETECTED' };
        }
        
        // ✅ Executor behavior
        const hasNoReferer = !req.headers['referer'];
        const hasNoCookie = !req.headers['cookie'];
        const simpleAccept = accept === '*/*' || accept === '' || !accept.includes('text/html');
        const noAcceptLanguage = !req.headers['accept-language'];
        const simpleUA = userAgent.length < 50 || userAgent === '';
        
        const executorScore = [hasNoReferer, hasNoCookie, simpleAccept, noAcceptLanguage, simpleUA].filter(Boolean).length;
        
        if (executorScore >= 3) {
            return { valid: true, type: 'EXECUTOR_BEHAVIOR' };
        }
        
        // 🌐 Browser detection
        const browserPatterns = [
            { ua: 'mozilla', accept: 'text/html' },
            { ua: 'chrome', accept: 'text/html' },
            { ua: 'safari', accept: 'text/html' },
            { ua: 'firefox', accept: 'text/html' },
            { ua: 'edg', accept: 'text/html' }
        ];
        
        const isBrowser = browserPatterns.some(p => 
            userAgent.includes(p.ua) && accept.includes(p.accept)
        );
        
        const hasAcceptLanguage = !!req.headers['accept-language'];
        const hasSecFetch = !!req.headers['sec-fetch-mode'];
        
        if (isBrowser && (hasAcceptLanguage || hasSecFetch)) {
            return { valid: false, reason: 'BROWSER_DETECTED' };
        }
        
        // Default: izinkan
        return { valid: true, type: 'UNKNOWN_ALLOWED' };
    }

    // 🚨 Track Suspicious
    trackSuspicious(ip, reason) {
        const current = this.suspiciousIPs.get(ip) || { count: 0, reasons: [], lastSeen: 0 };
        current.count++;
        current.reasons.push({ reason, time: Date.now() });
        current.lastSeen = Date.now();
        this.suspiciousIPs.set(ip, current);
        return current.count >= 15;
    }

    // 🚫 Check Blocked
    isBlocked(ip) {
        const record = this.suspiciousIPs.get(ip);
        if (!record) return false;
        
        if (record.count >= 15) {
            if (Date.now() - record.lastSeen < 30 * 60 * 1000) {
                return true;
            }
            this.suspiciousIPs.delete(ip);
        }
        return false;
    }

    // 🧹 Cleanup
    cleanup() {
        const now = Date.now();
        for (const [nonce, time] of this.usedTokens) {
            if (now - time > 60000) this.usedTokens.delete(nonce);
        }
        for (const [ip, record] of this.suspiciousIPs) {
            if (now - record.lastSeen > 1800000) this.suspiciousIPs.delete(ip);
        }
    }

    // 📊 Stats
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
