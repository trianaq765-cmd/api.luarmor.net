// ============================================================
// 🔐 CRYPTO LAYER - src/crypto-layer.js (FIXED)
// ============================================================

const CryptoJS = require('crypto-js');
const config = require('./config');

class CryptoLayer {
    constructor() {
        this.key = config.ENCRYPTION_KEY;
        this.signingSecret = config.SIGNING_SECRET;
    }

    // 🎲 Generate Random Token
    generateToken() {
        const timestamp = Date.now();
        const random = CryptoJS.lib.WordArray.random(16).toString();
        const data = `${timestamp}:${random}`;
        const signature = CryptoJS.HmacSHA256(data, this.signingSecret).toString();
        
        return Buffer.from(JSON.stringify({
            t: timestamp,
            r: random,
            s: signature
        })).toString('base64');
    }

    // 📦 Create Protected Payload - Standard (FIXED)
    createProtectedPayload(script) {
        const timestamp = Date.now();
        const hash = CryptoJS.SHA256(script).toString().substring(0, 16);
        const sessionId = CryptoJS.lib.WordArray.random(8).toString();

        // Wrapper yang sudah ditest dan berfungsi
        return `--[[ Protected | ${sessionId} ]]
local _protected_main_ = function()
    ${script}
end

local _ok_, _err_ = pcall(_protected_main_)
if not _ok_ then
    warn("[Loader] Error")
end
_protected_main_ = nil
`;
    }

    // 🛡️ Create Advanced Payload (FIXED)
    createAdvancedPayload(script) {
        const timestamp = Date.now();
        const sessionId = CryptoJS.lib.WordArray.random(8).toString();

        return `--[[ Premium | ${sessionId} ]]
local _run_ = function()
    local _env_ok_ = pcall(function()
        return game:GetService("Players")
    end)
    
    if not _env_ok_ then
        return
    end
    
    ${script}
end

pcall(_run_)
_run_ = nil
collectgarbage("collect")
`;
    }

    // 🎭 Light Obfuscation (FIXED)
    lightObfuscate(script) {
        // Langsung return script tanpa wrapper tambahan
        return script;
    }

    // 🎲 Generate Random Variable Name
    generateRandomVarName() {
        const chars = 'abcdefghijklmnopqrstuvwxyz';
        const prefix = chars[Math.floor(Math.random() * chars.length)];
        const suffix = CryptoJS.lib.WordArray.random(4).toString().substring(0, 6);
        return `_${prefix}${suffix}`;
    }
}

module.exports = new CryptoLayer();
