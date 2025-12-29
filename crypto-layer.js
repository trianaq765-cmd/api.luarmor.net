// ============================================================
// 🔐 CRYPTO LAYER - Protection + Anti-Tamper (Executor Safe)
// ============================================================

const CryptoJS = require('crypto-js');
const config = require('./config');

class CryptoLayer {
    constructor() {
        this.key = config.ENCRYPTION_KEY;
        this.signingSecret = config.SIGNING_SECRET;
    }

    // ============================================================
    // 🎲 Generate Random Token
    // ============================================================
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

    // ============================================================
    // 📦 Create Protected Payload - ANTI TAMPER (Ringan)
    // ============================================================
    createProtectedPayload(script) {
        const timestamp = Date.now();
        const hash = CryptoJS.SHA256(script).toString().substring(0, 16);
        const sessionId = CryptoJS.lib.WordArray.random(8).toString();
        const randomVarName = this.generateRandomVarName();
        
        // Anti-tamper wrapper yang RINGAN dan executor-friendly
        const payload = `--[[ Premium Protected | ${sessionId} ]]

local ${randomVarName} = (function()
    --// Environment Check (Ringan)
    local _ENV_CHECK = function()
        local success, result = pcall(function()
            return game:GetService("Players")
        end)
        return success and result ~= nil
    end
    
    if not _ENV_CHECK() then
        return function() end
    end
    
    --// Integrity Data
    local _INTEGRITY = {
        _h = "${hash}",
        _t = ${timestamp},
        _s = "${sessionId}"
    }
    
    --// Time Check (5 menit expiry)
    local function _verifyTime()
        local serverTime = os.time()
        local scriptTime = math.floor(_INTEGRITY._t / 1000)
        return (serverTime - scriptTime) < 300
    end
    
    --// Anti-Spy Detection (Ringan - tidak block executor)
    local function _checkEnv()
        local suspicious = false
        
        -- Check jika ada global spy yang umum
        pcall(function()
            if rawget(_G, "SimpleSpyExecuted") then suspicious = true end
            if rawget(_G, "RemoteSpy") then suspicious = true end
            if rawget(_G, "ScriptDump") then suspicious = true end
        end)
        
        return not suspicious
    end
    
    --// Verify sebelum execute
    if not _verifyTime() then
        pcall(function()
            game:GetService("StarterGui"):SetCore("SendNotification", {
                Title = "⚠️ Session",
                Text = "Session expired. Please reload.",
                Duration = 5
            })
        end)
        return function() end
    end
    
    --// Main Script
    ${script}
    
    --// Cleanup
    _INTEGRITY = nil
    
end)

-- Execute
if type(${randomVarName}) == "function" then
    local s, e = pcall(${randomVarName})
    if not s then
        warn("[Loader] Protected execution")
    end
end
${randomVarName} = nil
collectgarbage("collect")
`;
        
        return payload;
    }

    // ============================================================
    // 🛡️ Create Advanced Protected Payload (Lebih Kuat)
    // ============================================================
    createAdvancedPayload(script) {
        const timestamp = Date.now();
        const hash = CryptoJS.SHA256(script).toString().substring(0, 16);
        const sessionId = CryptoJS.lib.WordArray.random(8).toString();
        const v1 = this.generateRandomVarName();
        const v2 = this.generateRandomVarName();
        const v3 = this.generateRandomVarName();
        
        const payload = `--[[ ${this.generateRandomComment()} ]]

local ${v1}, ${v2}, ${v3}

${v1} = {
    _a = "${hash}",
    _b = ${timestamp},
    _c = "${sessionId}",
    _d = function(x) return x end
}

${v2} = function()
    local _g = getfenv and getfenv() or _G
    local _p = game:GetService("Players")
    local _r = game:GetService("RunService")
    
    --// Verify environment
    if not _p.LocalPlayer and not _r:IsStudio() then
        return nil
    end
    
    --// Time validation
    local _now = os.time()
    local _then = math.floor(${v1}._b / 1000)
    if (_now - _then) > 300 then
        game:GetService("StarterGui"):SetCore("SendNotification", {
            Title = "⏱️",
            Text = "Please reload script",
            Duration = 3
        })
        return nil
    end
    
    --// Anti basic dump (tidak ganggu executor)
    local _protected = setmetatable({}, {
        __tostring = function() return "protected" end,
        __metatable = "locked"
    })
    
    --// Execute main script
    local _main = function()
        ${script}
    end
    
    return _main
end

${v3} = ${v2}()
if ${v3} then
    local _ok, _err = pcall(${v3})
end

${v1} = nil
${v2} = nil
${v3} = nil
collectgarbage("collect")
`;
        
        return payload;
    }

    // ============================================================
    // 🎭 Light Obfuscation Layer
    // ============================================================
    lightObfuscate(script) {
        const funcName = this.generateRandomVarName();
        const noise = this.generateNoiseComment();
        
        return `${noise}local ${funcName}=(function()\n${script}\nend);${funcName}();${funcName}=nil;`;
    }

    // ============================================================
    // 🎲 Generate Random Variable Name
    // ============================================================
    generateRandomVarName() {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const prefix = chars[Math.floor(Math.random() * chars.length)];
        const suffix = CryptoJS.lib.WordArray.random(4).toString().substring(0, 8);
        return `_${prefix}${suffix}`;
    }

    // ============================================================
    // 💭 Generate Noise Comment
    // ============================================================
    generateNoiseComment() {
        const patterns = [
            `--[[${"=".repeat(Math.floor(Math.random() * 20) + 5)}]]`,
            `--[[ ${Date.now().toString(36)} ]]`,
            `--[[ ${CryptoJS.lib.WordArray.random(4).toString()} ]]`
        ];
        return patterns[Math.floor(Math.random() * patterns.length)] + '\n';
    }

    // ============================================================
    // 💭 Generate Random Comment
    // ============================================================
    generateRandomComment() {
        const words = ['Premium', 'Protected', 'Secure', 'Licensed', 'Verified'];
        const word = words[Math.floor(Math.random() * words.length)];
        const id = CryptoJS.lib.WordArray.random(4).toString();
        return `${word} Script | ${id}`;
    }
}

module.exports = new CryptoLayer();
