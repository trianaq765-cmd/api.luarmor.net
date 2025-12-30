// ============================================================
// 🔐 CRYPTO LAYER - src/crypto-layer.js
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

    // 📦 Create Protected Payload - Standard
    createProtectedPayload(script) {
        const timestamp = Date.now();
        const hash = CryptoJS.SHA256(script).toString().substring(0, 16);
        const sessionId = CryptoJS.lib.WordArray.random(8).toString();
        const v = this.generateRandomVarName();
        
        return `--[[ Premium Protected | ${sessionId} ]]

local ${v} = (function()
    local _ENV_CHECK = function()
        local s, r = pcall(function()
            return game:GetService("Players")
        end)
        return s and r ~= nil
    end
    
    if not _ENV_CHECK() then return function() end end
    
    local _I = { _h = "${hash}", _t = ${timestamp}, _s = "${sessionId}" }
    
    local function _vT()
        local sT = os.time()
        local scT = math.floor(_I._t / 1000)
        return (sT - scT) < 300
    end
    
    local function _cE()
        local sus = false
        pcall(function()
            if rawget(_G, "SimpleSpyExecuted") then sus = true end
            if rawget(_G, "RemoteSpy") then sus = true end
        end)
        return not sus
    end
    
    if not _vT() then
        pcall(function()
            game:GetService("StarterGui"):SetCore("SendNotification", {
                Title = "⚠️ Session",
                Text = "Session expired. Please reload.",
                Duration = 5
            })
        end)
        return function() end
    end
    
    ${script}
    
    _I = nil
end)

if type(${v}) == "function" then
    local s, e = pcall(${v})
end
${v} = nil
collectgarbage("collect")
`;
    }

    // 🛡️ Create Advanced Payload
    createAdvancedPayload(script) {
        const timestamp = Date.now();
        const hash = CryptoJS.SHA256(script).toString().substring(0, 16);
        const sessionId = CryptoJS.lib.WordArray.random(8).toString();
        const v1 = this.generateRandomVarName();
        const v2 = this.generateRandomVarName();
        const v3 = this.generateRandomVarName();
        
        return `--[[ ${this.generateRandomComment()} ]]

local ${v1}, ${v2}, ${v3}

${v1} = {
    _a = "${hash}",
    _b = ${timestamp},
    _c = "${sessionId}"
}

${v2} = function()
    local _p = game:GetService("Players")
    local _r = game:GetService("RunService")
    
    if not _p.LocalPlayer and not _r:IsStudio() then
        return nil
    end
    
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
    
    local _main = function()
        ${script}
    end
    
    return _main
end

${v3} = ${v2}()
if ${v3} then pcall(${v3}) end

${v1} = nil
${v2} = nil
${v3} = nil
collectgarbage("collect")
`;
    }

    // 🎭 Light Obfuscation
    lightObfuscate(script) {
        const funcName = this.generateRandomVarName();
        const noise = this.generateNoiseComment();
        return `${noise}local ${funcName}=(function()\n${script}\nend);${funcName}();${funcName}=nil;`;
    }

    // 🎲 Generate Random Variable Name
    generateRandomVarName() {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const prefix = chars[Math.floor(Math.random() * chars.length)];
        const suffix = CryptoJS.lib.WordArray.random(4).toString().substring(0, 8);
        return `_${prefix}${suffix}`;
    }

    // 💭 Generate Noise Comment
    generateNoiseComment() {
        return `--[[${"=".repeat(Math.floor(Math.random() * 20) + 5)}]]\n`;
    }

    // 💭 Generate Random Comment
    generateRandomComment() {
        const words = ['Premium', 'Protected', 'Secure', 'Licensed', 'Verified'];
        const word = words[Math.floor(Math.random() * words.length)];
        const id = CryptoJS.lib.WordArray.random(4).toString();
        return `${word} Script | ${id}`;
    }
}

module.exports = new CryptoLayer();
