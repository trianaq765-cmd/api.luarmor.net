# 🛡️ Roblox Script Protector

Backend server untuk melindungi Roblox loadstring dengan fitur keamanan lengkap.

## ✨ Fitur

- ✅ Key System + HWID Lock
- ✅ Anti-Tamper Protection
- ✅ Script Obfuscation
- ✅ Heartbeat System
- ✅ Admin Detection
- ✅ Browser Protection
- ✅ Rate Limiting
- ✅ Auto-Blacklist
- ✅ Universal Executor Support (PC & Mobile)

## 🚀 Supported Executors

**PC:** Synapse X, KRNL, Fluxus, Script-Ware, Evon, Solara, Wave, etc.

**Mobile:** Delta, Arceus X, Hydrogen, Codex, Vegax, Nihon, etc.

## 📖 Usage

```lua
local key = "YOUR-KEY-HERE"
local hwid = game:GetService("RbxAnalyticsService"):GetClientId()
local server = "https://your-app.onrender.com"

loadstring(game:HttpGet(server.."/api/script?key="..key.."&hwid="..hwid))()
