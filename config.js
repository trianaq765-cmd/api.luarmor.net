// ============================================================
// ⚙️ CONFIG - src/config.js (FIXED)
// ============================================================

// Untuk Render, tidak perlu dotenv karena env sudah di-inject
// Tapi tetap support lokal development
try {
    require('dotenv').config();
} catch (e) {
    // Ignore jika dotenv tidak ada
}

module.exports = {
    PORT: process.env.PORT || 3000,
    NODE_ENV: process.env.NODE_ENV || 'development',
    
    // 🔐 Dari environment variables
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL,
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || 'default-encryption-key-32chars!!',
    SIGNING_SECRET: process.env.SIGNING_SECRET || 'default-signing-secret-here!!!!',
    ADMIN_KEY: process.env.ADMIN_KEY || 'default-admin-key',
    
    // Rate Limit
    RATE_LIMIT: {
        WINDOW_MS: 60000,
        MAX_REQUESTS: 30
    },
    
    // Cache TTL (5 menit)
    CACHE_TTL: 5 * 60 * 1000,
    
    // Token expiry (30 detik)
    TOKEN_EXPIRY: 30 * 1000
};
