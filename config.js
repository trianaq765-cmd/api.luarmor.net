// ============================================================
// ⚙️ CONFIG - src/config.js
// ============================================================

require('dotenv').config({ path: '../.env' }); // .env di luar src

module.exports = {
    PORT: process.env.PORT || 3000,
    NODE_ENV: process.env.NODE_ENV || 'development',
    
    // 🔐 Tersembunyi di environment
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL,
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || 'default-key-change-this-now!!!!',
    SIGNING_SECRET: process.env.SIGNING_SECRET || 'default-secret-change-this!!!',
    ADMIN_KEY: process.env.ADMIN_KEY || 'change-this-admin-key',
    
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
