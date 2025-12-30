// ============================================================
// ⚙️ CONFIG - src/config.js
// ============================================================

module.exports = {
    PORT: process.env.PORT || 3000,
    NODE_ENV: process.env.NODE_ENV || 'development',
    
    // 🔐 Dari Render Environment Variables
    SCRIPT_SOURCE_URL: process.env.SCRIPT_SOURCE_URL,
    ADMIN_KEY: process.env.ADMIN_KEY || 'change-this-admin-key',
    
    // Rate Limit
    RATE_LIMIT: {
        WINDOW_MS: 60000,
        MAX_REQUESTS: 30
    }
};
