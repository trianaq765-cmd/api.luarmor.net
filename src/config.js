// ============================================================
// 🔧 CONFIGURATION FILE
// ============================================================

require('dotenv').config();

const config = {
    // Server
    PORT: process.env.PORT || 3000,
    NODE_ENV: process.env.NODE_ENV || 'development',
    
    // Security Keys
    SECRET_KEY: process.env.SECRET_KEY || 'default-secret-key-change-in-production',
    ADMIN_KEY: process.env.ADMIN_KEY || 'default-admin-key-change-in-production',
    
    // Original Script
    ORIGINAL_SCRIPT_URL: process.env.ORIGINAL_SCRIPT_URL || '',
    
    // Rate Limiting
    RATE_LIMIT: {
        WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
        MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 10
    },
    
    // Security Features
    SECURITY: {
        ENABLE_OBFUSCATION: process.env.ENABLE_OBFUSCATION === 'true',
        ENABLE_ANTI_TAMPER: process.env.ENABLE_ANTI_TAMPER === 'true',
        ENABLE_HEARTBEAT: process.env.ENABLE_HEARTBEAT === 'true',
        MAX_FAILED_ATTEMPTS: parseInt(process.env.MAX_FAILED_ATTEMPTS) || 5
    },
    
    // Cache
    CACHE: {
        SCRIPT_TTL: parseInt(process.env.SCRIPT_CACHE_TTL) || 300
    },
    
    // Server URL (untuk heartbeat)
    getServerURL: function() {
        if (process.env.RENDER_EXTERNAL_URL) {
            return process.env.RENDER_EXTERNAL_URL;
        }
        return `http://localhost:${this.PORT}`;
    }
};

// Validation
if (config.NODE_ENV === 'production') {
    if (config.SECRET_KEY.includes('default') || config.SECRET_KEY.includes('change')) {
        console.warn('⚠️  WARNING: Using default SECRET_KEY in production!');
    }
    if (config.ADMIN_KEY.includes('default') || config.ADMIN_KEY.includes('change')) {
        console.warn('⚠️  WARNING: Using default ADMIN_KEY in production!');
    }
}

module.exports = config;
