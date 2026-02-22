const logger = require('../config/logger');

/**
 * NATIVE APP SECURITY MIDDLEWARE
 * Strict Content-Security-Policy headers for mobile WebView protection.
 * Prevents XSS, data exfiltration, and script injection in native containers.
 */
module.exports = (req, res, next) => {
    const apiUrl = process.env.FRONTEND_URL || 'https://api.trustmarket.com';
    const googleApis = 'https://accounts.google.com https://*.googleapis.com';

    res.setHeader(
        'Content-Security-Policy',
        [
            "default-src 'self' data: blob:",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://accounts.google.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: https: blob:",
            "font-src 'self' https://fonts.gstatic.com",
            `connect-src 'self' ${apiUrl} ${googleApis} wss:`,
            "frame-src 'self' https://accounts.google.com",
            "object-src 'none'",
            "base-uri 'self'"
        ].join('; ')
    );

    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');

    // Prevent MIME sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    next();
};
