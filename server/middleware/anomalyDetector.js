const riskEngine = require('../services/quantumSecurity');
const logger = require('../config/logger');

// Sliding window request store (use Redis in production)
const requestStore = new Map();

// Clean up stale entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of requestStore.entries()) {
        const fresh = timestamps.filter(t => t > now - 60000);
        if (fresh.length === 0) requestStore.delete(ip);
        else requestStore.set(ip, fresh);
    }
}, 5 * 60 * 1000);

/**
 * ANOMALY DETECTION MIDDLEWARE
 * Uses standard deviation & request rate analysis to detect bot-like behavior.
 * Integrates behavioral biometric vectors from the frontend.
 */
module.exports = (req, res, next) => {
    // Bypass for health checks
    if (req.path === '/api/health') return next();

    const ip = req.ip;
    const now = Date.now();
    const windowMs = 60000; // 1 minute sliding window

    // Initialize or get window
    if (!requestStore.has(ip)) {
        requestStore.set(ip, []);
    }

    const timestamps = requestStore.get(ip);

    // Remove timestamps outside the window
    while (timestamps.length > 0 && timestamps[0] <= now - windowMs) {
        timestamps.shift();
    }

    // Record this request
    timestamps.push(now);
    const requestRate = timestamps.length;

    // Physics constraint: humans can't sustain > 100 complex API calls/min
    if (requestRate > 100) {
        logger.warn(`[ANOMALY] DDoS pattern detected from ${ip} — ${requestRate} req/min`);
        return res.status(429).json({
            success: false,
            error: 'Rate limit exceeded (Anomaly Detected)'
        });
    }

    // Behavioral analysis from frontend header
    const behaviorHeader = req.headers['x-behavior-vector'];
    if (behaviorHeader) {
        try {
            const vector = JSON.parse(behaviorHeader);
            const historical = req.session?.behavioralProfile || [];
            const analysis = riskEngine.analyzeBehavioralPattern(vector, historical);

            if (analysis.anomaly) {
                logger.warn(`[ANOMALY] Behavioral anomaly for ${ip}: score ${analysis.score}`);
                req.suspicious = true; // Flag for downstream middleware (e.g., trigger CAPTCHA)
            }
        } catch (e) {
            // Malformed header — ignore silently
        }
    }

    next();
};
