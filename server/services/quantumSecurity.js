const crypto = require('crypto');
const argon2 = require('argon2');

class QuantumSecurityService {
    constructor() {
        // Argon2id config — memory-hard, resistant to GPU/ASIC attacks
        this.hashOptions = {
            type: argon2.argon2id,
            memoryCost: 65536, // 64 MB
            timeCost: 3,       // 3 iterations
            parallelism: 4,    // 4 threads
            hashLength: 32
        };
    }

    /**
     * SHANNON ENTROPY ANALYSIS
     * Calculates the bits of entropy in a password string.
     * Higher entropy = stronger password.
     * H = -Σ p(x) * log2(p(x))
     */
    calculateEntropy(password) {
        if (!password || password.length === 0) return 0;

        const len = password.length;
        const freq = {};

        for (const char of password) {
            freq[char] = (freq[char] || 0) + 1;
        }

        let entropy = 0;
        for (const key in freq) {
            const p = freq[key] / len;
            entropy -= p * Math.log2(p);
        }

        // Normalize to 0-100 scale
        return Math.min(100, Math.floor((entropy / 4) * 10));
    }

    /**
     * PASSWORD STRENGTH GRADING
     * Combines entropy + pattern analysis for a comprehensive score.
     */
    gradePassword(password) {
        const entropy = this.calculateEntropy(password);
        let bonus = 0;

        // Bonus for character class diversity
        if (/[a-z]/.test(password)) bonus += 5;
        if (/[A-Z]/.test(password)) bonus += 5;
        if (/[0-9]/.test(password)) bonus += 5;
        if (/[^a-zA-Z0-9]/.test(password)) bonus += 10;
        if (password.length >= 12) bonus += 10;
        if (password.length >= 16) bonus += 10;

        const score = Math.min(100, entropy + bonus);

        let grade;
        if (score >= 80) grade = 'excellent';
        else if (score >= 60) grade = 'strong';
        else if (score >= 40) grade = 'moderate';
        else if (score >= 20) grade = 'weak';
        else grade = 'critical';

        return { score, grade, entropy };
    }

    /**
     * SECURE HASHING (Argon2id)
     * Resistant to side-channel attacks and GPU cracking.
     */
    async hashPassword(password) {
        try {
            return await argon2.hash(password, this.hashOptions);
        } catch (err) {
            console.error('Hashing failed:', err);
            throw new Error('Security processing failed');
        }
    }

    async verifyPassword(hash, password) {
        try {
            return await argon2.verify(hash, password);
        } catch (err) {
            return false;
        }
    }

    /**
     * QUANTUM-RESISTANT TOKEN GENERATION
     * Uses CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
     */
    generateQuantumToken(bytes = 32) {
        return crypto.randomBytes(bytes).toString('hex');
    }

    /**
     * BEHAVIORAL BIOMETRICS — Anomaly Detection
     * Compares current user behavior vector against historical baseline.
     * Uses Euclidean Distance: sqrt(Σ (xi - yi)^2)
     */
    analyzeBehavioralPattern(currentVector, historicalVector) {
        if (!historicalVector || historicalVector.length === 0) {
            return { anomaly: false, score: 0 };
        }

        let sumSquares = 0;
        const len = Math.min(currentVector.length, historicalVector.length);

        for (let i = 0; i < len; i++) {
            sumSquares += Math.pow(currentVector[i] - historicalVector[i], 2);
        }

        const distance = Math.sqrt(sumSquares);

        // Z-score concept — flag if distance exceeds threshold
        const threshold = 50.0;

        return {
            anomaly: distance > threshold,
            score: Math.round(distance * 100) / 100
        };
    }
}

module.exports = new QuantumSecurityService();
