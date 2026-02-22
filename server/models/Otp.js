const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    code: {
        type: String,
        required: true,
        minlength: 6,
        maxlength: 6
    },
    purpose: {
        type: String,
        enum: ['phone_verify', 'email_verify', 'password_reset', 'two_factor'],
        required: true
    },
    attempts: {
        type: Number,
        default: 0,
        max: 5 // Max verification attempts
    },
    expiresAt: {
        type: Date,
        required: true,
        default: () => new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    }
}, {
    timestamps: true
});

// TTL index: MongoDB automatically deletes expired documents
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
// Compound index for quick lookups
otpSchema.index({ userId: 1, purpose: 1 });

// Static: Generate and store a new OTP
otpSchema.statics.generate = async function (userId, purpose) {
    // Delete any existing OTP for this user + purpose
    await this.deleteMany({ userId, purpose });

    const code = Math.floor(100000 + Math.random() * 900000).toString();

    const otp = await this.create({
        userId,
        code,
        purpose,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    return otp;
};

// Static: Verify an OTP
otpSchema.statics.verify = async function (userId, purpose, code) {
    const otp = await this.findOne({ userId, purpose });

    if (!otp) {
        return { valid: false, error: 'OTP expired or not requested. Please request a new OTP.' };
    }

    if (otp.expiresAt < Date.now()) {
        await otp.deleteOne();
        return { valid: false, error: 'OTP expired. Please request a new OTP.' };
    }

    if (otp.attempts >= 5) {
        await otp.deleteOne();
        return { valid: false, error: 'Too many failed attempts. Please request a new OTP.' };
    }

    if (otp.code !== code) {
        otp.attempts += 1;
        await otp.save();
        return { valid: false, error: 'Invalid OTP' };
    }

    // OTP is valid — delete it
    await otp.deleteOne();
    return { valid: true };
};

module.exports = mongoose.model('Otp', otpSchema);
