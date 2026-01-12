const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { generateTokens, authenticateToken, refreshAccessToken } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   POST /api/auth/register
// @desc    Register new user
// @access  Public
router.post('/register', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character (@$!%*?&)'),
  body('phone').custom((value) => {
    // Accept: 9876543210, +919876543210, 919876543210
    if (!/^(\+91|91)?[6-9]\d{9}$/.test(value)) {
      throw new Error('Valid Indian phone number is required');
    }
    return true;
  }),
  body('firstName').trim().isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters'),
  body('lastName').trim().isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { email, password, phone, firstName, lastName } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({
    $or: [{ email }, { phone }]
  });

  if (existingUser) {
    return res.status(400).json({
      success: false,
      error: existingUser.email === email ? 'Email already registered' : 'Phone number already registered'
    });
  }

  // Create new user with refresh token
  const user = new User({
    email,
    password,
    phone,
    firstName,
    lastName,
    trustScore: {
      total: 0,
      level: 'newbie',
      factors: {
        accountAge: 0,
        successfulDeals: 0,
        responseTime: 0,
        communityHelp: 0,
        verification: 0,
        reports: 0,
        transactionVolume: 0
      }
    }
  });

  // Generate tokens before saving
  const tokens = generateTokens(user._id);
  user.refreshTokens.push({ token: tokens.refreshToken });

  await user.save();

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user: user.toJSON(),
      tokens
    }
  });
}));

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', [
  body('email').optional().isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('phone').optional().custom((value) => {
    if (value && !/^(\+91|91)?[6-9]\d{9}$/.test(value)) {
      throw new Error('Valid Indian phone number is required');
    }
    return true;
  }),
  body('password').notEmpty().withMessage('Password is required'),
  body().custom((value, { req }) => {
    if (!req.body.email && !req.body.phone) {
      throw new Error('Either email or phone number is required');
    }
    return true;
  })
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { email, phone, password } = req.body;

  // Find user by email or phone
  const query = email ? { email } : { phone };
  const user = await User.findOne(query);

  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'Invalid credentials'
    });
  }

  // Check if user is banned
  if (user.isBanned) {
    return res.status(403).json({
      success: false,
      error: 'Account is banned',
      banReason: user.banReason
    });
  }

  // Check password
  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    // Increment login attempts
    user.loginAttempts += 1;

    // Lock account after 5 failed attempts
    if (user.loginAttempts >= 5) {
      user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
    }

    await user.save();

    return res.status(401).json({
      success: false,
      error: 'Invalid credentials'
    });
  }

  // Reset login attempts on successful login and generate tokens
  user.loginAttempts = 0;
  user.lockUntil = null;
  user.lastLogin = new Date();

  // Generate tokens and store refresh token
  const tokens = generateTokens(user._id);
  user.refreshTokens.push({ token: tokens.refreshToken });

  await user.save();

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: user.toJSON(),
      tokens
    }
  });
}));

// @route   POST /api/auth/refresh
// @desc    Refresh access token
// @access  Public
router.post('/refresh', refreshAccessToken, asyncHandler(async (req, res) => {
  const { accessToken, refreshToken } = generateTokens(req.user._id);

  // Remove old refresh token
  req.user.refreshTokens = req.user.refreshTokens.filter(
    rt => rt.token !== req.refreshToken
  );

  // Add new refresh token
  req.user.refreshTokens.push({ token: refreshToken });
  await req.user.save();

  res.json({
    success: true,
    message: 'Token refreshed successfully',
    data: {
      accessToken,
      refreshToken
    }
  });
}));

// @route   POST /api/auth/logout
// @desc    Logout user
// @access  Private
router.post('/logout', authenticateToken, asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    // Remove specific refresh token
    req.user.refreshTokens = req.user.refreshTokens.filter(
      rt => rt.token !== refreshToken
    );
    await req.user.save();
  } else {
    // Remove all refresh tokens (logout from all devices)
    req.user.refreshTokens = [];
    await req.user.save();
  }

  res.json({
    success: true,
    message: 'Logged out successfully'
  });
}));

// @route   POST /api/auth/logout-all
// @desc    Logout from all devices
// @access  Private
router.post('/logout-all', authenticateToken, asyncHandler(async (req, res) => {
  req.user.refreshTokens = [];
  await req.user.save();

  res.json({
    success: true,
    message: 'Logged out from all devices successfully'
  });
}));

// @route   GET /api/auth/me
// @desc    Get current user
// @access  Private
router.get('/me', authenticateToken, asyncHandler(async (req, res) => {
  res.json({
    success: true,
    data: {
      user: req.user.toJSON()
    }
  });
}));

// In-memory OTP storage (use Redis or database in production)
// Structure: { email: { otp: '123456', expiresAt: Date } }
const otpStore = new Map();

// Generate a 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Clean expired OTPs
const cleanExpiredOTPs = () => {
  const now = Date.now();
  for (const [key, value] of otpStore.entries()) {
    if (value.expiresAt < now) {
      otpStore.delete(key);
    }
  }
};

// Run cleanup every 10 minutes
setInterval(cleanExpiredOTPs, 10 * 60 * 1000);

// @route   POST /api/auth/verify-phone
// @desc    Verify phone number
// @access  Private
router.post('/verify-phone', [
  body('otp').isLength({ min: 6, max: 6 }).withMessage('Valid OTP is required')
], authenticateToken, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { otp } = req.body;

  // Get stored OTP for this user
  const storedData = otpStore.get(`phone_${req.user._id}`);

  if (!storedData) {
    return res.status(400).json({
      success: false,
      error: 'OTP expired or not requested. Please request a new OTP.'
    });
  }

  // Check if OTP is expired
  if (storedData.expiresAt < Date.now()) {
    otpStore.delete(`phone_${req.user._id}`);
    return res.status(400).json({
      success: false,
      error: 'OTP expired. Please request a new OTP.'
    });
  }

  // Verify OTP
  if (otp !== storedData.otp) {
    return res.status(400).json({
      success: false,
      error: 'Invalid OTP'
    });
  }

  // Clear OTP after successful verification
  otpStore.delete(`phone_${req.user._id}`);

  // Update user's phone verification status
  req.user.verification.phone = {
    verified: true,
    date: new Date(),
    number: req.user.phone
  };

  // Add verification points to trust score
  req.user.trustScore.factors.verification += 5;
  await req.user.save();

  res.json({
    success: true,
    message: 'Phone verified successfully',
    data: {
      user: req.user.toJSON()
    }
  });
}));

// @route   POST /api/auth/resend-otp
// @desc    Resend phone verification OTP
// @access  Private
router.post('/resend-otp', authenticateToken, asyncHandler(async (req, res) => {
  // Generate new OTP
  const newOTP = generateOTP();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes expiration

  // Store OTP (in production, use Redis or database with proper indexing)
  otpStore.set(`phone_${req.user._id}`, {
    otp: newOTP,
    expiresAt
  });

  // In a real implementation, you would send OTP via SMS service
  // For demo purposes, we'll just return success with OTP (remove in production)

  res.json({
    success: true,
    message: 'OTP sent successfully',
    // Only for development/testing - remove in production
    ...(process.env.NODE_ENV === 'development' && { demoOtp: newOTP, expiresAt })
  });
}));

// @route   POST /api/auth/forgot-password
// @desc    Request password reset
// @access  Public
router.post('/forgot-password', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    // Don't reveal whether email exists or not
    return res.json({
      success: true,
      message: 'If the email exists, a password reset link has been sent'
    });
  }

  // Generate password reset token
  const crypto = require('crypto');
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetExpires = Date.now() + 60 * 60 * 1000; // 1 hour expiration

  // Store reset token and expiration in user document
  user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  user.resetPasswordExpires = resetExpires;
  await user.save();

  // In production, you would send email with reset link containing the token
  // For demo purposes, we'll return the hashed token for verification

  res.json({
    success: true,
    message: 'If the email exists, a password reset link has been sent',
    ...(process.env.NODE_ENV === 'development' && {
      resetToken,
      resetExpires,
      hashedToken: user.resetPasswordToken
    })
  });
}));

// @route   POST /api/auth/reset-password
// @desc    Reset password with token
// @access  Public
router.post('/reset-password', [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character (@$!%*?&)')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { token, password } = req.body;

  // Hash the token and find user
  const crypto = require('crypto');
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) {
    return res.status(400).json({
      success: false,
      error: 'Invalid or expired reset token'
    });
  }

  // Update password and clear reset tokens
  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  user.refreshTokens = []; // Invalidate all sessions

  await user.save();

  res.json({
    success: true,
    message: 'Password reset successfully. Please login with your new password.'
  });
}));

module.exports = router;
