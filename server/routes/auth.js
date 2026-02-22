const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const { generateTokens, authenticateToken, refreshAccessToken } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// Stricter rate limiter for auth endpoints (5 requests per 15 minutes)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    error: 'Too many authentication attempts. Please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Helper: set HttpOnly cookies for access and refresh tokens
const setTokenCookies = (res, tokens) => {
  const isProduction = process.env.NODE_ENV === 'production';

  res.cookie('accessToken', tokens.accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 15 * 60 * 1000, // 15 minutes
    path: '/'
  });

  res.cookie('refreshToken', tokens.refreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/api/auth' // Only sent to auth endpoints
  });
};

// Helper: clear auth cookies
const clearTokenCookies = (res) => {
  res.clearCookie('accessToken', { path: '/' });
  res.clearCookie('refreshToken', { path: '/api/auth' });
};

// @route   POST /api/auth/register
// @desc    Register new user
// @access  Public
router.post('/register', authLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  body('phone').isMobilePhone('en-IN').withMessage('Valid Indian phone number is required'),
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
    role: 'buyer', // Default role
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
  const tokens = generateTokens(user._id, user.role);
  user.refreshTokens.push({ token: tokens.refreshToken });

  await user.save();

  // Set HttpOnly cookies
  setTokenCookies(res, tokens);

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user: user.toJSON()
    }
  });
}));

// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', authLimiter, [
  body('email').optional().isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('phone').optional().isMobilePhone('en-IN').withMessage('Valid Indian phone number is required'),
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
  const tokens = generateTokens(user._id, user.role);
  user.refreshTokens.push({ token: tokens.refreshToken });

  await user.save();

  // Set HttpOnly cookies
  setTokenCookies(res, tokens);

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      user: user.toJSON()
    }
  });
}));

// @route   POST /api/auth/refresh
// @desc    Refresh access token
// @access  Public
router.post('/refresh', refreshAccessToken, asyncHandler(async (req, res) => {
  const { accessToken, refreshToken } = generateTokens(req.user._id, req.user.role);

  // Remove old refresh token
  req.user.refreshTokens = req.user.refreshTokens.filter(
    rt => rt.token !== req.refreshToken
  );

  // Add new refresh token
  req.user.refreshTokens.push({ token: refreshToken });
  await req.user.save();

  // Set new HttpOnly cookies
  setTokenCookies(res, { accessToken, refreshToken });

  res.json({
    success: true,
    message: 'Token refreshed successfully'
  });
}));

// @route   POST /api/auth/logout
// @desc    Logout user
// @access  Private
router.post('/logout', authenticateToken, asyncHandler(async (req, res) => {
  const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

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

  // Clear cookies
  clearTokenCookies(res);

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

  // Clear cookies
  clearTokenCookies(res);

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

// OTP is now stored in MongoDB via the Otp model (persistent, auto-expiring via TTL)
const Otp = require('../models/Otp');

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

  // Verify OTP using the persistent model
  const result = await Otp.verify(req.user._id, 'phone_verify', otp);

  if (!result.valid) {
    return res.status(400).json({
      success: false,
      error: result.error
    });
  }

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
  // Generate and store OTP persistently
  const otpDoc = await Otp.generate(req.user._id, 'phone_verify');

  // In a real implementation, send OTP via SMS service here
  // For demo purposes, return OTP in development mode only

  res.json({
    success: true,
    message: 'OTP sent successfully',
    // Only for development/testing - remove in production
    ...(process.env.NODE_ENV === 'development' && { demoOtp: otpDoc.code, expiresAt: otpDoc.expiresAt })
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
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number')
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

// ─── Google OAuth ────────────────────────────────────────────
const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// @route   POST /api/auth/google
// @desc    Sign in or sign up with Google
// @access  Public
router.post('/google', asyncHandler(async (req, res) => {
  const { credential } = req.body;

  if (!credential) {
    return res.status(400).json({
      success: false,
      error: 'Google credential token is required'
    });
  }

  // Verify the Google ID token
  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    payload = ticket.getPayload();
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Invalid Google credential'
    });
  }

  const { email, given_name, family_name, picture, email_verified } = payload;

  // Find existing user or create a new one
  let user = await User.findOne({ email });
  let isNewUser = false;

  if (!user) {
    isNewUser = true;
    user = new User({
      email,
      password: require('crypto').randomBytes(32).toString('hex'), // Random password (they'll use Google to login)
      firstName: given_name || 'User',
      lastName: family_name || '',
      phone: '', // Will be asked to add later
      role: 'buyer',
      profilePhoto: picture || '',
      verification: {
        email: {
          verified: email_verified || false,
          date: email_verified ? new Date() : null
        }
      },
      authProvider: 'google',
      googleId: payload.sub,
      trustScore: {
        total: 5, // Small bonus for Google-verified email
        level: 'newbie',
        factors: {
          verification: email_verified ? 5 : 0
        }
      }
    });
  } else {
    // Update Google info if they previously registered with email/password
    if (!user.googleId) {
      user.googleId = payload.sub;
    }
    if (!user.profilePhoto && picture) {
      user.profilePhoto = picture;
    }
  }

  user.lastLogin = new Date();

  // Generate tokens
  const tokens = generateTokens(user._id, user.role);
  user.refreshTokens.push({ token: tokens.refreshToken });

  await user.save();

  // Set HttpOnly cookies
  setTokenCookies(res, tokens);

  res.json({
    success: true,
    message: isNewUser ? 'Account created with Google' : 'Logged in with Google',
    data: {
      user: user.toJSON(),
      isNewUser
    }
  });
}));

// ─── Mobile OTP Login ────────────────────────────────────────

// @route   POST /api/auth/otp/send
// @desc    Send OTP to phone number for login
// @access  Public
router.post('/otp/send', authLimiter, [
  body('phone').matches(/^[6-9]\d{9}$/).withMessage('Valid 10-digit Indian mobile number required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { phone } = req.body;

  // Find or prepare user — we don't reveal if the user exists
  let user = await User.findOne({ phone });

  if (!user) {
    // Auto-create a new user for OTP login (they can fill in details later)
    user = new User({
      phone,
      email: `${phone}@otp.trustmarket.local`, // Placeholder, user will update
      password: require('crypto').randomBytes(32).toString('hex'),
      firstName: 'User',
      lastName: phone.slice(-4), // Last 4 digits as placeholder
      role: 'buyer',
      authProvider: 'phone',
      trustScore: { total: 0, level: 'newbie' }
    });
    await user.save();
  }

  // Generate OTP
  const otpDoc = await Otp.generate(user._id, 'phone_verify');

  // In production, send SMS via Twilio/MSG91 here
  // For now, return OTP in dev mode

  res.json({
    success: true,
    message: 'OTP sent to your phone number',
    ...(process.env.NODE_ENV === 'development' && { demoOtp: otpDoc.code })
  });
}));

// @route   POST /api/auth/otp/verify
// @desc    Verify OTP and log in
// @access  Public
router.post('/otp/verify', authLimiter, [
  body('phone').matches(/^[6-9]\d{9}$/).withMessage('Valid phone number required'),
  body('otp').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Valid 6-digit OTP required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { phone, otp } = req.body;

  const user = await User.findOne({ phone });
  if (!user) {
    return res.status(400).json({
      success: false,
      error: 'Invalid phone number or OTP'
    });
  }

  // Verify OTP
  const result = await Otp.verify(user._id, 'phone_verify', otp);
  if (!result.valid) {
    return res.status(400).json({
      success: false,
      error: result.error
    });
  }

  // Mark phone as verified
  if (!user.verification.phone.verified) {
    user.verification.phone = {
      verified: true,
      date: new Date(),
      number: phone
    };
    user.trustScore.factors.verification += 5;
  }

  user.lastLogin = new Date();

  // Generate tokens
  const tokens = generateTokens(user._id, user.role);
  user.refreshTokens.push({ token: tokens.refreshToken });

  await user.save();

  // Set HttpOnly cookies
  setTokenCookies(res, tokens);

  res.json({
    success: true,
    message: 'Logged in successfully',
    data: {
      user: user.toJSON()
    }
  });
}));

module.exports = router;