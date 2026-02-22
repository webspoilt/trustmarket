const jwt = require('jsonwebtoken');
const User = require('../models/User');

const generateTokens = (userId, role = 'buyer') => {
  const accessToken = jwt.sign(
    { userId, role, type: 'access' },
    process.env.JWT_SECRET || 'trustmarket-secret-key',
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId, role, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET || 'trustmarket-refresh-secret-key',
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

const verifyToken = (token, secret) => {
  try {
    return jwt.verify(token, secret);
  } catch (error) {
    throw new Error('Invalid token');
  }
};

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    // Try cookie first, then Authorization header (for API clients)
    const token = req.cookies?.accessToken ||
      (authHeader && authHeader.split(' ')[1]);

    if (!token) {
      return res.status(401).json({
        error: 'Access token required',
        code: 'TOKEN_MISSING'
      });
    }

    const decoded = verifyToken(
      token,
      process.env.JWT_SECRET || 'trustmarket-secret-key'
    );

    if (decoded.type !== 'access') {
      return res.status(401).json({
        error: 'Invalid token type',
        code: 'INVALID_TOKEN_TYPE'
      });
    }

    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive || user.isBanned) {
      return res.status(401).json({
        error: 'User not found or inactive',
        code: 'USER_INACTIVE'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({
      error: 'Invalid or expired token',
      code: 'TOKEN_INVALID'
    });
  }
};

const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = verifyToken(
        token,
        process.env.JWT_SECRET || 'trustmarket-secret-key'
      );

      if (decoded.type === 'access') {
        const user = await User.findById(decoded.userId);
        if (user && user.isActive && !user.isBanned) {
          req.user = user;
        }
      }
    }

    next();
  } catch (error) {
    // Silently continue without authentication
    next();
  }
};

const adminOnly = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }

  if (!req.user.isAdmin) {
    return res.status(403).json({
      error: 'Admin access required',
      code: 'ADMIN_REQUIRED'
    });
  }

  next();
};

/**
 * Role-based access control middleware.
 * Usage: requireRole('admin'), requireRole('seller', 'admin')
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Required role: ${roles.join(' or ')}`,
        code: 'INSUFFICIENT_ROLE'
      });
    }

    next();
  };
};

const refreshAccessToken = async (req, res, next) => {
  try {
    // Try cookie first, then request body
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        error: 'Refresh token required',
        code: 'REFRESH_TOKEN_MISSING'
      });
    }

    const decoded = verifyToken(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || 'trustmarket-refresh-secret-key'
    );

    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        error: 'Invalid token type',
        code: 'INVALID_TOKEN_TYPE'
      });
    }

    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive || user.isBanned) {
      return res.status(401).json({
        error: 'User not found or inactive',
        code: 'USER_INACTIVE'
      });
    }

    // Check if refresh token exists in user's tokens
    const tokenExists = user.refreshTokens.some(rt => rt.token === refreshToken);
    if (!tokenExists) {
      return res.status(401).json({
        error: 'Refresh token not found or invalid',
        code: 'REFRESH_TOKEN_INVALID'
      });
    }

    req.user = user;
    req.refreshToken = refreshToken;
    next();
  } catch (error) {
    console.error('Refresh token verification error:', error);
    return res.status(401).json({
      error: 'Invalid or expired refresh token',
      code: 'REFRESH_TOKEN_INVALID'
    });
  }
};

module.exports = {
  generateTokens,
  verifyToken,
  authenticateToken,
  optionalAuth,
  adminOnly,
  requireRole,
  refreshAccessToken
};