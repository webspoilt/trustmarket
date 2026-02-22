
# TrustMarket - Complete Source Code
---
# BACKEND

## server/index.js

```javascript
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();
const logger = require('./config/logger');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const listingRoutes = require('./routes/listings');
const messageRoutes = require('./routes/messages');
const adminRoutes = require('./routes/admin');
const orderRoutes = require('./routes/orders');
const { errorHandler } = require('./middleware/errorHandler');
const { setupSocket } = require('./services/socketService');
const { connectDB } = require('./config/database');
const { serveUploadMiddleware } = require('./config/cloudinary');

const app = express();
const server = createServer(app);

const io = new Server(server, {
  cors: {
    origin: [
      process.env.FRONTEND_URL || "http://localhost:3000",
      process.env.CLIENT_URL || "http://localhost:3000"
    ].filter(Boolean),
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100 // limit each IP to 100 requests per windowMs
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https:"],
      fontSrc: ["'self'", "https:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'", "https:"],
      frameSrc: ["'none'"]
    }
  }
}));

// CORS configuration
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || "http://localhost:3000",
    process.env.CLIENT_URL || "http://localhost:3000"
  ].filter(Boolean),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-requested-with']
}));

// Compression and logging
app.use(compression());
app.use(morgan('combined', { stream: logger.stream }));

// Body parsing middleware
app.use(express.json({ limit: process.env.MAX_FILE_SIZE || '10mb' }));
app.use(express.urlencoded({ extended: true, limit: process.env.MAX_FILE_SIZE || '10mb' }));

// Cookie parser
app.use(cookieParser());

// Rate limiting
app.use(limiter);

// Serve uploaded files (for local storage fallback)
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Serve placeholder images
app.use('/api/placeholder', (req, res) => {
  const { width = 320, height = 240 } = req.params;
  res.json({
    url: `https://via.placeholder.com/${width}x${height}?text=TrustMarket`,
    width: parseInt(width),
    height: parseInt(height)
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/listings', listingRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/orders', orderRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    path: req.originalUrl
  });
});

// Error handling middleware (must be last)
app.use(errorHandler);

// Socket.io setup
setupSocket(io);

// Connect to database and start server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    logger.info('ðŸ”§ Starting TrustMarket Server...');
    logger.info('ðŸ”— Connecting to database...');

    await connectDB();
    logger.info('âœ… Database connected successfully');

    server.listen(PORT, () => {
      logger.info('ðŸš€ TrustMarket Server Started Successfully!');
      logger.info(`ðŸŒ Server running on port ${PORT}`);
      logger.info(`ðŸ“± Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info('ðŸ“¡ Socket.io enabled for real-time features');
      logger.info(`ðŸ”— Frontend URL: ${process.env.FRONTEND_URL || process.env.CLIENT_URL || 'http://localhost:3000'}`);

      if (process.env.NODE_ENV === 'development') {
        logger.info('ðŸ§ª Development mode: Local file uploads enabled');
        logger.info(`ðŸ“ Uploads served at: http://localhost:${PORT}/uploads`);
      }
    });
  } catch (error) {
    logger.error('âŒ Failed to start server:', error);
    logger.info('ðŸ’¡ TROUBLESHOOTING:');
    logger.info('1. Check if MongoDB is running (local) or Atlas cluster is active');
    logger.info('2. Verify your .env file configuration');
    logger.info('3. Ensure all dependencies are installed');
    logger.info('4. Check if port 5000 is available');
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('ðŸ›‘ SIGTERM received, shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      logger.info('ðŸ“´ Server closed successfully');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  logger.info('ðŸ›‘ SIGINT received, shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      logger.info('ðŸ“´ Server closed successfully');
      process.exit(0);
    });
  });
});

startServer();

module.exports = { app, io };
``````
---

## server/package.json

```json
{"name":"trustmarket-server","version":"1.0.0","description":"TrustMarket Backend API - India's Safest P2P Marketplace","main":"index.js","scripts":{"start":"node index.js","dev":"nodemon index.js","test":"jest","lint":"eslint .","test-setup":"node test-setup.js","setup":"npm install && npm run test-setup"},"dependencies":{"bcryptjs":"^2.4.3","cloudinary":"^1.41.3","compression":"^1.7.4","cookie-parser":"^1.4.6","cors":"^2.8.5","dotenv":"^16.3.1","express":"^4.18.2","express-rate-limit":"^7.1.5","express-validator":"^7.0.1","google-auth-library":"^10.5.0","helmet":"^7.1.0","jsonwebtoken":"^9.0.2","mongoose":"^8.0.3","morgan":"^1.10.0","multer":"^1.4.5-lts.1","node-cron":"^3.0.3","socket.io":"^4.7.4","uuid":"^9.0.1","winston":"^3.19.0"},"devDependencies":{"eslint":"^8.56.0","jest":"^29.7.0","nodemon":"^3.0.2","supertest":"^6.3.3"},"keywords":["p2p-marketplace","video-verification","trust-scoring","safety-monitoring","indian-marketplace"],"author":"zeroday","license":"MIT"}
``````
---

## server/config/database.js

```javascript
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/trustmarket';
    
    console.log('ðŸ”Œ Connecting to MongoDB...');
    
    const conn = await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      family: 4, // Use IPv4, skip trying IPv6
      retryWrites: true,
      w: 'majority'
    });

    console.log(`ðŸ“Š MongoDB Connected: ${conn.connection.host}`);
    console.log(`ðŸ“Š Database Name: ${conn.connection.name}`);

    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('âŒ MongoDB connection error:', err);
      console.log('ðŸ’¡ If using MongoDB Atlas, check your connection string and network access');
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('âš ï¸ MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('ðŸ”„ MongoDB reconnected');
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        console.log('ðŸ”Œ MongoDB connection closed through app termination');
        process.exit(0);
      } catch (error) {
        console.error('âŒ Error closing MongoDB connection:', error);
        process.exit(1);
      }
    });

  } catch (error) {
    console.error('âŒ Database connection failed:', error);
    console.log('\nðŸ’¡ TROUBLESHOOTING TIPS:');
    console.log('1. Check your MONGODB_URI in .env file');
    console.log('2. For MongoDB Atlas: Ensure your IP is whitelisted');
    console.log('3. For local MongoDB: Make sure MongoDB is running');
    console.log('4. Check network connectivity');
    console.log('5. Verify your MongoDB Atlas cluster is active\n');
    
    process.exit(1);
  }
};

module.exports = { connectDB };
``````
---

## server/config/cloudinary.js

```javascript
const cloudinary = require('cloudinary').v2;
const fs = require('fs');
const path = require('path');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'demo',
  api_key: process.env.CLOUDINARY_API_KEY || 'demo',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'demo'
});

const uploadFile = async (filePath, options = {}) => {
  try {
    // Check if we're using real Cloudinary credentials
    const isRealCloudinary = process.env.CLOUDINARY_CLOUD_NAME !== 'demo' && 
                           process.env.CLOUDINARY_CLOUD_NAME && 
                           process.env.CLOUDINARY_API_KEY !== 'demo';

    if (isRealCloudinary) {
      // Use Cloudinary for real file upload
      const defaultOptions = {
        resource_type: 'auto',
        quality: 'auto:good',
        fetch_format: 'auto',
        folder: 'trustmarket',
        ...options
      };

      const result = await cloudinary.uploader.upload(filePath, defaultOptions);
      
      return {
        public_id: result.public_id,
        url: result.secure_url,
        width: result.width,
        height: result.height,
        format: result.format,
        resource_type: result.resource_type,
        duration: result.duration || null,
        bytes: result.bytes
      };
    } else {
      // Use local storage fallback for demo
      console.log('ðŸ–¼ï¸ Using local storage fallback (not Cloudinary)');
      
      const fileName = path.basename(filePath);
      const timestamp = Date.now();
      const newFileName = `${timestamp}-${fileName}`;
      const uploadsDir = path.join(__dirname, '../uploads');
      const newFilePath = path.join(uploadsDir, newFileName);
      
      // Create uploads directory if it doesn't exist
      if (!fs.existsSync(uploadsDir)) {
        fs.mkdirSync(uploadsDir, { recursive: true });
      }
      
      // Copy file to uploads directory
      fs.copyFileSync(filePath, newFilePath);
      
      // Get file stats
      const stats = fs.statSync(newFilePath);
      
      return {
        public_id: newFileName,
        url: `/uploads/${newFileName}`,
        width: null,
        height: null,
        format: path.extname(fileName).substring(1),
        resource_type: 'image',
        duration: null,
        bytes: stats.size
      };
    }
  } catch (error) {
    console.error('âŒ Cloudinary upload error:', error);
    throw new Error('File upload failed');
  }
};

const deleteFile = async (publicId) => {
  try {
    // Check if we're using real Cloudinary credentials
    const isRealCloudinary = process.env.CLOUDINARY_CLOUD_NAME !== 'demo' && 
                           process.env.CLOUDINARY_CLOUD_NAME && 
                           process.env.CLOUDINARY_API_KEY !== 'demo';

    if (isRealCloudinary) {
      await cloudinary.uploader.destroy(publicId);
      return { success: true };
    } else {
      // Delete from local storage
      const uploadsDir = path.join(__dirname, '../uploads');
      const filePath = path.join(uploadsDir, publicId);
      
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return { success: true };
      }
      return { success: false, message: 'File not found' };
    }
  } catch (error) {
    console.error('âŒ Cloudinary delete error:', error);
    throw new Error('File deletion failed');
  }
};

const generateVideoThumbnail = async (videoUrl) => {
  try {
    // Check if we're using real Cloudinary credentials
    const isRealCloudinary = process.env.CLOUDINARY_CLOUD_NAME !== 'demo' && 
                           process.env.CLOUDINARY_CLOUD_NAME && 
                           process.env.CLOUDINARY_API_KEY !== 'demo';

    if (isRealCloudinary && videoUrl.includes('cloudinary.com')) {
      const thumbnailUrl = cloudinary.url(videoUrl, {
        resource_type: 'video',
        start_offset: '0',
        format: 'jpg',
        transformation: [
          { width: 320, height: 240, crop: 'fill' },
          { quality: 'auto:good' }
        ]
      });
      
      return thumbnailUrl;
    } else {
      // Return a placeholder thumbnail for demo/local
      return '/api/placeholder/320/240';
    }
  } catch (error) {
    console.error('âŒ Thumbnail generation error:', error);
    return '/api/placeholder/320/240';
  }
};

// Middleware to serve uploaded files
const serveUploadMiddleware = (req, res) => {
  const uploadsDir = path.join(__dirname, '../uploads');
  res.sendFile(path.join(uploadsDir, req.params.filename));
};

module.exports = {
  cloudinary,
  uploadFile,
  deleteFile,
  generateVideoThumbnail,
  serveUploadMiddleware
};
``````
---

## server/config/logger.js

```javascript
const winston = require('winston');

const { combine, timestamp, errors, json, colorize, printf } = winston.format;

// Custom dev format: colorized + readable
const devFormat = combine(
    colorize(),
    timestamp({ format: 'HH:mm:ss' }),
    errors({ stack: true }),
    printf(({ level, message, timestamp, stack, ...meta }) => {
        let log = `${timestamp} ${level}: ${message}`;
        if (stack) log += `\n${stack}`;
        if (Object.keys(meta).length > 0) {
            log += ` ${JSON.stringify(meta)}`;
        }
        return log;
    })
);

// Production format: structured JSON
const prodFormat = combine(
    timestamp(),
    errors({ stack: true }),
    json()
);

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    format: process.env.NODE_ENV === 'production' ? prodFormat : devFormat,
    defaultMeta: { service: 'trustmarket-api' },
    transports: [
        new winston.transports.Console()
    ]
});

// Add file transports in production
if (process.env.NODE_ENV === 'production') {
    logger.add(new winston.transports.File({
        filename: 'logs/error.log',
        level: 'error',
        maxsize: 5 * 1024 * 1024, // 5MB
        maxFiles: 5
    }));

    logger.add(new winston.transports.File({
        filename: 'logs/combined.log',
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5
    }));
}

// Morgan stream for HTTP request logging
logger.stream = {
    write: (message) => {
        logger.http(message.trim());
    }
};

module.exports = logger;
``````
---

## server/middleware/auth.js

```javascript
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
``````
---

## server/middleware/errorHandler.js

```javascript
const logger = require('../config/logger');

const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log error
  logger.error('Request error', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = { message, statusCode: 404 };
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const message = 'Duplicate field value entered';
    error = { message, statusCode: 400 };
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message).join(', ');
    error = { message, statusCode: 400 };
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token';
    error = { message, statusCode: 401 };
  }

  if (err.name === 'TokenExpiredError') {
    const message = 'Token expired';
    error = { message, statusCode: 401 };
  }

  // Multer errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    const message = 'File too large';
    error = { message, statusCode: 400 };
  }

  if (err.code === 'LIMIT_FILE_COUNT') {
    const message = 'Too many files';
    error = { message, statusCode: 400 };
  }

  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    const message = 'Unexpected file field';
    error = { message, statusCode: 400 };
  }

  // Rate limiting errors
  if (err.status === 429) {
    const message = 'Too many requests, please try again later';
    error = { message, statusCode: 429 };
  }

  res.status(error.statusCode || 500).json({
    success: false,
    error: error.message || 'Server Error',
    ...(process.env.NODE_ENV === 'development' && {
      stack: err.stack,
      details: err
    }),
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method
  });
};

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const notFound = (req, res, next) => {
  const error = new Error(`Not found - ${req.originalUrl}`);
  res.status(404);
  next(error);
};

module.exports = {
  errorHandler,
  asyncHandler,
  notFound
};
``````
---

## server/middleware/upload.js

```javascript
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { uploadFile, generateVideoThumbnail } = require('../config/cloudinary');

// Ensure upload directories exist
const ensureDirectories = () => {
  const dirs = ['uploads/videos', 'uploads/images'];
  dirs.forEach(dir => {
    const fullPath = path.join(__dirname, '..', dir);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
    }
  });
};

// Initialize directories on module load
ensureDirectories();

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'video') {
      cb(null, 'uploads/videos/');
    } else {
      cb(null, 'uploads/images/');
    }
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  // Define allowed file types
  const allowedImageTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  const allowedVideoTypes = ['video/mp4', 'video/avi', 'video/mov', 'video/quicktime'];

  if (file.fieldname === 'video') {
    if (allowedVideoTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid video format. Only MP4, AVI, and MOV files are allowed.'), false);
    }
  } else {
    if (allowedImageTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid image format. Only JPEG, PNG, and WebP files are allowed.'), false);
    }
  }
};

// Configure multer
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 3 * 1024 * 1024, // 3MB max (videos are larger, images will be well under this)
    files: 10 // Maximum 10 files
  }
});

// Middleware for single video upload
const uploadVideo = upload.single('video');

// Middleware for multiple image uploads
const uploadImages = upload.array('images', 10);

// Middleware for mixed upload (video + images)
const uploadMedia = upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'images', maxCount: 10 }
]);

// Process uploaded files and upload to Cloudinary
const processUploads = async (req, res, next) => {
  try {
    if (!req.files) {
      return next();
    }

    const uploadPromises = [];

    // Process video if uploaded
    if (req.files.video) {
      const videoFile = req.files.video[0];

      // Validate video duration (basic check)
      if (videoFile.size === 0) {
        return res.status(400).json({
          success: false,
          error: 'Video file is empty'
        });
      }

      try {
        // Upload to Cloudinary
        const result = await uploadFile(videoFile.path, {
          resource_type: 'video',
          quality: 'auto:good',
          format: 'mp4',
          transformation: [
            { width: 1280, height: 720, crop: 'limit' }
          ]
        });

        // Generate thumbnail
        const thumbnailUrl = await generateVideoThumbnail(result.url);

        uploadPromises.push(Promise.resolve({
          type: 'video',
          url: result.url,
          thumbnail: thumbnailUrl,
          duration: result.duration,
          size: result.bytes,
          quality: result.quality || 'medium'
        }));
      } catch (error) {
        console.error('Video upload error:', error);
        throw new Error('Failed to upload video. Please try again.');
      }
    }

    // Process images if uploaded
    if (req.files.images) {
      const imagePromises = req.files.images.map(async (imageFile, index) => {
        const result = await uploadFile(imageFile.path, {
          resource_type: 'image',
          quality: 'auto:good',
          format: 'auto',
          transformation: [
            { width: 800, height: 600, crop: 'limit' }
          ]
        });

        return {
          url: result.url,
          alt: `Image ${index + 1}`,
          order: index
        };
      });

      uploadPromises.push(...imagePromises);
    }

    // Wait for all uploads to complete
    const results = await Promise.all(uploadPromises);

    // Organize results
    if (req.files.video && req.files.images) {
      // Both video and images
      const videoResult = results.find(r => r.type === 'video');
      const imageResults = results.filter(r => !r.type);

      req.uploadedMedia = {
        video: videoResult,
        images: imageResults
      };
    } else if (req.files.video) {
      // Only video
      req.uploadedMedia = {
        video: results[0],
        images: []
      };
    } else if (req.files.images) {
      // Only images
      req.uploadedMedia = {
        video: null,
        images: results
      };
    }

    next();
  } catch (error) {
    console.error('Upload processing error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process uploads',
      details: error.message
    });
  }
};

// Error handling for multer
const handleUploadError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large',
        maxSize: req.files?.video ? '3MB for videos, 1MB for images' : '1MB for images'
      });
    }

    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        error: 'Too many files uploaded',
        maxFiles: 10
      });
    }

    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        error: 'Unexpected file field'
      });
    }
  }

  if (error.message.includes('Invalid') || error.message.includes('only')) {
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }

  next(error);
};

module.exports = {
  upload,
  uploadVideo,
  uploadImages,
  uploadMedia,
  processUploads,
  handleUploadError
};
``````
---

## server/middleware/validation.js

```javascript
/**
 * Custom Validation Middleware
 * Additional validation schemas and helpers beyond express-validator
 */

const { body, query, param, validationResult } = require('express-validator');

/**
 * Validate request and return errors if any
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.path,
        message: err.msg,
        value: err.value
      }))
    });
  }
  next();
};

/**
 * User validation rules
 */
const userValidation = {
  register: [
    body('email')
      .isEmail()
      .withMessage('Please provide a valid email address')
      .normalizeEmail()
      .custom((value) => {
        // Check for disposable emails
        const disposableDomains = [
          'tempmail.com', 'throwawaymail.com', 'fakeinbox.com',
          'guerrillamail.com', 'maildrop.cc', 'yopmail.com'
        ];
        const domain = value.split('@')[1]?.toLowerCase();
        if (disposableDomains.includes(domain)) {
          throw new Error('Disposable email addresses are not allowed');
        }
        return true;
      }),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
    body('phone')
      .matches(/^[6-9]\d{9}$/)
      .withMessage('Please provide a valid Indian phone number (10 digits starting with 6-9)'),
    body('firstName')
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('First name must be between 2 and 50 characters')
      .matches(/^[a-zA-Z\s]+$/)
      .withMessage('First name can only contain letters and spaces'),
    body('lastName')
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('Last name must be between 2 and 50 characters')
      .matches(/^[a-zA-Z\s]+$/)
      .withMessage('Last name can only contain letters and spaces'),
    validate
  ],

  login: [
    body('email')
      .optional()
      .isEmail()
      .withMessage('Please provide a valid email address')
      .normalizeEmail(),
    body('phone')
      .optional()
      .matches(/^[6-9]\d{9}$/)
      .withMessage('Please provide a valid Indian phone number'),
    body('password')
      .notEmpty()
      .withMessage('Password is required'),
    body()
      .custom((value, { req }) => {
        if (!req.body.email && !req.body.phone) {
          throw new Error('Either email or phone number is required');
        }
        return true;
      }),
    validate
  ],

  updateProfile: [
    body('firstName')
      .optional()
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('First name must be between 2 and 50 characters')
      .matches(/^[a-zA-Z\s]+$/)
      .withMessage('First name can only contain letters and spaces'),
    body('lastName')
      .optional()
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('Last name must be between 2 and 50 characters')
      .matches(/^[a-zA-Z\s]+$/)
      .withMessage('Last name can only contain letters and spaces'),
    body('bio')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('Bio must be less than 500 characters'),
    body('location.city')
      .optional()
      .trim()
      .isLength({ min: 2, max: 100 })
      .withMessage('City name must be between 2 and 100 characters'),
    validate
  ]
};

/**
 * Listing validation rules
 */
const listingValidation = {
  create: [
    body('title')
      .trim()
      .isLength({ min: 10, max: 100 })
      .withMessage('Title must be between 10 and 100 characters')
      .matches(/^[a-zA-Z0-9\s\-_,.]+$/)
      .withMessage('Title can only contain letters, numbers, spaces, and basic punctuation'),
    body('description')
      .trim()
      .isLength({ min: 20, max: 2000 })
      .withMessage('Description must be between 20 and 2000 characters'),
    body('price')
      .isFloat({ min: 0 })
      .withMessage('Price must be a positive number')
      .custom((value) => {
        if (value > 100000000) {
          throw new Error('Price cannot exceed 10 crore');
        }
        return true;
      }),
    body('category')
      .isIn([
        'electronics', 'vehicles', 'furniture', 'books', 'clothing',
        'services', 'jobs', 'real_estate', 'other'
      ])
      .withMessage('Please select a valid category'),
    body('condition')
      .isIn(['new', 'like_new', 'good', 'fair', 'poor'])
      .withMessage('Please select a valid condition'),
    body('listingType.sellerType')
      .isIn(['owner', 'broker', 'agent', 'dealer'])
      .withMessage('Please select a valid seller type'),
    body('location.address')
      .trim()
      .isLength({ min: 10, max: 500 })
      .withMessage('Address must be between 10 and 500 characters'),
    body('location.city')
      .trim()
      .isLength({ min: 2, max: 100 })
      .withMessage('City must be between 2 and 100 characters'),
    body('location.state')
      .trim()
      .isLength({ min: 2, max: 100 })
      .withMessage('State must be between 2 and 100 characters'),
    body('location.pincode')
      .matches(/^\d{6}$/)
      .withMessage('Please enter a valid 6-digit pincode'),
    body('location.coordinates.latitude')
      .isFloat({ min: -90, max: 90 })
      .withMessage('Please enter valid latitude coordinates'),
    body('location.coordinates.longitude')
      .isFloat({ min: -180, max: 180 })
      .withMessage('Please enter valid longitude coordinates'),
    body('tags')
      .optional()
      .isArray({ max: 10 })
      .withMessage('Maximum 10 tags allowed'),
    body('tags.*')
      .optional()
      .isString()
      .isLength({ max: 30 })
      .withMessage('Each tag must be less than 30 characters'),
    validate
  ],

  update: [
    param('id')
      .isMongoId()
      .withMessage('Invalid listing ID'),
    body('title')
      .optional()
      .trim()
      .isLength({ min: 10, max: 100 })
      .withMessage('Title must be between 10 and 100 characters'),
    body('description')
      .optional()
      .trim()
      .isLength({ min: 20, max: 2000 })
      .withMessage('Description must be between 20 and 2000 characters'),
    body('price')
      .optional()
      .isFloat({ min: 0 })
      .withMessage('Price must be a positive number'),
    body('category')
      .optional()
      .isIn([
        'electronics', 'vehicles', 'furniture', 'books', 'clothing',
        'services', 'jobs', 'real_estate', 'other'
      ])
      .withMessage('Please select a valid category'),
    body('condition')
      .optional()
      .isIn(['new', 'like_new', 'good', 'fair', 'poor'])
      .withMessage('Please select a valid condition'),
    validate
  ],

  search: [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    query('minPrice')
      .optional()
      .isFloat({ min: 0 })
      .withMessage('Minimum price must be a positive number'),
    query('maxPrice')
      .optional()
      .isFloat({ min: 0 })
      .withMessage('Maximum price must be a positive number')
      .custom((value, { req }) => {
        if (req.query.minPrice && value < parseFloat(req.query.minPrice)) {
          throw new Error('Maximum price must be greater than minimum price');
        }
        return true;
      }),
    query('minTrustScore')
      .optional()
      .isInt({ min: 0, max: 100 })
      .withMessage('Trust score must be between 0 and 100'),
    validate
  ]
};

/**
 * Message validation rules
 */
const messageValidation = {
  send: [
    body('recipientId')
      .isMongoId()
      .withMessage('Invalid recipient ID'),
    body('content')
      .trim()
      .isLength({ min: 1, max: 2000 })
      .withMessage('Message must be between 1 and 2000 characters')
      .custom((value) => {
        // Check for potential scam patterns
        const scamPatterns = [
          /send me your (phone|email|whatsapp)/i,
          /upi:?\s*[a-zA-Z0-9@.]+/i,
          /bank account/i,
          /gift card/i,
          /western union/i,
          /never see the item/i
        ];
        
        if (scamPatterns.some(pattern => pattern.test(value))) {
          throw new Error('Message contains potentially unsafe content. Please avoid sharing personal financial information.');
        }
        return true;
      }),
    body('listingId')
      .optional()
      .isMongoId()
      .withMessage('Invalid listing ID'),
    validate
  ],

  report: [
    param('id')
      .isMongoId()
      .withMessage('Invalid message ID'),
    body('reason')
      .isIn(['spam', 'harassment', 'scam', 'inappropriate', 'other'])
      .withMessage('Please select a valid report reason'),
    body('description')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('Description must be less than 500 characters'),
    validate
  ]
};

/**
 * ID verification validation rules
 */
const verificationValidation = {
  submitID: [
    body('idType')
      .isIn(['aadhaar', 'pan', 'passport', 'driving_license', 'voter_id'])
      .withMessage('Please select a valid ID type'),
    body('documentNumber')
      .trim()
      .notEmpty()
      .withMessage('Document number is required'),
    body('name')
      .trim()
      .isLength({ min: 2, max: 100 })
      .withMessage('Name must be between 2 and 100 characters'),
    body('dob')
      .isISO8601()
      .withMessage('Please provide a valid date of birth')
      .custom((value) => {
        const dob = new Date(value);
        const age = (Date.now() - dob.getTime()) / (365.25 * 24 * 60 * 60 * 1000);
        if (age < 18) {
          throw new Error('You must be at least 18 years old to verify ID');
        }
        return true;
      }),
    body('frontImage')
      .notEmpty()
      .withMessage('Front image of ID is required'),
    body('backImage')
      .optional()
      .notEmpty()
      .withMessage('Back image is required for this ID type'),
    validate
  ]
};

/**
 * Sanitization helpers
 */
const sanitizers = {
  // Sanitize HTML to prevent XSS
  sanitizeHtml: (value) => {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  },

  // Normalize phone number
  normalizePhone: (phone) => {
    return phone.replace(/\D/g, ''); // Remove all non-digits
  },

  // Normalize price (remove currency symbols, commas)
  normalizePrice: (price) => {
    return parseFloat(String(price).replace(/[^0-9.]/g, ''));
  }
};

module.exports = {
  validate,
  userValidation,
  listingValidation,
  messageValidation,
  verificationValidation,
  sanitizers
};
``````
---

## server/models/User.js

```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const trustScoreSchema = new mongoose.Schema({
  total: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  level: {
    type: String,
    enum: ['newbie', 'active', 'regular', 'resident', 'veteran', 'elite', 'trusted', 'verified'],
    default: 'newbie'
  },
  factors: {
    accountAge: {
      type: Number,
      default: 0 // Months active
    },
    successfulDeals: {
      type: Number,
      default: 0
    },
    responseTime: {
      type: Number,
      default: 0 // Average response time in hours
    },
    communityHelp: {
      type: Number,
      default: 0 // Number of helpful actions
    },
    verification: {
      type: Number,
      default: 0 // Verification points (5 for phone, 15 for ID)
    },
    reports: {
      type: Number,
      default: 0 // Negative impact for false reports
    },
    transactionVolume: {
      type: Number,
      default: 0 // Total transaction value
    }
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, { _id: false });

const verificationSchema = new mongoose.Schema({
  phone: {
    verified: {
      type: Boolean,
      default: false
    },
    date: {
      type: Date,
      default: null
    },
    number: {
      type: String,
      default: null
    }
  },
  email: {
    verified: {
      type: Boolean,
      default: false
    },
    date: {
      type: Date,
      default: null
    }
  },
  id: {
    verified: {
      type: Boolean,
      default: false
    },
    date: {
      type: Date,
      default: null
    },
    documentType: {
      type: String,
      enum: ['aadhaar', 'pan', 'license', 'passport', null],
      default: null
    },
    documentNumber: {
      type: String,
      default: null
    },
    adminNotes: {
      type: String,
      default: ''
    }
  },
  address: {
    verified: {
      type: Boolean,
      default: false
    },
    date: {
      type: Date,
      default: null
    },
    addressType: {
      type: String,
      enum: ['home', 'work', 'other', null],
      default: null
    }
  }
}, { _id: false });

const userSettingsSchema = new mongoose.Schema({
  notifications: {
    type: Boolean,
    default: true
  },
  location: {
    enabled: {
      type: Boolean,
      default: true
    },
    city: {
      type: String,
      default: ''
    },
    state: {
      type: String,
      default: ''
    },
    coordinates: {
      latitude: {
        type: Number,
        default: null
      },
      longitude: {
        type: Number,
        default: null
      }
    }
  },
  privacy: {
    showContactInfo: {
      type: Boolean,
      default: false
    },
    showOnlineStatus: {
      type: Boolean,
      default: true
    },
    showLocation: {
      type: Boolean,
      default: true
    }
  },
  language: {
    type: String,
    enum: ['en', 'hi'],
    default: 'en'
  }
}, { _id: false });

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  phone: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function (v) {
        return /^[6-9]\d{9}$/.test(v);
      },
      message: 'Please enter a valid Indian mobile number'
    }
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  profilePhoto: {
    type: String,
    default: null
  },
  trustScore: {
    type: trustScoreSchema,
    default: () => ({})
  },
  verification: {
    type: verificationSchema,
    default: () => ({
      phone: { verified: false, date: null, number: null },
      id: { verified: false, date: null, documentType: null, documentNumber: null, adminNotes: '' }
    })
  },
  settings: {
    type: userSettingsSchema,
    default: () => ({})
  },
  role: {
    type: String,
    enum: ['buyer', 'seller', 'admin'],
    default: 'buyer'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isBanned: {
    type: Boolean,
    default: false
  },
  banReason: {
    type: String,
    default: ''
  },
  authProvider: {
    type: String,
    enum: ['local', 'google', 'phone'],
    default: 'local'
  },
  googleId: {
    type: String,
    default: null,
    sparse: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  refreshTokens: [{
    token: String,
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 604800 // 7 days
    }
  }],
  // Password reset fields
  resetPasswordToken: {
    type: String,
    default: null
  },
  resetPasswordExpires: {
    type: Date,
    default: null
  },
  // Transaction and activity tracking fields
  completedTransactions: {
    type: Number,
    default: 0
  },
  totalTransactionVolume: {
    type: Number,
    default: 0
  },
  helpfulVotes: {
    type: Number,
    default: 0
  },
  averageResponseTime: {
    type: Number,
    default: 0 // in hours
  },
  reportsReceived: {
    type: Number,
    default: 0
  },
  preferences: {
    currency: {
      type: String,
      default: 'INR'
    },
    timezone: {
      type: String,
      default: 'Asia/Kolkata'
    }
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function (doc, ret) {
      delete ret.password;
      delete ret.refreshTokens;
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ 'trustScore.total': -1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ 'verification.phone.verified': 1 });
userSchema.index({ 'verification.id.verified': 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function () {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for backward compatibility with isAdmin checks
userSchema.virtual('isAdmin').get(function () {
  return this.role === 'admin';
});

// Virtual for account age in months
userSchema.virtual('accountAgeMonths').get(function () {
  const now = new Date();
  const created = new Date(this.createdAt);
  const diffTime = Math.abs(now - created);
  const diffMonths = Math.ceil(diffTime / (1000 * 60 * 60 * 24 * 30));
  return diffMonths;
});

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Calculate trust score before saving
userSchema.pre('save', function (next) {
  const factors = this.trustScore.factors;

  // Account age factor (max 10 points)
  const ageFactor = Math.min(this.accountAgeMonths * 0.5, 10);

  // Successful deals factor (max 15 points)
  const dealsFactor = Math.min(factors.successfulDeals * 2, 15);

  // Response time factor (max 10 points)
  const responseFactor = factors.responseTime === 0 ? 10 : Math.max(0, 10 - (factors.responseTime / 4));

  // Community help factor (max 10 points)
  const helpFactor = Math.min(factors.communityHelp * 1, 10);

  // Verification factor (max 20 points)
  const verificationFactor = factors.verification;

  // Transaction volume factor (max 15 points)
  const volumeFactor = Math.min(Math.log(factors.transactionVolume / 1000 + 1) * 5, 15);

  // Reports penalty (max -20 points)
  const reportsPenalty = Math.min(factors.reports * 2, 20);

  const totalScore = ageFactor + dealsFactor + responseFactor + helpFactor +
    verificationFactor + volumeFactor - reportsPenalty;

  this.trustScore.total = Math.max(0, Math.min(100, Math.round(totalScore)));

  // Determine trust level
  if (this.trustScore.total >= 80) {
    this.trustScore.level = 'elite';
  } else if (this.trustScore.total >= 60) {
    this.trustScore.level = 'veteran';
  } else if (this.trustScore.total >= 30) {
    this.trustScore.level = 'resident';
  } else {
    this.trustScore.level = 'newbie';
  }

  this.trustScore.lastUpdated = new Date();
  next();
});

// Instance methods
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.updateTrustScore = function (factor, value) {
  this.trustScore.factors[factor] = value;
  return this.save();
};

userSchema.methods.addTrustPoints = function (factor, points) {
  this.trustScore.factors[factor] = (this.trustScore.factors[factor] || 0) + points;
  return this.save();
};

// Static methods
userSchema.statics.findByTrustLevel = function (level) {
  return this.find({ 'trustScore.level': level });
};

userSchema.statics.findVerified = function () {
  return this.find({
    $or: [
      { 'verification.phone.verified': true },
      { 'verification.id.verified': true }
    ]
  });
};

module.exports = mongoose.model('User', userSchema);
``````
---

## server/models/Listing.js

```javascript
const mongoose = require('mongoose');

const videoSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true
  },
  thumbnail: {
    type: String,
    required: true
  },
  duration: {
    type: Number, // in seconds
    required: true,
    min: 10,
    max: 30
  },
  size: {
    type: Number, // in bytes
    required: true,
    max: 3145728 // 3MB max
  },
  quality: {
    type: String,
    enum: ['low', 'medium', 'high', 'ultra'],
    default: 'medium'
  },
  uploadDate: {
    type: Date,
    default: Date.now
  },
  verification: {
    score: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    issues: [{
      type: String,
      enum: ['low_quality', 'too_short', 'too_long', 'no_content', 'stock_photo', 'fake_video']
    }],
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending'
    }
  }
}, { _id: false });

const locationSchema = new mongoose.Schema({
  address: {
    type: String,
    required: true,
    maxlength: 500
  },
  city: {
    type: String,
    required: true,
    trim: true
  },
  state: {
    type: String,
    required: true,
    trim: true
  },
  pincode: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        return /^\d{6}$/.test(v);
      },
      message: 'Please enter a valid 6-digit pincode'
    }
  },
  coordinates: {
    latitude: {
      type: Number,
      required: true,
      min: -90,
      max: 90
    },
    longitude: {
      type: Number,
      required: true,
      min: -180,
      max: 180
    }
  },
  landmark: {
    type: String,
    maxlength: 200,
    default: ''
  },
  area: {
    type: String,
    maxlength: 100,
    default: ''
  }
}, { _id: false });

const brokerFeeSchema = new mongoose.Schema({
  isFeeDisclosed: {
    type: Boolean,
    default: false
  },
  feeStructure: {
    type: String,
    enum: ['percentage', 'fixed', 'both', null],
    default: null
  },
  percentage: {
    type: Number,
    min: 0,
    max: 100,
    default: null
  },
  fixedAmount: {
    type: Number,
    min: 0,
    default: null
  },
  description: {
    type: String,
    maxlength: 500,
    default: ''
  },
  brokerLicense: {
    number: {
      type: String,
      maxlength: 50,
      default: ''
    },
    state: {
      type: String,
      maxlength: 50,
      default: ''
    }
  },
  terms: [{
    type: String,
    maxlength: 200
  }]
}, { _id: false });

const customCategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    maxlength: 100,
    trim: true
  },
  description: {
    type: String,
    maxlength: 500,
    default: ''
  },
  approved: {
    type: Boolean,
    default: false
  },
  moderationResult: {
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending'
    },
    issues: [{
      type: String,
      enum: ['inappropriate_content', 'spam', 'too_specific', 'duplicate']
    }],
    adminNotes: {
      type: String,
      default: ''
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    },
    reviewedAt: {
      type: Date,
      default: null
    }
  }
}, { _id: false });

const listingTypeSchema = new mongoose.Schema({
  sellerType: {
    type: String,
    enum: ['owner', 'broker', 'agent', 'dealer'],
    required: true
  },
  brokerFee: {
    type: brokerFeeSchema,
    default: () => ({})
  }
}, { _id: false });

const listingSchema = new mongoose.Schema({
  seller: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
    index: 'text'
  },
  description: {
    type: String,
    required: true,
    trim: true,
    maxlength: 2000,
    index: 'text'
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  category: {
    type: String,
    required: true,
    enum: [
      'electronics', 'vehicles', 'furniture', 'books', 'clothing',
      'services', 'jobs', 'real_estate', 'other'
    ]
  },
  customCategory: {
    type: customCategorySchema,
    default: null
  },
  condition: {
    type: String,
    enum: ['new', 'like_new', 'good', 'fair', 'poor'],
    required: true
  },
  location: {
    type: locationSchema,
    required: true
  },
  media: {
    video: {
      type: videoSchema,
      required: true
    },
    images: [{
      url: {
        type: String,
        required: true
      },
      alt: {
        type: String,
        default: ''
      },
      order: {
        type: Number,
        default: 0
      }
    }]
  },
  listingType: {
    type: listingTypeSchema,
    required: true
  },
  trustScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  stock: {
    type: Number,
    default: 1,
    min: 0
  },
  status: {
    type: String,
    enum: ['active', 'sold', 'expired', 'flagged', 'banned'],
    default: 'active',
    index: true
  },
  views: {
    type: Number,
    default: 0
  },
  inquiries: {
    type: Number,
    default: 0
  },
  saves: {
    type: Number,
    default: 0
  },
  isFeatured: {
    type: Boolean,
    default: false
  },
  featuredUntil: {
    type: Date,
    default: null
  },
  expiryDate: {
    type: Date,
    default: function () {
      // Auto-expire after 30 days
      return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    }
  },
  tags: [{
    type: String,
    maxlength: 30,
    trim: true
  }],
  attributes: [{
    key: {
      type: String,
      required: true,
      maxlength: 50
    },
    value: {
      type: String,
      required: true,
      maxlength: 200
    }
  }],
  reports: [{
    reportedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    reason: {
      type: String,
      enum: ['spam', 'fake', 'inappropriate', 'duplicate', 'other'],
      required: true
    },
    description: {
      type: String,
      maxlength: 500,
      default: ''
    },
    status: {
      type: String,
      enum: ['pending', 'resolved', 'dismissed'],
      default: 'pending'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  analytics: {
    viewsByDate: [{
      date: {
        type: Date,
        required: true
      },
      count: {
        type: Number,
        default: 0
      }
    }],
    inquiriesByDate: [{
      date: {
        type: Date,
        required: true
      },
      count: {
        type: Number,
        default: 0
      }
    }]
  }
}, {
  timestamps: true,
  optimisticConcurrency: true, // Prevents concurrent modification conflicts (double-spending)
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance and search
listingSchema.index({ seller: 1 });
listingSchema.index({ status: 1, createdAt: -1 });
listingSchema.index({ category: 1, status: 1 });
listingSchema.index({ 'location.city': 1, 'location.state': 1 });
listingSchema.index({ price: 1 });
listingSchema.index({ 'trustScore': -1 });
listingSchema.index({ isFeatured: 1, featuredUntil: 1 });
listingSchema.index({ expiryDate: 1 });
listingSchema.index({ createdAt: -1 });
// Text search index
listingSchema.index({ title: 'text', description: 'text', tags: 'text' });
// Geospatial index for location-based search
// Note: 2dsphere index requires GeoJSON format {type: "Point", coordinates: [lng, lat]}\n// Current schema uses {latitude, longitude} which works with Haversine formula in calculateDistance()\n// listingSchema.index({ 'location.coordinates': '2dsphere' });

// Virtual for days since posting
listingSchema.virtual('daysSincePosted').get(function () {
  const now = new Date();
  const created = new Date(this.createdAt);
  const diffTime = Math.abs(now - created);
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return diffDays;
});

// Virtual for is expired
listingSchema.virtual('isExpired').get(function () {
  return new Date() > this.expiryDate;
});

// Virtual for distance (if coordinates provided)
listingSchema.virtual('distance').get(function () {
  return this._distance || null;
});

// Pre-save middleware to update status if expired
listingSchema.pre('save', function (next) {
  if (this.isExpired && this.status === 'active') {
    this.status = 'expired';
  }
  next();
});

// Static methods
listingSchema.statics.findActive = function () {
  return this.find({ status: 'active' }).sort({ createdAt: -1 });
};

listingSchema.statics.findByCategory = function (category) {
  return this.find({ category, status: 'active' }).sort({ trustScore: -1, createdAt: -1 });
};

listingSchema.statics.findByLocation = function (latitude, longitude, maxDistance = 50000) { // 50km default
  return this.find({
    status: 'active',
    'location.coordinates': {
      $near: {
        $geometry: {
          type: 'Point',
          coordinates: [longitude, latitude]
        },
        $maxDistance: maxDistance
      }
    }
  });
};

listingSchema.statics.search = function (query, filters = {}) {
  const searchQuery = {
    status: 'active',
    $text: { $search: query }
  };

  // Add filters
  if (filters.category) searchQuery.category = filters.category;
  if (filters.minPrice || filters.maxPrice) {
    searchQuery.price = {};
    if (filters.minPrice) searchQuery.price.$gte = filters.minPrice;
    if (filters.maxPrice) searchQuery.price.$lte = filters.maxPrice;
  }
  if (filters.condition) searchQuery.condition = filters.condition;
  if (filters.sellerType) searchQuery['listingType.sellerType'] = filters.sellerType;
  if (filters.minTrustScore) searchQuery.trustScore = { $gte: filters.minTrustScore };

  return this.find(searchQuery).sort({ score: { $meta: 'textScore' } });
};

// Instance methods
listingSchema.methods.incrementViews = function () {
  this.views += 1;

  // Update daily analytics
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const todayAnalytics = this.analytics.viewsByDate.find(
    item => item.date.getTime() === today.getTime()
  );

  if (todayAnalytics) {
    todayAnalytics.count += 1;
  } else {
    this.analytics.viewsByDate.push({ date: today, count: 1 });
  }

  return this.save();
};

listingSchema.methods.incrementInquiries = function () {
  this.inquiries += 1;

  // Update daily analytics
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const todayAnalytics = this.analytics.inquiriesByDate.find(
    item => item.date.getTime() === today.getTime()
  );

  if (todayAnalytics) {
    todayAnalytics.count += 1;
  } else {
    this.analytics.inquiriesByDate.push({ date: today, count: 1 });
  }

  return this.save();
};

listingSchema.methods.updateTrustScore = async function () {
  // Calculate trust score based on seller trust and listing quality
  const seller = await mongoose.model('User').findById(this.seller);
  if (!seller) return this;

  const sellerTrust = seller.trustScore.total;
  const viewToInquiryRatio = this.views > 0 ? (this.inquiries / this.views) * 100 : 0;

  // Base score from seller trust (70% weight)
  let trustScore = sellerTrust * 0.7;

  // Listing quality factors (30% weight)
  const hasVideo = this.media.video ? 20 : 0;
  const hasImages = Math.min(this.media.images.length * 5, 15); // Max 15 points for images
  const inquiryRate = Math.min(viewToInquiryRatio * 2, 15); // Max 15 points for high inquiry rate

  trustScore += (hasVideo + hasImages + inquiryRate) * 0.3;

  this.trustScore = Math.max(0, Math.min(100, Math.round(trustScore)));
  return this.save();
};

module.exports = mongoose.model('Listing', listingSchema);
``````
---

## server/models/Message.js

```javascript
const mongoose = require('mongoose');

const safetyScoreSchema = new mongoose.Schema({
  overall: {
    type: Number,
    default: 100,
    min: 0,
    max: 100
  },
  riskFactors: {
    suspiciousKeywords: {
      type: Number,
      default: 0
    },
    urgencyLanguage: {
      type: Number,
      default: 0
    },
    offPlatformRequests: {
      type: Number,
      default: 0
    },
    paymentRequests: {
      type: Number,
      default: 0
    },
    tooGoodToBeTrue: {
      type: Number,
      default: 0
    }
  },
  flags: [{
    type: String,
    enum: [
      'advance_payment_urgent',
      'qr_code_processing_fee',
      'guaranteed_profit_wfh',
      'contact_whatsapp',
      'wire_transfer_only',
      'cryptocurrency_request',
      'verification_fee',
      'registration_fee',
      'too_good_to_be_true',
      'generic_response'
    ]
  }],
  warnings: [{
    type: String,
    maxlength: 200
  }]
}, { _id: false });

const messageSchema = new mongoose.Schema({
  conversationId: {
    type: String,
    required: true,
    index: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  receiver: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  listing: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Listing',
    required: true
  },
  content: {
    type: String,
    required: true,
    trim: true,
    maxlength: 2000
  },
  media: [{
    type: {
      type: String,
      enum: ['image', 'video'],
      required: true
    },
    url: {
      type: String,
      required: true
    },
    filename: {
      type: String,
      required: true
    },
    size: {
      type: Number,
      required: true
    }
  }],
  safetyScore: {
    type: safetyScoreSchema,
    default: () => ({})
  },
  status: {
    type: String,
    enum: ['sent', 'delivered', 'read'],
    default: 'sent',
    index: true
  },
  isSystemMessage: {
    type: Boolean,
    default: false
  },
  systemMessageType: {
    type: String,
    enum: [
      'safety_warning',
      'listing_sold',
      'user_blocked',
      'listing_flagged',
      'verification_required'
    ],
    default: null
  },
  replyTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message',
    default: null
  },
  reactions: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    emoji: {
      type: String,
      required: true,
      maxlength: 4
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  reports: [{
    reportedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    reason: {
      type: String,
      enum: ['spam', 'harassment', 'inappropriate', 'scam', 'other'],
      required: true
    },
    description: {
      type: String,
      maxlength: 500,
      default: ''
    },
    status: {
      type: String,
      enum: ['pending', 'resolved', 'dismissed'],
      default: 'pending'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  editedAt: {
    type: Date,
    default: null
  },
  deletedAt: {
    type: Date,
    default: null
  },
  readAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
messageSchema.index({ conversationId: 1, createdAt: -1 });
messageSchema.index({ sender: 1, createdAt: -1 });
messageSchema.index({ receiver: 1, status: 1 });
messageSchema.index({ listing: 1, createdAt: -1 });
messageSchema.index({ 'safetyScore.overall': 1 });
messageSchema.index({ status: 1, createdAt: -1 });

// Virtual for is flagged
messageSchema.virtual('isFlagged').get(function() {
  return this.safetyScore.overall < 50 || this.safetyScore.flags.length > 0;
});

// Virtual for time since sent
messageSchema.virtual('timeSinceSent').get(function() {
  const now = new Date();
  const sent = new Date(this.createdAt);
  const diffMinutes = Math.floor((now - sent) / (1000 * 60));
  
  if (diffMinutes < 1) return 'Just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
});

// Pre-save middleware to calculate safety score
messageSchema.pre('save', function(next) {
  if (this.isNew && !this.isSystemMessage) {
    this.calculateSafetyScore();
  }
  next();
});

// Static methods
messageSchema.statics.findByConversation = function(conversationId, limit = 50, skip = 0) {
  return this.find({ 
    conversationId, 
    deletedAt: { $exists: false }
  })
  .populate('sender', 'firstName lastName profilePhoto trustScore.verification')
  .populate('listing', 'title price images')
  .sort({ createdAt: -1 })
  .limit(limit)
  .skip(skip);
};

messageSchema.statics.findUnread = function(userId) {
  return this.find({
    receiver: userId,
    status: 'sent',
    deletedAt: { $exists: false }
  }).sort({ createdAt: -1 });
};

messageSchema.statics.findSafetyAlerts = function(userId) {
  return this.find({
    $or: [
      { sender: userId },
      { receiver: userId }
    ],
    'safetyScore.overall': { $lt: 50 },
    deletedAt: { $exists: false }
  }).sort({ createdAt: -1 });
};

// Instance methods
messageSchema.methods.calculateSafetyScore = function() {
  const content = this.content.toLowerCase();
  const safetyScore = this.safetyScore;
  
  // Reset scores
  safetyScore.overall = 100;
  safetyScore.riskFactors = {
    suspiciousKeywords: 0,
    urgencyLanguage: 0,
    offPlatformRequests: 0,
    paymentRequests: 0,
    tooGoodToBeTrue: 0
  };
  safetyScore.flags = [];
  safetyScore.warnings = [];

  // Suspicious keyword patterns
  const suspiciousPatterns = [
    { pattern: /advance\s+payment/i, flag: 'advance_payment_urgent', points: 30 },
    { pattern: /urgent\s+(payment|deal|response)/i, flag: 'advance_payment_urgent', points: 25 },
    { pattern: /qr\s+code/i, flag: 'qr_code_processing_fee', points: 35 },
    { pattern: /processing\s+fee/i, flag: 'qr_code_processing_fee', points: 30 },
    { pattern: /guaranteed\s+profit/i, flag: 'guaranteed_profit_wfh', points: 40 },
    { pattern: /work\s+from\s+home/i, flag: 'guaranteed_profit_wfh', points: 25 },
    { pattern: /whatsapp/i, flag: 'contact_whatsapp', points: 20 },
    { pattern: /telegram/i, flag: 'contact_whatsapp', points: 25 },
    { pattern: /wire\s+transfer/i, flag: 'wire_transfer_only', points: 30 },
    { pattern: /bitcoin|crypto/i, flag: 'cryptocurrency_request', points: 40 },
    { pattern: /verification\s+fee/i, flag: 'verification_fee', points: 35 },
    { pattern: /registration\s+fee/i, flag: 'registration_fee', points: 30 },
    { pattern: /too\s+good\s+to\s+be\s+true/i, flag: 'too_good_to_be_true', points: 45 }
  ];

  suspiciousPatterns.forEach(({ pattern, flag, points }) => {
    if (pattern.test(content)) {
      safetyScore.flags.push(flag);
      safetyScore.overall -= points;
      
      if (flag.includes('advance') || flag.includes('urgent')) {
        safetyScore.riskFactors.suspiciousKeywords += points * 0.4;
        safetyScore.riskFactors.urgencyLanguage += points * 0.6;
      } else if (flag.includes('whatsapp') || flag.includes('telegram')) {
        safetyScore.riskFactors.offPlatformRequests += points;
      } else if (flag.includes('payment') || flag.includes('fee') || flag.includes('transfer')) {
        safetyScore.riskFactors.paymentRequests += points;
      } else if (flag.includes('guaranteed') || flag.includes('profit')) {
        safetyScore.riskFactors.tooGoodToBeTrue += points;
      }
    }
  });

  // Additional risk factors
  if (content.includes('100%') || content.includes('guarantee')) {
    safetyScore.riskFactors.tooGoodToBeTrue += 15;
    safetyScore.overall -= 15;
  }

  if (content.includes('asap') || content.includes('immediately') || content.includes('quick')) {
    safetyScore.riskFactors.urgencyLanguage += 10;
    safetyScore.overall -= 10;
  }

  // Cap the minimum score
  safetyScore.overall = Math.max(0, Math.min(100, safetyScore.overall));

  // Generate warnings based on flags
  if (safetyScore.flags.includes('advance_payment_urgent')) {
    safetyScore.warnings.push('Never send advance payments to unknown sellers');
  }
  if (safetyScore.flags.includes('qr_code_processing_fee')) {
    safetyScore.warnings.push('Never scan QR codes to receive money - this is a common scam');
  }
  if (safetyScore.flags.includes('guaranteed_profit_wfh')) {
    safetyScore.warnings.push('Be cautious of guaranteed profit schemes');
  }
  if (safetyScore.flags.includes('contact_whatsapp')) {
    safetyScore.warnings.push('Off-platform communication requests may indicate scams');
  }

  return this;
};

messageSchema.methods.markAsRead = function() {
  this.status = 'read';
  this.readAt = new Date();
  return this.save();
};

messageSchema.methods.addReaction = function(userId, emoji) {
  // Remove existing reaction from this user
  this.reactions = this.reactions.filter(r => !r.user.equals(userId));
  
  // Add new reaction
  this.reactions.push({
    user: userId,
    emoji: emoji,
    createdAt: new Date()
  });
  
  return this.save();
};

messageSchema.methods.flag = function(reporterId, reason, description = '') {
  this.reports.push({
    reportedBy: reporterId,
    reason: reason,
    description: description,
    status: 'pending',
    createdAt: new Date()
  });
  
  return this.save();
};

module.exports = mongoose.model('Message', messageSchema);
``````
---

## server/models/Order.js

```javascript
const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
    buyer: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    seller: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    listing: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Listing',
        required: true
    },
    quantity: {
        type: Number,
        required: true,
        min: 1,
        default: 1
    },
    unitPrice: {
        type: Number,
        required: true,
        min: 0
    },
    totalPrice: {
        type: Number,
        required: true,
        min: 0
    },
    status: {
        type: String,
        enum: ['pending', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded'],
        default: 'pending'
    },
    paymentInfo: {
        method: {
            type: String,
            enum: ['cod', 'upi', 'card', 'bank_transfer', null],
            default: null
        },
        transactionId: {
            type: String,
            default: null
        },
        paidAt: {
            type: Date,
            default: null
        }
    },
    shippingAddress: {
        address: { type: String, default: '' },
        city: { type: String, default: '' },
        state: { type: String, default: '' },
        pincode: { type: String, default: '' }
    },
    statusHistory: [{
        status: {
            type: String,
            enum: ['pending', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded'],
            required: true
        },
        changedAt: {
            type: Date,
            default: Date.now
        },
        changedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        note: {
            type: String,
            maxlength: 500,
            default: ''
        }
    }],
    cancellationReason: {
        type: String,
        maxlength: 500,
        default: null
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Indexes for performance
orderSchema.index({ buyer: 1, createdAt: -1 });
orderSchema.index({ seller: 1, createdAt: -1 });
orderSchema.index({ listing: 1 });
orderSchema.index({ status: 1, createdAt: -1 });

// Pre-save: push status to history on status change
orderSchema.pre('save', function (next) {
    if (this.isModified('status')) {
        this.statusHistory.push({
            status: this.status,
            changedAt: new Date()
        });
    }
    next();
});

// Instance methods
orderSchema.methods.cancel = async function (userId, reason = '') {
    if (['delivered', 'refunded'].includes(this.status)) {
        throw new Error('Cannot cancel a delivered or refunded order');
    }
    this.status = 'cancelled';
    this.cancellationReason = reason;
    this.statusHistory.push({
        status: 'cancelled',
        changedAt: new Date(),
        changedBy: userId,
        note: reason
    });

    // Restore listing stock
    const Listing = mongoose.model('Listing');
    await Listing.findByIdAndUpdate(this.listing, {
        $inc: { stock: this.quantity }
    });

    return this.save();
};

// Static methods
orderSchema.statics.findByBuyer = function (buyerId) {
    return this.find({ buyer: buyerId })
        .populate('listing', 'title price media.video.thumbnail')
        .populate('seller', 'firstName lastName trustScore')
        .sort({ createdAt: -1 });
};

orderSchema.statics.findBySeller = function (sellerId) {
    return this.find({ seller: sellerId })
        .populate('listing', 'title price media.video.thumbnail')
        .populate('buyer', 'firstName lastName trustScore')
        .sort({ createdAt: -1 });
};

module.exports = mongoose.model('Order', orderSchema);
``````
---

## server/models/Otp.js

```javascript
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

    // OTP is valid â€” delete it
    await otp.deleteOne();
    return { valid: true };
};

module.exports = mongoose.model('Otp', otpSchema);
``````
---

## server/routes/auth.js

```javascript
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

// â”€â”€â”€ Google OAuth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€â”€ Mobile OTP Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

  // Find or prepare user â€” we don't reveal if the user exists
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
``````
---

## server/routes/orders.js

```javascript
const express = require('express');
const mongoose = require('mongoose');
const { body, param, validationResult } = require('express-validator');
const Order = require('../models/Order');
const Listing = require('../models/Listing');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   POST /api/orders
// @desc    Place a new order (uses Mongoose transaction for atomicity)
// @access  Private (buyer)
router.post('/', authenticateToken, [
    body('listingId').isMongoId().withMessage('Valid listing ID is required'),
    body('quantity').optional().isInt({ min: 1, max: 100 }).withMessage('Quantity must be between 1 and 100'),
    body('shippingAddress.address').optional().trim().isLength({ min: 5, max: 500 }),
    body('shippingAddress.city').optional().trim().isLength({ min: 2, max: 100 }),
    body('shippingAddress.state').optional().trim().isLength({ min: 2, max: 100 }),
    body('shippingAddress.pincode').optional().matches(/^\d{6}$/).withMessage('Valid 6-digit pincode required')
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            error: 'Validation failed',
            details: errors.array()
        });
    }

    const { listingId, quantity = 1, shippingAddress } = req.body;

    // Start a Mongoose session for ACID transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        // 1. Find the listing within the transaction
        const listing = await Listing.findById(listingId).session(session);

        if (!listing) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, error: 'Listing not found' });
        }

        if (listing.status !== 'active') {
            await session.abortTransaction();
            return res.status(400).json({ success: false, error: 'Listing is no longer active' });
        }

        // Prevent buying your own listing
        if (listing.seller.toString() === req.user._id.toString()) {
            await session.abortTransaction();
            return res.status(400).json({ success: false, error: 'Cannot purchase your own listing' });
        }

        // 2. Check stock availability
        if (listing.stock < quantity) {
            await session.abortTransaction();
            return res.status(409).json({
                success: false,
                error: listing.stock === 0
                    ? 'This item is out of stock'
                    : `Only ${listing.stock} item(s) remaining`
            });
        }

        // 3. Decrement stock atomically
        listing.stock -= quantity;
        if (listing.stock === 0) {
            listing.status = 'sold';
        }
        await listing.save({ session });

        // 4. Create the order
        const order = new Order({
            buyer: req.user._id,
            seller: listing.seller,
            listing: listing._id,
            quantity,
            unitPrice: listing.price,
            totalPrice: listing.price * quantity,
            status: 'pending',
            shippingAddress: shippingAddress || {},
            statusHistory: [{ status: 'pending', changedAt: new Date(), changedBy: req.user._id }]
        });

        await order.save({ session });

        // 5. Commit the transaction â€” both stock decrement and order creation succeed together
        await session.commitTransaction();

        // Populate order data for response
        await order.populate('listing', 'title price media.video.thumbnail');
        await order.populate('seller', 'firstName lastName trustScore');

        res.status(201).json({
            success: true,
            message: 'Order placed successfully',
            data: { order: order.toJSON() }
        });
    } catch (error) {
        await session.abortTransaction();

        // Handle optimistic concurrency conflict (VersionError)
        if (error.name === 'VersionError') {
            return res.status(409).json({
                success: false,
                error: 'This item was just purchased by another buyer. Please try again.'
            });
        }

        throw error; // Re-throw for global error handler
    } finally {
        session.endSession();
    }
}));

// @route   GET /api/orders
// @desc    Get current user's orders (as buyer or seller)
// @access  Private
router.get('/', authenticateToken, asyncHandler(async (req, res) => {
    const { role = 'buyer', status, page = 1, limit = 20 } = req.query;

    const query = role === 'seller'
        ? { seller: req.user._id }
        : { buyer: req.user._id };

    if (status) query.status = status;

    const skip = (page - 1) * limit;

    const [orders, total] = await Promise.all([
        Order.find(query)
            .populate('listing', 'title price media.video.thumbnail category')
            .populate('buyer', 'firstName lastName trustScore')
            .populate('seller', 'firstName lastName trustScore')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit)),
        Order.countDocuments(query)
    ]);

    res.json({
        success: true,
        data: {
            orders: orders.map(o => o.toJSON()),
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(total / limit),
                totalItems: total,
                hasNext: skip + orders.length < total,
                hasPrev: page > 1
            }
        }
    });
}));

// @route   GET /api/orders/:id
// @desc    Get single order
// @access  Private (buyer or seller of the order)
router.get('/:id', authenticateToken, [
    param('id').isMongoId().withMessage('Invalid order ID')
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Validation failed', details: errors.array() });
    }

    const order = await Order.findById(req.params.id)
        .populate('listing', 'title price media category location')
        .populate('buyer', 'firstName lastName trustScore profilePhoto')
        .populate('seller', 'firstName lastName trustScore profilePhoto');

    if (!order) {
        return res.status(404).json({ success: false, error: 'Order not found' });
    }

    // Only buyer, seller, or admin can view
    const userId = req.user._id.toString();
    if (order.buyer._id.toString() !== userId &&
        order.seller._id.toString() !== userId &&
        req.user.role !== 'admin') {
        return res.status(403).json({ success: false, error: 'Not authorized to view this order' });
    }

    res.json({ success: true, data: { order: order.toJSON() } });
}));

// @route   PUT /api/orders/:id/status
// @desc    Update order status
// @access  Private (seller or admin)
router.put('/:id/status', authenticateToken, [
    param('id').isMongoId().withMessage('Invalid order ID'),
    body('status').isIn(['paid', 'shipped', 'delivered', 'cancelled', 'refunded']).withMessage('Invalid status'),
    body('note').optional().trim().isLength({ max: 500 })
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Validation failed', details: errors.array() });
    }

    const order = await Order.findById(req.params.id);
    if (!order) {
        return res.status(404).json({ success: false, error: 'Order not found' });
    }

    // Only seller, buyer (for cancel), or admin can update
    const userId = req.user._id.toString();
    const isSeller = order.seller.toString() === userId;
    const isBuyer = order.buyer.toString() === userId;
    const isAdmin = req.user.role === 'admin';

    if (!isSeller && !isBuyer && !isAdmin) {
        return res.status(403).json({ success: false, error: 'Not authorized' });
    }

    // Buyers can only cancel
    if (isBuyer && !isAdmin && req.body.status !== 'cancelled') {
        return res.status(403).json({ success: false, error: 'Buyers can only cancel orders' });
    }

    const { status, note = '' } = req.body;

    // Use the cancel method for cancellation (restores stock)
    if (status === 'cancelled') {
        await order.cancel(req.user._id, note || req.body.cancellationReason || '');
    } else {
        order.status = status;
        order.statusHistory.push({
            status,
            changedAt: new Date(),
            changedBy: req.user._id,
            note
        });

        if (status === 'paid' && req.body.transactionId) {
            order.paymentInfo.paidAt = new Date();
            order.paymentInfo.transactionId = req.body.transactionId;
        }

        await order.save();
    }

    await order.populate('listing', 'title price');
    await order.populate('buyer', 'firstName lastName');
    await order.populate('seller', 'firstName lastName');

    res.json({
        success: true,
        message: `Order status updated to ${status}`,
        data: { order: order.toJSON() }
    });
}));

module.exports = router;
``````
---

## server/routes/users.js

```javascript
const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Listing = require('../models/Listing');
const Message = require('../models/Message');
const { authenticateToken, optionalAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { uploadFile, deleteFile } = require('../config/cloudinary');

const router = express.Router();

// @route   GET /api/users/profile
// @desc    Get user profile
// @access  Private
router.get('/profile', authenticateToken, asyncHandler(async (req, res) => {
  res.json({
    success: true,
    data: {
      user: req.user.toJSON()
    }
  });
}));

// @route   PUT /api/users/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', [
  body('firstName').optional().trim().isLength({ min: 2, max: 50 }).withMessage('First name must be 2-50 characters'),
  body('lastName').optional().trim().isLength({ min: 2, max: 50 }).withMessage('Last name must be 2-50 characters'),
  body('settings.notifications').optional().isBoolean(),
  body('settings.location.enabled').optional().isBoolean(),
  body('settings.location.city').optional().trim().isLength({ max: 100 }),
  body('settings.location.state').optional().trim().isLength({ max: 100 }),
  body('settings.privacy.showContactInfo').optional().isBoolean(),
  body('settings.privacy.showOnlineStatus').optional().isBoolean(),
  body('settings.privacy.showLocation').optional().isBoolean(),
  body('settings.language').optional().isIn(['en', 'hi'])
], authenticateToken, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const updates = req.body;
  
  // Update allowed fields
  const allowedUpdates = [
    'firstName', 'lastName', 'settings'
  ];
  
  const updateData = {};
  allowedUpdates.forEach(field => {
    if (updates[field] !== undefined) {
      updateData[field] = updates[field];
    }
  });

  const user = await User.findByIdAndUpdate(
    req.user._id,
    updateData,
    { new: true, runValidators: true }
  );

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: {
      user: user.toJSON()
    }
  });
}));

// @route   POST /api/users/upload-photo
// @desc    Upload profile photo
// @access  Private
router.post('/upload-photo', authenticateToken, asyncHandler(async (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: 'No file uploaded'
    });
  }

  try {
    // Delete old photo if exists
    if (req.user.profilePhoto) {
      const publicId = req.user.profilePhoto.split('/').pop().split('.')[0];
      try {
        await deleteFile(publicId);
      } catch (error) {
        console.warn('Failed to delete old profile photo:', error);
      }
    }

    // Upload new photo
    const result = await uploadFile(req.file.path, {
      resource_type: 'image',
      quality: 'auto:good',
      format: 'auto',
      transformation: [
        { width: 200, height: 200, crop: 'fill', gravity: 'face' },
        { quality: 'auto:good' }
      ]
    });

    // Update user profile photo
    req.user.profilePhoto = result.url;
    await req.user.save();

    res.json({
      success: true,
      message: 'Profile photo uploaded successfully',
      data: {
        profilePhoto: result.url
      }
    });
  } catch (error) {
    console.error('Profile photo upload error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to upload profile photo'
    });
  }
}));

// @route   GET /api/users/:id
// @desc    Get user public profile
// @access  Public
router.get('/:id', optionalAuth, asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Prepare public profile data
  const publicProfile = {
    _id: user._id,
    firstName: user.firstName,
    lastName: user.lastName,
    profilePhoto: user.profilePhoto,
    trustScore: user.trustScore,
    verification: {
      phone: {
        verified: user.verification.phone.verified
      },
      id: {
        verified: user.verification.id.verified
      }
    },
    createdAt: user.createdAt,
    // Only show additional info if user allows it
    ...(req.user && (req.user._id.equals(user._id) || req.user.settings.privacy.showLocation) && {
      location: user.settings.location
    })
  };

  res.json({
    success: true,
    data: {
      user: publicProfile
    }
  });
}));

// @route   GET /api/users/:id/listings
// @desc    Get user's active listings
// @access  Public
router.get('/:id/listings', optionalAuth, asyncHandler(async (req, res) => {
  const { page = 1, limit = 20 } = req.query;
  const skip = (page - 1) * limit;

  const listings = await Listing.find({ 
    seller: req.params.id, 
    status: 'active' 
  })
  .sort({ createdAt: -1 })
  .skip(skip)
  .limit(parseInt(limit))
  .select('title price category condition media listingType trustScore createdAt views');

  const total = await Listing.countDocuments({
    seller: req.params.id,
    status: 'active'
  });

  res.json({
    success: true,
    data: {
      listings,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        hasNext: skip + listings.length < total,
        hasPrev: page > 1
      }
    }
  });
}));

// @route   GET /api/users/:id/stats
// @desc    Get user statistics
// @access  Public
router.get('/:id/stats', optionalAuth, asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Get user's listing statistics
  const listingStats = await Listing.aggregate([
    { $match: { seller: user._id } },
    {
      $group: {
        _id: null,
        totalListings: { $sum: 1 },
        activeListings: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        soldListings: {
          $sum: { $cond: [{ $eq: ['$status', 'sold'] }, 1, 0] }
        },
        totalViews: { $sum: '$views' },
        totalInquiries: { $sum: '$inquiries' },
        averageTrustScore: { $avg: '$trustScore' }
      }
    }
  ]);

  // Get message statistics
  const messageStats = await Message.aggregate([
    { $match: { sender: user._id } },
    {
      $group: {
        _id: null,
        totalMessages: { $sum: 1 },
        conversations: { $addToSet: '$conversationId' }
      }
    }
  ]);

  // Get verification stats
  const verificationStats = {
    phoneVerified: user.verification.phone.verified,
    idVerified: user.verification.id.verified,
    trustLevel: user.trustScore.level,
    trustScore: user.trustScore.total
  };

  const stats = {
    listings: listingStats[0] || {
      totalListings: 0,
      activeListings: 0,
      soldListings: 0,
      totalViews: 0,
      totalInquiries: 0,
      averageTrustScore: 0
    },
    messages: messageStats[0] || {
      totalMessages: 0,
      conversations: []
    },
    verification: verificationStats,
    accountAge: {
      months: user.accountAgeMonths,
      days: Math.floor((new Date() - new Date(user.createdAt)) / (1000 * 60 * 60 * 24))
    }
  };

  res.json({
    success: true,
    data: {
      stats
    }
  });
}));

// @route   POST /api/users/verify-id
// @desc    Submit ID verification documents
// @access  Private
router.post('/verify-id', [
  body('documentType').isIn(['aadhaar', 'pan', 'license', 'passport']).withMessage('Valid document type is required'),
  body('documentNumber').trim().isLength({ min: 4, max: 20 }).withMessage('Valid document number is required')
], authenticateToken, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { documentType, documentNumber } = req.body;

  // Check if user already has ID verification pending or approved
  if (req.user.verification.id.verified || req.user.verification.id.date) {
    return res.status(400).json({
      success: false,
      error: 'ID verification already submitted or approved'
    });
  }

  // Update verification request
  req.user.verification.id = {
    verified: false,
    date: new Date(),
    documentType,
    documentNumber,
    adminNotes: ''
  };

  await req.user.save();

  res.json({
    success: true,
    message: 'ID verification submitted successfully. You will be notified once reviewed.',
    data: {
      verification: req.user.verification.id
    }
  });
}));

// @route   GET /api/users/trust-score/history
// @desc    Get trust score history
// @access  Private
router.get('/trust-score/history', authenticateToken, asyncHandler(async (req, res) => {
  // In a real implementation, you would store trust score changes in a separate collection
  // For now, we'll return the current trust score with some mock history
  
  const history = [
    {
      date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
      score: Math.max(0, req.user.trustScore.total - 10),
      level: 'newbie'
    },
    {
      date: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days ago
      score: Math.max(0, req.user.trustScore.total - 5),
      level: 'newbie'
    },
    {
      date: new Date(),
      score: req.user.trustScore.total,
      level: req.user.trustScore.level
    }
  ];

  res.json({
    success: true,
    data: {
      currentScore: req.user.trustScore,
      history,
      factors: req.user.trustScore.factors
    }
  });
}));

// @route   POST /api/users/block
// @desc    Block a user
// @access  Private
router.post('/block/:userId', authenticateToken, asyncHandler(async (req, res) => {
  const { userId } = req.params;

  if (userId === req.user._id.toString()) {
    return res.status(400).json({
      success: false,
      error: 'Cannot block yourself'
    });
  }

  const userToBlock = await User.findById(userId);
  if (!userToBlock) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // In a real implementation, you would maintain a blocked users list
  // For now, we'll just return success

  res.json({
    success: true,
    message: 'User blocked successfully'
  });
}));

// @route   DELETE /api/users/block/:userId
// @desc    Unblock a user
// @access  Private
router.delete('/block/:userId', authenticateToken, asyncHandler(async (req, res) => {
  const { userId } = req.params;

  res.json({
    success: true,
    message: 'User unblocked successfully'
  });
}));

module.exports = router;
``````
---

## server/routes/listings.js

```javascript
const express = require('express');
const { body, validationResult } = require('express-validator');
const Listing = require('../models/Listing');
const User = require('../models/User');
const { authenticateToken, optionalAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { uploadVideo, uploadImages, uploadMedia, processUploads, handleUploadError } = require('../middleware/upload');

const router = express.Router();

// IMPORTANT: Static routes must be defined BEFORE dynamic routes like /:id
// Otherwise Express will treat 'categories' and 'search' as listing IDs

// @route   GET /api/listings/categories
// @desc    Get all categories
// @access  Public
router.get('/categories', asyncHandler(async (req, res) => {
  const categories = [
    { id: 'electronics', name: 'Electronics', icon: 'smartphone' },
    { id: 'vehicles', name: 'Vehicles', icon: 'car' },
    { id: 'furniture', name: 'Furniture', icon: 'chair' },
    { id: 'books', name: 'Books', icon: 'book' },
    { id: 'clothing', name: 'Clothing', icon: 'shirt' },
    { id: 'services', name: 'Services', icon: 'briefcase' },
    { id: 'jobs', name: 'Jobs', icon: 'user-tie' },
    { id: 'real_estate', name: 'Real Estate', icon: 'home' },
    { id: 'other', name: 'Other', icon: 'more-horizontal' }
  ];

  res.json({
    success: true,
    data: {
      categories
    }
  });
}));

// @route   GET /api/listings/search/suggestions
// @desc    Get search suggestions
// @access  Public
router.get('/search/suggestions', asyncHandler(async (req, res) => {
  const { q } = req.query;

  if (!q || q.length < 2) {
    return res.json({
      success: true,
      data: { suggestions: [] }
    });
  }

  // Get popular search terms and categories
  const suggestions = [
    'iPhone', 'Samsung', 'Laptop', 'Bike', 'Car', 'Furniture', 'Books', 'Clothing',
    'Electronics', 'Vehicles', 'Real Estate', 'Services', 'Jobs'
  ].filter(item => item.toLowerCase().includes(q.toLowerCase())).slice(0, 5);

  res.json({
    success: true,
    data: {
      suggestions
    }
  });
}));

// @route   GET /api/listings
// @desc    Get all listings with filtering and pagination
// @access  Public
router.get('/', optionalAuth, asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 20,
    category,
    minPrice,
    maxPrice,
    condition,
    sellerType,
    minTrustScore,
    city,
    state,
    sort = 'createdAt',
    order = 'desc',
    search
  } = req.query;

  const skip = (page - 1) * limit;
  const sortOrder = order === 'asc' ? 1 : -1;

  // Build query
  const query = { status: 'active' };
  
  if (category) query.category = category;
  if (condition) query.condition = condition;
  if (sellerType) query['listingType.sellerType'] = sellerType;
  if (minTrustScore) query.trustScore = { $gte: parseInt(minTrustScore) };
  if (city) query['location.city'] = new RegExp(city, 'i');
  if (state) query['location.state'] = new RegExp(state, 'i');

  // Price range filter
  if (minPrice || maxPrice) {
    query.price = {};
    if (minPrice) query.price.$gte = parseFloat(minPrice);
    if (maxPrice) query.price.$lte = parseFloat(maxPrice);
  }

  // Search functionality
  let listings;
  if (search) {
    listings = await Listing.search(search, {
      category,
      minPrice: minPrice ? parseFloat(minPrice) : undefined,
      maxPrice: maxPrice ? parseFloat(maxPrice) : undefined,
      condition,
      sellerType,
      minTrustScore: minTrustScore ? parseInt(minTrustScore) : undefined
    })
    .populate('seller', 'firstName lastName profilePhoto trustScore verification')
    .skip(skip)
    .limit(parseInt(limit));
  } else {
    listings = await Listing.find(query)
      .populate('seller', 'firstName lastName profilePhoto trustScore verification')
      .sort({ [sort]: sortOrder })
      .skip(skip)
      .limit(parseInt(limit));
  }

  const total = await Listing.countDocuments(query);

  // Add distance calculation if coordinates provided
  if (req.query.lat && req.query.lng) {
    const lat = parseFloat(req.query.lat);
    const lng = parseFloat(req.query.lng);
    
    listings = listings.map(listing => {
      if (listing.location.coordinates) {
        const distance = calculateDistance(
          lat, lng,
          listing.location.coordinates.latitude,
          listing.location.coordinates.longitude
        );
        listing._doc.distance = distance;
      }
      return listing;
    });

    // Sort by distance if requested
    if (sort === 'distance') {
      listings.sort((a, b) => (a.distance || Infinity) - (b.distance || Infinity));
    }
  }

  res.json({
    success: true,
    data: {
      listings: listings.map(listing => listing.toJSON()),
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        hasNext: skip + listings.length < total,
        hasPrev: page > 1
      }
    }
  });
}));

// @route   GET /api/listings/:id
// @desc    Get single listing
// @access  Public
router.get('/:id', optionalAuth, asyncHandler(async (req, res) => {
  const listing = await Listing.findById(req.params.id)
    .populate('seller', 'firstName lastName profilePhoto trustScore verification createdAt')
    .populate('reports.reportedBy', 'firstName lastName');

  if (!listing) {
    return res.status(404).json({
      success: false,
      error: 'Listing not found'
    });
  }

  // Increment view count
  await listing.incrementViews();

  res.json({
    success: true,
    data: {
      listing: listing.toJSON()
    }
  });
}));

// @route   POST /api/listings
// @desc    Create new listing
// @access  Private
router.post('/', 
  authenticateToken,
  uploadMedia,
  handleUploadError,
  processUploads,
  [
    body('title').trim().isLength({ min: 10, max: 100 }).withMessage('Title must be 10-100 characters'),
    body('description').trim().isLength({ min: 20, max: 2000 }).withMessage('Description must be 20-2000 characters'),
    body('price').isFloat({ min: 0 }).withMessage('Valid price is required'),
    body('category').isIn([
      'electronics', 'vehicles', 'furniture', 'books', 'clothing', 
      'services', 'jobs', 'real_estate', 'other'
    ]).withMessage('Valid category is required'),
    body('condition').isIn(['new', 'like_new', 'good', 'fair', 'poor']).withMessage('Valid condition is required'),
    body('listingType.sellerType').isIn(['owner', 'broker', 'agent', 'dealer']).withMessage('Valid seller type is required'),
    body('location.address').trim().isLength({ min: 10, max: 500 }).withMessage('Valid address is required'),
    body('location.city').trim().isLength({ min: 2, max: 100 }).withMessage('Valid city is required'),
    body('location.state').trim().isLength({ min: 2, max: 100 }).withMessage('Valid state is required'),
    body('location.pincode').isLength({ min: 6, max: 6 }).withMessage('Valid pincode is required'),
    body('location.coordinates.latitude').isFloat({ min: -90, max: 90 }).withMessage('Valid latitude is required'),
    body('location.coordinates.longitude').isFloat({ min: -180, max: 180 }).withMessage('Valid longitude is required')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (!req.uploadedMedia.video) {
      return res.status(400).json({
        success: false,
        error: 'Video is required for all listings'
      });
    }

    const listingData = {
      ...req.body,
      seller: req.user._id,
      media: {
        video: req.uploadedMedia.video,
        images: req.uploadedMedia.images || []
      }
    };

    // Handle custom category if specified
    if (req.body.customCategoryName) {
      listingData.customCategory = {
        name: req.body.customCategoryName,
        description: req.body.customCategoryDescription || '',
        approved: false,
        moderationResult: {
          status: 'pending'
        }
      };
    }

    // Handle broker fee disclosure
    if (req.body.listingType && ['broker', 'agent'].includes(req.body.listingType.sellerType)) {
      listingData.listingType.brokerFee = {
        isFeeDisclosed: req.body.brokerFeeDisclosed === 'true',
        feeStructure: req.body.brokerFeeStructure,
        percentage: req.body.brokerFeePercentage ? parseFloat(req.body.brokerFeePercentage) : null,
        fixedAmount: req.body.brokerFeeAmount ? parseFloat(req.body.brokerFeeAmount) : null,
        description: req.body.brokerFeeDescription || '',
        brokerLicense: {
          number: req.body.brokerLicenseNumber || '',
          state: req.body.brokerLicenseState || ''
        }
      };
    }

    const listing = new Listing(listingData);
    await listing.save();

    // Calculate and update trust score
    await listing.updateTrustScore();

    // Populate seller information
    await listing.populate('seller', 'firstName lastName profilePhoto trustScore verification');

    res.status(201).json({
      success: true,
      message: 'Listing created successfully',
      data: {
        listing: listing.toJSON()
      }
    });
  })
);

// @route   PUT /api/listings/:id
// @desc    Update listing
// @access  Private
router.put('/:id',
  authenticateToken,
  uploadMedia,
  handleUploadError,
  processUploads,
  asyncHandler(async (req, res) => {
    const listing = await Listing.findById(req.params.id);

    if (!listing) {
      return res.status(404).json({
        success: false,
        error: 'Listing not found'
      });
    }

    if (listing.seller.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        error: 'Not authorized to update this listing'
      });
    }

    // Update listing data
    const updates = req.body;
    
    // Update media if new files uploaded
    if (req.uploadedMedia) {
      updates.media = {
        video: req.uploadedMedia.video || listing.media.video,
        images: req.uploadedMedia.images || listing.media.images
      };
    }

    Object.keys(updates).forEach(key => {
      if (key !== '_id' && key !== 'seller' && key !== 'createdAt') {
        listing[key] = updates[key];
      }
    });

    await listing.save();
    await listing.updateTrustScore();

    // Populate seller information
    await listing.populate('seller', 'firstName lastName profilePhoto trustScore verification');

    res.json({
      success: true,
      message: 'Listing updated successfully',
      data: {
        listing: listing.toJSON()
      }
    });
  })
);

// @route   DELETE /api/listings/:id
// @desc    Delete listing
// @access  Private
router.delete('/:id', authenticateToken, asyncHandler(async (req, res) => {
  const listing = await Listing.findById(req.params.id);

  if (!listing) {
    return res.status(404).json({
      success: false,
      error: 'Listing not found'
    });
  }

  if (listing.seller.toString() !== req.user._id.toString()) {
    return res.status(403).json({
      success: false,
      error: 'Not authorized to delete this listing'
    });
  }

  // Soft delete by marking as expired
  listing.status = 'expired';
  listing.expiryDate = new Date();
  await listing.save();

  res.json({
    success: true,
    message: 'Listing deleted successfully'
  });
}));

// @route   POST /api/listings/:id/inquire
// @desc    Create inquiry about listing
// @access  Private
router.post('/:id/inquire', authenticateToken, asyncHandler(async (req, res) => {
  const listing = await Listing.findById(req.params.id)
    .populate('seller', 'firstName lastName trustScore verification');

  if (!listing) {
    return res.status(404).json({
      success: false,
      error: 'Listing not found'
    });
  }

  if (listing.seller._id.toString() === req.user._id.toString()) {
    return res.status(400).json({
      success: false,
      error: 'Cannot inquire about your own listing'
    });
  }

  // Increment inquiry count
  await listing.incrementInquiries();

  res.json({
    success: true,
    message: 'Inquiry created successfully',
    data: {
      seller: {
        _id: listing.seller._id,
        firstName: listing.seller.firstName,
        lastName: listing.seller.lastName,
        trustScore: listing.seller.trustScore,
        verification: listing.seller.verification
      },
      listing: {
        _id: listing._id,
        title: listing.title,
        price: listing.price,
        media: {
          thumbnail: listing.media.video.thumbnail
        }
      }
    }
  });
}));

// @route   POST /api/listings/:id/save
// @desc    Save/unsave listing
// @access  Private
router.post('/:id/save', authenticateToken, asyncHandler(async (req, res) => {
  const listing = await Listing.findById(req.params.id);

  if (!listing) {
    return res.status(404).json({
      success: false,
      error: 'Listing not found'
    });
  }

  // In a real implementation, you would maintain a saved listings collection
  // For now, we'll just increment the saves counter
  
  listing.saves += 1;
  await listing.save();

  res.json({
    success: true,
    message: 'Listing saved successfully'
  });
}));

// @route   POST /api/listings/:id/report
// @desc    Report listing
// @access  Private
router.post('/:id/report', [
  body('reason').isIn(['spam', 'fake', 'inappropriate', 'duplicate', 'other']).withMessage('Valid reason is required'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('Description must be less than 500 characters')
], authenticateToken, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const listing = await Listing.findById(req.params.id);

  if (!listing) {
    return res.status(404).json({
      success: false,
      error: 'Listing not found'
    });
  }

  // Check if user already reported this listing
  const existingReport = listing.reports.find(
    report => report.reportedBy.toString() === req.user._id.toString()
  );

  if (existingReport) {
    return res.status(400).json({
      success: false,
      error: 'You have already reported this listing'
    });
  }

  // Add report
  listing.reports.push({
    reportedBy: req.user._id,
    reason: req.body.reason,
    description: req.body.description || '',
    status: 'pending'
  });

  await listing.save();

  res.json({
    success: true,
    message: 'Listing reported successfully'
  });
}));

// Note: /categories and /search/suggestions routes moved to top of file (before dynamic /:id route)

// Utility function to calculate distance between two coordinates
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Radius of the Earth in kilometers
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const distance = R * c; // Distance in kilometers
  return Math.round(distance * 10) / 10; // Round to 1 decimal place
}

module.exports = router;
``````
---

## server/routes/messages.js

```javascript
const express = require('express');
const { body, validationResult } = require('express-validator');
const Message = require('../models/Message');
const Listing = require('../models/Listing');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');
const { uploadFile } = require('../config/cloudinary');

const router = express.Router();

// @route   GET /api/messages/conversations
// @desc    Get user's conversations
// @access  Private
router.get('/conversations', authenticateToken, asyncHandler(async (req, res) => {
  const { page = 1, limit = 20 } = req.query;
  const skip = (page - 1) * limit;

  // Get all conversations where user is sender or receiver
  const conversations = await Message.aggregate([
    {
      $match: {
        $or: [
          { sender: req.user._id },
          { receiver: req.user._id }
        ],
        deletedAt: { $exists: false }
      }
    },
    {
      $sort: { createdAt: -1 }
    },
    {
      $group: {
        _id: '$conversationId',
        lastMessage: { $first: '$$ROOT' },
        unreadCount: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $eq: ['$receiver', req.user._id] },
                  { $eq: ['$status', 'sent'] }
                ]
              },
              1,
              0
            ]
          }
        },
        messageCount: { $sum: 1 }
      }
    },
    { $sort: { 'lastMessage.createdAt': -1 } },
    { $skip: skip },
    { $limit: parseInt(limit) }
  ]);

  // Populate conversation details
  const populatedConversations = await Promise.all(
    conversations.map(async (conv) => {
      const otherUserId = conv.lastMessage.sender.equals(req.user._id) 
        ? conv.lastMessage.receiver 
        : conv.lastMessage.sender;
      
      const otherUser = await User.findById(otherUserId)
        .select('firstName lastName profilePhoto trustScore verification');
      
      const listing = await Listing.findById(conv.lastMessage.listing)
        .select('title price media images trustScore');

      return {
        conversationId: conv._id,
        otherUser,
        listing,
        lastMessage: {
          _id: conv.lastMessage._id,
          content: conv.lastMessage.content,
          createdAt: conv.lastMessage.createdAt,
          sender: conv.lastMessage.sender,
          safetyScore: conv.lastMessage.safetyScore,
          isSystemMessage: conv.lastMessage.isSystemMessage
        },
        unreadCount: conv.unreadCount,
        messageCount: conv.messageCount
      };
    })
  );

  const total = await Message.aggregate([
    {
      $match: {
        $or: [
          { sender: req.user._id },
          { receiver: req.user._id }
        ],
        deletedAt: { $exists: false }
      }
    },
    {
      $group: {
        _id: '$conversationId'
      }
    },
    { $count: 'total' }
  ]);

  res.json({
    success: true,
    data: {
      conversations: populatedConversations,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil((total[0]?.total || 0) / limit),
        totalItems: total[0]?.total || 0,
        hasNext: skip + conversations.length < (total[0]?.total || 0),
        hasPrev: page > 1
      }
    }
  });
}));

// @route   GET /api/messages/conversations/:conversationId
// @desc    Get messages in a conversation
// @access  Private
router.get('/conversations/:conversationId', authenticateToken, asyncHandler(async (req, res) => {
  const { conversationId } = req.params;
  const { page = 1, limit = 50 } = req.query;
  const skip = (page - 1) * limit;

  // Verify user is part of this conversation
  const firstMessage = await Message.findOne({ conversationId });
  if (!firstMessage || 
      (!firstMessage.sender.equals(req.user._id) && !firstMessage.receiver.equals(req.user._id))) {
    return res.status(403).json({
      success: false,
      error: 'Access denied to this conversation'
    });
  }

  const messages = await Message.findByConversation(conversationId, parseInt(limit), skip);

  // Mark messages as read
  const unreadMessages = messages.filter(msg => 
    msg.receiver.equals(req.user._id) && msg.status === 'sent'
  );

  for (const message of unreadMessages) {
    await message.markAsRead();
  }

  res.json({
    success: true,
    data: {
      messages: messages.map(msg => msg.toJSON()),
      pagination: {
        currentPage: parseInt(page),
        hasNext: messages.length === parseInt(limit),
        hasPrev: page > 1
      }
    }
  });
}));

// @route   POST /api/messages
// @desc    Send new message
// @access  Private
router.post('/', [
  body('receiverId').isMongoId().withMessage('Valid receiver ID is required'),
  body('listingId').isMongoId().withMessage('Valid listing ID is required'),
  body('content').trim().isLength({ min: 1, max: 2000 }).withMessage('Message content is required (1-2000 characters)')
], authenticateToken, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { receiverId, listingId, content } = req.body;

  // Verify receiver exists and is active
  const receiver = await User.findById(receiverId);
  if (!receiver || !receiver.isActive || receiver.isBanned) {
    return res.status(404).json({
      success: false,
      error: 'Receiver not found or inactive'
    });
  }

  // Verify listing exists and is active
  const listing = await Listing.findById(listingId);
  if (!listing || listing.status !== 'active') {
    return res.status(404).json({
      success: false,
      error: 'Listing not found or inactive'
    });
  }

  // Check if user is trying to message themselves
  if (receiverId === req.user._id.toString()) {
    return res.status(400).json({
      success: false,
      error: 'Cannot send message to yourself'
    });
  }

  // Generate conversation ID (consistent between two users for a specific listing)
  const conversationId = [req.user._id, receiverId].sort().join('_') + '_' + listingId;

  // Create new message
  const message = new Message({
    conversationId,
    sender: req.user._id,
    receiver: receiverId,
    listing: listingId,
    content: content.trim(),
    media: req.body.media || [],
    status: 'sent'
  });

  await message.calculateSafetyScore();
  await message.save();

  // Populate message details
  await message.populate('sender', 'firstName lastName profilePhoto trustScore.verification');
  await message.populate('listing', 'title price images');

  // Emit socket event for real-time delivery
  if (req.io) {
    const receiverSocketId = req.io.connectedUsers?.get(receiverId);
    if (receiverSocketId) {
      req.io.to(receiverSocketId).emit('new_message', {
        message: message.toJSON(),
        conversationId
      });
    }
  }

  res.status(201).json({
    success: true,
    message: 'Message sent successfully',
    data: {
      message: message.toJSON()
    }
  });
}));

// @route   POST /api/messages/:id/reaction
// @desc    Add reaction to message
// @access  Private
router.post('/:id/reaction', [
  body('emoji').isLength({ min: 1, max: 4 }).withMessage('Valid emoji is required')
], authenticateToken, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const message = await Message.findById(req.params.id);
  
  if (!message) {
    return res.status(404).json({
      success: false,
      error: 'Message not found'
    });
  }

  // Check if user is part of this conversation
  if (!message.sender.equals(req.user._id) && !message.receiver.equals(req.user._id)) {
    return res.status(403).json({
      success: false,
      error: 'Access denied to this message'
    });
  }

  await message.addReaction(req.user._id, req.body.emoji);

  res.json({
    success: true,
    message: 'Reaction added successfully',
    data: {
      reactions: message.reactions
    }
  });
}));

// @route   POST /api/messages/:id/report
// @desc    Report message
// @access  Private
router.post('/:id/report', [
  body('reason').isIn(['spam', 'harassment', 'inappropriate', 'scam', 'other']).withMessage('Valid reason is required'),
  body('description').optional().trim().isLength({ max: 500 }).withMessage('Description must be less than 500 characters')
], authenticateToken, asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const message = await Message.findById(req.params.id);
  
  if (!message) {
    return res.status(404).json({
      success: false,
      error: 'Message not found'
    });
  }

  // Check if user is part of this conversation
  if (!message.sender.equals(req.user._id) && !message.receiver.equals(req.user._id)) {
    return res.status(403).json({
      success: false,
      error: 'Access denied to this message'
    });
  }

  // Check if user already reported this message
  const existingReport = message.reports.find(
    report => report.reportedBy.toString() === req.user._id.toString()
  );

  if (existingReport) {
    return res.status(400).json({
      success: false,
      error: 'You have already reported this message'
    });
  }

  await message.flag(req.user._id, req.body.reason, req.body.description || '');

  res.json({
    success: true,
    message: 'Message reported successfully'
  });
}));

// @route   GET /api/messages/unread
// @desc    Get unread message count
// @access  Private
router.get('/unread', authenticateToken, asyncHandler(async (req, res) => {
  const unreadCount = await Message.countDocuments({
    receiver: req.user._id,
    status: 'sent',
    deletedAt: { $exists: false }
  });

  const unreadMessages = await Message.findUnread(req.user._id)
    .populate('sender', 'firstName lastName profilePhoto')
    .populate('listing', 'title price')
    .limit(10)
    .sort({ createdAt: -1 });

  res.json({
    success: true,
    data: {
      count: unreadCount,
      messages: unreadMessages.map(msg => ({
        _id: msg._id,
        content: msg.content,
        sender: msg.sender,
        listing: msg.listing,
        createdAt: msg.createdAt,
        safetyScore: msg.safetyScore
      }))
    }
  });
}));

// @route   GET /api/messages/safety-alerts
// @desc    Get safety alerts for user
// @access  Private
router.get('/safety-alerts', authenticateToken, asyncHandler(async (req, res) => {
  const alerts = await Message.findSafetyAlerts(req.user._id)
    .populate('sender', 'firstName lastName profilePhoto')
    .populate('receiver', 'firstName lastName profilePhoto')
    .populate('listing', 'title price')
    .limit(20)
    .sort({ createdAt: -1 });

  res.json({
    success: true,
    data: {
      alerts: alerts.map(alert => ({
        _id: alert._id,
        content: alert.content,
        sender: alert.sender,
        receiver: alert.receiver,
        listing: alert.listing,
        safetyScore: alert.safetyScore,
        flags: alert.safetyScore.flags,
        warnings: alert.safetyScore.warnings,
        createdAt: alert.createdAt
      }))
    }
  });
}));

// @route   POST /api/messages/upload-media
// @desc    Upload media for messages
// @access  Private
router.post('/upload-media', authenticateToken, asyncHandler(async (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: 'No file uploaded'
    });
  }

  try {
    const isVideo = req.file.mimetype.startsWith('video/');
    
    const result = await uploadFile(req.file.path, {
      resource_type: isVideo ? 'video' : 'image',
      quality: 'auto:good',
      format: isVideo ? 'mp4' : 'auto',
      ...(isVideo && {
        transformation: [
          { width: 800, height: 600, crop: 'limit' }
        ]
      }),
      ...(!isVideo && {
        transformation: [
          { width: 800, height: 600, crop: 'limit' }
        ]
      })
    });

    res.json({
      success: true,
      data: {
        type: isVideo ? 'video' : 'image',
        url: result.url,
        filename: req.file.originalname,
        size: req.file.size
      }
    });
  } catch (error) {
    console.error('Media upload error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to upload media'
    });
  }
}));

// @route   DELETE /api/messages/:id
// @desc    Delete message (soft delete)
// @access  Private
router.delete('/:id', authenticateToken, asyncHandler(async (req, res) => {
  const message = await Message.findById(req.params.id);
  
  if (!message) {
    return res.status(404).json({
      success: false,
      error: 'Message not found'
    });
  }

  // Check if user is sender of the message
  if (!message.sender.equals(req.user._id)) {
    return res.status(403).json({
      success: false,
      error: 'Can only delete your own messages'
    });
  }

  // Soft delete
  message.deletedAt = new Date();
  await message.save();

  res.json({
    success: true,
    message: 'Message deleted successfully'
  });
}));

module.exports = router;
``````
---

## server/routes/admin.js

```javascript
const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Listing = require('../models/Listing');
const Message = require('../models/Message');
const { authenticateToken, adminOnly } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// All admin routes require authentication and admin privileges
router.use(authenticateToken, adminOnly);

// @route   GET /api/admin/dashboard
// @desc    Get admin dashboard statistics
// @access  Private (Admin only)
router.get('/dashboard', asyncHandler(async (req, res) => {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  // User statistics
  const userStats = await User.aggregate([
    {
      $group: {
        _id: null,
        totalUsers: { $sum: 1 },
        activeUsers: {
          $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
        },
        bannedUsers: {
          $sum: { $cond: [{ $eq: ['$isBanned', true] }, 1, 0] }
        },
        phoneVerified: {
          $sum: { $cond: [{ $eq: ['$verification.phone.verified', true] }, 1, 0] }
        },
        idVerified: {
          $sum: { $cond: [{ $eq: ['$verification.id.verified', true] }, 1, 0] }
        },
        averageTrustScore: { $avg: '$trustScore.total' }
      }
    }
  ]);

  // User growth over time
  const userGrowth = await User.aggregate([
    {
      $group: {
        _id: {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
          day: { $dayOfMonth: '$createdAt' }
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } },
    { $limit: 30 }
  ]);

  // Listing statistics
  const listingStats = await Listing.aggregate([
    {
      $group: {
        _id: null,
        totalListings: { $sum: 1 },
        activeListings: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        soldListings: {
          $sum: { $cond: [{ $eq: ['$status', 'sold'] }, 1, 0] }
        },
        flaggedListings: {
          $sum: { $cond: [{ $eq: ['$status', 'flagged'] }, 1, 0] }
        },
        totalViews: { $sum: '$views' },
        totalInquiries: { $sum: '$inquiries' },
        averageTrustScore: { $avg: '$trustScore' }
      }
    }
  ]);

  // Trust score distribution
  const trustDistribution = await User.aggregate([
    {
      $group: {
        _id: '$trustScore.level',
        count: { $sum: 1 }
      }
    }
  ]);

  // Recent activity
  const recentUsers = await User.find()
    .sort({ createdAt: -1 })
    .limit(10)
    .select('firstName lastName email trustScore verification createdAt');

  const recentListings = await Listing.find()
    .sort({ createdAt: -1 })
    .limit(10)
    .populate('seller', 'firstName lastName email')
    .select('title price category status trustScore createdAt');

  const recentReports = await Message.aggregate([
    { $unwind: '$reports' },
    { $match: { 'reports.status': 'pending' } },
    {
      $lookup: {
        from: 'users',
        localField: 'reports.reportedBy',
        foreignField: '_id',
        as: 'reporter'
      }
    },
    {
      $lookup: {
        from: 'users',
        localField: 'sender',
        foreignField: '_id',
        as: 'sender'
      }
    },
    {
      $lookup: {
        from: 'listings',
        localField: 'listing',
        foreignField: '_id',
        as: 'listing'
      }
    },
    {
      $project: {
        content: 1,
        createdAt: 1,
        reports: 1,
        reporter: { $arrayElemAt: ['$reporter', 0] },
        sender: { $arrayElemAt: ['$sender', 0] },
        listing: { $arrayElemAt: ['$listing', 0] }
      }
    },
    { $sort: { 'reports.createdAt': -1 } },
    { $limit: 10 }
  ]);

  res.json({
    success: true,
    data: {
      users: userStats[0] || {
        totalUsers: 0,
        activeUsers: 0,
        bannedUsers: 0,
        phoneVerified: 0,
        idVerified: 0,
        averageTrustScore: 0
      },
      listings: listingStats[0] || {
        totalListings: 0,
        activeListings: 0,
        soldListings: 0,
        flaggedListings: 0,
        totalViews: 0,
        totalInquiries: 0,
        averageTrustScore: 0
      },
      trustDistribution,
      userGrowth,
      recent: {
        users: recentUsers,
        listings: recentListings,
        reports: recentReports
      }
    }
  });
}));

// @route   GET /api/admin/users
// @desc    Get all users with filtering and pagination
// @access  Private (Admin only)
router.get('/users', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 20,
    search,
    status,
    trustLevel,
    verification,
    sort = 'createdAt',
    order = 'desc'
  } = req.query;

  const skip = (page - 1) * limit;
  const sortOrder = order === 'asc' ? 1 : -1;

  // Build query
  const query = {};

  if (search) {
    query.$or = [
      { firstName: new RegExp(search, 'i') },
      { lastName: new RegExp(search, 'i') },
      { email: new RegExp(search, 'i') },
      { phone: new RegExp(search, 'i') }
    ];
  }

  if (status) {
    if (status === 'active') query.isActive = true;
    if (status === 'banned') query.isBanned = true;
  }

  if (trustLevel) {
    query['trustScore.level'] = trustLevel;
  }

  if (verification === 'phone') {
    query['verification.phone.verified'] = true;
  } else if (verification === 'id') {
    query['verification.id.verified'] = true;
  }

  const users = await User.find(query)
    .sort({ [sort]: sortOrder })
    .skip(skip)
    .limit(parseInt(limit));

  const total = await User.countDocuments(query);

  res.json({
    success: true,
    data: {
      users,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        hasNext: skip + users.length < total,
        hasPrev: page > 1
      }
    }
  });
}));

// @route   GET /api/admin/users/:id
// @desc    Get user details for admin
// @access  Private (Admin only)
router.get('/users/:id', asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Get user's activity
  const userListings = await Listing.find({ seller: user._id })
    .sort({ createdAt: -1 })
    .limit(50);

  const userMessages = await Message.find({
    $or: [{ sender: user._id }, { receiver: user._id }]
  })
    .sort({ createdAt: -1 })
    .limit(100)
    .populate('sender', 'firstName lastName')
    .populate('receiver', 'firstName lastName')
    .populate('listing', 'title');

  const userReports = await Message.aggregate([
    { $unwind: '$reports' },
    { $match: { 'reports.reportedBy': user._id } },
    {
      $lookup: {
        from: 'users',
        localField: 'sender',
        foreignField: '_id',
        as: 'messageSender'
      }
    },
    {
      $project: {
        content: 1,
        createdAt: 1,
        reports: 1,
        sender: { $arrayElemAt: ['$messageSender', 0] }
      }
    },
    { $sort: { 'reports.createdAt': -1 } }
  ]);

  res.json({
    success: true,
    data: {
      user,
      activity: {
        listings: userListings,
        messages: userMessages,
        reports: userReports
      }
    }
  });
}));

// @route   PUT /api/admin/users/:id/ban
// @desc    Ban/unban user
// @access  Private (Admin only)
router.put('/users/:id/ban', [
  body('banReason').optional().trim().isLength({ max: 500 }).withMessage('Ban reason must be less than 500 characters'),
  body('ban').isBoolean().withMessage('Ban status must be boolean')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { ban, banReason } = req.body;

  const user = await User.findById(req.params.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  user.isBanned = ban;
  user.banReason = ban ? banReason || 'No reason provided' : '';

  if (ban) {
    user.isActive = false;
  }

  await user.save();

  res.json({
    success: true,
    message: `User ${ban ? 'banned' : 'unbanned'} successfully`,
    data: {
      user: user.toJSON()
    }
  });
}));

// @route   PUT /api/admin/users/:id/trust-score
// @desc    Adjust user's trust score
// @access  Private (Admin only)
router.put('/users/:id/trust-score', [
  body('points').isInt({ min: -50, max: 50 }).withMessage('Points must be between -50 and 50'),
  body('reason').trim().isLength({ min: 5, max: 200 }).withMessage('Reason must be 5-200 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { points, reason } = req.body;

  const user = await User.findById(req.params.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Adjust trust score (you might want to track these adjustments)
  user.trustScore.factors.reports = Math.max(0, user.trustScore.factors.reports - points);
  await user.save();

  res.json({
    success: true,
    message: 'Trust score adjusted successfully',
    data: {
      user: user.toJSON(),
      adjustment: {
        points,
        reason,
        timestamp: new Date()
      }
    }
  });
}));

// @route   PUT /api/admin/users/:id/verify
// @desc    Approve/reject ID verification
// @access  Private (Admin only)
router.put('/users/:id/verify', [
  body('status').isIn(['approved', 'rejected']).withMessage('Valid status is required'),
  body('notes').optional().trim().isLength({ max: 500 }).withMessage('Notes must be less than 500 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { status, notes } = req.body;

  const user = await User.findById(req.params.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  if (!user.verification.id.date) {
    return res.status(400).json({
      success: false,
      error: 'User has not submitted ID verification'
    });
  }

  // Update verification status
  user.verification.id.verified = status === 'approved';
  user.verification.id.adminNotes = notes || '';

  // Add verification points if approved
  if (status === 'approved') {
    user.trustScore.factors.verification = 15;
  } else {
    user.trustScore.factors.verification = 0;
  }

  await user.save();

  res.json({
    success: true,
    message: `ID verification ${status} successfully`,
    data: {
      user: user.toJSON()
    }
  });
}));

// @route   GET /api/admin/listings
// @desc    Get all listings with filtering
// @access  Private (Admin only)
router.get('/listings', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 20,
    status,
    category,
    search,
    sort = 'createdAt',
    order = 'desc'
  } = req.query;

  const skip = (page - 1) * limit;
  const sortOrder = order === 'asc' ? 1 : -1;

  // Build query
  const query = {};

  if (status) query.status = status;
  if (category) query.category = category;
  if (search) {
    query.$or = [
      { title: new RegExp(search, 'i') },
      { description: new RegExp(search, 'i') }
    ];
  }

  const listings = await Listing.find(query)
    .populate('seller', 'firstName lastName email trustScore')
    .sort({ [sort]: sortOrder })
    .skip(skip)
    .limit(parseInt(limit));

  const total = await Listing.countDocuments(query);

  res.json({
    success: true,
    data: {
      listings,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        hasNext: skip + listings.length < total,
        hasPrev: page > 1
      }
    }
  });
}));

// @route   PUT /api/admin/listings/:id/status
// @desc    Update listing status
// @access  Private (Admin only)
router.put('/listings/:id/status', [
  body('status').isIn(['active', 'sold', 'expired', 'flagged', 'banned']).withMessage('Valid status is required'),
  body('reason').optional().trim().isLength({ max: 500 }).withMessage('Reason must be less than 500 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { status, reason } = req.body;

  const listing = await Listing.findById(req.params.id)
    .populate('seller', 'firstName lastName email');

  if (!listing) {
    return res.status(404).json({
      success: false,
      error: 'Listing not found'
    });
  }

  listing.status = status;

  // Add report if listing is flagged
  if (status === 'flagged') {
    listing.reports.push({
      reportedBy: req.user._id,
      reason: 'other',
      description: reason || 'Flagged by admin',
      status: 'resolved'
    });
  }

  await listing.save();

  res.json({
    success: true,
    message: 'Listing status updated successfully',
    data: {
      listing: listing.toJSON()
    }
  });
}));

// @route   GET /api/admin/reports
// @desc    Get all reports for moderation
// @access  Private (Admin only)
router.get('/reports', asyncHandler(async (req, res) => {
  const {
    page = 1,
    limit = 20,
    status = 'pending',
    type = 'all'
  } = req.query;

  const skip = (page - 1) * limit;

  let reports = [];

  if (type === 'messages') {
    reports = await Message.aggregate([
      { $unwind: '$reports' },
      { $match: { 'reports.status': status } },
      {
        $lookup: {
          from: 'users',
          localField: 'reports.reportedBy',
          foreignField: '_id',
          as: 'reporter'
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'sender',
          foreignField: '_id',
          as: 'sender'
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'receiver',
          foreignField: '_id',
          as: 'receiver'
        }
      },
      {
        $lookup: {
          from: 'listings',
          localField: 'listing',
          foreignField: '_id',
          as: 'listing'
        }
      },
      {
        $project: {
          content: 1,
          createdAt: 1,
          reports: 1,
          reporter: { $arrayElemAt: ['$reporter', 0] },
          sender: { $arrayElemAt: ['$sender', 0] },
          receiver: { $arrayElemAt: ['$receiver', 0] },
          listing: { $arrayElemAt: ['$listing', 0] },
          type: { $literal: 'message' }
        }
      },
      { $sort: { 'reports.createdAt': -1 } },
      { $skip: skip },
      { $limit: parseInt(limit) }
    ]);
  } else if (type === 'listings') {
    const listings = await Listing.find({ 'reports.status': status })
      .populate('seller', 'firstName lastName email')
      .sort({ 'reports.createdAt': -1 })
      .skip(skip)
      .limit(parseInt(limit));

    reports = listings.map(listing => ({
      listing,
      reports: listing.reports.filter(r => r.status === status),
      type: 'listing'
    }));
  } else {
    // Both messages and listings
    const messageReports = await Message.aggregate([
      { $unwind: '$reports' },
      { $match: { 'reports.status': status } },
      {
        $lookup: {
          from: 'users',
          localField: 'reports.reportedBy',
          foreignField: '_id',
          as: 'reporter'
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: 'sender',
          foreignField: '_id',
          as: 'sender'
        }
      },
      {
        $lookup: {
          from: 'listings',
          localField: 'listing',
          foreignField: '_id',
          as: 'listing'
        }
      },
      {
        $project: {
          content: 1,
          createdAt: 1,
          reports: 1,
          reporter: { $arrayElemAt: ['$reporter', 0] },
          sender: { $arrayElemAt: ['$sender', 0] },
          listing: { $arrayElemAt: ['$listing', 0] },
          type: { $literal: 'message' }
        }
      },
      { $sort: { 'reports.createdAt': -1 } },
      { $limit: parseInt(limit) }
    ]);

    reports = messageReports;
  }

  res.json({
    success: true,
    data: {
      reports,
      pagination: {
        currentPage: parseInt(page),
        hasNext: reports.length === parseInt(limit),
        hasPrev: page > 1
      }
    }
  });
}));

// @route   PUT /api/admin/reports/:type/:id/resolve
// @desc    Resolve a report
// @access  Private (Admin only)
router.put('/reports/:type/:id/resolve', [
  body('status').isIn(['resolved', 'dismissed']).withMessage('Valid status is required'),
  body('notes').optional().trim().isLength({ max: 500 }).withMessage('Notes must be less than 500 characters')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { type, id } = req.params;
  const { status, notes } = req.body;

  let reportItem;

  if (type === 'message') {
    reportItem = await Message.findById(id);
    if (!reportItem) {
      return res.status(404).json({
        success: false,
        error: 'Message not found'
      });
    }

    // Find and update the specific report
    const report = reportItem.reports.find(r => r.status === 'pending');
    if (!report) {
      return res.status(400).json({
        success: false,
        error: 'No pending report found'
      });
    }

    report.status = status;
    report.adminNotes = notes || '';
    report.adminId = req.user._id;
    report.resolvedAt = new Date();

    await reportItem.save();
  } else if (type === 'listing') {
    reportItem = await Listing.findById(id);
    if (!reportItem) {
      return res.status(404).json({
        success: false,
        error: 'Listing not found'
      });
    }

    // Find and update the specific report
    const report = reportItem.reports.find(r => r.status === 'pending');
    if (!report) {
      return res.status(400).json({
        success: false,
        error: 'No pending report found'
      });
    }

    report.status = status;
    report.adminNotes = notes || '';
    report.adminId = req.user._id;
    report.resolvedAt = new Date();

    // If resolved, flag the listing
    if (status === 'resolved') {
      reportItem.status = 'flagged';
    }

    await reportItem.save();
  }

  res.json({
    success: true,
    message: 'Report resolved successfully',
    data: {
      type,
      status,
      notes
    }
  });
}));

// @route   GET /api/admin/analytics
// @desc    Get platform analytics
// @access  Private (Admin only)
router.get('/analytics', asyncHandler(async (req, res) => {
  const { period = '30d' } = req.query;

  let startDate = new Date();
  if (period === '7d') {
    startDate.setDate(startDate.getDate() - 7);
  } else if (period === '30d') {
    startDate.setDate(startDate.getDate() - 30);
  } else if (period === '90d') {
    startDate.setDate(startDate.getDate() - 90);
  }

  // Daily active users
  const dailyActiveUsers = await User.aggregate([
    {
      $match: {
        lastLogin: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          year: { $year: '$lastLogin' },
          month: { $month: '$lastLogin' },
          day: { $dayOfMonth: '$lastLogin' }
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
  ]);

  // Listing creation trends
  const listingTrends = await Listing.aggregate([
    {
      $match: {
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
          day: { $dayOfMonth: '$createdAt' }
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
  ]);

  // Category distribution
  const categoryDistribution = await Listing.aggregate([
    { $match: { status: 'active', createdAt: { $gte: startDate } } },
    {
      $group: {
        _id: '$category',
        count: { $sum: 1 }
      }
    },
    { $sort: { count: -1 } }
  ]);

  // Top performing listings
  const topListings = await Listing.find({ status: 'active' })
    .sort({ views: -1, inquiries: -1 })
    .limit(10)
    .populate('seller', 'firstName lastName')
    .select('title price category views inquiries trustScore');

  res.json({
    success: true,
    data: {
      period,
      dailyActiveUsers,
      listingTrends,
      categoryDistribution,
      topListings
    }
  });
}));

module.exports = router;
``````
---

## server/services/socketService.js

```javascript
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Message = require('../models/Message');
const { verifyToken } = require('../middleware/auth');

const connectedUsers = new Map(); // userId -> socketId
const userSockets = new Map(); // socketId -> userId
const conversationRooms = new Map(); // conversationId -> Set of socketIds

const setupSocket = (io) => {
  // Authentication middleware for Socket.io
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token;
      
      if (!token) {
        return next(new Error('Authentication error: Token required'));
      }

      const decoded = verifyToken(
        token,
        process.env.JWT_SECRET || 'trustmarket-secret-key'
      );

      if (decoded.type !== 'access') {
        return next(new Error('Authentication error: Invalid token type'));
      }

      const user = await User.findById(decoded.userId);
      if (!user || !user.isActive || user.isBanned) {
        return next(new Error('Authentication error: User inactive'));
      }

      socket.userId = user._id.toString();
      socket.user = user;
      next();
    } catch (error) {
      console.error('Socket authentication error:', error);
      next(new Error('Authentication error: Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    console.log(`User ${socket.user.firstName} connected: ${socket.id}`);
    
    // Store user connection
    connectedUsers.set(socket.userId, socket.id);
    userSockets.set(socket.id, socket.userId);
    
    // Join user to their personal room
    socket.join(`user_${socket.userId}`);
    
    // Update user's online status
    updateUserOnlineStatus(socket.userId, true);

    // Handle joining conversation rooms
    socket.on('join_conversation', (conversationId) => {
      try {
        socket.join(conversationId);
        
        // Track conversation participants
        if (!conversationRooms.has(conversationId)) {
          conversationRooms.set(conversationId, new Set());
        }
        conversationRooms.get(conversationId).add(socket.id);
        
        console.log(`User ${socket.userId} joined conversation ${conversationId}`);
      } catch (error) {
        console.error('Join conversation error:', error);
        socket.emit('error', { message: 'Failed to join conversation' });
      }
    });

    // Handle leaving conversation rooms
    socket.on('leave_conversation', (conversationId) => {
      try {
        socket.leave(conversationId);
        
        if (conversationRooms.has(conversationId)) {
          conversationRooms.get(conversationId).delete(socket.id);
          
          // Clean up empty conversation rooms
          if (conversationRooms.get(conversationId).size === 0) {
            conversationRooms.delete(conversationId);
          }
        }
        
        console.log(`User ${socket.userId} left conversation ${conversationId}`);
      } catch (error) {
        console.error('Leave conversation error:', error);
      }
    });

    // Handle new messages
    socket.on('send_message', async (data) => {
      try {
        const { conversationId, receiverId, listingId, content, media } = data;
        
        // Validate required fields
        if (!conversationId || !receiverId || !listingId || !content) {
          return socket.emit('error', { message: 'Missing required message fields' });
        }

        // Create new message
        const message = new Message({
          conversationId,
          sender: socket.userId,
          receiver: receiverId,
          listing: listingId,
          content: content.trim(),
          media: media || [],
          status: 'sent'
        });

        await message.calculateSafetyScore();
        await message.save();
        
        // Populate sender info
        await message.populate('sender', 'firstName lastName profilePhoto trustScore.verification');
        await message.populate('listing', 'title price images');

        // Send to receiver if online
        const receiverSocketId = connectedUsers.get(receiverId);
        if (receiverSocketId) {
          io.to(receiverSocketId).emit('new_message', {
            message: message.toJSON(),
            conversationId
          });
          
          // Update message status to delivered
          message.status = 'delivered';
          await message.save();
          
          // Notify sender of delivery
          socket.emit('message_delivered', {
            messageId: message._id,
            conversationId
          });
        }

        // Send confirmation to sender
        socket.emit('message_sent', {
          message: message.toJSON(),
          conversationId
        });

        // Check for safety warnings
        if (message.isFlagged) {
          socket.emit('safety_warning', {
            messageId: message._id,
            warnings: message.safetyScore.warnings,
            flags: message.safetyScore.flags,
            safetyScore: message.safetyScore.overall
          });
          
          if (receiverSocketId) {
            io.to(receiverSocketId).emit('safety_warning', {
              messageId: message._id,
              warnings: message.safetyScore.warnings,
              flags: message.safetyScore.flags,
              safetyScore: message.safetyScore.overall
            });
          }
        }

        console.log(`Message sent in conversation ${conversationId}`);
      } catch (error) {
        console.error('Send message error:', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    // Handle message read status
    socket.on('mark_message_read', async (messageId) => {
      try {
        const message = await Message.findById(messageId);
        
        if (message && message.receiver.toString() === socket.userId) {
          await message.markAsRead();
          
          // Notify sender that message was read
          const senderSocketId = connectedUsers.get(message.sender.toString());
          if (senderSocketId) {
            io.to(senderSocketId).emit('message_read', {
              messageId,
              readAt: message.readAt
            });
          }
        }
      } catch (error) {
        console.error('Mark message read error:', error);
      }
    });

    // Handle typing indicators
    socket.on('typing_start', (data) => {
      const { conversationId } = data;
      socket.to(conversationId).emit('user_typing', {
        userId: socket.userId,
        isTyping: true
      });
    });

    socket.on('typing_stop', (data) => {
      const { conversationId } = data;
      socket.to(conversationId).emit('user_typing', {
        userId: socket.userId,
        isTyping: false
      });
    });

    // Handle trust score updates
    socket.on('trust_score_update', async () => {
      try {
        const updatedUser = await User.findById(socket.userId);
        if (updatedUser) {
          socket.emit('trust_score_updated', {
            trustScore: updatedUser.trustScore
          });
        }
      } catch (error) {
        console.error('Trust score update error:', error);
      }
    });

    // Handle safety alerts
    socket.on('report_suspicious_activity', async (data) => {
      try {
        const { type, targetId, reason, description } = data;
        
        // Create system message for safety alert
        const systemMessage = new Message({
          conversationId: `safety_${targetId}`,
          sender: socket.userId,
          receiver: targetId,
          listing: data.listingId || null,
          content: `Safety Alert: ${reason}`,
          isSystemMessage: true,
          systemMessageType: 'safety_warning',
          safetyScore: {
            overall: 0,
            flags: ['safety_alert'],
            warnings: [description || 'Suspicious activity reported']
          }
        });

        await systemMessage.save();
        
        // Notify both parties
        const targetSocketId = connectedUsers.get(targetId);
        if (targetSocketId) {
          io.to(targetSocketId).emit('safety_alert', {
            type,
            reason,
            description,
            reportedBy: socket.userId,
            timestamp: new Date()
          });
        }
      } catch (error) {
        console.error('Safety alert error:', error);
      }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      console.log(`User ${socket.userId} disconnected: ${socket.id}`);
      
      // Remove from connected users
      connectedUsers.delete(socket.userId);
      userSockets.delete(socket.id);
      
      // Clean up conversation rooms
      conversationRooms.forEach((socketIds, conversationId) => {
        socketIds.delete(socket.id);
        if (socketIds.size === 0) {
          conversationRooms.delete(conversationId);
        }
      });
      
      // Update user's online status
      updateUserOnlineStatus(socket.userId, false);
    });

    // Handle errors
    socket.on('error', (error) => {
      console.error(`Socket error for user ${socket.userId}:`, error);
    });
  });

  // Utility functions
  const updateUserOnlineStatus = async (userId, isOnline) => {
    try {
      await User.findByIdAndUpdate(userId, {
        'settings.privacy.showOnlineStatus': isOnline,
        lastLogin: isOnline ? new Date() : undefined
      });
    } catch (error) {
      console.error('Update online status error:', error);
    }
  };

  const getOnlineUsers = () => {
    return Array.from(connectedUsers.keys());
  };

  const isUserOnline = (userId) => {
    return connectedUsers.has(userId);
  };

  const getConversationParticipants = (conversationId) => {
    const socketIds = conversationRooms.get(conversationId);
    if (!socketIds) return [];
    
    return Array.from(socketIds).map(socketId => userSockets.get(socketId)).filter(Boolean);
  };

  // Make utilities available globally
  io.getOnlineUsers = getOnlineUsers;
  io.isUserOnline = isUserOnline;
  io.getConversationParticipants = getConversationParticipants;

  console.log('Socket.io setup completed');
};

module.exports = { setupSocket };
``````
---

## server/services/verificationService.js

```javascript
/**
 * Verification Service
 * Handles video verification, ID verification, and trust score calculations
 */

const User = require('../models/User');
const Listing = require('../models/Listing');

/**
 * Video Verification Class
 * Analyzes and verifies video content for listings
 */
class VideoVerificationService {
  /**
   * Analyze video content for authenticity
   * @param {Object} videoData - Video metadata from Cloudinary
   * @returns {Object} Verification result with score and issues
   */
  static async analyzeVideo(videoData) {
    const issues = [];
    let score = 100;

    // Check video duration (10-30 seconds required)
    if (videoData.duration < 10) {
      issues.push('too_short');
      score -= 30;
    } else if (videoData.duration > 30) {
      issues.push('too_long');
      score -= 10;
    }

    // Check video quality
    if (videoData.quality === 'low') {
      issues.push('low_quality');
      score -= 20;
    }

    // Check file size (3MB max)
    if (videoData.size > 3145728) {
      score -= 10;
    }

    // Normalize score
    score = Math.max(0, Math.min(100, score));

    return {
      score,
      issues,
      status: score >= 70 ? 'approved' : score >= 40 ? 'pending' : 'rejected'
    };
  }

  /**
   * Verify if video shows actual product
   * In production, this would use AI/ML analysis
   * @param {string} videoUrl - URL of the video
   * @returns {Object} Verification result
   */
  static async verifyProductDisplay(videoUrl) {
    // Placeholder for actual video analysis
    // In production, integrate with:
    // - AWS Rekognition
    // - Google Cloud Video Intelligence
    // - Custom ML models

    return {
      isAuthentic: true,
      confidence: 85,
      suggestedIssues: []
    };
  }

  /**
   * Detect stock photos/fake videos
   * @param {string} videoUrl - URL of the video
   * @returns {Object} Detection result
   */
  static async detectStockOrFake(videoUrl) {
    // Placeholder for stock photo/fake detection
    // In production, use reverse image search APIs
    // and metadata analysis

    return {
      isStock: false,
      isFake: false,
      confidence: 90
    };
  }
}

/**
 * ID Verification Service
 * Handles user identity verification
 */
class IDVerificationService {
  /**
   * Verify ID document
   * @param {Object} idData - ID document data
   * @returns {Object} Verification result
   */
  static async verifyID(idData) {
    const verification = {
      isValid: false,
      confidence: 0,
      issues: [],
      details: {}
    };

    try {
      // Basic validation
      if (!idData.documentNumber || idData.documentNumber.length < 8) {
        verification.issues.push('invalid_document_number');
      }

      if (!idData.name || idData.name.length < 2) {
        verification.issues.push('invalid_name');
      }

      if (!idData.dob) {
        verification.issues.push('missing_date_of_birth');
      }

      // Check document expiry
      if (idData.expiryDate && new Date(idData.expiryDate) < new Date()) {
        verification.issues.push('document_expired');
      }

      // Calculate confidence based on data completeness
      const requiredFields = ['documentNumber', 'name', 'dob', 'frontImage', 'backImage'];
      const completedFields = requiredFields.filter(field => idData[field]);
      verification.confidence = (completedFields.length / requiredFields.length) * 100;

      // Set validation status
      verification.isValid = verification.issues.length === 0 && verification.confidence >= 80;
      verification.status = verification.isValid ? 'verified' : 'pending_review';

    } catch (error) {
      console.error('ID verification error:', error);
      verification.issues.push('verification_error');
    }

    return verification;
  }

  /**
   * Verify Aadhaar card
   * @param {string} aadhaarNumber - Aadhaar number
   * @param {string} otp - OTP for verification
   * @returns {Object} Verification result
   */
  static async verifyAadhaar(aadhaarNumber, otp) {
    // In production, integrate with UIDAI API
    // For demo, simulate verification

    if (aadhaarNumber && otp) {
      return {
        isVerified: true,
        lastFour: aadhaarNumber.slice(-4),
        timestamp: new Date()
      };
    }

    return {
      isVerified: false,
      error: 'Invalid Aadhaar number or OTP'
    };
  }

  /**
   * Verify PAN card
   * @param {string} panNumber - PAN number
   * @returns {Object} Verification result
   */
  static async verifyPAN(panNumber) {
    // PAN format: ABCDE1234F
    const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]$/;

    if (panRegex.test(panNumber)) {
      return {
        isValid: true,
        nameMatch: true, // In production, verify with IT Department
        timestamp: new Date()
      };
    }

    return {
      isValid: false,
      error: 'Invalid PAN format'
    };
  }
}

/**
 * Trust Score Calculation Service
 * Calculates and updates user and listing trust scores
 */
class TrustScoreService {
  /**
   * Calculate user trust score based on various factors
   * @param {string} userId - User ID
   * @returns {Object} Updated trust score
   */
  static async calculateUserTrustScore(userId) {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    let totalScore = 0;
    const factors = { ...user.trustScore.factors };

    // Account age factor (max 15 points)
    const accountAgeDays = Math.floor((Date.now() - user.createdAt) / (1000 * 60 * 60 * 24));
    factors.accountAge = Math.min(15, Math.floor(accountAgeDays / 7)); // 1 point per week, max 15

    // Successful deals factor (max 20 points)
    // Assuming user model has completedTransactions field
    const completedDeals = user.completedTransactions || 0;
    factors.successfulDeals = Math.min(20, completedDeals * 2); // 2 points per deal, max 20

    // Response time factor (max 15 points)
    // Lower average response time = higher score
    const avgResponseTime = user.averageResponseTime || 0; // in hours
    if (avgResponseTime <= 1) {
      factors.responseTime = 15;
    } else if (avgResponseTime <= 6) {
      factors.responseTime = 10;
    } else if (avgResponseTime <= 24) {
      factors.responseTime = 5;
    } else {
      factors.responseTime = 0;
    }

    // Community help factor (max 10 points)
    // Based on helpful votes, answers to questions, etc.
    factors.communityHelp = Math.min(10, (user.helpfulVotes || 0));

    // Verification factor (max 25 points)
    let verificationScore = 0;
    if (user.verification.phone?.verified) verificationScore += 5;
    if (user.verification.email?.verified) verificationScore += 5;
    if (user.verification.id?.status === 'verified') verificationScore += 10;
    if (user.verification.address?.verified) verificationScore += 5;
    factors.verification = Math.min(25, verificationScore);

    // Reports factor (max -15 points)
    // Negative impact from reports
    const reportCount = user.reportsReceived || 0;
    factors.reports = Math.max(-15, 0 - (reportCount * 3)); // -3 points per report

    // Transaction volume factor (max 10 points)
    const totalTransactions = user.totalTransactionVolume || 0;
    if (totalTransactions >= 100000) factors.transactionVolume = 10;
    else if (totalTransactions >= 50000) factors.transactionVolume = 7;
    else if (totalTransactions >= 10000) factors.transactionVolume = 5;
    else if (totalTransactions >= 1000) factors.transactionVolume = 2;
    else factors.transactionVolume = 0;

    // Calculate total score
    totalScore = Object.values(factors).reduce((sum, val) => sum + val, 0);

    // Determine trust level
    let level = 'newbie';
    if (totalScore >= 80) level = 'trusted';
    else if (totalScore >= 60) level = 'verified';
    else if (totalScore >= 40) level = 'regular';
    else if (totalScore >= 20) level = 'active';

    // Update user
    user.trustScore = { total: Math.max(0, Math.min(100, totalScore)), level, factors };
    await user.save();

    return user.trustScore;
  }

  /**
   * Calculate listing trust score
   * @param {string} listingId - Listing ID
   * @returns {Object} Updated trust score
   */
  static async calculateListingTrustScore(listingId) {
    const listing = await Listing.findById(listingId);
    if (!listing) {
      throw new Error('Listing not found');
    }

    const seller = await User.findById(listing.seller);
    if (!seller) {
      throw new Error('Seller not found');
    }

    // Base score from seller trust (60% weight)
    let trustScore = seller.trustScore.total * 0.6;

    // Listing quality factors (40% weight)
    const hasVideo = listing.media.video ? 25 : 0;
    const hasImages = Math.min(listing.media.images.length * 5, 20); // Max 20 points
    const hasDescription = listing.description.length >= 50 ? 10 : 5; // 10 points for good description
    const completeLocation = listing.location.area && listing.location.landmark ? 5 : 0;
    const reasonablePrice = this.checkReasonablePrice(listing.price, listing.category) ? 5 : 0;

    trustScore += (hasVideo + hasImages + hasDescription + completeLocation + reasonablePrice) * 0.4;

    // Normalize and save
    listing.trustScore = Math.max(0, Math.min(100, Math.round(trustScore)));
    await listing.save();

    return listing.trustScore;
  }

  /**
   * Check if price is reasonable for category
   * @param {number} price - Listing price
   * @param {string} category - Listing category
   * @returns {boolean} Is price reasonable
   */
  static checkReasonablePrice(price, category) {
    const priceRanges = {
      electronics: { min: 100, max: 500000 },
      vehicles: { min: 5000, max: 5000000 },
      furniture: { min: 100, max: 200000 },
      books: { min: 10, max: 10000 },
      clothing: { min: 50, max: 50000 },
      services: { min: 100, max: 1000000 },
      jobs: { min: 0, max: 1000000 },
      real_estate: { min: 10000, max: 100000000 },
      other: { min: 10, max: 1000000 }
    };

    const range = priceRanges[category] || priceRanges.other;
    return price >= range.min && price <= range.max;
  }

  /**
   * Update user trust score after transaction
   * @param {string} userId - User ID
   * @param {string} transactionType - 'buyer' or 'seller'
   * @param {Object} transactionData - Transaction details
   */
  static async updateAfterTransaction(userId, transactionType, transactionData) {
    const user = await User.findById(userId);
    if (!user) return;

    // Update transaction volume
    user.totalTransactionVolume = (user.totalTransactionVolume || 0) + transactionData.amount;
    user.completedTransactions = (user.completedTransactions || 0) + 1;

    // Recalculate trust score
    await this.calculateUserTrustScore(userId);

    return user.trustScore;
  }
}

/**
 * Fraud Detection Service
 * Detects potential fraud patterns
 */
class FraudDetectionService {
  /**
   * Check for suspicious user behavior
   * @param {Object} userData - User data to check
   * @returns {Object} Risk assessment
   */
  static assessUserRisk(userData) {
    const riskFactors = [];
    let riskScore = 0;

    // Check for suspicious email patterns
    if (this.isDisposableEmail(userData.email)) {
      riskFactors.push('disposable_email');
      riskScore += 20;
    }

    // Check phone number validity
    if (userData.phone && !this.isValidPhoneNumber(userData.phone)) {
      riskFactors.push('invalid_phone');
      riskScore += 15;
    }

    // Check for rapid account creation (IP-based)
    // This would typically check against recent registrations from same IP

    return {
      riskScore: Math.min(100, riskScore),
      riskLevel: riskScore >= 50 ? 'high' : riskScore >= 20 ? 'medium' : 'low',
      factors: riskFactors,
      requiresReview: riskScore >= 30
    };
  }

  /**
   * Check if email is from disposable provider
   * @param {string} email - Email to check
   * @returns {boolean} Is disposable
   */
  static isDisposableEmail(email) {
    const disposableDomains = [ // Common disposable email domains
      'tempmail.com', 'throwawaymail.com', 'fakeinbox.com',
      'guerrillamail.com', 'maildrop.cc', 'yopmail.com'
    ];
    const domain = email.split('@')[1]?.toLowerCase();
    return disposableDomains.includes(domain);
  }

  /**
   * Validate phone number format
   * @param {string} phone - Phone number
   * @returns {boolean} Is valid
   */
  static isValidPhoneNumber(phone) {
    // Indian phone number validation
    const indianPhoneRegex = /^[6-9]\d{9}$/;
    return indianPhoneRegex.test(phone.replace(/\s/g, ''));
  }

  /**
   * Detect listing fraud patterns
   * @param {Object} listingData - Listing data
   * @returns {Object} Risk assessment
   */
  static assessListingRisk(listingData) {
    const riskFactors = [];
    let riskScore = 0;

    // Check for unrealistically low prices
    if (listingData.price < 100 && listingData.category !== 'books') {
      riskFactors.push('suspiciously_low_price');
      riskScore += 25;
    }

    // Check for missing required fields
    if (!listingData.media?.video) {
      riskFactors.push('no_video');
      riskScore += 10;
    }

    // Check description quality
    if (listingData.description && listingData.description.length < 20) {
      riskFactors.push('poor_description');
      riskScore += 10;
    }

    return {
      riskScore: Math.min(100, riskScore),
      riskLevel: riskScore >= 50 ? 'high' : riskScore >= 20 ? 'medium' : 'low',
      factors: riskFactors,
      requiresReview: riskScore >= 30
    };
  }
}

module.exports = {
  VideoVerificationService,
  IDVerificationService,
  TrustScoreService,
  FraudDetectionService
};
``````
---

## server/.env.example

```text
# TrustMarket Server Environment Configuration

# Server Configuration
NODE_ENV=development
PORT=5000
CLIENT_URL=http://localhost:3000

# Database Configuration - MONGODB ATLAS SETUP
# Replace with your MongoDB Atlas connection string
MONGODB_URI=mongodb+srv://username:password@cluster0.mongodb.net/trustmarket?retryWrites=true&w=majority

# For local development, use:
# MONGODB_URI=mongodb://localhost:27017/trustmarket

# JWT Configuration
JWT_SECRET=trustmarket-super-secret-jwt-key-2025
JWT_REFRESH_SECRET=trustmarket-super-secret-refresh-key-2025
JWT_EXPIRE=7d
JWT_REFRESH_EXPIRE=30d

# Cloudinary Configuration - MEDIA STORAGE SETUP
# Sign up at https://cloudinary.com and get your credentials
CLOUDINARY_CLOUD_NAME=your-cloudinary-cloud-name
CLOUDINARY_API_KEY=your-cloudinary-api-key
CLOUDINARY_API_SECRET=your-cloudinary-api-secret

# CORS Configuration
FRONTEND_URL=http://localhost:3000
# For production, set to your Vercel URL:
# FRONTEND_URL=https://your-app.vercel.app

# Email Configuration (for password reset, notifications)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Google OAuth Configuration
# Get credentials from https://console.cloud.google.com/apis/credentials
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com

# SMS Configuration (for OTP verification)
SMS_API_KEY=your-sms-api-key
SMS_SENDER_ID=TRUSTM

# Security Configuration
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_TIME=15

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# File Upload Limits
MAX_FILE_SIZE=10485760
MAX_FILES_PER_REQUEST=10
ALLOWED_FILE_TYPES=jpg,jpeg,png,gif,mp4,mov,pdf,webp

# Trust Score Configuration
MIN_TRUST_SCORE=0
MAX_TRUST_SCORE=100
TRUST_SCORE_UPDATE_INTERVAL=3600000

# Admin Configuration
ADMIN_EMAIL=admin@trustmarket.com
ADMIN_PHONE=+919876543210

# Monitoring and Logging
LOG_LEVEL=info
ENABLE_REQUEST_LOGGING=true

# Cookie Configuration
COOKIE_SECURE=false
COOKIE_SAME_SITE=lax

# Session Configuration
SESSION_SECRET=trustmarket-session-secret-key-2025

# Socket.IO Configuration
SOCKET_CORS_ORIGIN=http://localhost:3000
# For production, set to your Vercel URL:
# SOCKET_CORS_ORIGIN=https://your-app.vercel.app
``````
---

## server/__tests__/auth.test.js

```javascript
const { generateTokens, verifyToken } = require('../middleware/auth');

// Mock the User model
jest.mock('../models/User', () => {
    const mockUser = {
        _id: '507f1f77bcf86cd799439011',
        role: 'buyer',
        isActive: true,
        isBanned: false,
        isAdmin: false,
        toJSON: function () { return { ...this }; }
    };
    return {
        findById: jest.fn().mockResolvedValue(mockUser)
    };
});

describe('Auth Middleware', () => {
    // Set env vars for tests
    beforeAll(() => {
        process.env.JWT_SECRET = 'test-secret';
        process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
    });

    describe('generateTokens', () => {
        it('should generate access and refresh tokens', () => {
            const tokens = generateTokens('user123', 'buyer');
            expect(tokens).toHaveProperty('accessToken');
            expect(tokens).toHaveProperty('refreshToken');
            expect(typeof tokens.accessToken).toBe('string');
            expect(typeof tokens.refreshToken).toBe('string');
        });

        it('should generate tokens with default role if not specified', () => {
            const tokens = generateTokens('user123');
            expect(tokens.accessToken).toBeTruthy();
        });

        it('should embed role in the token payload', () => {
            const tokens = generateTokens('user123', 'admin');
            const decoded = verifyToken(tokens.accessToken, process.env.JWT_SECRET);
            expect(decoded.role).toBe('admin');
            expect(decoded.type).toBe('access');
        });
    });

    describe('verifyToken', () => {
        it('should verify a valid token', () => {
            const tokens = generateTokens('user123', 'seller');
            const decoded = verifyToken(tokens.accessToken, process.env.JWT_SECRET);
            expect(decoded.userId).toBe('user123');
            expect(decoded.role).toBe('seller');
            expect(decoded.type).toBe('access');
        });

        it('should throw on invalid token', () => {
            expect(() => verifyToken('invalid-token', process.env.JWT_SECRET)).toThrow('Invalid token');
        });

        it('should throw when using wrong secret', () => {
            const tokens = generateTokens('user123', 'buyer');
            expect(() => verifyToken(tokens.accessToken, 'wrong-secret')).toThrow('Invalid token');
        });

        it('should verify refresh token with refresh secret', () => {
            const tokens = generateTokens('user123', 'buyer');
            const decoded = verifyToken(tokens.refreshToken, process.env.JWT_REFRESH_SECRET);
            expect(decoded.userId).toBe('user123');
            expect(decoded.type).toBe('refresh');
        });
    });

    describe('requireRole', () => {
        const { requireRole } = require('../middleware/auth');

        const mockRes = () => {
            const res = {};
            res.status = jest.fn().mockReturnValue(res);
            res.json = jest.fn().mockReturnValue(res);
            return res;
        };

        it('should allow access for matching role', () => {
            const middleware = requireRole('admin');
            const req = { user: { role: 'admin' } };
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).toHaveBeenCalled();
        });

        it('should allow access when user has any of the specified roles', () => {
            const middleware = requireRole('seller', 'admin');
            const req = { user: { role: 'seller' } };
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).toHaveBeenCalled();
        });

        it('should deny access for non-matching role', () => {
            const middleware = requireRole('admin');
            const req = { user: { role: 'buyer' } };
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ code: 'INSUFFICIENT_ROLE' })
            );
        });

        it('should return 401 when no user is present', () => {
            const middleware = requireRole('admin');
            const req = {};
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(401);
        });
    });
});
``````
---

## server/__tests__/user.test.js

```javascript
const mongoose = require('mongoose');

// We need to test the schema logic without connecting to a real database.
// We'll test the trust score calculation and password hashing logic.

describe('User Model', () => {
    let User;

    beforeAll(async () => {
        // Connect to in-memory test database or skip if not available
        try {
            await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/trustmarket-test', {
                serverSelectionTimeoutMS: 3000
            });
            User = require('../models/User');
        } catch {
            // If MongoDB is not running, skip DB-dependent tests
            console.warn('MongoDB not available â€” skipping integration tests');
        }
    });

    afterAll(async () => {
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.db.dropDatabase();
            await mongoose.disconnect();
        }
    });

    describe('Schema validation', () => {
        it('should require email, password, phone, firstName, lastName', () => {
            if (!User) return;
            const user = new User({});
            const error = user.validateSync();
            expect(error.errors.email).toBeDefined();
            expect(error.errors.password).toBeDefined();
            expect(error.errors.phone).toBeDefined();
            expect(error.errors.firstName).toBeDefined();
            expect(error.errors.lastName).toBeDefined();
        });

        it('should have default role of buyer', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'Test',
                lastName: 'User'
            });
            expect(user.role).toBe('buyer');
        });

        it('should reject invalid role values', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'Test',
                lastName: 'User',
                role: 'superadmin'
            });
            const error = user.validateSync();
            expect(error.errors.role).toBeDefined();
        });

        it('should reject invalid phone numbers', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '1234567890', // Doesn't start with 6-9
                firstName: 'Test',
                lastName: 'User'
            });
            const error = user.validateSync();
            expect(error.errors.phone).toBeDefined();
        });

        it('should accept valid Indian phone numbers', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'Test',
                lastName: 'User'
            });
            const error = user.validateSync();
            expect(error?.errors?.phone).toBeUndefined();
        });
    });

    describe('Virtuals', () => {
        it('should compute fullName correctly', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'John',
                lastName: 'Doe'
            });
            expect(user.fullName).toBe('John Doe');
        });

        it('should compute isAdmin from role', () => {
            if (!User) return;
            const adminUser = new User({
                email: 'admin@example.com',
                password: 'TestPass123',
                phone: '9876543211',
                firstName: 'Admin',
                lastName: 'User',
                role: 'admin'
            });
            expect(adminUser.isAdmin).toBe(true);

            const buyerUser = new User({
                email: 'buyer@example.com',
                password: 'TestPass123',
                phone: '9876543212',
                firstName: 'Buyer',
                lastName: 'User',
                role: 'buyer'
            });
            expect(buyerUser.isAdmin).toBe(false);
        });
    });

    describe('Password hashing', () => {
        it('should hash password on save', async () => {
            if (!User) return;
            const user = new User({
                email: 'hash-test@example.com',
                password: 'TestPass123',
                phone: '9876543213',
                firstName: 'Hash',
                lastName: 'Test'
            });
            await user.save();
            expect(user.password).not.toBe('TestPass123');
            expect(user.password.startsWith('$2')).toBe(true); // bcrypt hash
        });

        it('should correctly compare passwords', async () => {
            if (!User) return;
            const user = await User.findOne({ email: 'hash-test@example.com' });
            if (!user) return;
            const isValid = await user.comparePassword('TestPass123');
            expect(isValid).toBe(true);
            const isInvalid = await user.comparePassword('WrongPassword');
            expect(isInvalid).toBe(false);
        });
    });

    describe('Trust score calculation', () => {
        it('should default trust score to newbie level', () => {
            if (!User) return;
            const user = new User({
                email: 'trust@example.com',
                password: 'TestPass123',
                phone: '9876543214',
                firstName: 'Trust',
                lastName: 'Test'
            });
            expect(user.trustScore.level).toBe('newbie');
            expect(user.trustScore.total).toBe(0);
        });
    });
});
``````
---
# FRONTEND

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/components/common/LoadingSpinner.js

```javascript
import React from 'react';

const LoadingSpinner = ({ 
  size = 'medium', 
  color = 'primary', 
  className = '',
  text = '',
  variant = 'spinner' // 'spinner', 'dots', 'pulse'
}) => {
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12',
    xlarge: 'w-16 h-16',
  };

  const colorClasses = {
    primary: 'border-primary-500',
    white: 'border-white',
    gray: 'border-gray-400',
    success: 'border-success',
    warning: 'border-warning',
    error: 'border-error',
  };

  const textSizeClasses = {
    small: 'text-xs',
    medium: 'text-sm',
    large: 'text-base',
    xlarge: 'text-lg',
  };

  const renderSpinner = () => (
    <div
      className={`
        ${sizeClasses[size]} 
        ${colorClasses[color]} 
        border-2 border-t-transparent 
        rounded-full 
        animate-spin
        ${className}
      `}
      role="status"
      aria-label="Loading"
    />
  );

  const renderDots = () => (
    <div className="flex space-x-1">
      <div
        className={`
          ${size === 'small' ? 'w-1 h-1' : size === 'medium' ? 'w-2 h-2' : 'w-3 h-3'}
          ${color === 'white' ? 'bg-white' : `bg-${color}-500`}
          rounded-full animate-pulse
        `}
        style={{ animationDelay: '0ms' }}
      />
      <div
        className={`
          ${size === 'small' ? 'w-1 h-1' : size === 'medium' ? 'w-2 h-2' : 'w-3 h-3'}
          ${color === 'white' ? 'bg-white' : `bg-${color}-500`}
          rounded-full animate-pulse
        `}
        style={{ animationDelay: '200ms' }}
      />
      <div
        className={`
          ${size === 'small' ? 'w-1 h-1' : size === 'medium' ? 'w-2 h-2' : 'w-3 h-3'}
          ${color === 'white' ? 'bg-white' : `bg-${color}-500`}
          rounded-full animate-pulse
        `}
        style={{ animationDelay: '400ms' }}
      />
    </div>
  );

  const renderPulse = () => (
    <div
      className={`
        ${sizeClasses[size]} 
        ${colorClasses[color]} 
        rounded-full 
        animate-pulse
        ${className}
      `}
    />
  );

  const renderContent = () => {
    switch (variant) {
      case 'dots':
        return renderDots();
      case 'pulse':
        return renderPulse();
      default:
        return renderSpinner();
    }
  };

  if (text) {
    return (
      <div className="flex flex-col items-center justify-center space-y-2">
        {renderContent()}
        {text && (
          <span className={`${textSizeClasses[size]} text-gray-600 font-medium`}>
            {text}
          </span>
        )}
      </div>
    );
  }

  return renderContent();
};

// Inline loading component for buttons
export const ButtonSpinner = ({ color = 'white' }) => (
  <div className="flex items-center">
    <div
      className={`
        w-4 h-4 
        ${color === 'white' ? 'border-white' : `border-${color}-500`} 
        border-2 border-t-transparent 
        rounded-full 
        animate-spin
      `}
    />
  </div>
);

// Loading overlay component
export const LoadingOverlay = ({ 
  isVisible, 
  text = 'Loading...', 
  className = '',
  backdrop = true 
}) => {
  if (!isVisible) return null;

  return (
    <div 
      className={`
        fixed inset-0 z-50 
        flex items-center justify-center
        ${backdrop ? 'bg-black bg-opacity-50' : ''}
        ${className}
      `}
    >
      <div className="bg-white rounded-lg p-6 shadow-xl">
        <LoadingSpinner size="large" text={text} />
      </div>
    </div>
  );
};

// Page loading component
export const PageLoader = ({ text = 'Loading...' }) => (
  <div className="min-h-screen flex items-center justify-center bg-gray-50">
    <div className="text-center">
      <LoadingSpinner size="xlarge" />
      <p className="mt-4 text-gray-600 font-medium">{text}</p>
    </div>
  </div>
);

// Skeleton loader component for content
export const SkeletonLoader = ({ 
  count = 1, 
  className = '',
  height = 'h-4',
  width = 'w-full'
}) => {
  return (
    <>
      {Array.from({ length: count }).map((_, index) => (
        <div
          key={index}
          className={`
            ${height} 
            ${width} 
            bg-gray-200 
            rounded 
            animate-pulse
            ${className}
          `}
        />
      ))}
    </>
  );
};

// Card skeleton loader
export const CardSkeleton = ({ showImage = true }) => (
  <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 space-y-4">
    {showImage && (
      <div className="w-full h-48 bg-gray-200 rounded animate-pulse" />
    )}
    <div className="space-y-2">
      <SkeletonLoader height="h-6" />
      <SkeletonLoader height="h-4" width="w-3/4" />
    </div>
    <div className="flex justify-between items-center">
      <SkeletonLoader height="h-6" width="w-20" />
      <SkeletonLoader height="h-6" width="w-16" />
    </div>
  </div>
);

// List skeleton loader
export const ListSkeleton = ({ count = 3 }) => (
  <div className="space-y-4">
    {Array.from({ length: count }).map((_, index) => (
      <div key={index} className="flex items-center space-x-4 p-4 bg-white rounded-lg shadow-sm">
        <div className="w-12 h-12 bg-gray-200 rounded-full animate-pulse" />
        <div className="flex-1 space-y-2">
          <SkeletonLoader height="h-4" />
          <SkeletonLoader height="h-3" width="w-1/2" />
        </div>
        <SkeletonLoader height="h-8" width="w-20" />
      </div>
    ))}
  </div>
);

// Text skeleton loader
export const TextSkeleton = ({ lines = 3, className = '' }) => (
  <div className={`space-y-2 ${className}`}>
    {Array.from({ length: lines }).map((_, index) => (
      <SkeletonLoader
        key={index}
        height="h-4"
        width={index === lines - 1 ? 'w-3/4' : 'w-full'}
      />
    ))}
  </div>
);

// Image skeleton loader
export const ImageSkeleton = ({ width = 'w-full', height = 'h-48', className = '' }) => (
  <div className={`${width} ${height} bg-gray-200 rounded animate-pulse ${className}`} />
);

export default LoadingSpinner;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/components/layout/Header.js

```javascript
import React, { useState, useRef, useEffect, useCallback, memo } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useSocket } from '../../context/SocketContext';
import { useNotification } from '../../context/NotificationContext';
import {
  Bars3Icon,
  XMarkIcon,
  BellIcon,
  MagnifyingGlassIcon,
  UserIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  PlusIcon,
} from '@heroicons/react/24/outline';

// Memoized Header component for performance optimization
const Header = memo(() => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, isAuthenticated, logout } = useAuth();
  const { unreadCount } = useSocket();
  const { permission: notificationPermission } = useNotification();
  
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [isMobile, setIsMobile] = useState(false);
  const [atTop, setAtTop] = useState(true);

  const profileMenuRef = useRef(null);
  const menuRef = useRef(null);

  // Detect mobile viewport
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Handle scroll effects
  useEffect(() => {
    const handleScroll = () => {
      setAtTop(window.scrollY <= 10);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Close profile menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target)) {
        setIsProfileMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        setIsMenuOpen(false);
        setIsProfileMenuOpen(false);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleSearch = useCallback((e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/search?q=${encodeURIComponent(searchQuery.trim())}`);
      setSearchQuery('');
      setIsMenuOpen(false);
    }
  }, [searchQuery, navigate]);

  const handleLogout = useCallback(async () => {
    try {
      await logout();
      navigate('/');
    } catch (error) {
      console.error('Logout error:', error);
    }
    setIsProfileMenuOpen(false);
    setIsMenuOpen(false);
  }, [logout, navigate]);

  const isActive = useCallback((path) => {
    if (path === '/' && location.pathname === '/') return true;
    if (path !== '/' && location.pathname.startsWith(path)) return true;
    return false;
  }, [location.pathname]);

  const toggleMenu = useCallback(() => {
    setIsMenuOpen(prev => !prev);
    if (isProfileMenuOpen) setIsProfileMenuOpen(false);
  }, [isProfileMenuOpen]);

  return (
    <header 
      className={`
        fixed top-0 left-0 right-0 
        bg-white/95 backdrop-blur-sm
        border-b border-gray-200 
        z-50
        transition-all duration-300
        ${atTop ? '' : 'shadow-md'}
      `}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center flex-shrink-0">
            <Link 
              to="/" 
              className="flex items-center space-x-2"
              aria-label="TrustMarket Home"
            >
              <div className="w-8 h-8 bg-primary-600 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <span className="text-xl font-bold text-gray-900 hidden sm:block">TrustMarket</span>
            </Link>
          </div>

          {/* Desktop Search Bar */}
          <div className="hidden md:flex flex-1 max-w-xl mx-8">
            <form onSubmit={handleSearch} className="w-full relative">
              <label htmlFor="search" className="sr-only">Search</label>
              <input
                id="search"
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search for cars, mobiles, furniture..."
                className="
                  w-full pl-10 pr-4 py-2 
                  border border-gray-300 rounded-lg
                  focus:ring-2 focus:ring-primary-500 focus:border-primary-500
                  transition-all duration-200
                  text-sm
                "
              />
              <MagnifyingGlassIcon className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
            </form>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-3">
            {isAuthenticated ? (
              <>
                {/* Create Listing Button */}
                <Link
                  to="/create-listing"
                  className="
                    inline-flex items-center px-4 py-2 
                    border border-transparent text-sm font-medium rounded-lg
                    text-white bg-primary-600 
                    hover:bg-primary-700 
                    focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500
                    transition-all duration-200
                    touch-manipulation
                  "
                >
                  <PlusIcon className="w-4 h-4 mr-1.5" />
                  Sell
                </Link>

                {/* Notifications */}
                <Link
                  to="/notifications"
                  className="
                    relative p-2 
                    text-gray-600 hover:text-gray-900 
                    focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 rounded-full
                    transition-colors duration-200
                  "
                  aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
                >
                  <BellIcon className="w-6 h-6" />
                  {unreadCount > 0 && (
                    <span 
                      className="
                        absolute -top-0.5 -right-0.5 
                        h-5 w-5 bg-error text-white text-xs font-bold rounded-full 
                        flex items-center justify-center
                        animate-pulse
                      "
                    >
                      {unreadCount > 99 ? '99+' : unreadCount}
                    </span>
                  )}
                </Link>

                {/* Profile Menu */}
                <div className="relative" ref={profileMenuRef}>
                  <button
                    onClick={() => setIsProfileMenuOpen(!isProfileMenuOpen)}
                    className="
                      flex items-center space-x-2 p-1.5 
                      rounded-full hover:bg-gray-100 
                      focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500
                      transition-colors duration-200
                    "
                    aria-expanded={isProfileMenuOpen}
                    aria-haspopup="true"
                  >
                    {user?.profilePhoto ? (
                      <img
                        src={user.profilePhoto}
                        alt={user.firstName}
                        className="w-8 h-8 rounded-full object-cover"
                      />
                    ) : (
                      <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center">
                        <UserIcon className="w-5 h-5 text-gray-600" />
                      </div>
                    )}
                    <span className="text-sm font-medium text-gray-700 hidden lg:block">
                      {user?.firstName}
                    </span>
                  </button>

                  {/* Profile Dropdown */}
                  {isProfileMenuOpen && (
                    <div 
                      className="
                        absolute right-0 mt-2 w-56 
                        bg-white rounded-xl shadow-lg 
                        ring-1 ring-black ring-opacity-5 
                        focus:outline-none
                        animate-fade-in
                      "
                      role="menu"
                      aria-orientation="vertical"
                    >
                      <div className="py-1">
                        <div className="px-4 py-3 border-b border-gray-100">
                          <p className="text-sm font-medium text-gray-900">
                            {user?.firstName} {user?.lastName}
                          </p>
                          <p className="text-sm text-gray-500 truncate">{user?.email}</p>
                          {user?.trustScore && (
                            <div className="flex items-center mt-2">
                              <span className="text-xs text-gray-500">Trust Score:</span>
                              <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                {user.trustScore.total}%
                              </span>
                            </div>
                          )}
                        </div>
                        
                        <Link
                          to="/profile"
                          className="
                            flex items-center px-4 py-2.5 
                            text-sm text-gray-700 hover:bg-gray-50 
                            transition-colors duration-150
                          "
                          onClick={() => setIsProfileMenuOpen(false)}
                          role="menuitem"
                        >
                          <UserIcon className="w-4 h-4 mr-3" />
                          Profile
                        </Link>
                        
                        <Link
                          to="/dashboard"
                          className="
                            flex items-center px-4 py-2.5 
                            text-sm text-gray-700 hover:bg-gray-50 
                            transition-colors duration-150
                          "
                          onClick={() => setIsProfileMenuOpen(false)}
                          role="menuitem"
                        >
                          <Cog6ToothIcon className="w-4 h-4 mr-3" />
                          Dashboard
                        </Link>
                        
                        <button
                          onClick={handleLogout}
                          className="
                            flex items-center w-full px-4 py-2.5 
                            text-sm text-gray-700 hover:bg-gray-50 
                            transition-colors duration-150
                          "
                          role="menuitem"
                        >
                          <ArrowRightOnRectangleIcon className="w-4 h-4 mr-3" />
                          Sign out
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <>
                <Link
                  to="/login"
                  className="
                    px-4 py-2 
                    text-gray-600 hover:text-gray-900 
                    text-sm font-medium rounded-lg
                    transition-colors duration-200
                  "
                >
                  Sign in
                </Link>
                <Link
                  to="/register"
                  className="
                    px-4 py-2 
                    text-white bg-primary-600 hover:bg-primary-700 
                    text-sm font-medium rounded-lg
                    transition-colors duration-200
                  "
                >
                  Sign up
                </Link>
              </>
            )}
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={toggleMenu}
              className="
                p-2 rounded-lg 
                text-gray-600 hover:text-gray-900 hover:bg-gray-100 
                focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-500
                transition-colors duration-200
              "
              aria-expanded={isMenuOpen}
              aria-controls="mobile-menu"
              aria-label={isMenuOpen ? 'Close menu' : 'Open menu'}
            >
              {isMenuOpen ? (
                <XMarkIcon className="h-6 w-6" />
              ) : (
                <Bars3Icon className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Search Bar */}
      <div className="md:hidden px-4 pb-3">
        <form onSubmit={handleSearch}>
          <label htmlFor="mobile-search" className="sr-only">Search</label>
          <div className="relative">
            <input
              id="mobile-search"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search for items..."
              className="
                w-full pl-10 pr-4 py-2.5 
                border border-gray-300 rounded-lg
                focus:ring-2 focus:ring-primary-500 focus:border-primary-500
                transition-all duration-200 text-base
              />
            <MagnifyingGlassIcon className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
          </div>
        </form>
      </div>

      {/* Mobile Navigation Menu */}
      {isMenuOpen && (
        <div 
          id="mobile-menu"
          className="md:hidden"
          ref={menuRef}
        >
          <div className="px-2 pt-2 pb-3 space-y-1 bg-white border-t border-gray-200">
            {isAuthenticated ? (
              <>
                <MobileNavLink
                  to="/"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                    </svg>
                  }
                >
                  Home
                </MobileNavLink>
                
                <MobileNavLink
                  to="/create-listing"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/create-listing')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                  }
                >
                  Create Listing
                </MobileNavLink>
                
                <MobileNavLink
                  to="/messages"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/messages')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                    </svg>
                  }
                  badge={unreadCount}
                >
                  Messages
                </MobileNavLink>
                
                <MobileNavLink
                  to="/profile"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/profile')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                  }
                >
                  Profile
                </MobileNavLink>
                
                <MobileNavLink
                  to="/dashboard"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/dashboard')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                    </svg>
                  }
                >
                  Dashboard
                </MobileNavLink>
                
                <button
                  onClick={handleLogout}
                  className="
                    flex items-center w-full px-3 py-3 
                    text-base font-medium rounded-lg
                    text-gray-600 hover:text-gray-900 hover:bg-gray-50
                    transition-colors duration-200
                  "
                >
                  <ArrowRightOnRectangleIcon className="w-5 h-5 mr-3" />
                  Sign out
                </button>
              </>
            ) : (
              <>
                <MobileNavLink
                  to="/login"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/login')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                    </svg>
                  }
                >
                  Sign in
                </MobileNavLink>
                
                <Link
                  to="/register"
                  onClick={() => setIsMenuOpen(false)}
                  className="
                    flex items-center mx-2 px-4 py-3 
                    text-base font-medium rounded-lg
                    text-white bg-primary-600 hover:bg-primary-700
                    transition-colors duration-200
                  "
                >
                  Sign up
                </Link>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
});

// Mobile navigation link component
const MobileNavLink = memo(({ to, onClick, isActive, icon, children, badge }) => (
  <Link
    to={to}
    onClick={onClick}
    className={`
      flex items-center justify-between px-3 py-3 
      text-base font-medium rounded-lg
      transition-colors duration-200
      ${isActive 
        ? 'text-primary-700 bg-primary-50' 
        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
      }
    `}
    aria-current={isActive ? 'page' : undefined}
  >
    <div className="flex items-center">
      {icon}
      <span className="ml-3">{children}</span>
    </div>
    {badge > 0 && (
      <span className="bg-error text-white text-xs font-bold rounded-full px-2 py-0.5">
        {badge > 99 ? '99+' : badge}
      </span>
    )}
  </Link>
));

MobileNavLink.displayName = 'MobileNavLink';

// Display name for debugging
Header.displayName = 'Header';

export default Header;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/components/layout/Layout.js

```javascript
import React from 'react';
import { Link, Outlet } from 'react-router-dom';

const Layout = () => {
  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200 fixed top-0 left-0 right-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-bold text-blue-600">TrustMarket</h1>
            </div>
            <nav className="hidden md:flex space-x-8">
              <Link to="/" className="text-gray-700 hover:text-blue-600">Home</Link>
              <Link to="/search" className="text-gray-700 hover:text-blue-600">Search</Link>
              <Link to="/dashboard" className="text-gray-700 hover:text-blue-600">Dashboard</Link>
            </nav>
            <div className="flex items-center space-x-4">
              <Link to="/login" className="text-gray-700 hover:text-blue-600">Login</Link>
              <Link to="/register" className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                Sign Up
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content - Use Outlet for nested routes */}
      <main className="flex-1 pt-16">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-600">
            <p>&copy; 2024 TrustMarket. All rights reserved.</p>
            <p className="text-sm mt-2">India's Safest P2P Marketplace</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/components/layout/MobileLayout.js

```javascript
import React from 'react';
import { useNavigate } from 'react-router-dom';

const MobileLayout = ({ children }) => {
  const navigate = useNavigate();

  const handleBack = () => {
    if (window.history.length > 1) {
      navigate(-1);
    } else {
      navigate('/');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Mobile Header */}
      <header className="fixed top-0 left-0 right-0 bg-white border-b border-gray-200 z-50">
        <div className="flex items-center justify-between px-4 h-14">
          <button
            onClick={handleBack}
            className="p-2 -ml-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-full transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <h1 className="text-lg font-semibold text-gray-900">TrustMarket</h1>
          <div className="w-9"></div> {/* Spacer for centering */}
        </div>
      </header>
      
      {/* Main Content */}
      <main className="flex-1 pt-14 pb-16">
        {children}
      </main>
      
      {/* Bottom Navigation */}
      <nav className="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 z-50">
        <div className="flex items-center justify-around px-2 py-1">
          <button
            onClick={() => navigate('/')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-gray-600 hover:text-blue-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
            </svg>
            <span className="mt-1">Home</span>
          </button>
          
          <button
            onClick={() => navigate('/search')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-gray-600 hover:text-blue-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span className="mt-1">Search</span>
          </button>
          
          <button
            onClick={() => navigate('/create-listing')}
            className="relative -top-4 w-14 h-14 bg-blue-600 rounded-full flex items-center justify-center shadow-lg transition-transform active:scale-95"
          >
            <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
            </svg>
          </button>
          
          <button
            onClick={() => navigate('/messages')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-gray-600 hover:text-blue-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <span className="mt-1">Chat</span>
          </button>
          
          <button
            onClick={() => navigate('/profile')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-gray-600 hover:text-blue-600 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            <span className="mt-1">Profile</span>
          </button>
        </div>
      </nav>
    </div>
  );
};

export default MobileLayout;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/context/AuthContext.js

```javascript
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { apiService } from '../services/api';

// Create context
const AuthContext = createContext();

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    console.warn('useAuth was called outside of AuthProvider');
    return {
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      login: async () => ({ success: false, error: 'Context not initialized' }),
      register: async () => ({ success: false, error: 'Context not initialized' }),
      logout: async () => { },
      refreshUser: async () => { },
    };
  }
  return context;
};

// AuthProvider component
export const AuthProvider = ({ children }) => {
  const [state, setState] = useState({
    user: null,
    isAuthenticated: false,
    isLoading: true, // Start true to check for existing session
    error: null,
  });

  // Check for existing session on mount (cookie-based â€” call /auth/me)
  useEffect(() => {
    const checkSession = async () => {
      try {
        const response = await apiService.auth.me();
        if (response.data.success && response.data.data.user) {
          setState({
            user: response.data.data.user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } else {
          setState(prev => ({ ...prev, isLoading: false }));
        }
      } catch {
        // No valid session â€” that's fine, just mark as not authenticated
        setState(prev => ({ ...prev, isLoading: false }));
      }
    };

    checkSession();
  }, []);

  // Listen for session expired events (dispatched by api.js interceptor)
  useEffect(() => {
    const handleSessionExpired = () => {
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: 'Session expired. Please log in again.',
      });
    };

    window.addEventListener('auth:sessionExpired', handleSessionExpired);
    return () => window.removeEventListener('auth:sessionExpired', handleSessionExpired);
  }, []);

  // Login
  const login = useCallback(async (credentials) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await apiService.auth.login(credentials);

      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true };
      } else {
        setState(prev => ({
          ...prev,
          isLoading: false,
          error: response.data.error || 'Login failed',
        }));
        return { success: false, error: response.data.error };
      }
    } catch (error) {
      const message = error.response?.data?.error || 'Login failed. Please try again.';
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      return { success: false, error: message };
    }
  }, []);

  // Register
  const register = useCallback(async (userData) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await apiService.auth.register(userData);

      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true };
      } else {
        setState(prev => ({
          ...prev,
          isLoading: false,
          error: response.data.error || 'Registration failed',
        }));
        return { success: false, error: response.data.error };
      }
    } catch (error) {
      const message = error.response?.data?.error || 'Registration failed. Please try again.';
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      return { success: false, error: message };
    }
  }, []);

  // Logout
  const logout = useCallback(async () => {
    try {
      await apiService.auth.logout();
    } catch {
      // Even if the API call fails, clear local state
    }

    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  }, []);

  // Refresh user data (e.g., after profile update)
  const refreshUser = useCallback(async () => {
    try {
      const response = await apiService.auth.me();
      if (response.data.success && response.data.data.user) {
        setState(prev => ({
          ...prev,
          user: response.data.data.user,
        }));
      }
    } catch {
      // Silently fail â€” user data just won't be refreshed
    }
  }, []);

  // Google Login
  const googleLogin = useCallback(async (credential) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    try {
      const response = await apiService.auth.google(credential);
      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true, isNewUser: response.data.data.isNewUser };
      }
      setState(prev => ({ ...prev, isLoading: false, error: 'Google login failed' }));
      return { success: false, error: 'Google login failed' };
    } catch (error) {
      const message = error.response?.data?.error || 'Google login failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      return { success: false, error: message };
    }
  }, []);

  // OTP Login (verify step)
  const otpLogin = useCallback(async (phone, otp) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    try {
      const response = await apiService.auth.otpVerify(phone, otp);
      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true };
      }
      setState(prev => ({ ...prev, isLoading: false, error: 'OTP verification failed' }));
      return { success: false, error: 'OTP verification failed' };
    } catch (error) {
      const message = error.response?.data?.error || 'OTP verification failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      return { success: false, error: message };
    }
  }, []);

  const value = {
    ...state,
    login,
    register,
    logout,
    refreshUser,
    googleLogin,
    otpLogin,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/context/NotificationContext.js

```javascript
import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { toast } from 'react-hot-toast';

const NotificationContext = createContext();

export const useNotification = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
};

// Action types
const NOTIFICATION_ACTIONS = {
  ADD_NOTIFICATION: 'ADD_NOTIFICATION',
  REMOVE_NOTIFICATION: 'REMOVE_NOTIFICATION',
  MARK_AS_READ: 'MARK_AS_READ',
  CLEAR_ALL: 'CLEAR_ALL',
  SET_PERMISSION: 'SET_PERMISSION',
};

// Initial state
const initialState = {
  notifications: [],
  unreadCount: 0,
  permission: 'default', // 'default', 'granted', 'denied'
  isLoading: false,
};

// Reducer
const notificationReducer = (state, action) => {
  switch (action.type) {
    case NOTIFICATION_ACTIONS.ADD_NOTIFICATION:
      const newNotification = {
        id: action.payload.id || Date.now().toString(),
        ...action.payload,
        timestamp: new Date(),
        read: false,
      };
      
      return {
        ...state,
        notifications: [newNotification, ...state.notifications],
        unreadCount: state.unreadCount + 1,
      };

    case NOTIFICATION_ACTIONS.REMOVE_NOTIFICATION:
      const notificationToRemove = state.notifications.find(n => n.id === action.payload);
      
      return {
        ...state,
        notifications: state.notifications.filter(n => n.id !== action.payload),
        unreadCount: notificationToRemove && !notificationToRemove.read 
          ? state.unreadCount - 1 
          : state.unreadCount,
      };

    case NOTIFICATION_ACTIONS.MARK_AS_READ:
      return {
        ...state,
        notifications: state.notifications.map(notification =>
          notification.id === action.payload
            ? { ...notification, read: true }
            : notification
        ),
        unreadCount: Math.max(0, state.unreadCount - 1),
      };

    case NOTIFICATION_ACTIONS.CLEAR_ALL:
      return {
        ...state,
        notifications: [],
        unreadCount: 0,
      };

    case NOTIFICATION_ACTIONS.SET_PERMISSION:
      return {
        ...state,
        permission: action.payload,
      };

    default:
      return state;
  }
};

export const NotificationProvider = ({ children }) => {
  const [state, dispatch] = useReducer(notificationReducer, initialState);

  // Check notification permission on mount
  useEffect(() => {
    if ('Notification' in window) {
      dispatch({
        type: NOTIFICATION_ACTIONS.SET_PERMISSION,
        payload: Notification.permission,
      });
    }
  }, []);

  // Request notification permission
  const requestPermission = async () => {
    if (!('Notification' in window)) {
      toast.error('Notifications are not supported in this browser');
      return false;
    }

    try {
      const permission = await Notification.requestPermission();
      
      dispatch({
        type: NOTIFICATION_ACTIONS.SET_PERMISSION,
        payload: permission,
      });

      if (permission === 'granted') {
        toast.success('Notifications enabled successfully!');
        return true;
      } else {
        toast.error('Notification permission denied');
        return false;
      }
    } catch (error) {
      console.error('Failed to request notification permission:', error);
      toast.error('Failed to enable notifications');
      return false;
    }
  };

  // Show browser notification
  const showBrowserNotification = (title, options = {}) => {
    if (!('Notification' in window) || state.permission !== 'granted') {
      return false;
    }

    try {
      const notification = new Notification(title, {
        icon: options.icon || '/icons/icon-192.png',
        badge: '/icons/badge-72.png',
        image: options.image,
        tag: options.tag || 'trustmarket-notification',
        requireInteraction: options.requireInteraction || false,
        silent: options.silent || false,
        ...options,
      });

      // Auto-close after 5 seconds unless requireInteraction is true
      if (!options.requireInteraction) {
        setTimeout(() => {
          notification.close();
        }, 5000);
      }

      // Handle notification click
      notification.onclick = () => {
        window.focus();
        notification.close();
        
        // Navigate to specific page if URL provided
        if (options.url) {
          window.location.href = options.url;
        }
      };

      return true;
    } catch (error) {
      console.error('Failed to show browser notification:', error);
      return false;
    }
  };

  // Add notification
  const addNotification = (notification) => {
    const id = notification.id || Date.now().toString();
    
    dispatch({
      type: NOTIFICATION_ACTIONS.ADD_NOTIFICATION,
      payload: { ...notification, id },
    });

    // Show toast notification
    showToast(notification);

    // Show browser notification if enabled and not in foreground
    if (document.hidden && notification.browserNotification !== false) {
      showBrowserNotification(notification.title, {
        body: notification.message,
        icon: notification.icon,
        image: notification.image,
        tag: notification.tag || `notification-${id}`,
        url: notification.url,
        requireInteraction: notification.requireInteraction,
      });
    }

    return id;
  };

  // Show toast notification
  const showToast = (notification) => {
    const { type = 'info', message, title, duration, ...toastOptions } = notification;

    switch (type) {
      case 'success':
        toast.success(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 3000,
            icon: notification.icon || 'âœ…',
            ...toastOptions,
          }
        );
        break;

      case 'error':
        toast.error(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 5000,
            icon: notification.icon || 'âŒ',
            ...toastOptions,
          }
        );
        break;

      case 'warning':
        toast(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 4000,
            icon: notification.icon || 'âš ï¸',
            ...toastOptions,
          }
        );
        break;

      case 'loading':
        toast.loading(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            ...toastOptions,
          }
        );
        break;

      default:
        toast(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 4000,
            icon: notification.icon || 'ðŸ””',
            ...toastOptions,
          }
        );
    }
  };

  // Remove notification
  const removeNotification = (id) => {
    dispatch({
      type: NOTIFICATION_ACTIONS.REMOVE_NOTIFICATION,
      payload: id,
    });
  };

  // Mark notification as read
  const markAsRead = (id) => {
    dispatch({
      type: NOTIFICATION_ACTIONS.MARK_AS_READ,
      payload: id,
    });
  };

  // Mark all as read
  const markAllAsRead = () => {
    state.notifications.forEach(notification => {
      if (!notification.read) {
        markAsRead(notification.id);
      }
    });
  };

  // Clear all notifications
  const clearAll = () => {
    dispatch({
      type: NOTIFICATION_ACTIONS.CLEAR_ALL,
    });
  };

  // Utility functions for common notification types
  const showSuccess = (message, title, options = {}) => {
    return addNotification({
      type: 'success',
      message,
      title,
      ...options,
    });
  };

  const showError = (message, title, options = {}) => {
    return addNotification({
      type: 'error',
      message,
      title,
      ...options,
    });
  };

  const showWarning = (message, title, options = {}) => {
    return addNotification({
      type: 'warning',
      message,
      title,
      ...options,
    });
  };

  const showInfo = (message, title, options = {}) => {
    return addNotification({
      type: 'info',
      message,
      title,
      ...options,
    });
  };

  const showLoading = (message, title, options = {}) => {
    return addNotification({
      type: 'loading',
      message,
      title,
      ...options,
    });
  };

  // Specialized notification types
  const showTrustScoreUpdate = (oldScore, newScore, level) => {
    const improved = newScore > oldScore;
    
    return addNotification({
      type: improved ? 'success' : 'info',
      message: `Your trust score ${improved ? 'increased' : 'updated'} to ${newScore}`,
      title: improved ? 'Trust Score Improved!' : 'Trust Score Updated',
      icon: improved ? 'ðŸ“ˆ' : 'ðŸ“Š',
      duration: 5000,
      tag: 'trust-score-update',
    });
  };

  const showSafetyAlert = (message, severity = 'medium', options = {}) => {
    const alertOptions = {
      type: 'error',
      message,
      title: 'Safety Alert',
      icon: severity === 'high' ? 'ðŸš¨' : 'âš ï¸',
      duration: severity === 'high' ? 10000 : 6000,
      requireInteraction: severity === 'high',
      ...options,
    };

    return addNotification(alertOptions);
  };

  const showNewMessage = (senderName, preview, options = {}) => {
    return addNotification({
      type: 'info',
      message: preview,
      title: `New message from ${senderName}`,
      icon: 'ðŸ’¬',
      duration: 4000,
      tag: 'new-message',
      ...options,
    });
  };

  const showListingUpdate = (action, title, options = {}) => {
    const messages = {
      created: 'Your listing has been created successfully',
      updated: 'Your listing has been updated',
      sold: 'Congratulations! Your listing has been sold',
      expired: 'Your listing has expired',
    };

    return addNotification({
      type: action === 'sold' ? 'success' : 'info',
      message: messages[action] || `Your listing "${title}" has been ${action}`,
      title: action === 'sold' ? 'Listing Sold!' : 'Listing Update',
      icon: action === 'sold' ? 'ðŸŽ‰' : 'ðŸ“',
      duration: 5000,
      tag: 'listing-update',
      ...options,
    });
  };

  const showVerificationUpdate = (type, status, options = {}) => {
    const messages = {
      phone: {
        verified: 'Phone number verified successfully!',
        pending: 'Phone verification is being processed',
      },
      id: {
        verified: 'ID verification approved!',
        pending: 'ID verification is being reviewed',
        rejected: 'ID verification was rejected',
      },
    };

    return addNotification({
      type: status === 'verified' ? 'success' : status === 'rejected' ? 'error' : 'info',
      message: messages[type]?.[status] || `${type} verification ${status}`,
      title: status === 'verified' ? 'Verification Complete!' : 'Verification Update',
      icon: status === 'verified' ? 'âœ…' : status === 'rejected' ? 'âŒ' : 'ðŸ”„',
      duration: 6000,
      tag: 'verification-update',
      ...options,
    });
  };

  // Context value
  const value = {
    // State
    ...state,
    
    // Permission
    requestPermission,
    
    // Actions
    addNotification,
    removeNotification,
    markAsRead,
    markAllAsRead,
    clearAll,
    
    // Browser notifications
    showBrowserNotification,
    
    // Toast notifications
    showToast,
    
    // Utility methods
    showSuccess,
    showError,
    showWarning,
    showInfo,
    showLoading,
    
    // Specialized notifications
    showTrustScoreUpdate,
    showSafetyAlert,
    showNewMessage,
    showListingUpdate,
    showVerificationUpdate,
  };

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
};

export default NotificationContext;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/context/SocketContext.js

```javascript
import React, { createContext, useContext, useState, useEffect } from 'react';

// Create context
const SocketContext = createContext();

// Custom hook to use socket context
export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    console.warn('useSocket was called outside of SocketProvider');
    return {
      isConnected: false,
      unreadCount: 0,
      onlineUsers: [],
      typingUsers: {},
      safetyAlerts: [],
      sendMessage: async () => {},
      joinConversation: () => {},
      leaveConversation: () => {},
    };
  }
  return context;
};

// SocketProvider component
export const SocketProvider = ({ children }) => {
  const [state, setState] = useState({
    isConnected: false,
    unreadCount: 0,
    onlineUsers: [],
    typingUsers: {},
    safetyAlerts: [],
  });

  // Mock connection for demo
  const connectSocket = () => {
    console.log('Connecting to socket...');
    setState(prev => ({ ...prev, isConnected: true }));
  };

  const disconnectSocket = () => {
    console.log('Disconnecting from socket...');
    setState(prev => ({ ...prev, isConnected: false }));
  };

  const joinConversation = (conversationId) => {
    console.log('Joining conversation:', conversationId);
  };

  const leaveConversation = (conversationId) => {
    console.log('Leaving conversation:', conversationId);
  };

  const sendMessage = async (messageData) => {
    console.log('Sending message:', messageData);
    // Simulate successful send
    return { success: true };
  };

  const startTyping = (conversationId) => {
    console.log('Start typing in conversation:', conversationId);
  };

  const stopTyping = (conversationId) => {
    console.log('Stop typing in conversation:', conversationId);
  };

  const markMessageRead = (messageId) => {
    console.log('Mark message as read:', messageId);
    setState(prev => ({ ...prev, unreadCount: Math.max(0, prev.unreadCount - 1) }));
  };

  const reportSuspiciousActivity = (data) => {
    console.log('Reporting suspicious activity:', data);
  };

  const requestTrustScoreUpdate = () => {
    console.log('Requesting trust score update');
  };

  const requestNotificationPermission = async () => {
    if ('Notification' in window) {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }
    return false;
  };

  const clearUnreadCount = () => {
    setState(prev => ({ ...prev, unreadCount: 0 }));
  };

  const dismissSafetyAlert = (index) => {
    setState(prev => ({
      ...prev,
      safetyAlerts: prev.safetyAlerts.filter((_, i) => i !== index)
    }));
  };

  const isUserOnline = (userId) => {
    return state.onlineUsers.includes(userId);
  };

  const getTypingUsers = (conversationId) => {
    return Object.values(state.typingUsers).filter(user => user.conversationId === conversationId);
  };

  // Mock connection on mount
  useEffect(() => {
    const timer = setTimeout(() => {
      connectSocket();
    }, 1000);

    return () => {
      clearTimeout(timer);
      disconnectSocket();
    };
  }, []);

  const value = {
    ...state,
    joinConversation,
    leaveConversation,
    sendMessage,
    startTyping,
    stopTyping,
    markMessageRead,
    reportSuspiciousActivity,
    requestTrustScoreUpdate,
    requestNotificationPermission,
    clearUnreadCount,
    dismissSafetyAlert,
    isUserOnline,
    getTypingUsers,
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
};

export default SocketContext;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/auth/Login.js

```javascript
import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { apiService } from '../../services/api';

const Login = () => {
  const [activeTab, setActiveTab] = useState('email'); // 'email' | 'phone'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [phone, setPhone] = useState('');
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otpTimer, setOtpTimer] = useState(0);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();
  const { login, googleLogin, otpLogin } = useAuth();

  // OTP countdown timer
  useEffect(() => {
    if (otpTimer > 0) {
      const interval = setInterval(() => setOtpTimer(t => t - 1), 1000);
      return () => clearInterval(interval);
    }
  }, [otpTimer]);

  // Load Google Sign-In script
  useEffect(() => {
    const clientId = process.env.REACT_APP_GOOGLE_CLIENT_ID;
    if (!clientId) return;

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => {
      window.google?.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleResponse,
      });
      window.google?.accounts.id.renderButton(
        document.getElementById('google-signin-btn'),
        {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'signin_with',
          shape: 'rectangular',
        }
      );
    };
    document.body.appendChild(script);
    return () => {
      document.body.removeChild(script);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleGoogleResponse = useCallback(async (response) => {
    setError('');
    setIsSubmitting(true);
    try {
      const result = await googleLogin(response.credential);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Google sign-in failed');
      }
    } catch {
      setError('Google sign-in failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate]);

  // Email/Password login
  const handleEmailLogin = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const result = await login({ email, password });
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Login failed. Please try again.');
      }
    } catch {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Send OTP
  const handleSendOtp = async () => {
    setError('');
    if (!/^[6-9]\d{9}$/.test(phone)) {
      setError('Enter a valid 10-digit Indian mobile number');
      return;
    }
    setIsSubmitting(true);
    try {
      const response = await apiService.auth.otpSend(phone);
      if (response.data.success) {
        setOtpSent(true);
        setOtpTimer(60);
        if (response.data.demoOtp) {
          setOtp(response.data.demoOtp); // Auto-fill in dev mode
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send OTP');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Verify OTP
  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const result = await otpLogin(phone, otp);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'OTP verification failed');
      }
    } catch {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const tabClass = (tab) =>
    `flex-1 py-2.5 text-sm font-medium rounded-md transition-all ${activeTab === tab
      ? 'bg-blue-600 text-white shadow-sm'
      : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
    }`;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-6">
        <div>
          <h2 className="text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Welcome back to TrustMarket
          </p>
        </div>

        {/* Google Sign-In */}
        <div className="flex justify-center">
          <div id="google-signin-btn" className="w-full"></div>
        </div>

        {!process.env.REACT_APP_GOOGLE_CLIENT_ID && (
          <button
            disabled
            className="w-full flex items-center justify-center gap-3 py-2.5 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 cursor-not-allowed"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
            </svg>
            Google Sign-In (set up GOOGLE_CLIENT_ID)
          </button>
        )}

        {/* Divider */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-gray-50 text-gray-500">or continue with</span>
          </div>
        </div>

        {/* Tabs: Email | Phone */}
        <div className="flex bg-gray-100 rounded-lg p-1 gap-1">
          <button onClick={() => { setActiveTab('email'); setError(''); }} className={tabClass('email')}>
            Email & Password
          </button>
          <button onClick={() => { setActiveTab('phone'); setError(''); }} className={tabClass('phone')}>
            Phone & OTP
          </button>
        </div>

        {/* Error display */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded relative text-sm" role="alert">
            {error}
          </div>
        )}

        {/* Email/Password Form */}
        {activeTab === 'email' && (
          <form onSubmit={handleEmailLogin} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email</label>
              <input
                id="email" type="email" required autoComplete="email"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="you@example.com"
                value={email} onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
              <input
                id="password" type="password" required autoComplete="current-password"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Enter your password"
                value={password} onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <button
              type="submit" disabled={isSubmitting}
              className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {isSubmitting ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        )}

        {/* Phone/OTP Form */}
        {activeTab === 'phone' && (
          <form onSubmit={handleVerifyOtp} className="space-y-4">
            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-gray-700">Phone Number</label>
              <div className="mt-1 flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-500 bg-gray-100 border border-r-0 border-gray-300 rounded-l-md">
                  +91
                </span>
                <input
                  id="phone" type="tel" required maxLength={10}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-r-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="10-digit mobile number"
                  value={phone} onChange={(e) => setPhone(e.target.value.replace(/\D/g, ''))}
                  disabled={otpSent}
                />
              </div>
            </div>

            {!otpSent ? (
              <button
                type="button" onClick={handleSendOtp} disabled={isSubmitting}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                {isSubmitting ? 'Sending...' : 'Send OTP'}
              </button>
            ) : (
              <>
                <div>
                  <label htmlFor="otp" className="block text-sm font-medium text-gray-700">Enter OTP</label>
                  <input
                    id="otp" type="text" required maxLength={6}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-center tracking-[0.5em] text-lg font-mono"
                    placeholder="â— â— â— â— â— â—"
                    value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                    autoFocus
                  />
                  <div className="mt-2 flex justify-between items-center text-xs text-gray-500">
                    <span>OTP sent to +91 {phone}</span>
                    {otpTimer > 0 ? (
                      <span>Resend in {otpTimer}s</span>
                    ) : (
                      <button type="button" onClick={handleSendOtp} className="text-blue-600 hover:underline font-medium">
                        Resend OTP
                      </button>
                    )}
                  </div>
                </div>
                <button
                  type="submit" disabled={isSubmitting || otp.length < 6}
                  className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  {isSubmitting ? 'Verifying...' : 'Verify & Sign in'}
                </button>
                <button
                  type="button"
                  onClick={() => { setOtpSent(false); setOtp(''); setPhone(''); setOtpTimer(0); }}
                  className="w-full text-sm text-gray-500 hover:text-gray-700"
                >
                  â† Change phone number
                </button>
              </>
            )}
          </form>
        )}

        <div className="text-center">
          <p className="text-sm text-gray-600">
            Don't have an account?{' '}
            <Link to="/register" className="font-medium text-blue-600 hover:text-blue-500">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/auth/Register.js

```javascript
import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { apiService } from '../../services/api';

const Register = () => {
  const [activeTab, setActiveTab] = useState('email'); // 'email' | 'phone'
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: ''
  });
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otpTimer, setOtpTimer] = useState(0);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();
  const { register, googleLogin, otpLogin } = useAuth();

  // OTP countdown timer
  useEffect(() => {
    if (otpTimer > 0) {
      const interval = setInterval(() => setOtpTimer(t => t - 1), 1000);
      return () => clearInterval(interval);
    }
  }, [otpTimer]);

  // Load Google Sign-In script
  useEffect(() => {
    const clientId = process.env.REACT_APP_GOOGLE_CLIENT_ID;
    if (!clientId) return;

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => {
      window.google?.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleResponse,
      });
      window.google?.accounts.id.renderButton(
        document.getElementById('google-signup-btn'),
        {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'signup_with',
          shape: 'rectangular',
        }
      );
    };
    document.body.appendChild(script);
    return () => {
      document.body.removeChild(script);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleGoogleResponse = useCallback(async (response) => {
    setError('');
    setIsSubmitting(true);
    try {
      const result = await googleLogin(response.credential);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Google sign-up failed');
      }
    } catch {
      setError('Google sign-up failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  // Email/Password register
  const handleEmailRegister = async (e) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (formData.phone && !/^[6-9]\d{9}$/.test(formData.phone)) {
      setError('Please enter a valid 10-digit Indian mobile number');
      return;
    }

    setIsSubmitting(true);
    try {
      const result = await register({
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        phone: formData.phone,
        password: formData.password
      });
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Registration failed.');
      }
    } catch {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Send OTP for phone registration
  const handleSendOtp = async () => {
    setError('');
    if (!/^[6-9]\d{9}$/.test(formData.phone)) {
      setError('Enter a valid 10-digit Indian mobile number');
      return;
    }
    setIsSubmitting(true);
    try {
      const response = await apiService.auth.otpSend(formData.phone);
      if (response.data.success) {
        setOtpSent(true);
        setOtpTimer(60);
        if (response.data.demoOtp) {
          setOtp(response.data.demoOtp);
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send OTP');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Verify OTP for phone registration
  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const result = await otpLogin(formData.phone, otp);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'OTP verification failed');
      }
    } catch {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const tabClass = (tab) =>
    `flex-1 py-2.5 text-sm font-medium rounded-md transition-all ${activeTab === tab
      ? 'bg-blue-600 text-white shadow-sm'
      : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
    }`;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-6">
        <div>
          <h2 className="text-center text-3xl font-extrabold text-gray-900">
            Create your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Join India's safest P2P marketplace
          </p>
        </div>

        {/* Google Sign-Up */}
        <div className="flex justify-center">
          <div id="google-signup-btn" className="w-full"></div>
        </div>

        {!process.env.REACT_APP_GOOGLE_CLIENT_ID && (
          <button
            disabled
            className="w-full flex items-center justify-center gap-3 py-2.5 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 cursor-not-allowed"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
            </svg>
            Google Sign-Up (set up GOOGLE_CLIENT_ID)
          </button>
        )}

        {/* Divider */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-gray-50 text-gray-500">or register with</span>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex bg-gray-100 rounded-lg p-1 gap-1">
          <button onClick={() => { setActiveTab('email'); setError(''); }} className={tabClass('email')}>
            Email & Password
          </button>
          <button onClick={() => { setActiveTab('phone'); setError(''); }} className={tabClass('phone')}>
            Phone & OTP
          </button>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm" role="alert">
            {error}
          </div>
        )}

        {/* Email/Password Registration */}
        {activeTab === 'email' && (
          <form onSubmit={handleEmailRegister} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-gray-700">First Name</label>
                <input id="firstName" name="firstName" type="text" required
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="First name" value={formData.firstName} onChange={handleChange} />
              </div>
              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-gray-700">Last Name</label>
                <input id="lastName" name="lastName" type="text" required
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Last name" value={formData.lastName} onChange={handleChange} />
              </div>
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email</label>
              <input id="email" name="email" type="email" required autoComplete="email"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="you@example.com" value={formData.email} onChange={handleChange} />
            </div>
            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-gray-700">Phone (optional)</label>
              <div className="mt-1 flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-500 bg-gray-100 border border-r-0 border-gray-300 rounded-l-md">+91</span>
                <input id="phone" name="phone" type="tel" maxLength={10}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-r-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="10-digit number" value={formData.phone} onChange={handleChange} />
              </div>
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
              <input id="password" name="password" type="password" required minLength={8} autoComplete="new-password"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Min 8 chars, upper, lower & number" value={formData.password} onChange={handleChange} />
            </div>
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">Confirm Password</label>
              <input id="confirmPassword" name="confirmPassword" type="password" required autoComplete="new-password"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Confirm password" value={formData.confirmPassword} onChange={handleChange} />
            </div>
            <button type="submit" disabled={isSubmitting}
              className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {isSubmitting ? 'Creating Account...' : 'Create Account'}
            </button>
          </form>
        )}

        {/* Phone/OTP Registration */}
        {activeTab === 'phone' && (
          <form onSubmit={handleVerifyOtp} className="space-y-4">
            <div>
              <label htmlFor="reg-phone" className="block text-sm font-medium text-gray-700">Phone Number</label>
              <div className="mt-1 flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-500 bg-gray-100 border border-r-0 border-gray-300 rounded-l-md">+91</span>
                <input id="reg-phone" type="tel" required maxLength={10}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-r-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="10-digit mobile number"
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value.replace(/\D/g, '') })}
                  disabled={otpSent}
                />
              </div>
              <p className="mt-1 text-xs text-gray-500">We'll create your account and verify your number</p>
            </div>

            {!otpSent ? (
              <button type="button" onClick={handleSendOtp} disabled={isSubmitting}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
              >
                {isSubmitting ? 'Sending...' : 'Send OTP'}
              </button>
            ) : (
              <>
                <div>
                  <label htmlFor="reg-otp" className="block text-sm font-medium text-gray-700">Enter OTP</label>
                  <input id="reg-otp" type="text" required maxLength={6}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-center tracking-[0.5em] text-lg font-mono"
                    placeholder="â— â— â— â— â— â—"
                    value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))} autoFocus
                  />
                  <div className="mt-2 flex justify-between items-center text-xs text-gray-500">
                    <span>OTP sent to +91 {formData.phone}</span>
                    {otpTimer > 0 ? (
                      <span>Resend in {otpTimer}s</span>
                    ) : (
                      <button type="button" onClick={handleSendOtp} className="text-blue-600 hover:underline font-medium">Resend OTP</button>
                    )}
                  </div>
                </div>
                <button type="submit" disabled={isSubmitting || otp.length < 6}
                  className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
                >
                  {isSubmitting ? 'Verifying...' : 'Verify & Create Account'}
                </button>
                <button type="button"
                  onClick={() => { setOtpSent(false); setOtp(''); setOtpTimer(0); }}
                  className="w-full text-sm text-gray-500 hover:text-gray-700"
                >
                  â† Change phone number
                </button>
              </>
            )}
          </form>
        )}

        <div className="text-center">
          <p className="text-sm text-gray-600">
            Already have an account?{' '}
            <Link to="/login" className="font-medium text-blue-600 hover:text-blue-500">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/CreateListing.js

```javascript
import React from 'react';

const CreateListing = () => {
  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow p-6">
        <h1 className="text-2xl font-bold text-gray-900 mb-6">Create New Listing</h1>
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Product Name
              </label>
              <input
                type="text"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter product name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Price (â‚¹)
              </label>
              <input
                type="number"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter price"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Description
            </label>
            <textarea
              rows="4"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="Describe your product"
            ></textarea>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Category
            </label>
            <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500">
              <option value="electronics">Electronics</option>
              <option value="vehicles">Vehicles</option>
              <option value="furniture">Furniture</option>
              <option value="books">Books</option>
              <option value="clothing">Clothing</option>
              <option value="services">Services</option>
              <option value="jobs">Jobs</option>
              <option value="real_estate">Real Estate</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div className="flex justify-end">
            <button className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 transition-colors">
              Create Listing
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CreateListing;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/Dashboard.js

```javascript
import React from 'react';

const Dashboard = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600">Manage your TrustMarket account</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
              <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-gray-900">24</p>
              <p className="text-sm text-gray-600">Active Listings</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
              <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-gray-900">18</p>
              <p className="text-sm text-gray-600">Completed Sales</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center">
              <svg className="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-gray-900">32</p>
              <p className="text-sm text-gray-600">Messages</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center">
              <svg className="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-gray-900">98%</p>
              <p className="text-sm text-gray-600">Trust Score</p>
            </div>
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold">Recent Activity</h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                  <span className="text-sm text-gray-600">Activity {i + 1}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold">Quick Actions</h3>
          </div>
          <div className="p-6 space-y-3">
            <button className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors">
              Create New Listing
            </button>
            <button className="w-full border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50 transition-colors">
              View Messages
            </button>
            <button className="w-full border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50 transition-colors">
              Edit Profile
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/Home.js

```javascript
import React from 'react';

const Home = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">
          Welcome to TrustMarket
        </h1>
        <p className="text-xl text-gray-600 mb-8">
          India's Safest P2P Marketplace
        </p>
        <div className="bg-white rounded-lg shadow p-8">
          <h2 className="text-2xl font-semibold mb-4">Features</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold mb-2">Video Verification</h3>
              <p className="text-gray-600">All users verified through video calls</p>
            </div>
            <div className="text-center">
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold mb-2">Trust Scoring</h3>
              <p className="text-gray-600">Real-time trust scores for all users</p>
            </div>
            <div className="text-center">
              <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <svg className="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold mb-2">Safety Monitoring</h3>
              <p className="text-gray-600">24/7 safety and security monitoring</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/ListingDetails.js

```javascript
import React from 'react';
import { useParams } from 'react-router-dom';

const ListingDetails = () => {
  // eslint-disable-next-line no-unused-vars
  const { id } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 p-6">
          <div>
            <div className="bg-gray-200 rounded-lg h-64 flex items-center justify-center">
              <span className="text-gray-500">Product Image</span>
            </div>
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 mb-4">Product Title</h1>
            <p className="text-3xl font-bold text-blue-600 mb-4">â‚¹1,299</p>
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold mb-2">Description</h3>
                <p className="text-gray-600">This is a sample product description. The actual content will be loaded based on the listing ID.</p>
              </div>
              <div>
                <h3 className="text-lg font-semibold mb-2">Seller Information</h3>
                <p className="text-gray-600">Seller name and trust score will be displayed here.</p>
              </div>
              <div className="flex space-x-4">
                <button className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 transition-colors">
                  Contact Seller
                </button>
                <button className="border border-gray-300 text-gray-700 px-6 py-2 rounded-md hover:bg-gray-50 transition-colors">
                  Report Listing
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ListingDetails;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/Messages.js

```javascript
import React from 'react';
import { useParams } from 'react-router-dom';

const Messages = () => {
  // eslint-disable-next-line no-unused-vars
  const { conversationId } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="flex h-96">
          <div className="w-1/3 border-r border-gray-200">
            <div className="p-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold">Messages</h2>
            </div>
            <div className="overflow-y-auto h-80">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="p-4 border-b border-gray-100 hover:bg-gray-50 cursor-pointer">
                  <div className="flex items-center">
                    <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                      <span className="text-sm font-medium">U{i + 1}</span>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm font-medium text-gray-900">User {i + 1}</p>
                      <p className="text-xs text-gray-500">Last message...</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex-1 flex flex-col">
            <div className="p-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold">Conversation</h3>
            </div>
            <div className="flex-1 p-4 overflow-y-auto">
              <div className="space-y-4">
                <div className="flex">
                  <div className="bg-blue-100 rounded-lg px-3 py-2">
                    <p className="text-sm">Hello! I'm interested in your product.</p>
                  </div>
                </div>
                <div className="flex justify-end">
                  <div className="bg-gray-100 rounded-lg px-3 py-2">
                    <p className="text-sm">Hi! Thanks for your interest. It's available.</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="p-4 border-t border-gray-200">
              <div className="flex space-x-2">
                <input
                  type="text"
                  placeholder="Type a message..."
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
                <button className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                  Send
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Messages;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/NotFound.js

```javascript
import React from 'react';
import { Link } from 'react-router-dom';

const NotFound = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full text-center">
        <div className="mb-8">
          <div className="w-24 h-24 mx-auto bg-gray-200 rounded-full flex items-center justify-center mb-6">
            <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6-4h6m2 5.291A7.962 7.962 0 0112 15c-2.34 0-4.29-1.207-5.428-3.02L3 20l1.572-4.291A7.962 7.962 0 0112 15z" />
            </svg>
          </div>
          <h1 className="text-6xl font-bold text-gray-300 mb-4">404</h1>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Page Not Found</h2>
          <p className="text-gray-600 mb-8">
            Sorry, we couldn't find the page you're looking for. It might have been moved, deleted, or the URL might be incorrect.
          </p>
        </div>

        <div className="space-y-4">
          <Link
            to="/"
            className="block w-full bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 transition-colors font-medium"
          >
            Go to Homepage
          </Link>
          <button
            onClick={() => window.history.back()}
            className="block w-full border border-gray-300 text-gray-700 px-6 py-3 rounded-md hover:bg-gray-50 transition-colors font-medium"
          >
            Go Back
          </button>
        </div>

        <div className="mt-8 pt-6 border-t border-gray-200">
          <p className="text-sm text-gray-500">
            Need help? Visit our{' '}
            <button type="button" className="text-blue-600 hover:text-blue-500 bg-transparent border-none cursor-pointer">
              help center
            </button>{' '}
            or{' '}
            <button type="button" className="text-blue-600 hover:text-blue-500 bg-transparent border-none cursor-pointer">
              contact support
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/Premium.js

```javascript
import React from 'react';

const Premium = () => {
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-4">Upgrade to Premium</h1>
        <p className="text-lg text-gray-600">Get advanced features and boost your marketplace success</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white rounded-lg shadow border-2 border-gray-200 p-6">
          <div className="text-center mb-6">
            <h3 className="text-xl font-bold text-gray-900">Basic</h3>
            <div className="mt-4">
              <span className="text-4xl font-bold text-gray-900">Free</span>
            </div>
          </div>
          <ul className="space-y-3">
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Basic listing creation</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Standard messaging</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Basic verification</span>
            </li>
          </ul>
          <button className="w-full mt-6 bg-gray-100 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-200 transition-colors">
            Current Plan
          </button>
        </div>
        
        <div className="bg-white rounded-lg shadow-lg border-2 border-blue-500 p-6 relative">
          <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
            <span className="bg-blue-500 text-white px-4 py-1 rounded-full text-sm font-medium">Popular</span>
          </div>
          <div className="text-center mb-6">
            <h3 className="text-xl font-bold text-gray-900">Premium</h3>
            <div className="mt-4">
              <span className="text-4xl font-bold text-blue-600">â‚¹299</span>
              <span className="text-gray-600">/month</span>
            </div>
          </div>
          <ul className="space-y-3">
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Everything in Basic</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Priority listings</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Advanced analytics</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">24/7 support</span>
            </li>
          </ul>
          <button className="w-full mt-6 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors">
            Upgrade Now
          </button>
        </div>
        
        <div className="bg-white rounded-lg shadow border-2 border-gray-200 p-6">
          <div className="text-center mb-6">
            <h3 className="text-xl font-bold text-gray-900">Pro</h3>
            <div className="mt-4">
              <span className="text-4xl font-bold text-purple-600">â‚¹599</span>
              <span className="text-gray-600">/month</span>
            </div>
          </div>
          <ul className="space-y-3">
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Everything in Premium</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Unlimited listings</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">Custom branding</span>
            </li>
            <li className="flex items-center">
              <svg className="w-5 h-5 text-green-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span className="text-sm">API access</span>
            </li>
          </ul>
          <button className="w-full mt-6 bg-purple-600 text-white px-4 py-2 rounded-md hover:bg-purple-700 transition-colors">
            Upgrade Now
          </button>
        </div>
      </div>
    </div>
  );
};

export default Premium;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/Profile.js

```javascript
import React from 'react';
import { useParams } from 'react-router-dom';

const Profile = () => {
  // eslint-disable-next-line no-unused-vars
  const { userId } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center">
            <div className="w-16 h-16 bg-blue-500 rounded-full flex items-center justify-center">
              <span className="text-2xl font-bold text-white">U</span>
            </div>
            <div className="ml-4">
              <h1 className="text-2xl font-bold text-gray-900">John Doe</h1>
              <p className="text-gray-600">Verified User</p>
              <div className="flex items-center mt-1">
                <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs font-medium">
                  Trust Score: 98%
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">User Information</h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-gray-600">Member Since</span>
                  <span className="text-gray-900">January 2024</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Total Listings</span>
                  <span className="text-gray-900">24</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Successful Transactions</span>
                  <span className="text-gray-900">18</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Response Rate</span>
                  <span className="text-gray-900">95%</span>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-4">Recent Activity</h3>
              <div className="space-y-3">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                  <span className="text-sm text-gray-600">Listed "iPhone 13" - 2 hours ago</span>
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                  <span className="text-sm text-gray-600">Completed transaction - 1 day ago</span>
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mr-3"></div>
                  <span className="text-sm text-gray-600">Video verification completed - 2 days ago</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/pages/SearchResults.js

```javascript
import React from 'react';
import { useSearchParams } from 'react-router-dom';

const SearchResults = () => {
  const [searchParams] = useSearchParams();
  const query = searchParams.get('q') || '';

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">
          Search Results {query && `for "${query}"`}
        </h1>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="bg-white rounded-lg shadow overflow-hidden hover:shadow-md transition-shadow">
            <div className="bg-gray-200 h-48 flex items-center justify-center">
              <span className="text-gray-500">Product {i + 1}</span>
            </div>
            <div className="p-4">
              <h3 className="text-lg font-semibold mb-2">Sample Product {i + 1}</h3>
              <p className="text-2xl font-bold text-blue-600">â‚¹{(i + 1) * 299}</p>
              <div className="mt-2 flex items-center text-sm text-gray-500">
                <span>Trust Score: 95%</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SearchResults;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/services/api.js

```javascript
import axios from 'axios';
import { toast } from 'react-hot-toast';

// Create axios instance
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
  timeout: 30000, // 30 seconds
  withCredentials: true, // Send HttpOnly cookies with every request
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor (cookies are sent automatically via withCredentials)
api.interceptors.request.use(
  (config) => {
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh and errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 errors (unauthorized) â€” attempt silent token refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Attempt to refresh token â€” cookies are sent automatically
        await axios.post(
          `${process.env.REACT_APP_API_URL || 'http://localhost:5000/api'}/auth/refresh`,
          {},
          { withCredentials: true }
        );

        // Retry the original request (new cookie is already set by server)
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed â€” session expired, redirect to login
        if (!window.location.pathname.includes('/login') &&
          !window.location.pathname.includes('/register')) {
          window.dispatchEvent(new CustomEvent('auth:sessionExpired', {
            detail: { reason: 'token_refresh_failed' }
          }));
        }

        return Promise.reject(refreshError);
      }
    }

    // Handle network errors
    if (!error.response) {
      if (error.code === 'ECONNABORTED') {
        toast.error('Request timeout. Please try again.');
      } else if (error.message === 'Network Error') {
        toast.error('Network error. Please check your connection.');
      } else {
        toast.error('Something went wrong. Please try again.');
      }
      return Promise.reject(error);
    }

    // Handle specific error status codes
    const { status, data } = error.response;

    switch (status) {
      case 400:
        if (data.error) {
          if (typeof data.error === 'string') {
            toast.error(data.error);
          } else if (Array.isArray(data.error)) {
            data.error.forEach(err => toast.error(err));
          }
        }
        break;

      case 403:
        toast.error('Access denied. You do not have permission to perform this action.');
        break;

      case 404:
        toast.error(data.error || 'Resource not found.');
        break;

      case 429:
        toast.error('Too many requests. Please try again later.');
        break;

      case 500:
        toast.error('Server error. Please try again later.');
        break;

      default:
        if (data.error) {
          toast.error(data.error);
        }
    }

    return Promise.reject(error);
  }
);

// API service object with all endpoints
const apiService = {
  // Auth endpoints
  auth: {
    login: (credentials) => api.post('/auth/login', credentials),
    register: (userData) => api.post('/auth/register', userData),
    logout: () => api.post('/auth/logout'),
    logoutAll: () => api.post('/auth/logout-all'),
    refresh: () => api.post('/auth/refresh'),
    me: () => api.get('/auth/me'),
    verifyPhone: (otp) => api.post('/auth/verify-phone', { otp }),
    resendOTP: () => api.post('/auth/resend-otp'),
    forgotPassword: (email) => api.post('/auth/forgot-password', { email }),
    google: (credential) => api.post('/auth/google', { credential }),
    otpSend: (phone) => api.post('/auth/otp/send', { phone }),
    otpVerify: (phone, otp) => api.post('/auth/otp/verify', { phone, otp }),
  },

  // User endpoints
  users: {
    getProfile: () => api.get('/users/profile'),
    updateProfile: (data) => api.put('/users/profile', data),
    uploadPhoto: (formData) =>
      api.post('/users/upload-photo', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    getUser: (id) => api.get(`/users/${id}`),
    getUserListings: (id, params) => api.get(`/users/${id}/listings`, { params }),
    getUserStats: (id) => api.get(`/users/${id}/stats`),
    submitIDVerification: (data) => api.post('/users/verify-id', data),
    getTrustScoreHistory: () => api.get('/users/trust-score/history'),
    blockUser: (userId) => api.post(`/users/block/${userId}`),
    unblockUser: (userId) => api.delete(`/users/block/${userId}`),
  },

  // Listing endpoints
  listings: {
    getListings: (params) => api.get('/listings', { params }),
    getListing: (id) => api.get(`/listings/${id}`),
    createListing: (formData) =>
      api.post('/listings', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    updateListing: (id, formData) =>
      api.put(`/listings/${id}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    deleteListing: (id) => api.delete(`/listings/${id}`),
    inquireAboutListing: (id) => api.post(`/listings/${id}/inquire`),
    saveListing: (id) => api.post(`/listings/${id}/save`),
    reportListing: (id, data) => api.post(`/listings/${id}/report`, data),
    getCategories: () => api.get('/listings/categories'),
    getSearchSuggestions: (q) => api.get('/listings/search/suggestions', { params: { q } }),
  },

  // Message endpoints
  messages: {
    getConversations: (params) => api.get('/messages/conversations', { params }),
    getConversationMessages: (conversationId, params) =>
      api.get(`/messages/conversations/${conversationId}`, { params }),
    sendMessage: (data) => api.post('/messages', data),
    addReaction: (messageId, emoji) => api.post(`/messages/${messageId}/reaction`, { emoji }),
    reportMessage: (messageId, data) => api.post(`/messages/${messageId}/report`, data),
    getUnreadMessages: () => api.get('/messages/unread'),
    getSafetyAlerts: () => api.get('/messages/safety-alerts'),
    uploadMedia: (formData) =>
      api.post('/messages/upload-media', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    deleteMessage: (id) => api.delete(`/messages/${id}`),
  },

  // Admin endpoints
  admin: {
    getDashboard: () => api.get('/admin/dashboard'),
    getUsers: (params) => api.get('/admin/users', { params }),
    getUser: (id) => api.get(`/admin/users/${id}`),
    banUser: (id, data) => api.put(`/admin/users/${id}/ban`, data),
    adjustTrustScore: (id, data) => api.put(`/admin/users/${id}/trust-score`, data),
    verifyID: (id, data) => api.put(`/admin/users/${id}/verify`, data),
    getListings: (params) => api.get('/admin/listings', { params }),
    updateListingStatus: (id, data) => api.put(`/admin/listings/${id}/status`, data),
    getReports: (params) => api.get('/admin/reports', { params }),
    resolveReport: (type, id, data) => api.put(`/admin/reports/${type}/${id}/resolve`, data),
    getAnalytics: (params) => api.get('/admin/analytics', { params }),
  },

  // Search endpoints
  search: {
    search: (query, filters) => api.get('/search', { params: { q: query, ...filters } }),
    searchListings: (query, filters) => api.get('/search/listings', { params: { q: query, ...filters } }),
    searchUsers: (query, filters) => api.get('/search/users', { params: { q: query, ...filters } }),
  },

  // Upload endpoints
  upload: {
    uploadImage: (formData) =>
      api.post('/upload/image', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    uploadVideo: (formData) =>
      api.post('/upload/video', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    uploadMultiple: (formData) =>
      api.post('/upload/multiple', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
  },

  // Utility endpoints
  utils: {
    healthCheck: () => api.get('/health'),
    getVersion: () => api.get('/version'),
    getConfig: () => api.get('/config'),
  },

  // Order endpoints
  orders: {
    placeOrder: (data) => api.post('/orders', data),
    getOrders: (params) => api.get('/orders', { params }),
    getOrder: (id) => api.get(`/orders/${id}`),
    updateOrderStatus: (id, data) => api.put(`/orders/${id}/status`, data),
  },
};

// Helper functions for common API patterns
const createFormData = (data) => {
  const formData = new FormData();

  Object.keys(data).forEach(key => {
    if (data[key] !== undefined && data[key] !== null) {
      if (Array.isArray(data[key])) {
        data[key].forEach((item, index) => {
          if (item instanceof File) {
            formData.append(`${key}[${index}]`, item);
          } else {
            formData.append(`${key}[${index}]`, item);
          }
        });
      } else if (data[key] instanceof File) {
        formData.append(key, data[key]);
      } else {
        formData.append(key, data[key]);
      }
    }
  });

  return formData;
};

const handleApiError = (error) => {
  if (error.response) {
    // Server responded with error status
    const { status, data } = error.response;

    return {
      status,
      message: data.error || 'An error occurred',
      details: data.details,
      isNetworkError: false,
    };
  } else if (error.request) {
    // Request was made but no response received
    return {
      status: 0,
      message: 'Network error - please check your connection',
      isNetworkError: true,
    };
  } else {
    // Something else happened
    return {
      status: 0,
      message: error.message || 'An unexpected error occurred',
      isNetworkError: false,
    };
  }
};

const retryRequest = async (requestFn, maxRetries = 3, delay = 1000) => {
  let lastError;

  for (let i = 0; i < maxRetries; i++) {
    try {
      return await requestFn();
    } catch (error) {
      lastError = error;

      // Don't retry on client errors (4xx)
      if (error.response && error.response.status >= 400 && error.response.status < 500) {
        throw error;
      }

      // Wait before retrying (exponential backoff)
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, i)));
      }
    }
  }

  throw lastError;
};

// Export API service and utilities
export { api, apiService, createFormData, handleApiError, retryRequest };
export default api;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/App.js

```javascript
import React, { Suspense, useState, useCallback, useMemo, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
import { Toaster } from 'react-hot-toast';
import { HelmetProvider } from 'react-helmet-async';

// Context Providers
import { AuthProvider } from './context/AuthContext';
import { SocketProvider } from './context/SocketContext';
import { NotificationProvider } from './context/NotificationContext';

// Layout Components
import Layout from './components/layout/Layout';
import MobileLayout from './components/layout/MobileLayout';
import LoadingSpinner from './components/common/LoadingSpinner';

// Lazy-loaded page components
const Home = React.lazy(() => import('./pages/Home'));
const Login = React.lazy(() => import('./pages/auth/Login'));
const Register = React.lazy(() => import('./pages/auth/Register'));
const CreateListing = React.lazy(() => import('./pages/CreateListing'));
const ListingDetails = React.lazy(() => import('./pages/ListingDetails'));
const SearchResults = React.lazy(() => import('./pages/SearchResults'));
const Messages = React.lazy(() => import('./pages/Messages'));
const Profile = React.lazy(() => import('./pages/Profile'));
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Premium = React.lazy(() => import('./pages/Premium'));
const NotFound = React.lazy(() => import('./pages/NotFound'));

// Enhanced Loading Component with skeleton
const LoadingFallback = () => (
  <div className="min-h-screen bg-gray-50 flex items-center justify-center">
    <div className="text-center">
      <LoadingSpinner size="large" />
      <p className="mt-4 text-gray-500 text-sm font-medium">Loading...</p>
    </div>
  </div>
);

// Skeleton loader for page content - used by child components
// eslint-disable-next-line no-unused-vars
const PageSkeleton = () => (
  <div className="animate-pulse">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="h-8 bg-gray-200 rounded w-1/3 mb-8"></div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="bg-white rounded-lg shadow overflow-hidden">
            <div className="h-48 bg-gray-200"></div>
            <div className="p-4">
              <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
              <div className="h-4 bg-gray-200 rounded w-1/2"></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

// Page preloader hook for intelligent prefetching - available for future use
// eslint-disable-next-line no-unused-vars
const usePagePreloader = () => {
  return useCallback((path) => {
    // Prefetch page chunks when user hovers over links
    const link = document.querySelector(`a[href="${path}"]`);
    if (link) {
      link.addEventListener('mouseenter', () => {
        // Trigger React Router's prefetching
        const preloadLink = document.createElement('link');
        preloadLink.rel = 'prefetch';
        preloadLink.href = path;
        document.head.appendChild(preloadLink);
      }, { once: true });
    }
  }, []);
};

// Error Boundary with retry functionality
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: 0
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    this.setState({ errorInfo });

    // Report error to monitoring service
    if (process.env.NODE_ENV === 'production') {
      this.reportError(error, errorInfo);
    }
  }

  reportError = async (error, errorInfo) => {
    try {
      await fetch('/api/analytics/errors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: error.message,
          stack: error.stack,
          componentStack: errorInfo.componentStack,
          timestamp: new Date().toISOString(),
          url: window.location.href,
          userAgent: navigator.userAgent,
        }),
      });
    } catch (e) {
      console.error('Failed to report error:', e);
    }
  };

  handleRetry = () => {
    this.setState(prev => ({
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: prev.retryCount + 1
    }));
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
          <div className="max-w-md w-full bg-white rounded-xl shadow-lg p-8 text-center">
            <div className="w-16 h-16 mx-auto mb-4 bg-red-100 rounded-full flex items-center justify-center">
              <svg className="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h2 className="text-xl font-semibold text-gray-900 mb-2">Something went wrong</h2>
            <p className="text-gray-600 mb-6">
              We're sorry, but an unexpected error occurred. Our team has been notified.
            </p>

            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <button
                onClick={this.handleRetry}
                className="bg-blue-600 text-white px-6 py-2.5 rounded-lg hover:bg-blue-700 transition-colors font-medium"
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.reload()}
                className="bg-gray-100 text-gray-700 px-6 py-2.5 rounded-lg hover:bg-gray-200 transition-colors font-medium"
              >
                Refresh Page
              </button>
            </div>

            {process.env.NODE_ENV === 'development' && this.state.error && (
              <div className="mt-6 p-4 bg-gray-100 rounded-lg text-left">
                <p className="text-sm font-mono text-red-600">{this.state.error.toString()}</p>
                {this.state.errorInfo && (
                  <pre className="mt-2 text-xs text-gray-600 overflow-auto">
                    {this.state.errorInfo.componentStack}
                  </pre>
                )}
              </div>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Create React Query client with optimized configuration
const createQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000),
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: true,
      refetchOnReconnect: 'always',
      suspense: true,
    },
    mutations: {
      retry: 1,
      onError: (error) => {
        console.error('Mutation error:', error);
      },
    },
  },
});

// Route prefetching component
const RoutePrefetcher = ({ children }) => {
  const location = useLocation();
  const [prefetched, setPrefetched] = useState(new Set());

  useEffect(() => {
    // Prefetch likely next routes based on current route
    const prefetchRoutes = () => {
      const routePatterns = {
        '/': ['/search', '/listing/', '/create-listing'],
        '/listing/': ['/messages/', '/profile'],
        '/messages': ['/profile', '/dashboard'],
      };

      const patterns = routePatterns[location.pathname] || [];
      patterns.forEach(pattern => {
        if (!prefetched.has(pattern)) {
          // Use React Router's built-in prefetching
          setPrefetched(prev => new Set([...prev, pattern]));
        }
      });
    };

    // Prefetch after initial load
    const timer = setTimeout(prefetchRoutes, 2000);
    return () => clearTimeout(timer);
  }, [location.pathname, prefetched]);

  return children;
};

// Scroll to top component
const ScrollToTop = () => {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  return null;
};

// Network-aware loading wrapper
const NetworkAwareSuspense = ({ children, fallback }) => {
  const [, setIsOnline] = useState(navigator.onLine);
  const [wasOffline, setWasOffline] = useState(false);

  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      if (wasOffline) {
        setWasOffline(false);
      }
    };

    const handleOffline = () => {
      setIsOnline(false);
      setWasOffline(true);
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [wasOffline]);

  return (
    <>
      {wasOffline && (
        <div className="fixed top-0 left-0 right-0 bg-amber-500 text-white text-center py-2 text-sm font-medium z-50">
          <span>You are back online. Content has been refreshed.</span>
        </div>
      )}
      <Suspense fallback={fallback}>
        {children}
      </Suspense>
    </>
  );
};

// Main App Component
function App() {
  const [queryClient] = useState(() => createQueryClient());

  const toastOptions = useMemo(() => ({
    duration: 4000,
    style: {
      background: '#ffffff',
      color: '#0f172a',
      borderRadius: '12px',
      boxShadow: '0 10px 40px -10px rgba(0, 0, 0, 0.15)',
      border: '1px solid #e2e8f0',
      fontSize: '14px',
      fontWeight: '500',
      maxWidth: '400px',
      padding: '12px 16px',
    },
    success: {
      duration: 3000,
      style: {
        borderLeft: '4px solid #10b981',
      },
      iconTheme: {
        primary: '#10b981',
        secondary: '#ffffff',
      },
    },
    error: {
      duration: 5000,
      style: {
        borderLeft: '4px solid #ef4444',
      },
      iconTheme: {
        primary: '#ef4444',
        secondary: '#ffffff',
      },
    },
    loading: {
      duration: Infinity,
      style: {
        borderLeft: '4px solid #3b82f6',
      },
    },
  }), []);

  return (
    <HelmetProvider>
      <ErrorBoundary>
        <QueryClientProvider client={queryClient}>
          <Router>
            <ScrollToTop />
            <RoutePrefetcher>
              <AuthProvider>
                <NotificationProvider>
                  <SocketProvider>
                    <div className="App min-h-screen bg-gray-50">
                      <NetworkAwareSuspense fallback={<LoadingFallback />}>
                        <Routes>
                          {/* Public Routes */}
                          <Route path="/login" element={<Login />} />
                          <Route path="/register" element={<Register />} />

                          {/* Main Application Routes */}
                          <Route path="/" element={<Layout />}>
                            <Route index element={<Home />} />
                            <Route path="search" element={<SearchResults />} />
                            <Route path="listing/:id" element={<ListingDetails />} />
                            <Route path="messages" element={<Messages />} />
                            <Route path="messages/:conversationId" element={<Messages />} />
                            <Route path="profile" element={<Profile />} />
                            <Route path="profile/:userId" element={<Profile />} />
                            <Route path="dashboard" element={<Dashboard />} />
                            <Route path="premium" element={<Premium />} />
                          </Route>

                          {/* Mobile-optimized routes */}
                          <Route
                            path="/create-listing"
                            element={<MobileLayout><CreateListing /></MobileLayout>}
                          />

                          {/* 404 Route */}
                          <Route path="*" element={<NotFound />} />
                        </Routes>
                      </NetworkAwareSuspense>

                      {/* Toast Notifications */}
                      <Toaster
                        position="top-center"
                        reverseOrder={false}
                        gutter={8}
                        toastOptions={toastOptions}
                      />

                      {/* React Query Dev Tools (only in development) */}
                      {process.env.NODE_ENV === 'development' && (
                        <ReactQueryDevtools initialIsOpen={false} />
                      )}
                    </div>
                  </SocketProvider>
                </NotificationProvider>
              </AuthProvider>
            </RoutePrefetcher>
          </Router>
        </QueryClientProvider>
      </ErrorBoundary>
    </HelmetProvider>
  );
}

export default App;
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/index.css

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Custom CSS Variables for TrustMarket Design System */
:root {
  /* Primary Colors */
  --color-primary-50: #eff6ff;
  --color-primary-100: #dbeafe;
  --color-primary-200: #bfdbfe;
  --color-primary-300: #93c5fd;
  --color-primary-400: #60a5fa;
  --color-primary-500: #3b82f6;
  --color-primary-600: #2563eb;
  --color-primary-700: #1d4ed8;
  --color-primary-800: #1e40af;
  --color-primary-900: #1e3a8a;

  /* Trust Colors */
  --color-success: #10b981;
  --color-success-light: #d1fae5;
  --color-warning: #f59e0b;
  --color-warning-light: #fef3c7;
  --color-error: #ef4444;
  --color-error-light: #fee2e2;
  --color-elite: #854d0e;
  --color-elite-light: #fef9c3;

  /* Neutral Colors */
  --color-neutral-0: #ffffff;
  --color-neutral-50: #f8fafc;
  --color-neutral-100: #f1f5f9;
  --color-neutral-200: #e2e8f0;
  --color-neutral-300: #cbd5e1;
  --color-neutral-400: #94a3b8;
  --color-neutral-500: #64748b;
  --color-neutral-600: #475569;
  --color-neutral-700: #334155;
  --color-neutral-800: #1e293b;
  --color-neutral-900: #0f172a;

  /* Typography */
  --font-family-base: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;

  /* Spacing (4px base unit) */
  --space-xs: 0.25rem;
  --space-sm: 0.5rem;
  --space-md: 1rem;
  --space-lg: 1.5rem;
  --space-xl: 2rem;
  --space-xxl: 3rem;

  /* Border Radius */
  --radius-sm: 0.25rem;
  --radius-md: 0.5rem;
  --radius-lg: 0.75rem;
  --radius-xl: 1rem;
  --radius-full: 9999px;

  /* Shadows */
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);

  /* Transitions */
  --transition-fast: 150ms;
  --transition-normal: 200ms;
  --transition-slow: 300ms;
}

/* Base Styles */
@layer base {
  * {
    box-sizing: border-box;
    border-width: 0;
    border-style: solid;
    border-color: currentColor;
  }

  html {
    scroll-behavior: smooth;
    -webkit-text-size-adjust: 100%;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
  }

  body {
    @apply bg-neutral-50 text-neutral-900;
    font-family: var(--font-family-base);
    line-height: 1.5;
    font-feature-settings: 'cv11', 'ss01';
    font-variation-settings: 'opsz' 32;
    overflow-x: hidden;
    min-height: 100vh;
  }

  /* Prevent iOS zoom on input focus */
  @media (max-width: 768px) {

    input,
    select,
    textarea {
      font-size: 16px;
    }
  }

  /* Focus styles for accessibility */
  :focus {
    outline: 2px solid var(--color-primary-500);
    outline-offset: 2px;
  }

  :focus:not(:focus-visible) {
    outline: none;
  }

  :focus-visible {
    outline: 2px solid var(--color-primary-500);
    outline-offset: 2px;
  }

  /* Selection styles */
  ::selection {
    background-color: var(--color-primary-100);
    color: var(--color-primary-900);
  }

  /* Custom scrollbar */
  ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  ::-webkit-scrollbar-track {
    background: var(--color-neutral-50);
    border-radius: var(--radius-sm);
  }

  ::-webkit-scrollbar-thumb {
    background: var(--color-neutral-300);
    border-radius: var(--radius-sm);
  }

  ::-webkit-scrollbar-thumb:hover {
    background: var(--color-neutral-400);
  }

  /* Hide scrollbar for Chrome, Safari and Opera */
  .hide-scrollbar::-webkit-scrollbar {
    display: none;
  }

  /* Hide scrollbar for IE, Edge and Firefox */
  .hide-scrollbar {
    -ms-overflow-style: none;
    scrollbar-width: none;
  }

  /* Default link styles */
  a {
    @apply text-primary-600 hover:text-primary-700 transition-colors duration-200;
  }

  /* Heading styles */
  h1,
  h2,
  h3,
  h4,
  h5,
  h6 {
    @apply font-semibold text-neutral-900;
    line-height: 1.25;
  }

  h1 {
    @apply text-3xl md:text-4xl;
  }

  h2 {
    @apply text-2xl md:text-3xl;
  }

  h3 {
    @apply text-xl md:text-2xl;
  }

  h4 {
    @apply text-lg md:text-xl;
  }

  h5 {
    @apply text-base md:text-lg;
  }

  h6 {
    @apply text-sm md:text-base;
  }
}

/* Component Styles */
@layer components {

  /* Button Components with touch optimization */
  .btn {
    @apply inline-flex items-center justify-center px-4 py-2.5 text-sm font-medium rounded-lg transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed;
    min-height: 48px;
    min-width: 48px;
    touch-action: manipulation;
    -webkit-tap-highlight-color: transparent;
  }

  .btn:active {
    transform: scale(0.98);
  }

  .btn-primary {
    @apply bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500 shadow-sm;
  }

  .btn-primary:hover {
    @apply shadow-md;
  }

  .btn-secondary {
    @apply bg-white text-neutral-900 border border-neutral-300 hover:bg-neutral-50 focus:ring-primary-500;
  }

  .btn-success {
    @apply bg-success text-white hover:bg-green-600 focus:ring-success shadow-sm;
  }

  .btn-warning {
    @apply bg-warning text-white hover:bg-yellow-600 focus:ring-warning shadow-sm;
  }

  .btn-error {
    @apply bg-error text-white hover:bg-red-600 focus:ring-error shadow-sm;
  }

  .btn-ghost {
    @apply text-neutral-600 hover:text-neutral-900 hover:bg-neutral-100 focus:ring-primary-500;
  }

  .btn-sm {
    @apply px-3 py-1.5 text-xs min-h-10;
  }

  .btn-lg {
    @apply px-6 py-3.5 text-base min-h-14;
  }

  .btn-icon {
    @apply p-2.5 min-w-12;
  }

  /* Input Components with touch optimization */
  .input {
    @apply block w-full px-4 py-3 border border-neutral-300 rounded-lg shadow-sm placeholder-neutral-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 text-base;
    min-height: 48px;
    touch-action: manipulation;
  }

  .input-error {
    @apply border-error focus:ring-error focus:border-error bg-error-light;
  }

  .textarea {
    @apply block w-full px-4 py-3 border border-neutral-300 rounded-lg shadow-sm placeholder-neutral-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 text-base;
    min-height: 100px;
    resize: vertical;
  }

  .select {
    @apply block w-full px-4 py-3 border border-neutral-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 text-base appearance-none;
    min-height: 48px;
    background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e");
    background-position: right 0.75rem center;
    background-repeat: no-repeat;
    background-size: 1.5em 1.5em;
    padding-right: 2.5rem;
  }

  .label {
    @apply block text-sm font-medium text-neutral-700 mb-1.5;
  }

  .error-message {
    @apply text-sm text-error mt-1;
  }

  .helper-text {
    @apply text-sm text-neutral-500 mt-1;
  }

  /* Form group */
  .form-group {
    @apply mb-4;
  }

  .form-row {
    @apply grid gap-4 md:grid-cols-2;
  }

  /* Card Components */
  .card {
    @apply bg-white rounded-xl shadow-sm border border-neutral-200 overflow-hidden;
  }

  .card-hover {
    @apply hover:shadow-lg hover:border-neutral-300 transition-all duration-200;
  }

  .card-body {
    @apply p-4 md:p-6;
  }

  .card-header {
    @apply px-4 py-4 md:px-6 border-b border-neutral-200 bg-neutral-50;
  }

  .card-footer {
    @apply px-4 py-4 md:px-6 border-t border-neutral-200 bg-neutral-50;
  }

  /* Badge Components */
  .badge {
    @apply inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium;
  }

  .badge-primary {
    @apply bg-primary-100 text-primary-800;
  }

  .badge-success {
    @apply bg-green-100 text-green-800;
  }

  .badge-warning {
    @apply bg-yellow-100 text-yellow-800;
  }

  .badge-error {
    @apply bg-red-100 text-red-800;
  }

  .badge-neutral {
    @apply bg-neutral-100 text-neutral-800;
  }

  /* Trust Score Badges */
  .trust-badge {
    @apply inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold;
  }

  .trust-newbie {
    @apply bg-neutral-100 text-neutral-700;
  }

  .trust-resident {
    @apply bg-blue-100 text-blue-700;
  }

  .trust-veteran {
    @apply bg-green-100 text-green-700;
  }

  .trust-elite {
    @apply bg-yellow-100 text-yellow-800;
  }

  /* Verification Badges */
  .verification-badge {
    @apply inline-flex items-center justify-center w-5 h-5 rounded-full;
  }

  .verification-phone {
    @apply bg-green-500 text-white;
  }

  .verification-id {
    @apply bg-blue-500 text-white;
  }

  .verification-elite {
    @apply bg-yellow-500 text-white;
  }

  /* Loading Components */
  .loading-spinner {
    @apply animate-spin rounded-full border-2 border-neutral-200 border-t-primary-500;
  }

  .loading-dots {
    @apply flex space-x-1;
  }

  .loading-dots>div {
    @apply w-2 h-2 bg-primary-500 rounded-full animate-pulse;
    animation-delay: 0.2s;
  }

  .loading-dots>div:nth-child(2) {
    animation-delay: 0.4s;
  }

  .loading-dots>div:nth-child(3) {
    animation-delay: 0.6s;
  }

  .skeleton {
    @apply bg-neutral-200 animate-pulse rounded;
  }

  /* Video Components */
  .video-container {
    @apply relative bg-black rounded-lg overflow-hidden;
    aspect-ratio: 4/5;
  }

  .video-overlay {
    @apply absolute inset-0 flex items-center justify-center bg-black bg-opacity-30 opacity-0 hover:opacity-100 transition-opacity duration-200 cursor-pointer;
  }

  .video-duration {
    @apply absolute bottom-2 right-2 bg-black bg-opacity-70 text-white text-xs px-2 py-1 rounded;
  }

  /* Listing Card */
  .listing-card {
    @apply bg-white rounded-xl shadow-sm border border-neutral-200 overflow-hidden hover:shadow-lg transition-all duration-200;
  }

  .listing-card:active {
    transform: scale(0.99);
  }

  .listing-thumbnail {
    @apply w-full h-48 md:h-56 bg-neutral-100 object-cover;
  }

  .listing-info {
    @apply p-3 md:p-4;
  }

  .listing-title {
    @apply font-semibold text-neutral-900 text-sm md:text-base mb-1 line-clamp-2;
  }

  .listing-price {
    @apply text-lg md:text-xl font-bold text-neutral-900 mb-2;
  }

  .listing-meta {
    @apply flex items-center justify-between text-xs md:text-sm text-neutral-500;
  }

  /* Navigation Components */
  .nav-link {
    @apply flex items-center px-3 py-2.5 text-sm font-medium rounded-lg transition-colors duration-200;
  }

  .nav-link-active {
    @apply bg-primary-100 text-primary-700;
  }

  .nav-link-inactive {
    @apply text-neutral-600 hover:text-neutral-900 hover:bg-neutral-100;
  }

  /* Mobile Bottom Navigation */
  .bottom-nav {
    @apply fixed bottom-0 left-0 right-0 bg-white border-t border-neutral-200 px-2 py-1;
    padding-bottom: env(safe-area-inset-bottom, 0);
    z-index: 50;
    box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.05);
  }

  .bottom-nav-item {
    @apply flex flex-col items-center justify-center py-2 px-1 text-xs font-medium transition-colors duration-200 min-w-14;
  }

  .bottom-nav-item:active {
    transform: scale(0.95);
  }

  .bottom-nav-item-active {
    @apply text-primary-600;
  }

  .bottom-nav-item-inactive {
    @apply text-neutral-500;
  }

  /* Modal Components */
  .modal-overlay {
    @apply fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50;
    backdrop-filter: blur(4px);
  }

  .modal-content {
    @apply bg-white rounded-xl shadow-xl max-w-md w-full max-h-[90vh] overflow-auto;
    animation: modalIn 0.2s ease-out;
  }

  .modal-content-sm {
    @apply max-w-sm;
  }

  .modal-content-md {
    @apply max-w-lg;
  }

  .modal-content-lg {
    @apply max-w-2xl;
  }

  .modal-content-xl {
    @apply max-w-4xl;
  }

  .modal-header {
    @apply px-4 py-4 md:px-6 border-b border-neutral-200 flex items-center justify-between;
  }

  .modal-body {
    @apply px-4 py-4 md:px-6;
  }

  .modal-footer {
    @apply px-4 py-4 md:px-6 border-t border-neutral-200 flex flex-col-reverse sm:flex-row justify-end gap-3 sm:space-x-3;
  }

  /* Toast Components */
  .toast {
    @apply max-w-sm w-full bg-white shadow-lg rounded-lg pointer-events-auto ring-1 ring-black ring-opacity-5;
  }

  .toast-success {
    @apply border-l-4 border-success;
  }

  .toast-error {
    @apply border-l-4 border-error;
  }

  .toast-warning {
    @apply border-l-4 border-warning;
  }

  .toast-info {
    @apply border-l-4 border-primary-500;
  }

  /* Safety Warning */
  .safety-warning {
    @apply bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg;
  }

  /* Trust Score Circle */
  .trust-circle {
    @apply relative w-20 h-20 md:w-24 md:h-24;
  }

  .trust-circle svg {
    @apply w-full h-full transform -rotate-90;
  }

  .trust-circle-fill {
    transition: stroke-dasharray 0.8s ease-in-out;
  }

  /* Avatar Components */
  .avatar {
    @apply inline-flex items-center justify-center rounded-full bg-neutral-200 text-neutral-600 font-medium;
  }

  .avatar-sm {
    @apply w-8 h-8 text-xs;
  }

  .avatar-md {
    @apply w-10 h-10 text-sm;
  }

  .avatar-lg {
    @apply w-12 h-12 text-base;
  }

  .avatar-xl {
    @apply w-16 h-16 text-lg;
  }

  .avatar img {
    @apply w-full h-full object-cover rounded-full;
  }

  /* Empty State */
  .empty-state {
    @apply flex flex-col items-center justify-center py-12 px-4 text-center;
  }

  .empty-state-icon {
    @apply w-16 h-16 text-neutral-300 mb-4;
  }

  .empty-state-title {
    @apply text-lg font-medium text-neutral-900 mb-2;
  }

  .empty-state-description {
    @apply text-sm text-neutral-500 max-w-sm;
  }
}

/* Utility Classes */
@layer utilities {

  /* Text utilities */
  .text-balance {
    text-wrap: balance;
  }

  .line-clamp-1 {
    overflow: hidden;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 1;
  }

  .line-clamp-2 {
    overflow: hidden;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 2;
  }

  .line-clamp-3 {
    overflow: hidden;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 3;
  }

  /* Safe area utilities */
  .safe-area-pb {
    padding-bottom: env(safe-area-inset-bottom, 0);
  }

  .safe-area-pt {
    padding-top: env(safe-area-inset-top, 0);
  }

  .safe-area-pl {
    padding-left: env(safe-area-inset-left, 0);
  }

  .safe-area-pr {
    padding-right: env(safe-area-inset-right, 0);
  }

  .safe-area-all {
    padding-top: env(safe-area-inset-top, 0);
    padding-right: env(safe-area-inset-right, 0);
    padding-bottom: env(safe-area-inset-bottom, 0);
    padding-left: env(safe-area-inset-left, 0);
  }

  /* Touch target utilities */
  .touch-target {
    min-height: 48px;
    min-width: 48px;
  }

  .touch-target-sm {
    min-height: 40px;
    min-width: 40px;
  }

  /* Glass effect */
  .glass {
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    background: rgba(255, 255, 255, 0.8);
  }

  .glass-dark {
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    background: rgba(0, 0, 0, 0.8);
  }

  /* Hardware acceleration */
  .gpu-accelerated {
    transform: translateZ(0);
    will-change: transform;
  }

  /* Aspect ratios */
  .aspect-video {
    aspect-ratio: 16 / 9;
  }

  .aspect-portrait {
    aspect-ratio: 4 / 5;
  }

  .aspect-square {
    aspect-ratio: 1 / 1;
  }

  /* Truncate text */
  .truncate {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Hide visually but keep accessible */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  }

  /* Disable touch action */
  .touch-none {
    touch-action: none;
  }

  /* Prevent text selection */
  .select-none {
    -webkit-user-select: none;
    user-select: none;
  }
}

/* Keyframe Animations */
@keyframes fadeIn {
  from {
    opacity: 0;
  }

  to {
    opacity: 1;
  }
}

@keyframes fadeOut {
  from {
    opacity: 1;
  }

  to {
    opacity: 0;
  }
}

@keyframes slideUp {
  from {
    transform: translateY(20px);
    opacity: 0;
  }

  to {
    transform: translateY(0);
    opacity: 1;
  }
}

@keyframes slideDown {
  from {
    transform: translateY(-20px);
    opacity: 0;
  }

  to {
    transform: translateY(0);
    opacity: 1;
  }
}

@keyframes slideLeft {
  from {
    transform: translateX(20px);
    opacity: 0;
  }

  to {
    transform: translateX(0);
    opacity: 1;
  }
}

@keyframes slideRight {
  from {
    transform: translateX(-20px);
    opacity: 0;
  }

  to {
    transform: translateX(0);
    opacity: 1;
  }
}

@keyframes scaleIn {
  from {
    transform: scale(0.95);
    opacity: 0;
  }

  to {
    transform: scale(1);
    opacity: 1;
  }
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes pulse {

  0%,
  100% {
    opacity: 1;
  }

  50% {
    opacity: 0.5;
  }
}

@keyframes bounce {

  0%,
  100% {
    transform: translateY(-25%);
    animation-timing-function: cubic-bezier(0.8, 0, 1, 1);
  }

  50% {
    transform: translateY(0);
    animation-timing-function: cubic-bezier(0, 0, 0.2, 1);
  }
}

@keyframes modalIn {
  from {
    opacity: 0;
    transform: scale(0.95) translateY(10px);
  }

  to {
    opacity: 1;
    transform: scale(1) translateY(0);
  }
}

/* Animation classes */
.animate-fade-in {
  animation: fadeIn 0.3s ease-in-out;
}

.animate-fade-out {
  animation: fadeOut 0.2s ease-in-out;
}

.animate-slide-up {
  animation: slideUp 0.3s ease-out;
}

.animate-slide-down {
  animation: slideDown 0.3s ease-out;
}

.animate-slide-left {
  animation: slideLeft 0.3s ease-out;
}

.animate-slide-right {
  animation: slideRight 0.3s ease-out;
}

.animate-scale-in {
  animation: scaleIn 0.2s ease-out;
}

.animate-spin {
  animation: spin 1s linear infinite;
}

.animate-pulse {
  animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

.animate-bounce {
  animation: bounce 1s infinite;
}

/* Print styles */
@media print {
  .no-print {
    display: none !important;
  }

  .print-break {
    page-break-after: always;
  }

  body {
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
}

/* Dark mode support */
@media (prefers-color-scheme: dark) {
  :root {
    --color-neutral-0: #0f172a;
    --color-neutral-50: #1e293b;
    --color-neutral-100: #334155;
    --color-neutral-200: #475569;
    --color-neutral-900: #f8fafc;
  }

  body {
    @apply bg-neutral-800 text-neutral-100;
  }

  .card {
    @apply bg-neutral-800 border-neutral-700;
  }

  .btn-secondary {
    @apply bg-neutral-700 border-neutral-600 text-neutral-100;
  }

  .input,
  .select,
  .textarea {
    @apply bg-neutral-700 border-neutral-600 text-neutral-100;
  }
}

/* High contrast mode support */
@media (prefers-contrast: high) {
  .btn {
    border-width: 2px;
  }

  .card {
    border-width: 2px;
  }

  .input,
  .select,
  .textarea {
    border-width: 2px;
  }

  :focus {
    outline-width: 3px;
  }
}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {

  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}

/* Responsive typography */
@media (max-width: 640px) {
  html {
    font-size: 14px;
  }
}

/* Mobile-specific optimizations */
@media (max-width: 768px) {

  /* Prevent pull-to-refresh on Chrome Android */
  body {
    overscroll-behavior-y: none;
  }

  /* Improve tap highlight on mobile */
  a,
  button {
    -webkit-tap-highlight-color: rgba(59, 130, 246, 0.2);
  }

  /* Better touch feedback */
  .btn:active,
  .bottom-nav-item:active,
  .listing-card:active {
    transform: scale(0.97);
    transition-duration: 0.05s;
  }
}

/* Tablet optimizations */
@media (min-width: 768px) and (max-width: 1024px) {

  /* Optimize for tablet touch */
  .btn,
  .input,
  .select,
  .textarea {
    min-height: 44px;
  }
}

/* Desktop optimizations */
@media (min-width: 1024px) {

  /* Larger touch targets on desktop */
  .btn,
  .input,
  .select,
  .textarea {
    min-height: 48px;
  }
}
``````
---

## C:/Users/biswa/Downloads/trustmarket (3)/trustmarket/client/src/index.js

```javascript
import React from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

// Get the root element
const container = document.getElementById('root');

// Create root and render the app
const root = createRoot(container);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// Performance monitoring
if (process.env.NODE_ENV === 'production') {
  reportWebVitals((metric) => {
    // Log to console in development, send to analytics in production
    console.log('[Web Vitals]', metric.name, metric.value);

    // Send to analytics service if available
    if (typeof window.gtag !== 'undefined') {
      window.gtag('event', metric.name, {
        value: Math.round(metric.name === 'CLS' ? metric.value * 1000 : metric.value),
        event_category: 'Web Vitals',
        event_label: metric.id,
        non_interaction: true,
      });
    }

    // Send to custom analytics endpoint
    if (metric.label === 'web-vital') {
      fetch('/api/analytics/vitals', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: metric.name,
          value: metric.value,
          rating: metric.rating,
          id: metric.id,
          delta: metric.delta,
        }),
      }).catch(() => {
        // Silently fail if analytics endpoint is unavailable
      });
    }
  });
}

// Handle online/offline status with app-wide event dispatching
function updateOnlineStatus() {
  const event = new CustomEvent('app-network-change', {
    detail: { isOnline: navigator.onLine }
  });
  window.dispatchEvent(event);

  // Dispatch to React context via global event
  window.dispatchEvent(new CustomEvent(navigator.onLine ? 'app-online' : 'app-offline'));
}

window.addEventListener('online', updateOnlineStatus);
window.addEventListener('offline', updateOnlineStatus);

// Initial network status check
updateOnlineStatus();

// Expose global helper for triggering browser feedback
window.showToast = function (message, type = 'info', duration = 4000) {
  // Create toast element
  const toastId = 'toast-' + Date.now();
  const toast = document.createElement('div');
  toast.id = toastId;
  toast.style.cssText = `
    position: fixed;
    bottom: 80px;
    left: 50%;
    transform: translateX(-50%) translateY(100px);
    background: ${type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : type === 'warning' ? '#F59E0B' : '#3B82F6'};
    color: white;
    padding: 12px 24px;
    border-radius: 8px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
    z-index: 10000;
    font-family: Inter, sans-serif;
    font-weight: 500;
    font-size: 14px;
    max-width: 90vw;
    width: max-content;
    opacity: 0;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 8px;
  `;

  const icon = type === 'success'
    ? '<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>'
    : type === 'error'
      ? '<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'
      : '<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';

  toast.innerHTML = `${icon}<span>${message}</span>`;
  document.body.appendChild(toast);

  // Trigger animation
  requestAnimationFrame(() => {
    toast.style.transform = 'translateX(-50%) translateY(0)';
    toast.style.opacity = '1';
  });

  // Remove after duration
  setTimeout(() => {
    toast.style.transform = 'translateX(-50%) translateY(100px)';
    toast.style.opacity = '0';
    setTimeout(() => {
      if (document.body.contains(toast)) {
        document.body.removeChild(toast);
      }
    }, 300);
  }, duration);

  return toastId;
};

// Expose global helper for hiding toasts
window.hideToast = function (toastId) {
  const toast = document.getElementById(toastId || 'toast-' + Date.now());
  if (toast) {
    toast.style.transform = 'translateX(-50%) translateY(100px)';
    toast.style.opacity = '0';
    setTimeout(() => {
      if (document.body.contains(toast)) {
        document.body.removeChild(toast);
      }
    }, 300);
  }
};

// Performance optimization: Defer non-critical operations
if ('requestIdleCallback' in window) {
  requestIdleCallback(() => {
    // Load non-critical resources when browser is idle
    console.log('[Performance] Browser idle, deferred operations can proceed');
  });
}
``````
---
# DEVOPS

## Dockerfile

```text
# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files for caching
COPY server/package*.json ./server/
COPY client/package*.json ./client/
COPY package*.json ./

# Install server dependencies
RUN cd server && npm ci --only=production

# Install client dependencies and build
RUN cd client && npm ci && npm run build

# Copy source code
COPY server/ ./server/
COPY client/build/ ./server/public/

# â”€â”€â”€ Production stage â”€â”€â”€
FROM node:20-alpine

WORKDIR /app

# Add non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S trustmarket -u 1001 -G nodejs

# Copy built artifacts
COPY --from=builder /app/server/ ./
COPY --from=builder /app/server/public/ ./public/

# Create logs directory
RUN mkdir -p logs && chown trustmarket:nodejs logs

USER trustmarket

EXPOSE 5000

ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD wget -qO- http://localhost:5000/api/health || exit 1

CMD ["node", "index.js"]
``````
---

## docker-compose.yml

```yaml
version: '3.8'

services:
  server:
    build: .
    ports:
      - '5000:5000'
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongo:27017/trustmarket
      - JWT_SECRET=${JWT_SECRET:-trustmarket-super-secret-jwt-key-2025}
      - JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET:-trustmarket-super-secret-refresh-key-2025}
      - FRONTEND_URL=${FRONTEND_URL:-http://localhost:3000}
      - CLIENT_URL=${CLIENT_URL:-http://localhost:3000}
    depends_on:
      mongo:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - trustmarket-net

  mongo:
    image: mongo:7
    ports:
      - '27017:27017'
    volumes:
      - mongo-data:/data/db
    healthcheck:
      test: [ 'CMD', 'mongosh', '--eval', "db.adminCommand('ping')" ]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - trustmarket-net

  mongo-express:
    image: mongo-express:latest
    ports:
      - '8081:8081'
    environment:
      - ME_CONFIG_MONGODB_URL=mongodb://mongo:27017/
      - ME_CONFIG_BASICAUTH=false
    depends_on:
      mongo:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - trustmarket-net
    profiles:
      - dev # Only starts with `docker compose --profile dev up`

volumes:
  mongo-data:


networks:
  trustmarket-net:
    driver: bridge
``````
---

## .dockerignore

```text
# Dependencies
node_modules/

# Build output
client/build/

# Environment
.env
.env.local
.env.*.local

# Logs
logs/
*.log

# OS files
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/

# Docker volumes
mongo-data/
``````
---

## .github/workflows/ci.yml

```yaml
name: CI/CD Pipeline

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  lint-and-test:
    name: Lint & Test
    runs-on: ubuntu-latest

    services:
      mongo:
        image: mongo:7
        ports:
          - 27017:27017
        options: >-
          --health-cmd "mongosh --eval 'db.adminCommand({ping:1})'"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: |
            server/package-lock.json
            client/package-lock.json

      - name: Install server dependencies
        run: cd server && npm ci

      - name: Install client dependencies
        run: cd client && npm ci

      - name: Run server tests
        run: cd server && npx jest --verbose --no-coverage
        env:
          MONGODB_URI: mongodb://localhost:27017/trustmarket-test
          JWT_SECRET: ci-test-secret
          JWT_REFRESH_SECRET: ci-test-refresh-secret
          NODE_ENV: test

      - name: Build client
        run: cd client && npm run build
        env:
          CI: true

  docker-build:
    name: Docker Build
    runs-on: ubuntu-latest
    needs: lint-and-test
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'

    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t trustmarket:${{ github.sha }} .

      - name: Verify Docker image
        run: docker image inspect trustmarket:${{ github.sha }}
``````
---
