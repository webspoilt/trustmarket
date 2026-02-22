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

// Anomaly detection (behavioral analysis + DDoS pattern detection)
const anomalyDetector = require('./middleware/anomalyDetector');
app.use(anomalyDetector);

// Native app security (CSP headers for WebView protection)
const nativeSecurity = require('./middleware/nativeSecurity');
app.use(nativeSecurity);

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
    logger.info('🔧 Starting TrustMarket Server...');
    logger.info('🔗 Connecting to database...');

    await connectDB();
    logger.info('✅ Database connected successfully');

    server.listen(PORT, () => {
      logger.info('🚀 TrustMarket Server Started Successfully!');
      logger.info(`🌍 Server running on port ${PORT}`);
      logger.info(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info('📡 Socket.io enabled for real-time features');
      logger.info(`🔗 Frontend URL: ${process.env.FRONTEND_URL || process.env.CLIENT_URL || 'http://localhost:3000'}`);

      if (process.env.NODE_ENV === 'development') {
        logger.info('🧪 Development mode: Local file uploads enabled');
        logger.info(`📁 Uploads served at: http://localhost:${PORT}/uploads`);
      }
    });
  } catch (error) {
    logger.error('❌ Failed to start server:', error);
    logger.info('💡 TROUBLESHOOTING:');
    logger.info('1. Check if MongoDB is running (local) or Atlas cluster is active');
    logger.info('2. Verify your .env file configuration');
    logger.info('3. Ensure all dependencies are installed');
    logger.info('4. Check if port 5000 is available');
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      logger.info('📴 Server closed successfully');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  logger.info('🛑 SIGINT received, shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      logger.info('📴 Server closed successfully');
      process.exit(0);
    });
  });
});

startServer();

module.exports = { app, io };