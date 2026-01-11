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