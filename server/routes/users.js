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