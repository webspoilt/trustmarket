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