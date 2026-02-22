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