const mongoose = require('mongoose');
const security = require('../services/quantumSecurity');

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

// Hash password before saving using Argon2id (memory-hard, GPU-resistant)
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    this.password = await security.hashPassword(this.password);
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
  return await security.verifyPassword(this.password, candidatePassword);
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