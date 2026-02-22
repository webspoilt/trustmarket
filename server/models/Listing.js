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