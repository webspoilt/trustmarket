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