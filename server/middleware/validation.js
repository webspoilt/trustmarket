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
