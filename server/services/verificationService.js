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
