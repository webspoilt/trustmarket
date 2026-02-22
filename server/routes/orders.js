const express = require('express');
const mongoose = require('mongoose');
const { body, param, validationResult } = require('express-validator');
const Order = require('../models/Order');
const Listing = require('../models/Listing');
const { authenticateToken, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// @route   POST /api/orders
// @desc    Place a new order (uses Mongoose transaction for atomicity)
// @access  Private (buyer)
router.post('/', authenticateToken, [
    body('listingId').isMongoId().withMessage('Valid listing ID is required'),
    body('quantity').optional().isInt({ min: 1, max: 100 }).withMessage('Quantity must be between 1 and 100'),
    body('shippingAddress.address').optional().trim().isLength({ min: 5, max: 500 }),
    body('shippingAddress.city').optional().trim().isLength({ min: 2, max: 100 }),
    body('shippingAddress.state').optional().trim().isLength({ min: 2, max: 100 }),
    body('shippingAddress.pincode').optional().matches(/^\d{6}$/).withMessage('Valid 6-digit pincode required')
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            error: 'Validation failed',
            details: errors.array()
        });
    }

    const { listingId, quantity = 1, shippingAddress } = req.body;

    // Start a Mongoose session for ACID transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        // 1. Find the listing within the transaction
        const listing = await Listing.findById(listingId).session(session);

        if (!listing) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, error: 'Listing not found' });
        }

        if (listing.status !== 'active') {
            await session.abortTransaction();
            return res.status(400).json({ success: false, error: 'Listing is no longer active' });
        }

        // Prevent buying your own listing
        if (listing.seller.toString() === req.user._id.toString()) {
            await session.abortTransaction();
            return res.status(400).json({ success: false, error: 'Cannot purchase your own listing' });
        }

        // 2. Check stock availability
        if (listing.stock < quantity) {
            await session.abortTransaction();
            return res.status(409).json({
                success: false,
                error: listing.stock === 0
                    ? 'This item is out of stock'
                    : `Only ${listing.stock} item(s) remaining`
            });
        }

        // 3. Decrement stock atomically
        listing.stock -= quantity;
        if (listing.stock === 0) {
            listing.status = 'sold';
        }
        await listing.save({ session });

        // 4. Create the order
        const order = new Order({
            buyer: req.user._id,
            seller: listing.seller,
            listing: listing._id,
            quantity,
            unitPrice: listing.price,
            totalPrice: listing.price * quantity,
            status: 'pending',
            shippingAddress: shippingAddress || {},
            statusHistory: [{ status: 'pending', changedAt: new Date(), changedBy: req.user._id }]
        });

        await order.save({ session });

        // 5. Commit the transaction — both stock decrement and order creation succeed together
        await session.commitTransaction();

        // Populate order data for response
        await order.populate('listing', 'title price media.video.thumbnail');
        await order.populate('seller', 'firstName lastName trustScore');

        res.status(201).json({
            success: true,
            message: 'Order placed successfully',
            data: { order: order.toJSON() }
        });
    } catch (error) {
        await session.abortTransaction();

        // Handle optimistic concurrency conflict (VersionError)
        if (error.name === 'VersionError') {
            return res.status(409).json({
                success: false,
                error: 'This item was just purchased by another buyer. Please try again.'
            });
        }

        throw error; // Re-throw for global error handler
    } finally {
        session.endSession();
    }
}));

// @route   GET /api/orders
// @desc    Get current user's orders (as buyer or seller)
// @access  Private
router.get('/', authenticateToken, asyncHandler(async (req, res) => {
    const { role = 'buyer', status, page = 1, limit = 20 } = req.query;

    const query = role === 'seller'
        ? { seller: req.user._id }
        : { buyer: req.user._id };

    if (status) query.status = status;

    const skip = (page - 1) * limit;

    const [orders, total] = await Promise.all([
        Order.find(query)
            .populate('listing', 'title price media.video.thumbnail category')
            .populate('buyer', 'firstName lastName trustScore')
            .populate('seller', 'firstName lastName trustScore')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit)),
        Order.countDocuments(query)
    ]);

    res.json({
        success: true,
        data: {
            orders: orders.map(o => o.toJSON()),
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(total / limit),
                totalItems: total,
                hasNext: skip + orders.length < total,
                hasPrev: page > 1
            }
        }
    });
}));

// @route   GET /api/orders/:id
// @desc    Get single order
// @access  Private (buyer or seller of the order)
router.get('/:id', authenticateToken, [
    param('id').isMongoId().withMessage('Invalid order ID')
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Validation failed', details: errors.array() });
    }

    const order = await Order.findById(req.params.id)
        .populate('listing', 'title price media category location')
        .populate('buyer', 'firstName lastName trustScore profilePhoto')
        .populate('seller', 'firstName lastName trustScore profilePhoto');

    if (!order) {
        return res.status(404).json({ success: false, error: 'Order not found' });
    }

    // Only buyer, seller, or admin can view
    const userId = req.user._id.toString();
    if (order.buyer._id.toString() !== userId &&
        order.seller._id.toString() !== userId &&
        req.user.role !== 'admin') {
        return res.status(403).json({ success: false, error: 'Not authorized to view this order' });
    }

    res.json({ success: true, data: { order: order.toJSON() } });
}));

// @route   PUT /api/orders/:id/status
// @desc    Update order status
// @access  Private (seller or admin)
router.put('/:id/status', authenticateToken, [
    param('id').isMongoId().withMessage('Invalid order ID'),
    body('status').isIn(['paid', 'shipped', 'delivered', 'cancelled', 'refunded']).withMessage('Invalid status'),
    body('note').optional().trim().isLength({ max: 500 })
], asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, error: 'Validation failed', details: errors.array() });
    }

    const order = await Order.findById(req.params.id);
    if (!order) {
        return res.status(404).json({ success: false, error: 'Order not found' });
    }

    // Only seller, buyer (for cancel), or admin can update
    const userId = req.user._id.toString();
    const isSeller = order.seller.toString() === userId;
    const isBuyer = order.buyer.toString() === userId;
    const isAdmin = req.user.role === 'admin';

    if (!isSeller && !isBuyer && !isAdmin) {
        return res.status(403).json({ success: false, error: 'Not authorized' });
    }

    // Buyers can only cancel
    if (isBuyer && !isAdmin && req.body.status !== 'cancelled') {
        return res.status(403).json({ success: false, error: 'Buyers can only cancel orders' });
    }

    const { status, note = '' } = req.body;

    // Use the cancel method for cancellation (restores stock)
    if (status === 'cancelled') {
        await order.cancel(req.user._id, note || req.body.cancellationReason || '');
    } else {
        order.status = status;
        order.statusHistory.push({
            status,
            changedAt: new Date(),
            changedBy: req.user._id,
            note
        });

        if (status === 'paid' && req.body.transactionId) {
            order.paymentInfo.paidAt = new Date();
            order.paymentInfo.transactionId = req.body.transactionId;
        }

        await order.save();
    }

    await order.populate('listing', 'title price');
    await order.populate('buyer', 'firstName lastName');
    await order.populate('seller', 'firstName lastName');

    res.json({
        success: true,
        message: `Order status updated to ${status}`,
        data: { order: order.toJSON() }
    });
}));

module.exports = router;
