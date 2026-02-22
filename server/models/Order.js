const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
    buyer: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    seller: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    listing: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Listing',
        required: true
    },
    quantity: {
        type: Number,
        required: true,
        min: 1,
        default: 1
    },
    unitPrice: {
        type: Number,
        required: true,
        min: 0
    },
    totalPrice: {
        type: Number,
        required: true,
        min: 0
    },
    status: {
        type: String,
        enum: ['pending', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded'],
        default: 'pending'
    },
    paymentInfo: {
        method: {
            type: String,
            enum: ['cod', 'upi', 'card', 'bank_transfer', null],
            default: null
        },
        transactionId: {
            type: String,
            default: null
        },
        paidAt: {
            type: Date,
            default: null
        }
    },
    shippingAddress: {
        address: { type: String, default: '' },
        city: { type: String, default: '' },
        state: { type: String, default: '' },
        pincode: { type: String, default: '' }
    },
    statusHistory: [{
        status: {
            type: String,
            enum: ['pending', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded'],
            required: true
        },
        changedAt: {
            type: Date,
            default: Date.now
        },
        changedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        note: {
            type: String,
            maxlength: 500,
            default: ''
        }
    }],
    cancellationReason: {
        type: String,
        maxlength: 500,
        default: null
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Indexes for performance
orderSchema.index({ buyer: 1, createdAt: -1 });
orderSchema.index({ seller: 1, createdAt: -1 });
orderSchema.index({ listing: 1 });
orderSchema.index({ status: 1, createdAt: -1 });

// Pre-save: push status to history on status change
orderSchema.pre('save', function (next) {
    if (this.isModified('status')) {
        this.statusHistory.push({
            status: this.status,
            changedAt: new Date()
        });
    }
    next();
});

// Instance methods
orderSchema.methods.cancel = async function (userId, reason = '') {
    if (['delivered', 'refunded'].includes(this.status)) {
        throw new Error('Cannot cancel a delivered or refunded order');
    }
    this.status = 'cancelled';
    this.cancellationReason = reason;
    this.statusHistory.push({
        status: 'cancelled',
        changedAt: new Date(),
        changedBy: userId,
        note: reason
    });

    // Restore listing stock
    const Listing = mongoose.model('Listing');
    await Listing.findByIdAndUpdate(this.listing, {
        $inc: { stock: this.quantity }
    });

    return this.save();
};

// Static methods
orderSchema.statics.findByBuyer = function (buyerId) {
    return this.find({ buyer: buyerId })
        .populate('listing', 'title price media.video.thumbnail')
        .populate('seller', 'firstName lastName trustScore')
        .sort({ createdAt: -1 });
};

orderSchema.statics.findBySeller = function (sellerId) {
    return this.find({ seller: sellerId })
        .populate('listing', 'title price media.video.thumbnail')
        .populate('buyer', 'firstName lastName trustScore')
        .sort({ createdAt: -1 });
};

module.exports = mongoose.model('Order', orderSchema);
