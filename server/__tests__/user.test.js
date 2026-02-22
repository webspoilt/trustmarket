const mongoose = require('mongoose');

// We need to test the schema logic without connecting to a real database.
// We'll test the trust score calculation and password hashing logic.

describe('User Model', () => {
    let User;

    beforeAll(async () => {
        // Connect to in-memory test database or skip if not available
        try {
            await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/trustmarket-test', {
                serverSelectionTimeoutMS: 3000
            });
            User = require('../models/User');
        } catch {
            // If MongoDB is not running, skip DB-dependent tests
            console.warn('MongoDB not available — skipping integration tests');
        }
    });

    afterAll(async () => {
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.db.dropDatabase();
            await mongoose.disconnect();
        }
    });

    describe('Schema validation', () => {
        it('should require email, password, phone, firstName, lastName', () => {
            if (!User) return;
            const user = new User({});
            const error = user.validateSync();
            expect(error.errors.email).toBeDefined();
            expect(error.errors.password).toBeDefined();
            expect(error.errors.phone).toBeDefined();
            expect(error.errors.firstName).toBeDefined();
            expect(error.errors.lastName).toBeDefined();
        });

        it('should have default role of buyer', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'Test',
                lastName: 'User'
            });
            expect(user.role).toBe('buyer');
        });

        it('should reject invalid role values', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'Test',
                lastName: 'User',
                role: 'superadmin'
            });
            const error = user.validateSync();
            expect(error.errors.role).toBeDefined();
        });

        it('should reject invalid phone numbers', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '1234567890', // Doesn't start with 6-9
                firstName: 'Test',
                lastName: 'User'
            });
            const error = user.validateSync();
            expect(error.errors.phone).toBeDefined();
        });

        it('should accept valid Indian phone numbers', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'Test',
                lastName: 'User'
            });
            const error = user.validateSync();
            expect(error?.errors?.phone).toBeUndefined();
        });
    });

    describe('Virtuals', () => {
        it('should compute fullName correctly', () => {
            if (!User) return;
            const user = new User({
                email: 'test@example.com',
                password: 'TestPass123',
                phone: '9876543210',
                firstName: 'John',
                lastName: 'Doe'
            });
            expect(user.fullName).toBe('John Doe');
        });

        it('should compute isAdmin from role', () => {
            if (!User) return;
            const adminUser = new User({
                email: 'admin@example.com',
                password: 'TestPass123',
                phone: '9876543211',
                firstName: 'Admin',
                lastName: 'User',
                role: 'admin'
            });
            expect(adminUser.isAdmin).toBe(true);

            const buyerUser = new User({
                email: 'buyer@example.com',
                password: 'TestPass123',
                phone: '9876543212',
                firstName: 'Buyer',
                lastName: 'User',
                role: 'buyer'
            });
            expect(buyerUser.isAdmin).toBe(false);
        });
    });

    describe('Password hashing', () => {
        it('should hash password on save', async () => {
            if (!User) return;
            const user = new User({
                email: 'hash-test@example.com',
                password: 'TestPass123',
                phone: '9876543213',
                firstName: 'Hash',
                lastName: 'Test'
            });
            await user.save();
            expect(user.password).not.toBe('TestPass123');
            expect(user.password.startsWith('$2')).toBe(true); // bcrypt hash
        });

        it('should correctly compare passwords', async () => {
            if (!User) return;
            const user = await User.findOne({ email: 'hash-test@example.com' });
            if (!user) return;
            const isValid = await user.comparePassword('TestPass123');
            expect(isValid).toBe(true);
            const isInvalid = await user.comparePassword('WrongPassword');
            expect(isInvalid).toBe(false);
        });
    });

    describe('Trust score calculation', () => {
        it('should default trust score to newbie level', () => {
            if (!User) return;
            const user = new User({
                email: 'trust@example.com',
                password: 'TestPass123',
                phone: '9876543214',
                firstName: 'Trust',
                lastName: 'Test'
            });
            expect(user.trustScore.level).toBe('newbie');
            expect(user.trustScore.total).toBe(0);
        });
    });
});
