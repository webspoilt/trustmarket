const { generateTokens, verifyToken } = require('../middleware/auth');

// Mock the User model
jest.mock('../models/User', () => {
    const mockUser = {
        _id: '507f1f77bcf86cd799439011',
        role: 'buyer',
        isActive: true,
        isBanned: false,
        isAdmin: false,
        toJSON: function () { return { ...this }; }
    };
    return {
        findById: jest.fn().mockResolvedValue(mockUser)
    };
});

describe('Auth Middleware', () => {
    // Set env vars for tests
    beforeAll(() => {
        process.env.JWT_SECRET = 'test-secret';
        process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
    });

    describe('generateTokens', () => {
        it('should generate access and refresh tokens', () => {
            const tokens = generateTokens('user123', 'buyer');
            expect(tokens).toHaveProperty('accessToken');
            expect(tokens).toHaveProperty('refreshToken');
            expect(typeof tokens.accessToken).toBe('string');
            expect(typeof tokens.refreshToken).toBe('string');
        });

        it('should generate tokens with default role if not specified', () => {
            const tokens = generateTokens('user123');
            expect(tokens.accessToken).toBeTruthy();
        });

        it('should embed role in the token payload', () => {
            const tokens = generateTokens('user123', 'admin');
            const decoded = verifyToken(tokens.accessToken, process.env.JWT_SECRET);
            expect(decoded.role).toBe('admin');
            expect(decoded.type).toBe('access');
        });
    });

    describe('verifyToken', () => {
        it('should verify a valid token', () => {
            const tokens = generateTokens('user123', 'seller');
            const decoded = verifyToken(tokens.accessToken, process.env.JWT_SECRET);
            expect(decoded.userId).toBe('user123');
            expect(decoded.role).toBe('seller');
            expect(decoded.type).toBe('access');
        });

        it('should throw on invalid token', () => {
            expect(() => verifyToken('invalid-token', process.env.JWT_SECRET)).toThrow('Invalid token');
        });

        it('should throw when using wrong secret', () => {
            const tokens = generateTokens('user123', 'buyer');
            expect(() => verifyToken(tokens.accessToken, 'wrong-secret')).toThrow('Invalid token');
        });

        it('should verify refresh token with refresh secret', () => {
            const tokens = generateTokens('user123', 'buyer');
            const decoded = verifyToken(tokens.refreshToken, process.env.JWT_REFRESH_SECRET);
            expect(decoded.userId).toBe('user123');
            expect(decoded.type).toBe('refresh');
        });
    });

    describe('requireRole', () => {
        const { requireRole } = require('../middleware/auth');

        const mockRes = () => {
            const res = {};
            res.status = jest.fn().mockReturnValue(res);
            res.json = jest.fn().mockReturnValue(res);
            return res;
        };

        it('should allow access for matching role', () => {
            const middleware = requireRole('admin');
            const req = { user: { role: 'admin' } };
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).toHaveBeenCalled();
        });

        it('should allow access when user has any of the specified roles', () => {
            const middleware = requireRole('seller', 'admin');
            const req = { user: { role: 'seller' } };
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).toHaveBeenCalled();
        });

        it('should deny access for non-matching role', () => {
            const middleware = requireRole('admin');
            const req = { user: { role: 'buyer' } };
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ code: 'INSUFFICIENT_ROLE' })
            );
        });

        it('should return 401 when no user is present', () => {
            const middleware = requireRole('admin');
            const req = {};
            const res = mockRes();
            const next = jest.fn();

            middleware(req, res, next);
            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(401);
        });
    });
});
