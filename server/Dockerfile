# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files for caching
COPY server/package*.json ./server/
COPY client/package*.json ./client/
COPY package*.json ./

# Install server dependencies
RUN cd server && npm ci --only=production

# Install client dependencies and build
RUN cd client && npm ci && npm run build

# Copy source code
COPY server/ ./server/
COPY client/build/ ./server/public/

# ─── Production stage ───
FROM node:20-alpine

WORKDIR /app

# Add non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S trustmarket -u 1001 -G nodejs

# Copy built artifacts
COPY --from=builder /app/server/ ./
COPY --from=builder /app/server/public/ ./public/

# Create logs directory
RUN mkdir -p logs && chown trustmarket:nodejs logs

USER trustmarket

EXPOSE 5000

ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD wget -qO- http://localhost:5000/api/health || exit 1

CMD ["node", "index.js"]
