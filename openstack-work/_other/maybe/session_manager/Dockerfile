FROM node:18-alpine

WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    curl \
    bash

# Copy package files
COPY package*.json ./

# Install npm dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p /var/log/session_manager

# Set proper permissions
RUN chown -R node:node /app /var/log/session_manager

# Switch to non-root user
USER node

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

# Start the application
CMD ["node", "server.js"]