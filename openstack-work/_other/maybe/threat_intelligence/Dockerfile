FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /data /var/log/threat_intel

# Set proper permissions
RUN chmod +x threat_intel.py
RUN chown -R nobody:nogroup /app /data /var/log/threat_intel

# Switch to non-root user
USER nobody

# Expose port (if needed for health checks)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Start the threat intelligence service
CMD ["python", "threat_intel.py"]