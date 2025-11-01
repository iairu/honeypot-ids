#!/bin/sh

# Docker Compose Up Script for Honeypot IDS System
# Starts all services defined in docker-compose.yml

set -e

echo "Starting Honeypot IDS System..."
echo "================================"

# Check if docker compose is available
if ! docker compose version >/dev/null 2>&1; then
    echo "Error: docker compose is not installed or not available"
    exit 1
fi

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    echo "Error: docker-compose.yml not found in current directory"
    exit 1
fi

# Start services
echo "Starting services with docker compose..."
docker compose up

echo ""
echo "Services stopped."