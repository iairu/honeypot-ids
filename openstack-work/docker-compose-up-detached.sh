#!/bin/sh

# Docker Compose Up (Detached) Script for Honeypot IDS System
# Starts all services in detached mode (background)

set -e

echo "Starting Honeypot IDS System in detached mode..."
echo "=================================================="

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

# Deliberately plain `docker compose up -d`, no --profile -- see
# docker-compose-up.sh's comment: vector (profiles: [elk]) is meant to
# stay opt-in, not force-started here.
echo "Starting services with docker compose in background..."
docker compose up -d

echo ""
echo "Services started successfully in detached mode."
echo ""
echo "Useful commands:"
echo "  docker compose ps          - View running containers"
echo "  docker compose logs -f     - Follow all logs"
echo "  ./docker-compose-down.sh   - Stop all services, including any profiled ones (e.g. vector)"