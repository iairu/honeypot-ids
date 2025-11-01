#!/bin/sh

# Stop and remove all containers, networks, and volumes defined in docker-compose.yml
echo "Stopping and removing all containers, networks, and volumes..."
docker compose down

echo "Docker Compose services stopped and removed successfully."