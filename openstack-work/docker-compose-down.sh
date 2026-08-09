#!/bin/sh

# Stop and remove all containers, networks, and volumes defined in docker-compose.yml
echo "Stopping and removing all containers, networks, and volumes..."
# --profile '*': without this, any service gated behind a Compose profile
# (e.g. vector, profiles: [elk]) that happens to be running is silently
# excluded from `down`'s scope -- left orphaned instead of stopped. Unlike
# docker-compose-up.sh (which deliberately does NOT force-start vector),
# tearing down must always cover everything that might be running,
# regardless of which profile started it.
docker compose --profile '*' down

echo "Docker Compose services stopped and removed successfully."