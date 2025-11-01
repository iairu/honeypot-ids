#!/bin/sh

# Docker Purge Script
# This script removes all containers, volumes, and networks for the honeypot-ids-system

set -e

echo "=== Docker Purge Script ==="
echo "This will remove all containers, volumes, and networks for honeypot-ids-system-v1"
echo ""
echo "WARNING: This will delete all data including databases and logs!"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Purge cancelled."
    exit 0
fi

echo ""
echo "Stopping and removing all containers..."
docker compose down

echo ""
echo "Removing all volumes..."
docker compose down -v

echo ""
echo "Removing orphaned containers..."
docker compose down --remove-orphans

echo ""
echo "Cleaning up Docker system..."
docker system prune -f

echo ""
echo "=== Purge Complete ==="
echo "All containers, networks, and volumes have been removed."
echo "Local data directories may still contain files. To remove them, run:"
echo "  rm -rf production_eshop_files production_database_data"
echo "  rm -rf honeypot_eshop_files honeypot_database_data"
echo "  rm -rf redis_data ssl_certificates nginx_logs suricata_logs"