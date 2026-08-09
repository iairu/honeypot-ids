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
echo "Stopping and removing all containers, networks, and volumes..."
# --profile '*': without this, `docker compose down` silently excludes any
# service gated behind a Compose profile (e.g. vector, profiles: [elk]) from
# its scope entirely -- confirmed live, the same issue dashboard/core/
# docker_ctl.py's Target.build() already works around for every compose
# command the dashboard itself runs. Without it here, a profiled service
# that happened to be running (`docker compose --profile elk up -d`) is left
# orphaned: not stopped, not removed, and its volumes untouched -- exactly
# the kind of leftover state a "purge everything" script exists to prevent.
# One combined `down -v --remove-orphans` instead of three separate `down`
# calls -- the second and third calls were redundant repeats of the first
# (which already stops+removes containers/networks) doing nothing extra
# except finally passing -v/--remove-orphans on their own separate pass.
docker compose --profile '*' down -v --remove-orphans

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