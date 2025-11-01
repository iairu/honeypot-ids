#!/bin/sh

# Dump Production Database Script
# Generates a SQL dump of the production database and saves it to honeypot_database_migrations

set -e

echo "=== Production Database Dump Script ==="
echo ""

# Configuration
CONTAINER_NAME="honeypot-ids-system-v1-production_database-1"
DB_NAME="production_database"
DB_USER="production_user"
DB_PASSWORD="db_is_not_externally_exposed_but_can_be_accessed_from_this_container"
DUMP_DIR="./production-database-sql-dumps"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DUMP_FILE="production_database_dump_${TIMESTAMP}.sql"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "${CONTAINER_NAME}"; then
    echo "Error: Production database container is not running"
    echo "Please start the containers first with: ./docker-compose-up-detached.sh"
    exit 1
fi

# Create dump directory if it doesn't exist
if [ ! -d "${DUMP_DIR}" ]; then
    echo "Creating dump directory: ${DUMP_DIR}"
    mkdir -p "${DUMP_DIR}"
fi

echo "Dumping database: ${DB_NAME}"
echo "Container: ${CONTAINER_NAME}"
echo "Output file: ${DUMP_DIR}/${DUMP_FILE}"
echo ""

# Create the dump
docker exec ${CONTAINER_NAME} mysqldump \
    -u${DB_USER} \
    -p${DB_PASSWORD} \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    --add-drop-table \
    --add-locks \
    --create-options \
    --disable-keys \
    --extended-insert \
    --quick \
    ${DB_NAME} > "${DUMP_DIR}/${DUMP_FILE}"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Database dump created successfully!"
    echo ""
    echo "File: ${DUMP_DIR}/${DUMP_FILE}"
    echo "Size: $(du -h "${DUMP_DIR}/${DUMP_FILE}" | cut -f1)"
    echo ""
    
    # Create a symlink to the latest dump
    ln -sf "${DUMP_FILE}" "${DUMP_DIR}/latest.sql"
    echo "Latest dump symlink: ${DUMP_DIR}/latest.sql"
    echo ""
    echo "To import this dump into honeypot database, run:"
    echo "  docker exec -i honeypot-ids-system-v1-honeypot_database-1 mysql -uproduction_user -pdb_is_not_externally_exposed_but_can_be_accessed_from_this_container production_database < ${DUMP_DIR}/${DUMP_FILE}"
else
    echo ""
    echo "✗ Error: Database dump failed"
    exit 1
fi
