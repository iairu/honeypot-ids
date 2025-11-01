#!/bin/bash

# Redis Show Tables Script
# Displays all Redis keys and their types in the session_store container

echo "=========================================="
echo "Redis Database Contents"
echo "=========================================="
echo ""

# Check if session_store container is running
if ! docker ps --format '{{.Names}}' | grep -q "session_store"; then
    echo "Error: session_store container is not running"
    echo "Please start the containers first with docker-compose up"
    exit 1
fi

echo "Connecting to Redis..."
echo ""

# Get all keys
KEYS=$(docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning KEYS '*' 2>/dev/null)

if [ -z "$KEYS" ]; then
    echo "No keys found in Redis database"
    exit 0
fi

echo "Found keys:"
echo "----------------------------------------"

# Display each key with its type and value
echo "$KEYS" | while read -r key; do
    if [ -n "$key" ]; then
        TYPE=$(docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning TYPE "$key" 2>/dev/null)
        echo ""
        echo "Key: $key"
        echo "Type: $TYPE"
        
        case "$TYPE" in
            string)
                VALUE=$(docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning GET "$key" 2>/dev/null)
                echo "Value: $VALUE"
                ;;
            hash)
                echo "Hash contents:"
                docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning HGETALL "$key" 2>/dev/null
                ;;
            list)
                echo "List contents:"
                docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning LRANGE "$key" 0 -1 2>/dev/null
                ;;
            set)
                echo "Set contents:"
                docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning SMEMBERS "$key" 2>/dev/null
                ;;
            zset)
                echo "Sorted set contents:"
                docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning ZRANGE "$key" 0 -1 WITHSCORES 2>/dev/null
                ;;
        esac
        echo "----------------------------------------"
    fi
done

echo ""
echo "Database info:"
docker exec honeypot-ids-system-v1-session_store-1 redis-cli -a session_redis_password --no-auth-warning INFO keyspace 2>/dev/null

echo ""
echo "=========================================="