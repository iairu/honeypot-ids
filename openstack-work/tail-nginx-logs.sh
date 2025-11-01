#!/bin/sh

# Tail Nginx logs script for honeypot-ids-system-v1

echo "=== Tailing Nginx logs ==="
echo "Press Ctrl+C to stop"
echo ""

# Check if nginx_logs directory exists
if [ ! -d "./nginx_logs" ]; then
    echo "Warning: nginx_logs directory not found. Creating it..."
    mkdir -p ./nginx_logs
fi

# Tail all nginx log files
tail -f ./nginx_logs/*.log 2>/dev/null || echo "No nginx log files found yet. Waiting for logs to be created..."