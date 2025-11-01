#!/bin/sh

# Tail Suricata logs script for honeypot-ids-system-v1

echo "=== Tailing Suricata logs ==="
echo "Press Ctrl+C to stop"
echo ""

# Check if suricata_logs directory exists
if [ ! -d "./suricata_logs" ]; then
    echo "Warning: suricata_logs directory not found. Creating it..."
    mkdir -p ./suricata_logs
fi

# Check if any log files exist
if [ -z "$(find ./suricata_logs -name '*.log' -o -name '*.json' 2>/dev/null)" ]; then
    echo "No Suricata log files found yet. Waiting for logs to be created..."
fi

# Tail all suricata log files (fast.log, eve.json, etc.)
tail -f ./suricata_logs/*.log ./suricata_logs/*.json 2>/dev/null &

# Keep the script running
wait