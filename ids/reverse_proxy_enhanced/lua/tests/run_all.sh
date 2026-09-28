#!/usr/bin/env bash
# Runs every test_*.lua suite; exits non-zero if any suite fails.
# Usage: ids/reverse_proxy_enhanced/lua/tests/run_all.sh [lua-binary]
set -u
cd "$(dirname "$0")"
LUA="${1:-lua}"
status=0
for f in test_*.lua; do
    if out=$("$LUA" "$f" 2>&1); then
        echo "ok   $f  ($(echo "$out" | tail -1))"
    else
        echo "FAIL $f"
        echo "$out" | grep -E 'FAIL|error|traceback' | sed 's/^/     /'
        status=1
    fi
done
exit $status
