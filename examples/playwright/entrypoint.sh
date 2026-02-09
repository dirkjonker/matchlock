#!/bin/bash
set -e

# Ensure localhost resolves (matchlock's init doesn't populate /etc/hosts)
grep -q localhost /etc/hosts 2>/dev/null || {
    echo '127.0.0.1 localhost' >> /etc/hosts
    echo '::1 localhost' >> /etc/hosts
}

CLAUDE_ARGS="--dangerously-skip-permissions --mcp-config /etc/matchlock-mcp.json"

if [ $# -eq 0 ]; then
    exec claude $CLAUDE_ARGS
else
    exec claude $CLAUDE_ARGS -p "$*"
fi
