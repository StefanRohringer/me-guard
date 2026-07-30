#!/bin/bash
# Me-Guard Startup Script
# Checks ALL skills first, then starts your agent.
# Usage: bash start-me-guard.sh

set -e

# === Configuration ===
# Replace with your actual agent command (e.g. "AGENT_BIN=\"my-agent\" AGENT_ARGS=\"run\"")
AGENT_BIN=""
AGENT_ARGS=""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PRELOAD_SCRIPT="$SCRIPT_DIR/scripts/me-guard-preload.py"
LOG_DIR="$HOME/.me-guard/logs"
mkdir -p "$LOG_DIR"

START_LOG="$LOG_DIR/start-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$START_LOG") 2>&1

echo "🛡️  Me-Guard Startup"
echo "======================="
echo "Time: $(date)"
echo "Log:  $START_LOG"
echo ""

# === 1. Preload Check ===
echo "Step 1/2: Skill Governance Check..."
echo ""

if [ ! -f "$PRELOAD_SCRIPT" ]; then
    echo "❌ Preload script missing: $PRELOAD_SCRIPT"
    exit 1
fi

if ! python3 "$PRELOAD_SCRIPT"; then
    echo ""
    echo "🚫 Preload check failed."
    echo "   Agent will NOT be started."
    echo ""
    echo "What to do?"
    echo "  - Check invalid skills:"
    echo "      python3 $SCRIPT_DIR/scripts/governance.py list"
    echo "  - Re-sign skills:"
    echo "      python3 $SCRIPT_DIR/scripts/governance.py sign <PATH> --approve"
    echo ""
    exit 1
fi

echo ""
echo "✅ All skills checked, signatures valid."
echo ""

# === 2. Start Agent ===
if [ -z "$AGENT_BIN" ]; then
    echo "✅ Preload passed. Set AGENT_BIN in start-me-guard.sh to auto-start your agent."
    echo "   Example: AGENT_BIN=\"my-agent\" AGENT_ARGS=\"run\""
    exit 0
fi

echo "🚀 Step 2/2: Starting $AGENT_BIN $AGENT_ARGS..."
echo ""

if ! command -v "$AGENT_BIN" >/dev/null 2>&1; then
    echo "❌ Command '$AGENT_BIN' not found."
    echo "   Adjust AGENT_BIN in start-me-guard.sh"
    exit 1
fi

exec "$AGENT_BIN" $AGENT_ARGS "$@"
