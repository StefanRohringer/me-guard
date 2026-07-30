#!/bin/bash
# Me-Guard Demo — demonstrates scan → sign → verify → preload
# Usage: bash scripts/demo.sh
# Requires: ME_GUARD_PASSPHRASE environment variable or interactive prompt

set -e
cd "$(dirname "$0")/.."

echo "=== Me-Guard Demo ==="
echo ""

# Create a test skill
SKILL_DIR=$(mktemp -d)
mkdir -p "$SKILL_DIR/demo-skill"
cat > "$SKILL_DIR/demo-skill/SKILL.md" << 'EOF'
# Demo Skill
A safe skill for demonstrating Me-Guard.
EOF

cat > "$SKILL_DIR/demo-skill/greet.py" << 'EOF'
def greet(name):
    return f"Hello, {name}!"

def add(a, b):
    return a + b
EOF

echo "📁 Created demo skill"

# 1. SCAN
echo ""
echo "--- Step 1: Scan ---"
python3 scripts/governance.py scan "$SKILL_DIR/demo-skill/"

# 2. SIGN
echo ""
echo "--- Step 2: Sign ---"
python3 scripts/governance.py sign "$SKILL_DIR/demo-skill/" --approve

# 3. VERIFY
echo ""
echo "--- Step 3: Verify ---"
python3 scripts/governance.py verify "$SKILL_DIR/demo-skill/"

# 4. PRELOAD
echo ""
echo "--- Step 4: Preload Check ---"
mkdir -p ~/.me-guard/skills
cp -r "$SKILL_DIR/demo-skill" ~/.me-guard/skills/
python3 scripts/me-guard-preload.py 2>&1 | grep "demo-skill" || true

# Cleanup
rm -rf "$SKILL_DIR" ~/.me-guard/skills/demo-skill

echo ""
echo "=== ✅ DEMO COMPLETE ==="
