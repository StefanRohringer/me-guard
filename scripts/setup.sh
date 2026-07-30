#!/bin/bash
# ============================================================
# Me-Guard - One-time Setup
# ============================================================
# Creates the directory structure, a local root CA and
# sets all permissions correctly.
#
# Everything stays LOCAL. Nothing goes to the internet.
# ============================================================

set -e

ME_GUARD_DIR="$HOME/.me-guard"
GOV_DIR="$ME_GUARD_DIR/governance"

echo "🔧 Me-Guard - Setup"
echo "===================================="
echo ""

# 1. Create directories
echo "📂 Creating directory structure..."
mkdir -p "$ME_GUARD_DIR/skills"
mkdir -p "$ME_GUARD_DIR/skill_catalog"
mkdir -p "$ME_GUARD_DIR/skill_signatures"
mkdir -p "$ME_GUARD_DIR/rules"
mkdir -p "$GOV_DIR"

# Strict permissions on governance folder
chmod 700 "$GOV_DIR"

# 2. Generate root CA (if not already present)
if [ -f "$GOV_DIR/root-ca.key" ]; then
    echo "⚠️  Root CA already exists — skipping generation."
    echo "    If you want to start over: delete $GOV_DIR/root-ca.*"
else
    echo ""
    echo "🔐 Generating local root CA (Ed25519, with passphrase)..."
    echo ""
    echo "The passphrase is required EVERY time you sign a skill."
    echo "(NOT when verifying — don't worry!)"
    echo ""

    # Use ME_GUARD_PASSPHRASE env var if set, otherwise prompt interactively
    if [ -n "$ME_GUARD_PASSPHRASE" ]; then
        echo "   Using passphrase from ME_GUARD_PASSPHRASE environment variable."
        PASSPHRASE="$ME_GUARD_PASSPHRASE"
    else
        # Prompt user for passphrase (twice for confirmation)
        while true; do
            read -s -p "Enter passphrase for CA key: " PASSPHRASE
            echo ""
            read -s -p "Confirm passphrase: " PASSPHRASE2
            echo ""
            if [ "$PASSPHRASE" = "$PASSPHRASE2" ] && [ -n "$PASSPHRASE" ]; then
                break
            elif [ -z "$PASSPHRASE" ]; then
                echo "❌ Passphrase cannot be empty. Try again."
            else
                echo "❌ Passphrases do not match. Try again."
            fi
        done
    fi

    echo ""
    echo "🔐 Creating CA key (keep this passphrase safe!)..."

    # Ed25519 is modern, secure, and fast on Raspberry Pi
    openssl genpkey \
        -algorithm ed25519 \
        -aes256 \
        -pass "pass:$PASSPHRASE" \
        -out "$GOV_DIR/root-ca.key"

    # Extract public key from private key
    openssl pkey \
        -in "$GOV_DIR/root-ca.key" \
        -passin "pass:$PASSPHRASE" \
        -pubout \
        -out "$GOV_DIR/root-ca-pub.pem"

    # Save a hint for the user (NOT the passphrase itself!)
    echo "$(date) — CA key created" > "$GOV_DIR/.key-info"
    chmod 600 "$GOV_DIR/.key-info"

    echo "✅ Root CA generated."
    echo "⚠️  IMPORTANT: Remember your passphrase! Without it, you cannot sign new skills."
    echo "   The passphrase is NOT stored anywhere — this is intentional for security."
    echo "   If you lose it, delete root-ca.* and run setup.sh again (all signatures become invalid)."
fi

# 3. Set permissions STRICTLY
echo ""
echo "🔒 Setting permissions..."
chmod 600 "$GOV_DIR/root-ca.key"          # Only you may read the private key
chmod 644 "$GOV_DIR/root-ca-pub.pem"      # Public key: readable

# 4. Remove old RSA certificate (Migration)
if [ -f "$GOV_DIR/root-ca.pem" ] && [ -f "$GOV_DIR/root-ca.key" ]; then
    echo "🧹 Old RSA certificate removed (migration to Ed25519)."
    rm -f "$GOV_DIR/root-ca.pem"
fi

# 5. Prepare log file
touch "$GOV_DIR/scan.log"
chmod 600 "$GOV_DIR/scan.log"

# 6. Initialize revocation list
if [ ! -f "$GOV_DIR/revoked.json" ]; then
    echo '{"revoked_skills": []}' > "$GOV_DIR/revoked.json"
fi

# 7. Create default rules (if not present)
RULES_FILE="$ME_GUARD_DIR/rules/default.yaml"
if [ ! -f "$RULES_FILE" ]; then
    cat > "$RULES_FILE" <<'EOF'
# Me-Guard - Default Rules
# Edit this file to define your own rules.

# --- Blocked Patterns (BLOCKED IMMEDIATELY) ---
blocked_patterns:
  - 'rm\s+-rf\s+/'
  - 'rm\s+-r\s+-f\s+/'
  - ':\(\)\{.*\|:&\};:'          # Fork Bomb
  - 'mkfs\.'                      # Format filesystem
  - 'dd\s+if=.*of=/dev/'         # dd on block devices
  - '/dev/sd[a-z]'                # Direct block device access
  - 'nc\s+-e'                     # Reverse Shell
  - 'bash\s+-i\s+>&\s+/dev/tcp'  # Reverse Shell
  - 'python.*-c.*__import__'     # Obfuscated Python
  - 'eval\s*\(\s*.*base64'        # Base64-decoded eval

# --- Review Patterns (MANUAL REVIEW) ---
review_patterns:
  - '(?i)api[_-]?key\s*=\s*[''"][^''"]{10,}'
  - '(?i)secret\s*=\s*[''"][^''"]{10,}'
  - '(?i)password\s*=\s*[''"][^''"]{6,}'
  - '(?i)token\s*=\s*[''"][^''"]{10,}'
  - 'https?://(?!localhost|127\.0\.0\.1|192\.168\.|10\.)'  # External URLs
  - 'requests\.(get|post|put|delete|patch)'
  - 'urllib\.'
  - 'curl\s+http'
  - 'wget\s+http'
  - 'socket\.(connect|create_connection)'

# --- AST: Forbidden Python Imports (BLOCKED IMMEDIATELY) ---
ast_forbidden_imports:
  - subprocess
  - os
  - eval
  - exec

# --- AST: Review Python Imports (MANUAL REVIEW) ---
ast_review_imports:
  - socket
  - requests
  - urllib
  - http.client
EOF
    echo "✅ Default rules created: $RULES_FILE"
fi

# 8. Summary
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo ""
echo "✅ Setup complete!"
echo ""
echo "📂 Structure:"
echo "   $ME_GUARD_DIR/"
echo "   ├── skills/              (Me-Guard stores skills here)"
echo "   ├── skill_catalog/       (Metadata as YAML)"
echo "   ├── skill_signatures/    (Crypto signatures .sig)"
echo "   ├── rules/               (Your scan rules)"
echo "   └── governance/"
echo "       ├── root-ca.key      🔐 PRIVATE (chmod 600, with passphrase)"
echo "       ├── root-ca-pub.pem  🔑 For verification (local only!)"
echo "       ├── revoked.json     🚫 Revocation list"
echo "       └── scan.log         📋 Hash-chained audit log"
echo ""
echo "📌 Important:"
echo "   - NONE of this goes to the internet."
echo "   - All files reside locally on your machine."
echo "   - Make a backup of root-ca.key on a USB stick!"
echo ""
echo "Next step: scan a skill with:"
echo "   python3 $SCRIPT_DIR/governance.py scan \$HOME/.me-guard/skills/YOUR-SKILL/"
echo ""
echo "Then sign with:"
echo "   python3 $SCRIPT_DIR/governance.py sign \$HOME/.me-guard/skills/YOUR-SKILL/ --approve"
