#!/bin/bash
# Me-Guard - Key Backup to USB
# Backs up root-ca.key + Public Key + revoked.json to USB stick.
# In case of SD card failure: recovery possible.

set -e

GOV_DIR="$HOME/.me-guard/governance"
TARGET="${1:-}"

echo "🔐 Me-Guard - Key Backup"
echo "================================="
echo ""

# 1. Check source
if [ ! -f "$GOV_DIR/root-ca.key" ]; then
    echo "❌ No key found: $GOV_DIR/root-ca.key"
    echo "   Run setup.sh first."
    exit 1
fi

# 2. Find target (if not specified)
if [ -z "$TARGET" ]; then
    echo "🔍 Searching for USB sticks under /media/$USER/ and /mnt/..."
    CANDIDATES=$(find /media/"$USER" /mnt -maxdepth 2 -type d 2>/dev/null || true)
    if [ -z "$CANDIDATES" ]; then
        echo "❌ No USB stick found."
        echo "   Insert a stick and specify the path:"
        echo "   bash $0 /media/$USER/STICK-NAME"
        exit 1
    fi
    echo ""
    echo "Found targets:"
    echo "$CANDIDATES" | nl
    echo ""
    read -rp "Which one (number)? " NUM
    TARGET=$(echo "$CANDIDATES" | sed -n "${NUM}p")
fi

if [ ! -d "$TARGET" ]; then
    echo "❌ Target is not a directory: $TARGET"
    exit 1
fi

# 3. Write test
TEST_FILE="$TARGET/.me-guard-write-test"
if ! touch "$TEST_FILE" 2>/dev/null; then
    echo "❌ Target is not writable: $TARGET"
    exit 1
fi
rm -f "$TEST_FILE"

# 4. Backup directory with timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$TARGET/me-guard-backup-$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

# 5. Copy
echo ""
echo "📂 Copying to: $BACKUP_DIR"
cp "$GOV_DIR/root-ca.key" "$BACKUP_DIR/"
cp "$GOV_DIR/root-ca-pub.pem" "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$GOV_DIR/revoked.json" ] && cp "$GOV_DIR/revoked.json" "$BACKUP_DIR/"
chmod 600 "$BACKUP_DIR/root-ca.key"
chmod 700 "$BACKUP_DIR"

# 6. Integrity check
echo ""
echo "🔍 Comparing hashes..."
ORIG_HASH=$(sha256sum "$GOV_DIR/root-ca.key" | awk '{print $1}')
BACKUP_HASH=$(sha256sum "$BACKUP_DIR/root-ca.key" | awk '{print $1}')
if [ "$ORIG_HASH" = "$BACKUP_HASH" ]; then
    echo "✅ Hashes match."
else
    echo "❌ HASH MISMATCH! Backup is corrupted."
    exit 1
fi

# 7. README into backup
cat > "$BACKUP_DIR/README.txt" <<EOF
Me-Guard - CA Backup
Created: $(date)
Host: $(hostname)

Files:
  - root-ca.key       Private key (passphrase-protected)
  - root-ca-pub.pem   Public key (for verification)
  - revoked.json      Revocation list

Recovery:
  mkdir -p ~/.me-guard/governance
  cp root-ca.key root-ca-pub.pem ~/.me-guard/governance/
  chmod 600 ~/.me-guard/governance/root-ca.key
  chmod 644 ~/.me-guard/governance/root-ca-pub.pem

Important: Store the stick securely. Passphrase is NOT in the backup!
EOF

echo ""
echo "✅ Backup successful!"
echo ""
echo "📍 Location:  $BACKUP_DIR"
echo "📦 Size:      $(du -sh "$BACKUP_DIR" | awk '{print $1}')"
echo "🔒 Perms:    chmod 600 (you only)"
echo ""

# Write marker (for automatic reminder logic)
MARKER="$GOV_DIR/.last-usb-backup"
touch "$MARKER"
echo "🏷️  Marker set: $MARKER ($(date -Iminutes))"
echo ""
echo "⚠️  Important:"
echo "   - Store the stick securely (drawer, safe)"
echo "   - Passphrase only in your head — DO NOT forget it!"
echo "   - Renew backup quarterly"
echo ""
echo "Eject:       sudo umount $TARGET"
