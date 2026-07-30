# 🛡️ Me-Guard

**Local security and trust system for AI agent skills. 100% offline. Deterministic. For everyone.**

---

## What is Me-Guard?

Me-Guard checks and signs AI skills **before** they are executed. Think of it as a digital security gate for your agent skills:

- **Scan** → Searches every skill's code for dangerous patterns (Regex + Python AST)
- **Sign** → Signs verified skills with a local Ed25519 root CA
- **Verify** → Checks before every startup whether signatures are still valid
- **Preload Hook** → Blocks gateway startup on compromised skills

Inspired by [NVIDIA Verified Agent Skills](https://developer.nvidia.com/blog/nvidia-verified-agent-skills-provide-capability-governance-for-ai-agents/), but completely local on your machine.

> 📌 **Guarantee:** No upload, no external API, no cloud logging. Everything runs under `~/.me-guard/`.

---

## Features

| Feature | Description |
|---------|-------------|
| **Regex Scanner** | API keys, secrets, `rm -rf /`, reverse shells, fork bombs |
| **AST Scanner (Python)** | Finds obfuscated code like `__import__('os').system(...)` |
| **Ed25519 + AES-256** | Modern cryptography, fast even on Raspberry Pi |
| **Full Skill Directory** | Manifest hash over ALL files, not just SKILL.md |
| **Hash-chained Audit Log** | Tampering visible immediately |
| **Revocation List** | Signatures revocable with history |
| **YAML Rules** | Custom scan rules editable in `~/.me-guard/rules/` |
| **FAIL_CLOSED (Default)** | Every CRITICAL skill stops the gateway (OT safety) |
| **FAIL_SAFE (Configurable)** | CRITICAL skills → quarantine, gateway starts with N-1 |
| **Weekly Audit** | Automatic report on skill status + hash chain integrity |

---

## Prerequisites

- **Python 3.8+**
- **OpenSSL 3.x** (for Ed25519 cryptography)
- **Linux** (tested on Raspberry Pi OS, Debian, Ubuntu)

Optional:
- `pyyaml` (Python YAML — `pip install pyyaml` or `apt install python3-yaml`)

---

## Installation

```bash
# 1. Clone the repository (anywhere you want)
git clone https://github.com/YOUR_USERNAME/me-guard.git
cd me-guard

# 2. One-time setup (creates Ed25519 CA + directory structure)
make setup
# or: bash scripts/setup.sh

# 3. Verify everything is ready
python3 scripts/governance.py list
```

**What setup does:**
- Creates directory structure under `~/.me-guard/`
- Generates Ed25519 root CA with passphrase
- Writes default scan rules
- Sets strict permissions (`chmod 600` for private keys)

---

## Quick Start

```bash
# Try the built-in demo (no Hermes needed)
bash scripts/demo.sh

# Or scan the example skills directly:
python3 scripts/governance.py scan examples/demo-skill/      # → trusted
python3 scripts/governance.py scan examples/danger-skill/    # → blocked
```

### Real usage

```bash
# Scan a skill (inspection only, no changes)
python3 scripts/governance.py scan ~/.me-guard/skills/my-skill/

# If scan says "trusted" → sign it
python3 scripts/governance.py sign ~/.me-guard/skills/my-skill/ --approve

# Verify signature
python3 scripts/governance.py verify ~/.me-guard/skills/my-skill/

# List all signed skills
python3 scripts/governance.py list
```

---

## Commands

| Command | Description |
|---------|-------------|
| `scan <path>` | Scan skill → classification + findings |
| `sign <path> --approve` | Create card + signature (requires `--approve`!) |
| `verify <path>` | Check signature + manifest + revocation |
| `list` | Show all signed skills |
| `revoke <name> --reason "..."` | Revoke a skill signature |
| `govern <path> --yes-i-know-what-im-doing` | All steps in one (not recommended) |

## Classifications

| Level | Meaning |
|-------|---------|
| `trusted` ✅ | No findings — ready to sign |
| `review` ⚠️ | Suspicious patterns — manual review needed |
| `blocked` 🚫 | Clearly dangerous — signing denied |

## Examples

The repository includes two ready-to-use example skills:

| Directory | Classification | Description |
|-----------|---------------|-------------|
| `examples/demo-skill/` | ✅ `trusted` | Safe Python functions — demonstrates scanning + signing |
| `examples/danger-skill/` | 🚫 `blocked` | Intentionally dangerous code — demonstrates what gets blocked |

```bash
python3 scripts/governance.py scan examples/demo-skill/      # Try it!
python3 scripts/governance.py scan examples/danger-skill/    # See blocking
```

---

## Preload Hook (Gateway Protection)

Me-Guard can check all skills before every gateway startup and abort on danger:

### FAIL_CLOSED (Default for OT/Manufacturing)
```bash
# Every CRITICAL skill stops the gateway
python3 scripts/me-guard-preload.py || exit 1
```

### FAIL_SAFE (Enterprise/Cloud)
```bash
# CRITICAL skills → quarantine, gateway starts anyway
ME_GUARD_MODE=FAIL_SAFE python3 scripts/me-guard-preload.py || exit 1
```

### Persistent Configuration
```bash
echo '{"mode": "FAIL_SAFE"}' > ~/.me-guard/governance/preload_config.json
```

### Use in Your Startup Script
```bash
# Run preload check before any agent starts
python3 /path/to/me-guard/scripts/me-guard-preload.py || exit 1

# Or use the built-in wrapper:
bash /path/to/me-guard/start-me-guard.sh
```

---

## Autonomous Operation (Cron)

### Weekly Audit
```bash
# Generate automatic report (via cron)
0 8 * * 1 cd /path/to/me-guard && \
  python3 scripts/weekly-audit.py --quiet 2>&1 | \
  mail -s "Me-Guard Weekly Audit" your@email.com

# Or as a cron job:
# 0 8 * * 1 cd /path/to/me-guard && python3 scripts/weekly-audit.py --quiet
```

### Preload Hook at Every Gateway Start
Add to your gateway startup script:
```bash
python3 /path/to/me-guard/scripts/me-guard-preload.py || exit 1
```

---

## Architecture

```
~/.me-guard/
├── skills/              ← Your AI skills (being checked)
├── skill_catalog/       ← Metadata as YAML (.card.yaml)
├── skill_signatures/    ← Cryptographic signatures (.sig)
├── quarantine/          ← In FAIL_SAFE mode: blocked skills
├── rules/               ← YAML scan rules
├── reports/             ← Weekly audit reports
└── governance/          ← Keys + Log
    ├── root-ca.key      🔐 PRIVATE (chmod 600, passphrase protected)
    ├── root-ca-pub.pem  🔑 Public key
    ├── revoked.json     🚫 Revocation list
    └── scan.log         📋 Hash-chained audit log
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ME_GUARD_MODE` | `FAIL_CLOSED` | `FAIL_CLOSED` or `FAIL_SAFE` |
| `ME_GUARD_PASSPHRASE` | *(prompt)* | Passphrase for the private key. If not set, you'll be prompted interactively. |

> ⚠️ **Security:** The passphrase is NEVER stored in code or config files.
> Set via environment variable or enter it interactively when signing.

---

## Security

- **No network access** — all checks performed locally
- **No cloud logging** — audit log stays on your machine
- **Hash chain** — every log entry references the previous one
- **Ed25519** — no weak RSA keys
- **AES-256** — private keys additionally passphrase-protected
- **chmod 600** — strictest file permissions

---

## Backup

The private key is **irreplaceable**:
```bash
# Backup to USB stick
bash scripts/backup-key-to-usb.sh /media/$USER/STICK-NAME

# Without argument: automatic search
bash scripts/backup-key-to-usb.sh
```

---

## License

**GNU General Public License v3.0** — Open source, free to use, but:
- Modifications must remain under GPL
- No liability for damages (OT environments at your own risk)

---

**Project:** Me-Guard v2.0  
**Status:** ✅ Production  
**Updated:** 2026-07-30  
**Architect:** Stefan Rohringer  
**License:** GPL v3
