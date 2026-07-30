#!/usr/bin/env python3
"""
Me-Guard - Main script

Local governance system for AI skills.
Inspired by NVIDIA Verified Agent Skills, but 100% local.

Subcommands:
  scan    - Scan skill, output classification (NO Sign)
  sign    - Sign skill (only after explicit --approve!)
  verify  - Verify signature
  list    - List all signed skills
  revoke  - Revoke signature
  govern  - All steps (ONLY with --yes-i-know-what-im-doing)

Important: Scan and Sign are SEPARATE.
First scan -> manually review -> then sign.
"""

import argparse
import ast as ast_mod
import hashlib
import json
import os
import re
import subprocess
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# Constants
# ============================================================

ME_GUARD_DIR = Path.home() / ".me-guard"
GOV_DIR = ME_GUARD_DIR / "governance"
CATALOG_DIR = ME_GUARD_DIR / "skill_catalog"
SIGS_DIR = ME_GUARD_DIR / "skill_signatures"
RULES_DIR = ME_GUARD_DIR / "rules"
SCAN_LOG = GOV_DIR / "scan.log"
PRIVATE_KEY = GOV_DIR / "root-ca.key"
PUBLIC_KEY = GOV_DIR / "root-ca-pub.pem"
PRIVATE_KEY_PASS = os.environ.get("ME_GUARD_PASSPHRASE")


def get_passphrase() -> str:
    """Get CA passphrase: env var first, fallback to interactive prompt."""
    global PRIVATE_KEY_PASS
    if PRIVATE_KEY_PASS:
        return PRIVATE_KEY_PASS
    import getpass
    PRIVATE_KEY_PASS = getpass.getpass("Enter CA passphrase: ")
    return PRIVATE_KEY_PASS
REVOCATION_LIST = GOV_DIR / "revoked.json"


# ============================================================
# Helper functions
# ============================================================

def log_event(action: str, target: str, result: str, details: str = ""):
    """Hash-chained logs for audit trail."""
    GOV_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()

    # Get previous hash (for hash chain)
    prev_hash = "0" * 64
    if SCAN_LOG.exists() and SCAN_LOG.stat().st_size > 0:
        with open(SCAN_LOG, "rb") as f:
            try:
                f.seek(-512, 2)
            except OSError:
                f.seek(0)
            content = f.read().decode("utf-8", errors="ignore").strip()
            if content:
                try:
                    last_line = content.split("\n")[-1]
                    prev_entry = json.loads(last_line)
                    prev_hash = prev_entry.get("hash", prev_hash)
                except (json.JSONDecodeError, ValueError):
                    pass

    entry = {
        "ts": ts,
        "action": action,
        "target": target,
        "result": result,
        "details": details,
        "prev_hash": prev_hash,
    }
    entry_str = json.dumps(entry, sort_keys=True)
    entry["hash"] = hashlib.sha256(
        (entry_str + prev_hash).encode("utf-8")
    ).hexdigest()

    with open(SCAN_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def compute_skill_manifest(skill_path: Path) -> dict:
    """
    Generates a manifest hash over ALL files in the skill folder.
    This way not just SKILL.md, but the entire skill can be signed.
    """
    if skill_path.is_file():
        with open(skill_path, "rb") as f:
            content = f.read()
        return {
            "type": "file",
            "name": skill_path.name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }

    files = []
    for fp in sorted(skill_path.rglob("*")):
        if fp.is_file() and not fp.name.startswith("."):
            with open(fp, "rb") as f:
                content = f.read()
            files.append({
                "path": str(fp.relative_to(skill_path)),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            })

    combined = "".join(f["sha256"] for f in files)
    manifest_hash = hashlib.sha256(combined.encode()).hexdigest()

    return {
        "type": "directory",
        "name": skill_path.name,
        "manifest_hash": manifest_hash,
        "files": files,
    }


def load_rules() -> dict:
    """Load scan rules from YAML."""
    rules_file = RULES_DIR / "default.yaml"
    if not rules_file.exists():
        print(f"⚠️  No rules found: {rules_file}")
        return {"blocked_patterns": [], "review_patterns": [],
                "ast_forbidden_imports": [], "ast_review_imports": []}
    with open(rules_file) as f:
        return yaml.safe_load(f)


# ============================================================
# Scanner: Regex + AST (for Python)
# ============================================================

# File type categories for context-aware scanning
CODE_EXTENSIONS   = {".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".php", ".go"}
DOC_EXTENSIONS    = {".md", ".txt", ".rst", ".adoc"}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini"}


def file_category(filepath: Path) -> str:
    """Determines: 'code', 'docs', 'config' or 'other'."""
    suffix = filepath.suffix.lower()
    if suffix in CODE_EXTENSIONS:
        return "code"
    if suffix in DOC_EXTENSIONS:
        return "docs"
    if suffix in CONFIG_EXTENSIONS:
        return "config"
    return "other"


def scan_file_regex(filepath: Path, rules: dict) -> list:
    """
    Regex-based scan with context awareness.

    - 'blocked_patterns'         -> apply everywhere (always hard block)
    - 'review_patterns_any'      -> apply everywhere (secrets etc.)
    - 'review_patterns_code'     -> only in code files
    - 'review_patterns_docs'     -> only in doc files
    - 'review_patterns_config'   -> only in config files
    - 'review_patterns'          -> fallback (like code), backwards compatibility
    """
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return [{"severity": "review", "file": str(filepath),
                 "msg": f"File not readable: {e}"}]

    category = file_category(filepath)

    # 1. Blocked patterns: always, everywhere
    for pattern in rules.get("blocked_patterns", []):
        for m in re.finditer(pattern, content):
            findings.append({
                "severity": "blocked",
                "file": str(filepath),
                "pattern": pattern,
                "match": m.group(0)[:80],
                "line": content[:m.start()].count("\n") + 1,
            })

    # 2. Review patterns "any": secrets, tokens — everywhere
    for pattern in rules.get("review_patterns_any", []):
        for m in re.finditer(pattern, content):
            findings.append({
                "severity": "review",
                "file": str(filepath),
                "pattern": pattern,
                "match": m.group(0)[:80],
                "line": content[:m.start()].count("\n") + 1,
                "category": "secret",
            })

    # 3. Category-specific patterns
    category_key = f"review_patterns_{category}"
    for pattern in rules.get(category_key, []):
        for m in re.finditer(pattern, content):
            findings.append({
                "severity": "review",
                "file": str(filepath),
                "pattern": pattern,
                "match": m.group(0)[:80],
                "line": content[:m.start()].count("\n") + 1,
                "category": category,
            })

    # 4. Backwards compatibility: old 'review_patterns'
    if category == "code":
        for pattern in rules.get("review_patterns", []):
            for m in re.finditer(pattern, content):
                findings.append({
                    "severity": "review",
                    "file": str(filepath),
                    "pattern": pattern,
                    "match": m.group(0)[:80],
                    "line": content[:m.start()].count("\n") + 1,
                    "category": "legacy",
                })

    return findings


def scan_file_ast(filepath: Path, rules: dict) -> list:
    """AST-based scan for Python files.
    Also finds obfuscated code like __import__('os').system(...).
    """
    if filepath.suffix != ".py":
        return []

    findings = []
    forbidden = set(rules.get("ast_forbidden_imports", []))
    review = set(rules.get("ast_review_imports", []))

    try:
        tree = ast_mod.parse(
            filepath.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError as e:
        return [{"severity": "review", "file": str(filepath),
                 "msg": f"Python syntax error: {e}"}]

    for node in ast_mod.walk(tree):
        # Imports
        if isinstance(node, ast_mod.Import):
            for alias in node.names:
                if alias.name in forbidden:
                    findings.append({"severity": "blocked",
                                     "file": str(filepath),
                                     "msg": f"Forbidden import: {alias.name}",
                                     "line": node.lineno})
                elif alias.name in review:
                    findings.append({"severity": "review",
                                     "file": str(filepath),
                                     "msg": f"Review import: {alias.name}",
                                     "line": node.lineno})

        if isinstance(node, ast_mod.ImportFrom) and node.module:
            if node.module in forbidden:
                findings.append({"severity": "blocked",
                                 "file": str(filepath),
                                 "msg": f"Forbidden import: from {node.module}",
                                 "line": node.lineno})
            elif node.module in review:
                findings.append({"severity": "review",
                                 "file": str(filepath),
                                 "msg": f"Review import: from {node.module}",
                                 "line": node.lineno})

        # Dangerous function calls
        if isinstance(node, ast_mod.Call):
            func_name = None
            if isinstance(node.func, ast_mod.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast_mod.Attribute):
                func_name = node.func.attr

            if func_name in ("eval", "exec", "compile", "__import__"):
                findings.append({"severity": "blocked",
                                 "file": str(filepath),
                                 "msg": f"Dangerous call: {func_name}()",
                                 "line": node.lineno})
            if func_name == "system":
                findings.append({"severity": "blocked",
                                 "file": str(filepath),
                                 "msg": "os.system() Call",
                                 "line": node.lineno})

    return findings


def scan_skill(skill_path: Path) -> dict:
    """Main scan function. Classification: trusted/review/blocked."""
    rules = load_rules()
    all_findings = []

    if skill_path.is_file():
        files_to_scan = [skill_path]
    else:
        files_to_scan = [
            fp for fp in skill_path.rglob("*")
            if fp.is_file() and fp.suffix in (
                ".py", ".sh", ".md", ".yaml", ".yml", ".txt")
        ]

    for fp in files_to_scan:
        all_findings.extend(scan_file_regex(fp, rules))
        all_findings.extend(scan_file_ast(fp, rules))

    if any(f["severity"] == "blocked" for f in all_findings):
        classification = "blocked"
    elif any(f["severity"] == "review" for f in all_findings):
        classification = "review"
    else:
        classification = "trusted"

    return {
        "skill": str(skill_path),
        "classification": classification,
        "findings": all_findings,
        "scanned_files": len(files_to_scan),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================
# Skill Card (Metadata)
# ============================================================

def create_card(skill_path: Path, scan_result: dict) -> Path:
    """Create skill_card.yaml with metadata."""
    CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    manifest = compute_skill_manifest(skill_path)

    card = {
        "skill_name": skill_path.name,
        "skill_path": str(skill_path),
        "created": datetime.now(timezone.utc).isoformat(),
        "classification": scan_result["classification"],
        "scanned_files": scan_result["scanned_files"],
        "findings_count": len(scan_result["findings"]),
        "manifest": manifest,
        "governance_version": "1.0",
    }

    card_file = CATALOG_DIR / f"{skill_path.name}.card.yaml"
    with open(card_file, "w") as f:
        yaml.dump(card, f, sort_keys=False, default_flow_style=False)
    return card_file


# ============================================================
# Signing (Ed25519 via OpenSSL)
# ============================================================

def sign_skill(skill_path: Path, card_file: Path) -> Path:
    """Sign the skill card with the private key.
    Since the card contains the manifest hash, the entire skill is co-signed.
    """
    if not PRIVATE_KEY.exists():
        print(f"❌ Private key missing: {PRIVATE_KEY}")
        print("   Run setup.sh first!")
        sys.exit(1)

    SIGS_DIR.mkdir(parents=True, exist_ok=True)
    sig_file = SIGS_DIR / f"{skill_path.name}.sig"

    # Signature over the card file (contains the manifest hash)
    result = subprocess.run(
        ["openssl", "pkeyutl", "-sign",
         "-inkey", str(PRIVATE_KEY), "-passin", f"pass:{get_passphrase()}",
         "-rawin", "-in", str(card_file), "-out", str(sig_file)],
        capture_output=True,
    )

    if result.returncode != 0:
        print(f"❌ Signing failed: {result.stderr.decode()}")
        sys.exit(1)

    return sig_file


def verify_skill(skill_path: Path) -> bool:
    """Verify signature and manifest hash."""
    card_file = CATALOG_DIR / f"{skill_path.name}.card.yaml"
    sig_file = SIGS_DIR / f"{skill_path.name}.sig"

    if not card_file.exists():
        print(f"❌ No card found: {card_file}")
        return False
    if not sig_file.exists():
        print(f"❌ No signature found: {sig_file}")
        return False
    if not PUBLIC_KEY.exists():
        print(f"❌ Public key missing: {PUBLIC_KEY}")
        return False

    # Verify signature
    result = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin",
         "-inkey", str(PUBLIC_KEY), "-rawin",
         "-in", str(card_file), "-sigfile", str(sig_file)],
        capture_output=True,
    )

    if result.returncode != 0:
        print(f"❌ Signature invalid!")
        return False

    # Verify manifest hash
    with open(card_file) as f:
        card = yaml.safe_load(f)

    current_manifest = compute_skill_manifest(skill_path)
    stored_manifest = card["manifest"]

    if current_manifest != stored_manifest:
        print(f"❌ Skill was modified after signing!")
        print(f"   Manifest no longer matches.")
        return False

    # Revocation Check
    if is_revoked(skill_path.name):
        print(f"❌ Skill has been revoked!")
        return False

    return True


# ============================================================
# Revocation
# ============================================================

def is_revoked(skill_name: str) -> bool:
    if not REVOCATION_LIST.exists():
        return False
    with open(REVOCATION_LIST) as f:
        revoked = json.load(f)
    return skill_name in revoked.get("revoked_skills", [])


def revoke_skill(skill_name: str, reason: str):
    revoked = {"revoked_skills": []}
    if REVOCATION_LIST.exists():
        with open(REVOCATION_LIST) as f:
            revoked = json.load(f)

    if skill_name in revoked["revoked_skills"]:
        print(f"⚠️  {skill_name} is already revoked.")
        return

    revoked["revoked_skills"].append(skill_name)
    revoked.setdefault("history", []).append({
        "skill": skill_name,
        "reason": reason,
        "ts": datetime.now(timezone.utc).isoformat(),
    })

    with open(REVOCATION_LIST, "w") as f:
        json.dump(revoked, f, indent=2)

    print(f"✅ {skill_name} revoked: {reason}")
    log_event("revoke", skill_name, "revoked", reason)


# ============================================================
# CLI
# ============================================================

def cmd_scan(args):
    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    result = scan_skill(skill_path)

    # JSON mode (for preload script)
    if getattr(args, 'json_output', False):
        print(json.dumps(result))
        return

    icon = {"trusted": "✅", "review": "⚠️ ", "blocked": "🚫"}[
        result["classification"]]
    print(f"\n{icon} Classification: {result['classification'].upper()}")
    print(f"   Files scanned: {result['scanned_files']}")
    print(f"   Findings: {len(result['findings'])}")

    if result["findings"]:
        print(f"\n📋 Details:")
        for f_item in result["findings"]:
            sev_icon = {"blocked": "🚫", "review": "⚠️ "}.get(
                f_item["severity"], "•")
            print(f"   {sev_icon} {f_item.get('msg', f_item.get('pattern', '?'))}"
                  f" (line {f_item.get('line', '?')})")

    log_event("scan", str(skill_path), result["classification"],
              f"{len(result['findings'])} findings, {result['scanned_files']} files")


def cmd_sign(args):
    """Sign a skill (card + signature). Requires --approve."""
    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    # Scan first
    result = scan_skill(skill_path)
    if result["classification"] == "blocked":
        print(f"🚫 Skill is BLOCKED — cannot sign!")
        print("   Fix issues first, then scan again.")
        log_event("sign", str(skill_path), "blocked",
                  f"{len(result['findings'])} critical findings")
        sys.exit(1)

    if not getattr(args, 'approve', False):
        print("❌ --approve is required for signing!")
        print("   This prevents accidental signatures.")
        print("   Reason: scan and sign are deliberately separate steps.")
        sys.exit(1)

    card_file = create_card(skill_path, result)
    sig_file = sign_skill(skill_path, card_file)
    print(f"✅ Card created: {card_file}")
    print(f"✅ Signature:    {sig_file}")
    log_event("sign", str(skill_path), "signed",
              f"classification={result['classification']}, files={result['scanned_files']}")


def cmd_verify(args):
    """Verify a skill signature."""
    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    if verify_skill(skill_path):
        print(f"✅ {skill_path.name}: Signature VALID, manifest intact.")
    else:
        print(f"❌ {skill_path.name}: Verification FAILED.")
        sys.exit(1)


def cmd_list(args):
    """List all signed skills."""
    if not CATALOG_DIR.exists():
        print("ℹ️  No signed skills found.")
        return

    cards = sorted(CATALOG_DIR.glob("*.card.yaml"))
    if not cards:
        print("ℹ️  No signed skills found.")
        return

    print(f"📋 Signed Skills ({len(cards)}):")
    print("=" * 50)
    for card_file in cards:
        with open(card_file) as f:
            card = yaml.safe_load(f)
        sig_file = SIGS_DIR / f"{card['skill_name']}.sig"
        sig_ok = sig_file.exists()
        revoked = is_revoked(card['skill_name'])
        icon = "✅" if sig_ok and not revoked else "🚫" if revoked else "⚠️"
        print(f"  {icon} {card['skill_name']}")
        print(f"     Classification: {card.get('classification', '?')}")
        print(f"     Created:        {card.get('created', '?')[:19]}")
        print(f"     Files:          {card.get('scanned_files', '?')}")
        if revoked:
            print(f"     Status:         ❌ REVOKED")
        print()


def cmd_revoke(args):
    """Revoke a skill signature."""
    if not args.reason:
        print("❌ --reason is required for revocation!")
        print("   Example: --reason \"Vulnerability found in version 1.2\"")
        sys.exit(1)
    revoke_skill(args.name, args.reason)


def cmd_govern(args):
    """All-in-one: scan + sign + verify (NOT recommended)."""
    if not getattr(args, 'yes_i_know_what_im_doing', False):
        print("❌ This is a DANGEROUS command.")
        print("   Use --yes-i-know-what-im-doing to proceed.")
        print("")
        print("   Recommended workflow:")
        print("     governance.py scan <path>")
        print("     governance.py sign <path> --approve")
        print("     governance.py verify <path>")
        sys.exit(1)

    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    result = scan_skill(skill_path)
    if result["classification"] == "blocked":
        print(f"🚫 Skill is BLOCKED — aborting!")
        sys.exit(1)

    card_file = create_card(skill_path, result)
    sig_file = sign_skill(skill_path, card_file)
    print(f"✅ Card: {card_file}")
    print(f"✅ Sig:  {sig_file}")
    print()

    if verify_skill(skill_path):
        print(f"✅ {skill_path.name}: All good.")
    else:
        print(f"❌ {skill_path.name}: Something went wrong.")
        sys.exit(1)


# ============================================================
# CLI Entry Point
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Me-Guard - Local governance system for AI skills")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a skill (classification + findings)")
    p_scan.add_argument("path", help="Path to the skill directory or file")
    p_scan.add_argument("--json", action="store_true", dest="json_output",
                        help="Output as JSON (for preload script integration)")
    p_scan.set_defaults(func=cmd_scan)

    # sign
    p_sign = sub.add_parser("sign", help="Sign a skill (requires --approve)")
    p_sign.add_argument("path", help="Path to the skill directory or file")
    p_sign.add_argument("--approve", action="store_true",
                        help="Confirm that you want to sign this skill")
    p_sign.set_defaults(func=cmd_sign)

    # verify
    p_verify = sub.add_parser("verify", help="Verify a skill signature")
    p_verify.add_argument("path", help="Path to the skill directory or file")
    p_verify.set_defaults(func=cmd_verify)

    # list
    p_list = sub.add_parser("list", help="List all signed skills")
    p_list.set_defaults(func=cmd_list)

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke a skill signature")
    p_revoke.add_argument("name", help="Skill name to revoke")
    p_revoke.add_argument("--reason", required=True,
                          help="Reason for revocation")
    p_revoke.set_defaults(func=cmd_revoke)

    # govern
    p_govern = sub.add_parser("govern",
                              help="All steps in one (NOT recommended)")
    p_govern.add_argument("path", help="Path to the skill directory or file")
    p_govern.add_argument("--yes-i-know-what-im-doing", action="store_true",
                          dest="yes_i_know_what_im_doing",
                          help="Confirm dangerous all-in-one mode")
    p_govern.set_defaults(func=cmd_govern)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
