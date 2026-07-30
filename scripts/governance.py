#!/usr/bin/env python3
"""
Me-Guard — Local governance system for AI skills.

Inspired by NVIDIA Verified Agent Skills, but 100% local.

NOTE: This is a BLOCKLIST scanner, not a sandbox.
It detects known dangerous patterns but CAN be bypassed by
obfuscation (e.g. exec(base64_decode(...)), string splitting).
ALWAYS manually review 'review' and 'trusted' classifications.

Subcommands:
  scan           - Scan skill, output classification (NO Sign)
  sign           - Sign skill (only after explicit --approve!)
  verify         - Verify signature
  list           - List all signed skills
  revoke         - Revoke signature
  govern         - All steps (ONLY with --yes-i-know-what-im-doing)
  sign-scripts   - (Re-)sign script integrity manifest
  sign-config    - (Re-)sign rules, revocation list, and config

Important: Scan and Sign are SEPARATE.
First scan -> manually review -> then sign.
"""

import argparse
import json
import os
import sys
import yaml
from pathlib import Path

# Import extracted modules
from scanner import scan_skill
from crypto import (
    get_passphrase, compute_skill_manifest, sign_skill,
    verify_skill_openssl, verify_manifest, is_revoked,
    revoke_skill, create_card, log_event,
    sign_file, verify_file_signature,
    compute_script_manifest, verify_script_integrity,
    verify_passphrase_strength,
)

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
REVOCATION_LIST = GOV_DIR / "revoked.json"
SCRIPTS_MANIFEST = GOV_DIR / "scripts-manifest.json"
SCRIPTS_DIR = Path(__file__).parent.resolve()


# ============================================================
# Self-Integrity Check
# ============================================================

def check_self_integrity(quiet: bool = False) -> bool:
    """Verify script integrity before any command. Returns True if OK."""
    if not PRIVATE_KEY.exists():
        # First-time setup — no key yet, skip check
        return True
    if not SCRIPTS_MANIFEST.exists():
        if not quiet:
            print("ℹ️  No script manifest yet — run 'governance.py sign-scripts'")
        return True

    ok, msg = verify_script_integrity(SCRIPTS_DIR, SCRIPTS_MANIFEST, PUBLIC_KEY)
    if not ok and not quiet:
        print(f"❌ {msg}")
        print("   Run 'governance.py sign-scripts' to resign after updates.")
    return ok


# ============================================================
# Verified Loaders
# ============================================================

def load_rules() -> dict:
    """Load scan rules from YAML. Verifies signature if key exists."""
    rules_file = RULES_DIR / "default.yaml"
    if not rules_file.exists():
        print(f"⚠️  No rules found: {rules_file}")
        return {"blocked_patterns": [], "review_patterns": [],
                "ast_forbidden_imports": [], "ast_review_imports": []}

    # Verify rules signature (non-fatal — warn only)
    if PUBLIC_KEY.exists():
        sig_ok = verify_file_signature(rules_file, PUBLIC_KEY)
        if not sig_ok:
            sig_path = rules_file.with_suffix(rules_file.suffix + ".sig")
            if sig_path.exists():
                print(f"🚫 RULES SIGNATURE INVALID: {rules_file}")
                print("   Possible tampering! Run 'governance.py sign-config' to fix.")
            else:
                print(f"⚠️  Rules not signed: {rules_file}")
                print("   Run 'governance.py sign-config' to sign.")

    with open(rules_file) as f:
        return yaml.safe_load(f)


def load_revocation_list() -> dict:
    """Load revocation list. Verifies signature if key exists."""
    revoked = {"revoked_skills": []}
    if not REVOCATION_LIST.exists():
        return revoked

    # Verify signature
    if PUBLIC_KEY.exists():
        sig_ok = verify_file_signature(REVOCATION_LIST, PUBLIC_KEY)
        if not sig_ok:
            sig_path = REVOCATION_LIST.with_suffix(".json.sig")
            if sig_path.exists():
                print(f"🚫 REVOCATION LIST SIGNATURE INVALID: {REVOCATION_LIST}")
                print("   Possible tampering! Run 'governance.py sign-config' to fix.")
            else:
                print(f"⚠️  Revocation list not signed — run 'governance.py sign-config'")

    with open(REVOCATION_LIST) as f:
        try:
            revoked = json.load(f)
        except json.JSONDecodeError:
            revoked = {"revoked_skills": []}
    return revoked


# ============================================================
# CLI Commands
# ============================================================

def cmd_scan(args):
    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    if not check_self_integrity():
        sys.exit(1)

    rules = load_rules()
    result = scan_skill(skill_path, rules)

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

    log_event(GOV_DIR, SCAN_LOG, "scan", str(skill_path),
              result["classification"],
              f"{len(result['findings'])} findings, {result['scanned_files']} files")


def cmd_sign(args):
    """Sign a skill (card + signature). Requires --approve."""
    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    if not check_self_integrity():
        sys.exit(1)

    # Scan first
    rules = load_rules()
    result = scan_skill(skill_path, rules)
    if result["classification"] == "blocked":
        print(f"🚫 Skill is BLOCKED — cannot sign!")
        print("   Fix issues first, then scan again.")
        log_event(GOV_DIR, SCAN_LOG, "sign", str(skill_path), "blocked",
                  f"{len(result['findings'])} critical findings")
        sys.exit(1)

    if not getattr(args, 'approve', False):
        print("❌ --approve is required for signing!")
        print("   This prevents accidental signatures.")
        print("   Reason: scan and sign are deliberately separate steps.")
        sys.exit(1)

    card_file = create_card(CATALOG_DIR, skill_path, result)
    passphrase = get_passphrase("ME_GUARD_PASSPHRASE")
    sig_file = sign_skill(PRIVATE_KEY, PUBLIC_KEY, card_file,
                          SIGS_DIR, skill_path.name, passphrase)
    print(f"✅ Card created: {card_file}")
    print(f"✅ Signature:    {sig_file}")
    log_event(GOV_DIR, SCAN_LOG, "sign", str(skill_path), "signed",
              f"classification={result['classification']}, files={result['scanned_files']}")


def cmd_verify(args):
    """Verify a skill signature."""
    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    if not check_self_integrity():
        sys.exit(1)

    card_file = CATALOG_DIR / f"{skill_path.name}.card.yaml"
    sig_file = SIGS_DIR / f"{skill_path.name}.sig"

    if not card_file.exists():
        print(f"❌ No card found: {card_file}")
        sys.exit(1)
    if not sig_file.exists():
        print(f"❌ No signature found: {sig_file}")
        sys.exit(1)
    if not PUBLIC_KEY.exists():
        print(f"❌ Public key missing: {PUBLIC_KEY}")
        sys.exit(1)

    # 1. Verify cryptographic signature (via OpenSSL exit code)
    sig_ok = verify_skill_openssl(PUBLIC_KEY, card_file, sig_file)
    if not sig_ok:
        print(f"❌ {skill_path.name}: Signature INVALID.")
        sys.exit(1)

    # 2. Verify manifest hash
    manifest_ok = verify_manifest(skill_path, card_file)
    if not manifest_ok:
        print(f"❌ {skill_path.name}: Manifest mismatch — skill was modified!")
        sys.exit(1)

    # 3. Check revocation (uses verified revocation list)
    revoked = load_revocation_list()
    if skill_path.name in revoked.get("revoked_skills", []):
        print(f"❌ {skill_path.name}: Signature REVOKED.")
        sys.exit(1)

    print(f"✅ {skill_path.name}: Signature VALID, manifest intact.")
    log_event(GOV_DIR, SCAN_LOG, "verify", str(skill_path), "valid", "")


def cmd_list(args):
    """List all signed skills."""
    if not check_self_integrity():
        sys.exit(1)

    if not CATALOG_DIR.exists():
        print("ℹ️  No signed skills found.")
        return

    cards = sorted(CATALOG_DIR.glob("*.card.yaml"))
    if not cards:
        print("ℹ️  No signed skills found.")
        return

    revoked = load_revocation_list()
    revoked_names = set(revoked.get("revoked_skills", []))

    print(f"📋 Signed Skills ({len(cards)}):")
    print("=" * 50)
    for card_file in cards:
        with open(card_file) as f:
            card = yaml.safe_load(f)
        sig_file = SIGS_DIR / f"{card['skill_name']}.sig"
        sig_ok = sig_file.exists()
        is_revoked_flag = card['skill_name'] in revoked_names
        icon = "✅" if sig_ok and not is_revoked_flag else "🚫" if is_revoked_flag else "⚠️"
        print(f"  {icon} {card['skill_name']}")
        print(f"     Classification: {card.get('classification', '?')}")
        print(f"     Created:        {card.get('created', '?')[:19]}")
        print(f"     Files:          {card.get('scanned_files', '?')}")
        if is_revoked_flag:
            print(f"     Status:         ❌ REVOKED")
        print()


def cmd_revoke(args):
    """Revoke a skill signature."""
    if not args.reason:
        print("❌ --reason is required for revocation!")
        print('   Example: --reason "Vulnerability found in version 1.2"')
        sys.exit(1)

    if not check_self_integrity():
        sys.exit(1)

    revoke_skill(REVOCATION_LIST, args.name, args.reason)

    # Re-sign revocation list
    passphrase = get_passphrase("ME_GUARD_PASSPHRASE")
    try:
        sign_file(REVOCATION_LIST, PRIVATE_KEY, passphrase)
        print(f"✅ Revocation list re-signed.")
    except Exception as e:
        print(f"⚠️  Could not sign revocation list: {e}")
        print("   Run 'governance.py sign-config' manually.")

    log_event(GOV_DIR, SCAN_LOG, "revoke", args.name, "revoked", args.reason)


def cmd_govern(args):
    """All-in-one: scan + sign + verify (NOT recommended)."""
    if not getattr(args, 'yes_i_know_what_im_doing', False):
        print("❌ This is a DANGEROUS command.")
        print("   Use --yes-i-know-what-im-doing to proceed.\n")
        print("   Recommended workflow:")
        print("     governance.py scan <path>")
        print("     governance.py sign <path> --approve")
        print("     governance.py verify <path>")
        sys.exit(1)

    if not check_self_integrity():
        sys.exit(1)

    skill_path = Path(args.path).expanduser().resolve()
    if not skill_path.exists():
        print(f"❌ Path not found: {skill_path}")
        sys.exit(1)

    rules = load_rules()
    result = scan_skill(skill_path, rules)
    if result["classification"] == "blocked":
        print(f"🚫 Skill is BLOCKED — aborting!")
        sys.exit(1)

    card_file = create_card(CATALOG_DIR, skill_path, result)
    passphrase = get_passphrase("ME_GUARD_PASSPHRASE")
    sig_file = sign_skill(PRIVATE_KEY, PUBLIC_KEY, card_file,
                          SIGS_DIR, skill_path.name, passphrase)
    print(f"✅ Card: {card_file}")
    print(f"✅ Sig:  {sig_file}")
    print()

    card_file_path = CATALOG_DIR / f"{skill_path.name}.card.yaml"
    sig_file_path = SIGS_DIR / f"{skill_path.name}.sig"

    sig_ok = verify_skill_openssl(PUBLIC_KEY, card_file_path, sig_file_path)
    manifest_ok = verify_manifest(skill_path, card_file_path)
    if sig_ok and manifest_ok:
        print(f"✅ {skill_path.name}: All good.")
    else:
        print(f"❌ {skill_path.name}: Something went wrong.")
        sys.exit(1)


# ─── Admin: Sign Config Files ───────────────────────────────

def cmd_sign_scripts(args):
    """Compute and sign script integrity manifest."""
    if not PRIVATE_KEY.exists():
        print("❌ No CA key found. Run 'make setup' or 'bash scripts/setup.sh' first.")
        sys.exit(1)

    manifest = compute_script_manifest(SCRIPTS_DIR)
    with open(SCRIPTS_MANIFEST, "w") as f:
        json.dump(manifest, f, indent=2)

    passphrase = get_passphrase("ME_GUARD_PASSPHRASE")
    sig_path = sign_file(SCRIPTS_MANIFEST, PRIVATE_KEY, passphrase)

    print(f"✅ Script manifest signed: {SCRIPTS_MANIFEST}")
    print(f"   Signature: {sig_path}")
    print(f"   Files: {manifest['count']} scripts hashed")
    log_event(GOV_DIR, SCAN_LOG, "sign-scripts", "all", "signed",
              f"{manifest['count']} scripts, hash={manifest['manifest_hash'][:16]}")


def cmd_sign_config(args):
    """Sign rules, revocation list, and preload config."""
    if not PRIVATE_KEY.exists():
        print("❌ No CA key found. Run 'make setup' or 'bash scripts/setup.sh' first.")
        sys.exit(1)

    passphrase = get_passphrase("ME_GUARD_PASSPHRASE")

    files_to_sign = []

    # 1. Rules
    rules_file = RULES_DIR / "default.yaml"
    if rules_file.exists():
        sig = sign_file(rules_file, PRIVATE_KEY, passphrase)
        files_to_sign.append(str(rules_file))
        print(f"✅ Rules signed: {sig}")
    else:
        print(f"⚠️  No rules file: {rules_file}")

    # 2. Revocation list
    if REVOCATION_LIST.exists():
        sig = sign_file(REVOCATION_LIST, PRIVATE_KEY, passphrase)
        files_to_sign.append(str(REVOCATION_LIST))
        print(f"✅ Revocation list signed: {sig}")
    else:
        print(f"⚠️  No revocation list: {REVOCATION_LIST}")

    # 3. Preload config
    config_file = GOV_DIR / "preload_config.json"
    if config_file.exists():
        sig = sign_file(config_file, PRIVATE_KEY, passphrase)
        files_to_sign.append(str(config_file))
        print(f"✅ Preload config signed: {sig}")
    # (optional, no warning if missing)

    if files_to_sign:
        log_event(GOV_DIR, SCAN_LOG, "sign-config", ", ".join(files_to_sign),
                  "signed", f"{len(files_to_sign)} file(s)")
    else:
        print("⚠️  No config files found to sign.")


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

    # sign-scripts (admin)
    p_sign_scripts = sub.add_parser("sign-scripts",
                                    help="(Re-)sign script integrity manifest")
    p_sign_scripts.set_defaults(func=cmd_sign_scripts)

    # sign-config (admin)
    p_sign_config = sub.add_parser("sign-config",
                                   help="Sign rules, revocation list, config")
    p_sign_config.set_defaults(func=cmd_sign_config)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
