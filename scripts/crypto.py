"""
Me-Guard — Crypto Module

Ed25519 signing, verification, revocation, manifest computation,
file signing (rules/config/revocation-list), self-integrity checking,
and file-locked audit logging.

Passphrase is handled via stdin pipe to prevent CLI leak.
"""

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# ─── Passphrase ───────────────────────────────────────────────

_MIN_PASSPHRASE_LENGTH = 12


def verify_passphrase_strength(passphrase: str) -> tuple:
    """Check passphrase strength. Returns (ok: bool, message: str)."""
    if len(passphrase) < _MIN_PASSPHRASE_LENGTH:
        return False, (
            f"Too short ({len(passphrase)} chars). "
            f"Minimum {_MIN_PASSPHRASE_LENGTH} characters required."
        )
    # Entropy heuristics
    has_upper = bool(re.search(r'[A-Z]', passphrase))
    has_lower = bool(re.search(r'[a-z]', passphrase))
    has_digit = bool(re.search(r'[0-9]', passphrase))
    has_special = bool(re.search(r'[^A-Za-z0-9]', passphrase))
    score = sum([has_upper, has_lower, has_digit, has_special])
    if score < 3:
        return False, (
            "Weak passphrase. Use at least 3 of: uppercase, lowercase, "
            "digits, special characters."
        )
    # Common patterns
    weak = {'password', '123456', 'passphrase', 'me-guard', 'abcdef'}
    if passphrase.lower() in weak:
        return False, "This is a commonly used passphrase — choose something unique."
    return True, "Strong passphrase."


def get_passphrase(env_var: str = None, prompt: str = "Enter CA passphrase: ") -> str:
    """Get CA passphrase: env var first, fallback to interactive prompt.

    SECURITY NOTE: Environment variables leak via /proc/<pid>/environ
    and are inherited by child processes. For OT/production environments,
    prefer interactive entry over setting ME_GUARD_PASSPHRASE.
    """
    if env_var:
        passphrase = os.environ.get(env_var)
        if passphrase:
            return passphrase
    import getpass
    return getpass.getpass(prompt)


# ─── Manifest Computation ────────────────────────────────────

def compute_skill_manifest(skill_path: Path) -> dict:
    """Generate a manifest hash over ALL files in the skill folder."""
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
            # Warn on symlinks but still hash the target
            if fp.is_symlink():
                real = fp.resolve()
                print(f"  ⚠️  Symlink detected: {fp.relative_to(skill_path)} → {real}")
            with open(fp, "rb") as f:
                content = f.read()
            files.append({
                "path": str(fp.relative_to(skill_path)),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
                "symlink": fp.is_symlink(),
            })

    combined = "".join(f["sha256"] for f in files)
    manifest_hash = hashlib.sha256(combined.encode()).hexdigest()

    return {
        "type": "directory",
        "name": skill_path.name,
        "manifest_hash": manifest_hash,
        "files": files,
    }


# ─── Audit Log (Hash-Chained + File-Locked) ──────────────────

def log_event(gov_dir: Path, scan_log: Path, action: str,
              target: str, result: str, details: str = ""):
    """Hash-chained logs for audit trail. Thread- and process-safe via flock.

    NOTE: The log is stored locally. Anyone with write access to the
    log file can recalculate the hash chain (tamper-evident, not
    tamper-proof). For production OT environments, consider shipping
    logs to a write-once medium or external logging system.
    """
    gov_dir.mkdir(parents=True, exist_ok=True)
    scan_log.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()

    # Open file once, hold lock across read + write
    with open(scan_log, "a+") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            # Read previous hash (file is open in append mode, seek to read)
            f.seek(0)
            prev_hash = "0" * 64
            content = f.read().strip()
            if content:
                try:
                    last_line = content.split("\n")[-1]
                    prev_entry = json.loads(last_line)
                    prev_hash = prev_entry.get("hash", prev_hash)
                except (json.JSONDecodeError, ValueError, IndexError):
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

            # Seek to end (we opened in a+ mode, but write may be at position 0)
            f.seek(0, 2)
            f.write(json.dumps(entry) + "\n")
            f.flush()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


# ─── Skill Card ──────────────────────────────────────────────

def create_card(catalog_dir: Path, skill_path: Path, scan_result: dict) -> Path:
    """Create skill_card.yaml with metadata."""
    import yaml
    catalog_dir.mkdir(parents=True, exist_ok=True)
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

    card_file = catalog_dir / f"{skill_path.name}.card.yaml"
    with open(card_file, "w") as f:
        yaml.dump(card, f, sort_keys=False, default_flow_style=False)
    return card_file


# ─── Skill Signing / Verification ────────────────────────────

def sign_skill(private_key: Path, public_key: Path, card_file: Path,
               sigs_dir: Path, skill_name: str, passphrase: str) -> Path:
    """Sign the skill card with Ed25519 private key.

    SECURITY: Passphrase via stdin pipe, NOT via CLI arg
    (prevents leak through /proc/<pid>/cmdline or ps aux).
    """
    if not private_key.exists():
        raise FileNotFoundError(f"Private key missing: {private_key}")

    sigs_dir.mkdir(parents=True, exist_ok=True)
    sig_file = sigs_dir / f"{skill_name}.sig"

    result = subprocess.run(
        ["openssl", "pkeyutl", "-sign",
         "-inkey", str(private_key), "-passin", "stdin",
         "-rawin", "-in", str(card_file), "-out", str(sig_file)],
        input=passphrase.encode(),
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Signing failed: {result.stderr.decode()}")

    return sig_file


def verify_skill_openssl(public_key: Path, card_file: Path, sig_file: Path) -> bool:
    """Verify Ed25519 signature via OpenSSL.

    SECURITY: Uses OpenSSL exit code ($?), not stdout text match.
    """
    if not public_key.exists():
        raise FileNotFoundError(f"Public key missing: {public_key}")
    if not card_file.exists():
        raise FileNotFoundError(f"Card missing: {card_file}")
    if not sig_file.exists():
        raise FileNotFoundError(f"Signature missing: {sig_file}")

    result = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin",
         "-inkey", str(public_key), "-rawin",
         "-in", str(card_file), "-sigfile", str(sig_file)],
        capture_output=True,
    )

    return result.returncode == 0


def verify_manifest(skill_path: Path, card_file: Path) -> bool:
    """Verify that the current skill files match the card manifest."""
    import yaml
    with open(card_file) as f:
        card = yaml.safe_load(f)

    current_manifest = compute_skill_manifest(skill_path)
    stored_manifest = card.get("manifest", {})

    return current_manifest == stored_manifest


# ─── Config / Rules / Revocation Signing ─────────────────────

def sign_file(file_path: Path, private_key: Path, passphrase: str) -> Path:
    """Sign an arbitrary file with Ed25519.

    Creates <filename>.sig alongside the file.
    SECURITY: Passphrase via stdin pipe.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File to sign not found: {file_path}")
    if not private_key.exists():
        raise FileNotFoundError(f"Private key missing: {private_key}")

    sig_path = file_path.with_suffix(file_path.suffix + ".sig")
    result = subprocess.run(
        ["openssl", "pkeyutl", "-sign",
         "-inkey", str(private_key), "-passin", "stdin",
         "-rawin", "-in", str(file_path), "-out", str(sig_path)],
        input=passphrase.encode(),
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"File signing failed ({file_path.name}): "
                           f"{result.stderr.decode()}")
    return sig_path


def verify_file_signature(file_path: Path, public_key: Path) -> bool:
    """Verify Ed25519 signature of an arbitrary file.

    Signature expected at <filename>.sig alongside the file.
    """
    sig_path = file_path.with_suffix(file_path.suffix + ".sig")
    if not sig_path.exists():
        return False
    if not public_key.exists():
        raise FileNotFoundError(f"Public key missing: {public_key}")
    if not file_path.exists():
        return False

    result = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin",
         "-inkey", str(public_key), "-rawin",
         "-in", str(file_path), "-sigfile", str(sig_path)],
        capture_output=True,
    )
    return result.returncode == 0


# ─── Script Self-Integrity ───────────────────────────────────

def compute_script_manifest(scripts_dir: Path) -> dict:
    """Hash all scripts in the scripts/ directory.

    Returns a dict with file → sha256 mappings plus a combined hash.
    """
    if not scripts_dir.is_dir():
        raise NotADirectoryError(f"Not found: {scripts_dir}")

    files = {}
    for fp in sorted(scripts_dir.rglob("*")):
        if not fp.is_file():
            continue
        if fp.name.startswith("."):
            continue
        rel = str(fp.relative_to(scripts_dir))
        with open(fp, "rb") as f:
            files[rel] = hashlib.sha256(f.read()).hexdigest()

    combined = "".join(files.get(k, "") for k in sorted(files))
    return {
        "manifest_hash": hashlib.sha256(combined.encode()).hexdigest(),
        "files": files,
        "count": len(files),
    }


def verify_script_integrity(scripts_dir: Path, manifest_path: Path,
                            public_key: Path) -> tuple:
    """Verify script integrity against signed manifest.

    Returns (ok: bool, message: str).
    """
    sig_path = manifest_path.with_suffix(manifest_path.suffix + ".sig")

    # No manifest → first setup or not yet signed
    if not manifest_path.exists() or not sig_path.exists():
        return False, "No script manifest found — run 'governance.py sign-scripts'"

    # Verify signature of manifest
    if not verify_file_signature(manifest_path, public_key):
        return False, "Script manifest signature INVALID — possible tampering!"

    # Load manifest
    with open(manifest_path) as f:
        stored = json.load(f)

    # Recompute current state
    current = compute_script_manifest(scripts_dir)

    if current["manifest_hash"] != stored.get("manifest_hash"):
        changed = []
        for rel, sha in current["files"].items():
            if stored.get("files", {}).get(rel) != sha:
                changed.append(rel)
        return False, (
            f"Script integrity FAILED! {len(changed)} file(s) changed:\n"
            + "\n".join(f"  - {c}" for c in changed)
        )

    return True, f"Script integrity OK ({current['count']} files)"


# ─── Revocation ─────────────────────────────────────────────

def is_revoked(revocation_list: Path, skill_name: str) -> bool:
    """Check if a skill has been revoked."""
    if not revocation_list.exists():
        return False
    with open(revocation_list) as f:
        revoked = json.load(f)
    return skill_name in revoked.get("revoked_skills", [])


def revoke_skill(revocation_list: Path, skill_name: str, reason: str):
    """Revoke a skill signature."""
    revoked = {"revoked_skills": []}
    if revocation_list.exists():
        with open(revocation_list) as f:
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

    with open(revocation_list, "w") as f:
        json.dump(revoked, f, indent=2)

    print(f"✅ {skill_name} revoked: {reason}")
