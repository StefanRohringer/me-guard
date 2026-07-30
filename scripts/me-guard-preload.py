#!/usr/bin/env python3

"""
Me-Guard Preload Check v2.1 — Hybrid Fail-Closed / Fail-Safe

Checks all skills in ~/.me-guard/skills/ before gateway start.
Supports severity levels + configurable mode.

Exit codes:
  0 - All skills OK or only WARNINGS in FAIL_SAFE mode
  1 - Critical errors -> Gateway will NOT start

Modes (via ME_GUARD_MODE):
  "FAIL_CLOSED" (default): Any CRITICAL error stops the gateway
  "FAIL_SAFE":            CRITICAL error -> Skill quarantined, gateway starts anyway

Severity levels from governance.py scan:
  blocked  = CRITICAL  -> Hard Fail
  review   = WARNING   -> Soft Fail (log + quarantine in FAIL_SAFE)
  trusted  = OK        -> No problem

Integration into start-me-guard.sh:
  python3 .../me-guard-preload.py || exit 1
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ─── Configuration ──────────────────────────────────────────────
ME_GUARD_DIR = Path.home() / ".me-guard"
SKILLS_DIR = ME_GUARD_DIR / "skills"
QUARANTINE_DIR = ME_GUARD_DIR / "quarantine"
GOVERNANCE_SCRIPT = Path(__file__).parent / "governance.py"
CONFIG_FILE = ME_GUARD_DIR / "governance" / "preload_config.json"

DEFAULT_MODE = "FAIL_CLOSED"  # FAIL_CLOSED | FAIL_SAFE

SEVERITY_MAP = {
    "blocked": "CRITICAL",
    "review": "WARNING",
    "trusted": "OK",
}


def load_config() -> dict:
    """Load configuration if present."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"mode": DEFAULT_MODE}


def get_mode() -> str:
    """Determine mode: ENV takes precedence over config."""
    env_mode = os.environ.get("ME_GUARD_MODE", "").upper()
    if env_mode in ("FAIL_CLOSED", "FAIL_SAFE"):
        return env_mode
    cfg = load_config()
    return cfg.get("mode", DEFAULT_MODE)


def scan_skill(skill_path: Path) -> dict:
    """Run governance.py scan and parse classification + findings."""
    result = subprocess.run(
        ["python3", str(GOVERNANCE_SCRIPT), "scan", str(skill_path), "--json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return {
            "name": skill_path.name,
            "classification": "blocked",
            "severity": "CRITICAL",
            "findings": [{"severity": "blocked", "reason": "Scan failed"}],
        }

    # Parse last JSON line (governance.py outputs JSON)
    for line in reversed(result.stdout.strip().split("\n")):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
                classification = data.get("classification", "review")
                findings = data.get("findings", [])
                return {
                    "name": skill_path.name,
                    "classification": classification,
                    "severity": SEVERITY_MAP.get(classification, "WARNING"),
                    "findings": findings,
                }
            except json.JSONDecodeError:
                continue

    return {
        "name": skill_path.name,
        "classification": "review",
        "severity": "WARNING",
        "findings": [{"severity": "review", "reason": "No JSON output"}],
    }


def quarantine_skill(skill_path: Path) -> Path | None:
    """Move skill to quarantine. Returns quarantine path or None."""
    if not skill_path.exists():
        return None
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = QUARANTINE_DIR / f"{skill_path.name}_quarantined_{ts}"

    try:
        shutil.move(str(skill_path), str(dest))
        return dest
    except OSError as e:
        print(f"  ⚠️  Quarantine failed: {e}")
        return None


def main():
    mode = get_mode()
    print(f"🛡️  Me-Guard Preload Check v2.1  [Mode: {mode}]")
    print("=" * 55)

    if not SKILLS_DIR.exists():
        print(f"ℹ️  Skills directory missing: {SKILLS_DIR}")
        return 0

    # Find all skills
    skills = sorted(
        [e for e in SKILLS_DIR.iterdir() if e.is_dir() or e.suffix == ".md"],
        key=lambda p: p.name,
    )
    if not skills:
        print("ℹ️  No skills found.")
        return 0

    print(f"Checking {len(skills)} skill(s)...\n")

    passed = []
    warnings = []
    criticals = []

    for skill in skills:
        result = scan_skill(skill)

        if result["severity"] == "OK":
            print(f"  ✅ {skill.name}")
            passed.append(result)

        elif result["severity"] == "WARNING":
            findings_str = "; ".join(
                f.get("reason", f.get("pattern", "")) for f in result["findings"]
            )
            print(f"  ⚠️  {skill.name} — {findings_str or 'Review recommendation'}")
            warnings.append(result)

        else:  # CRITICAL
            findings_str = "; ".join(
                f.get("reason", f.get("pattern", "")) for f in result["findings"]
            )
            print(f"  🚫 {skill.name} — {findings_str or 'Blocked'}")
            criticals.append(result)

    # ─── Summary ───
    print()
    print("=" * 55)
    print(f"  ✅ OK:       {len(passed)}")
    print(f"  ⚠️  Warning:  {len(warnings)}")
    print(f"  🚫 Critical: {len(criticals)}")

    # ─── Decision ───
    if mode == "FAIL_SAFE" and criticals:
        # FAIL_SAFE: Move skills to quarantine, gateway starts anyway
        print(f"\n⚡ FAIL-SAFE mode: Moving {len(criticals)} critical skill(s) to quarantine...")
        for c in criticals:
            skill_path = SKILLS_DIR / c["name"]
            if skill_path.exists():
                dest = quarantine_skill(skill_path)
                if dest:
                    print(f"  ➡️  {c['name']} → {dest}")
                else:
                    print(f"  ⚠️  {c['name']} could not be moved — skipping")
            else:
                print(f"  ⚠️  {c['name']} not found — skipping")
        print(f"\n✅ Gateway starting with {len(passed) + len(warnings)} validated skills.")
        print(f"📋 Checked: {len(skills)} | Active: {len(passed) + len(warnings)} | Quarantined: {len(criticals)}")
        if warnings:
            print(f"⚠️  {len(warnings)} skill(s) with WARNINGS active — please review:")
            for w in warnings:
                print(f"   - {w['name']}")
        return 0  # Gateway starts anyway

    elif mode == "FAIL_CLOSED" and criticals:
        # FAIL_CLOSED: Critical errors stop the gateway
        print(f"\n🚫 FAIL-CLOSED: {len(criticals)} critical skill(s) blocking startup.")
        print(f"   Gateway should NOT start.")
        print(f"\n   Affected skills:")
        for c in criticals:
            print(f"   - {c['name']}")
        print(f"\n   Fix with:")
        print(f"   governance.py scan ~/.me-guard/skills/<name>")
        print(f"   governance.py sign ~/.me-guard/skills/<name> --approve")
        return 1

    elif warnings:
        # No CRITICALS but WARNINGS — log, gateway starts
        print(f"\n⚠️  {len(warnings)} skill(s) with WARNINGS — but no hard block.")
        print(f"✅ All {len(skills)} skills OK. Gateway may start.")
        return 0

    else:
        print(f"\n✅ All {len(skills)} skills OK. Gateway may start.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
