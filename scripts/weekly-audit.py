#!/usr/bin/env python3
"""
Me-Guard — Weekly Audit Report

Generates a report covering:
- All signed skills (with status)
- New skills since last week
- Removed skills (revoked / deleted)
- Verify status of all skills (valid / broken)
- Audit log activity over the last 7 days
- Hash-chain integrity of the audit log

Exit codes: 0=ok, 1=check, 2=critical
"""

import argparse
import hashlib
import json
import subprocess
import sys
import yaml
from datetime import datetime, timedelta, timezone
from pathlib import Path

ME_GUARD_DIR = Path.home() / ".me-guard"
CATALOG_DIR = ME_GUARD_DIR / "skill_catalog"
SIGS_DIR = ME_GUARD_DIR / "skill_signatures"
GOV_DIR = ME_GUARD_DIR / "governance"
SKILLS_DIR = ME_GUARD_DIR / "skills"
SCAN_LOG = GOV_DIR / "scan.log"
REVOCATION_LIST = GOV_DIR / "revoked.json"
REPORTS_DIR = ME_GUARD_DIR / "reports"
LAST_SNAPSHOT = REPORTS_DIR / ".last-snapshot.json"
GOVERNANCE_SCRIPT = Path(__file__).parent / "governance.py"


def collect_current_state() -> dict:
    """Collect current state of all skills from the cards."""
    skills = {}
    if not CATALOG_DIR.exists():
        return skills

    for card_file in sorted(CATALOG_DIR.glob("*.card.yaml")):
        with open(card_file) as f:
            card = yaml.safe_load(f)
        skills[card["skill_name"]] = {
            "classification": card.get("classification", "?"),
            "created": card.get("created", "?"),
            "findings": card.get("findings_count", 0),
        }
    return skills


def load_last_snapshot() -> dict:
    """Load last week's snapshot."""
    if LAST_SNAPSHOT.exists():
        with open(LAST_SNAPSHOT) as f:
            return json.load(f)
    return {}


def save_snapshot(state: dict):
    """Save snapshot for next week."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(LAST_SNAPSHOT, "w") as f:
        json.dump(state, f, indent=2)


def verify_all_skills() -> tuple:
    """Verify all skills. Returns (valid, invalid)."""
    valid, invalid = [], []
    if not SKILLS_DIR.exists():
        return valid, invalid

    for entry in sorted(SKILLS_DIR.iterdir()):
        if not (entry.is_dir() or entry.suffix == ".md"):
            continue
        if entry.name.startswith("."):
            continue  # Skip hidden dirs like .curator_backups
        result = subprocess.run(
            ["python3", str(GOVERNANCE_SCRIPT), "verify", str(entry)],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            valid.append(entry.name)
        else:
            lines = result.stdout.strip().split("\n")
            err = lines[-1] if lines else "unknown error"
            invalid.append((entry.name, err))
    return valid, invalid


def check_log_chain() -> tuple:
    """Check hash-chain integrity. Returns (ok, count, error_msg)."""
    if not SCAN_LOG.exists() or SCAN_LOG.stat().st_size == 0:
        return True, 0, ""

    entries = []
    with open(SCAN_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                return False, len(entries), f"Defective line #{len(entries)+1}"

    prev_hash = "0" * 64
    for i, entry in enumerate(entries):
        if entry.get("prev_hash") != prev_hash:
            return False, i, f"prev_hash breaks at entry #{i+1}"

        stored_hash = entry.get("hash", "")
        check_entry = {k: v for k, v in entry.items() if k != "hash"}
        entry_str = json.dumps(check_entry, sort_keys=True)
        recomputed = hashlib.sha256(
            (entry_str + prev_hash).encode()
        ).hexdigest()

        if recomputed != stored_hash:
            return False, i, f"Hash wrong at entry #{i+1}"
        prev_hash = stored_hash

    return True, len(entries), ""


def get_recent_log_entries(days: int = 7) -> list:
    """Audit log entries from the last N days."""
    if not SCAN_LOG.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    entries = []
    with open(SCAN_LOG) as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                ts = datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
                if ts >= cutoff:
                    entries.append(e)
            except (json.JSONDecodeError, ValueError, KeyError):
                continue
    return entries


def load_revoked() -> list:
    """Load revocation list."""
    if not REVOCATION_LIST.exists():
        return []
    with open(REVOCATION_LIST) as f:
        return json.load(f).get("revoked_skills", [])


def format_report(data: dict) -> str:
    """Format report as Markdown."""
    lines = []
    today = datetime.now().strftime("%A, %Y-%m-%d")
    lines.append("# Me-Guard — Weekly Audit")
    lines.append(f"*{today}*\n")
    lines.append("---\n")

    # 1. Overview
    lines.append("## 📊 Overview\n")
    lines.append(f"- **Total skills:** {data['total']}")
    lines.append(
        f"- **Validly signed:** {len(data['valid'])} ✅")
    lines.append(
        f"- **Invalid:** {len(data['invalid'])} "
        f"{'❌' if data['invalid'] else ''}")
    lines.append(f"- **Revoked:** {len(data['revoked'])}")
    lines.append(
        f"- **New since last week:** {len(data['new'])} "
        f"{'🆕' if data['new'] else ''}")
    lines.append(
        f"- **Removed:** {len(data['removed'])} "
        f"{'⚠️' if data['removed'] else ''}\n")

    # Classifications
    classifications = {}
    for info in data['current'].values():
        c = info.get('classification', '?')
        classifications[c] = classifications.get(c, 0) + 1

    lines.append("**Classifications:**")
    for c in ("trusted", "review", "blocked"):
        if c in classifications:
            icon = {"trusted": "✅", "review": "⚠️", "blocked": "🚫"}[c]
            lines.append(f"- {icon} {c}: {classifications[c]}")
    lines.append("")

    # 2. Audit Log Integrity
    lines.append("## 🔐 Audit Log Integrity\n")
    if data['log_ok']:
        lines.append(
            f"✅ Hash chain intact ({data['log_entries']} entries)\n")
    else:
        lines.append(
            f"❌ **HASH CHAIN BROKEN**: {data['log_error']}")
        lines.append("   Possible log tampering! Check immediately.\n")

    # 3. New Skills
    if data['new']:
        lines.append("## 🆕 New Skills (since last week)\n")
        for name in sorted(data['new']):
            info = data['current'].get(name, {})
            lines.append(
                f"- **{name}** — {info.get('classification', '?')} "
                f"({info.get('findings', 0)} findings)")
        lines.append("")

    # 4. Removed Skills
    if data['removed']:
        lines.append("## ⚠️ Removed Skills\n")
        lines.append("_These skills were present last week. "
                     "Check manually!_\n")
        for name in sorted(data['removed']):
            lines.append(f"- **{name}**")
        lines.append("")

    # 5. Invalid Skills
    if data['invalid']:
        lines.append("## ❌ Invalid Skills\n")
        lines.append("_Verify failed:_\n")
        for name, err in data['invalid']:
            lines.append(f"- **{name}** — {err}")
        lines.append("")
        lines.append("**Action:** Re-sign or revoke.\n")

    # 6. Activity
    lines.append("## 📝 Activity (last 7 days)\n")
    recent = data['log_entries_recent']
    if not recent:
        lines.append("_No activity._\n")
    else:
        actions = {}
        for e in recent:
            a = e.get('action', '?')
            actions[a] = actions.get(a, 0) + 1
        for action, count in sorted(actions.items()):
            lines.append(f"- **{action}:** {count}x")

        notable = [e for e in recent
                   if e.get('result') in ('blocked', 'invalid', 'revoked')]
        if notable:
            lines.append("\n**Notable:**")
            for e in notable[-10:]:
                target = Path(e.get('target', '?')).name
                lines.append(
                    f"- `{e.get('ts', '?')[:19]}` "
                    f"**{e.get('action')}** {target} -> {e.get('result')}")
        lines.append("")

    # 7. Recommendations
    lines.append("## 💡 Recommendations\n")
    recs = []
    if data['invalid']:
        recs.append("🔴 **Immediate:** Re-sign invalid skills")
    if data['removed']:
        recs.append("🟡 **Check:** Removed skills — intentional?")
    if not data['log_ok']:
        recs.append("🔴 **Critical:** Audit log tampered with!")
    if len(data['new']) > 5:
        recs.append("🟡 Many new skills — unusual")

    if not recs:
        recs.append("✅ All clear. No actions needed.")
    for r in recs:
        lines.append(f"- {r}")
    lines.append("")

    lines.append("---")
    lines.append(f"_Report generated: {datetime.now().isoformat()}_")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Me-Guard - Weekly Audit")
    parser.add_argument("--quiet", action="store_true",
                        help="No debug output, only report to stdout")
    args = parser.parse_args()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if not args.quiet:
        print("📋 Collecting data...")
    current = collect_current_state()
    last = load_last_snapshot()
    valid, invalid = verify_all_skills()
    log_ok, log_count, log_err = check_log_chain()
    recent = get_recent_log_entries(7)
    revoked = load_revoked()

    # Diff vs last week
    new_skills = sorted(set(current.keys()) - set(last.keys()))
    removed_skills = sorted(set(last.keys()) - set(current.keys()))

    data = {
        "total": len(current),
        "current": current,
        "valid": valid,
        "invalid": invalid,
        "revoked": revoked,
        "new": new_skills,
        "removed": removed_skills,
        "log_ok": log_ok,
        "log_entries": log_count,
        "log_error": log_err,
        "log_entries_recent": recent,
    }

    report_md = format_report(data)
    report_file = (
        REPORTS_DIR
        / f"weekly-{datetime.now().strftime('%Y-%m-%d')}.md"
    )
    with open(report_file, "w") as f:
        f.write(report_md)

    save_snapshot(current)

    if not args.quiet:
        print(f"\n✅ Report created: {report_file}")

    # With --quiet: ONLY the report to stdout (for no_agent cron)
    if args.quiet:
        print("")  # Blank line before report
    print(report_md)

    if invalid or not log_ok:
        sys.exit(2)
    if removed_skills:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
