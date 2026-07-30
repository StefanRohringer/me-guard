"""
Me-Guard — Scanner Module

Regex + AST based skill scanner.
Scans skills for dangerous patterns, obfuscated code, and secrets.
"""

import ast as ast_mod
import re
from datetime import datetime, timezone
from pathlib import Path


# ─── File type categories ─────────────────────────────────────
CODE_EXTENSIONS   = {".py", ".sh", ".bash", ".js", ".ts", ".rb", ".pl", ".php",
                     ".go", ".rs", ".java", ".c", ".h", ".cpp"}
DOC_EXTENSIONS    = {".md", ".txt", ".rst", ".adoc", ".html", ".htm", ".xml"}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf"}
SKIP_EXTENSIONS   = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
                     ".mp3", ".wav", ".ogg", ".flac", ".mp4", ".avi", ".mov",
                     ".zip", ".gz", ".tar", ".bz2", ".xz", ".rar", ".7z",
                     ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                     ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a",
                     ".ttf", ".otf", ".woff", ".woff2",
                     ".pub", ".sig", ".asc", ".gpg",
                     ".db", ".sqlite", ".sqlite3",
                     ".pyc", ".pyo", ".pyd"}


def file_category(filepath: Path) -> str:
    """Determine file category: 'code', 'docs', 'config' or 'other'."""
    suffix = filepath.suffix.lower()
    if suffix in CODE_EXTENSIONS:
        return "code"
    if suffix in DOC_EXTENSIONS:
        return "docs"
    if suffix in CONFIG_EXTENSIONS:
        return "config"
    return "other"


def scan_file_regex(filepath: Path, rules: dict) -> list:
    """Regex-based scan with context awareness.

    Scans for blocked and review patterns, applying category-specific rules.
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

    # 4. Backwards compatibility: old 'review_patterns' (code only)
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

    Detects forbidden/review imports and dangerous function calls.
    Catches obfuscated code like __import__('os').system(...).
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
        # ── Standard Imports ──
        if isinstance(node, ast_mod.Import):
            for alias in node.names:
                mod = alias.name
                if mod in forbidden:
                    findings.append({"severity": "blocked",
                                     "file": str(filepath),
                                     "msg": f"Forbidden import: {mod}",
                                     "line": node.lineno})
                elif mod in review:
                    findings.append({"severity": "review",
                                     "file": str(filepath),
                                     "msg": f"Review import: {mod}",
                                     "line": node.lineno})

        if isinstance(node, ast_mod.ImportFrom) and node.module:
            mod = node.module
            if mod in forbidden:
                findings.append({"severity": "blocked",
                                 "file": str(filepath),
                                 "msg": f"Forbidden import: from {mod}",
                                 "line": node.lineno})
            elif mod in review:
                findings.append({"severity": "review",
                                 "file": str(filepath),
                                 "msg": f"Review import: from {mod}",
                                 "line": node.lineno})

        # ── Dynamic Imports: importlib.import_module('os') ──
        if (isinstance(node, ast_mod.Call)
                and isinstance(node.func, ast_mod.Attribute)
                and isinstance(node.func.value, ast_mod.Name)
                and node.func.value.id == "importlib"
                and node.func.attr == "import_module"):
            findings.append({"severity": "blocked",
                             "file": str(filepath),
                             "msg": "Dynamic import: importlib.import_module()",
                             "line": node.lineno})

        # ── Dynamic Imports: builtins.__import__() / importlib.__import__() ──
        if (isinstance(node, ast_mod.Call)
                and isinstance(node.func, ast_mod.Attribute)
                and isinstance(node.func.value, ast_mod.Name)
                and node.func.value.id in ("builtins", "__builtins__")
                and node.func.attr == "__import__"):
            findings.append({"severity": "blocked",
                             "file": str(filepath),
                             "msg": f"Dynamic import via {node.func.value.id}.__import__()",
                             "line": node.lineno})

        # ── getattr(__builtins__, ...) / getattr(builtins, ...) ──
        if (isinstance(node, ast_mod.Call)
                and isinstance(node.func, ast_mod.Name)
                and node.func.id == "getattr"
                and node.args):
            args = node.args
            getattr_target = ast_mod.dump(args[0])
            for builtin_name in ("builtins", "__builtins__"):
                if builtin_name in getattr_target:
                    findings.append({"severity": "blocked",
                                     "file": str(filepath),
                                     "msg": f"Dangerous getattr({getattr_target})",
                                     "line": node.lineno})
                    break

        # ── eval / exec used as variable or alias ──
        # detect: func = eval  →  func("code")
        if (isinstance(node, ast_mod.Call)
                and isinstance(node.func, ast_mod.Name)
                and node.func.id in ("eval", "exec", "compile", "__import__")):
            findings.append({"severity": "blocked",
                             "file": str(filepath),
                             "msg": f"Dangerous call: {node.func.id}()",
                             "line": node.lineno})

        # ── os.system() / subprocess.call() / subprocess.Popen() ──
        if (isinstance(node, ast_mod.Call)
                and isinstance(node.func, ast_mod.Attribute)
                and node.func.attr in ("system", "popen", "Popen",
                                        "call", "run", "check_call",
                                        "check_output")
                and isinstance(node.func.value, ast_mod.Name)
                and node.func.value.id in ("os", "subprocess")):
            findings.append({"severity": "blocked",
                             "file": str(filepath),
                             "msg": f"Dangerous call: {node.func.value.id}.{node.func.attr}()",
                             "line": node.lineno})

        # ── os.popen / subprocess.Popen with Name constant ──
        if (isinstance(node, ast_mod.Call)
                and isinstance(node.func, ast_mod.Attribute)
                and node.func.attr == "Popen"
                and isinstance(node.func.value, ast_mod.Name)
                and node.func.value.id in ("os", "subprocess")):
            findings.append({"severity": "blocked",
                             "file": str(filepath),
                             "msg": f"Dangerous: {node.func.value.id}.Popen()",
                             "line": node.lineno})

        # ── os Module Attribute Access (os.system etc) ──
        if (isinstance(node, ast_mod.Attribute)
                and isinstance(node.value, ast_mod.Name)
                and node.value.id in ("os",)
                and node.attr in ("system", "popen", "execl", "execle",
                                  "execlp", "execv", "execve", "execvp",
                                  "fork", "kill", "nice")):
            # Only flag if it's a call (not just a reference)
            for parent in ast_mod.walk(tree):
                if (isinstance(parent, ast_mod.Call)
                        and parent.func is node):
                    findings.append({"severity": "blocked",
                                     "file": str(filepath),
                                     "msg": f"Dangerous os.{node.attr}() call",
                                     "line": node.lineno})
                    break

    return findings


def scan_skill(skill_path: Path, rules: dict) -> dict:
    """Main scan function. Classification: trusted/review/blocked.

    NOTE: This is a BLOCKLIST scanner, not a sandbox.
    It finds known dangerous patterns but can be bypassed by
    obfuscation (e.g. exec(base64_decode(...)), string splitting).
    ALWAYS manually review 'review' and 'trusted' classifications.
    """
    all_findings = []

    if skill_path.is_file():
        files_to_scan = [skill_path]
    else:
        files_to_scan = [
            fp for fp in skill_path.rglob("*")
            if fp.is_file() and not fp.name.startswith(".")
            and fp.suffix.lower() not in SKIP_EXTENSIONS
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
