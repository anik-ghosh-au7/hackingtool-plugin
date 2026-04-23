#!/usr/bin/env python3
"""
ht_scope.py — Authorization gate for destructive tools.

Maintains a scope.md in the current working directory declaring what's in
scope for this pentest session. Without a valid scope.md, ht_run.py refuses
to run tools tagged destructive (DDoS, phishing, RAT, payloads, exploit
frameworks, web/xss/sql attacks).

Subcommands:
  ht_scope.py init   — create scope.md from the bundled template
  ht_scope.py check  — validate ./scope.md (exits 0 ok, 1 if missing/invalid)
  ht_scope.py show   — print current scope to stdout
"""

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


SCOPE_FILE = Path.cwd() / "scope.md"
TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "skills" / "pentest" / "reference" / "scope-template.md"


REQUIRED_SECTIONS = ["# Target", "# Authorization", "# Dates", "# Out of Scope"]


def _template_fallback() -> str:
    # Used if the bundled template file is missing (e.g. dev setup).
    today = date.today().isoformat()
    return f"""# Pentest Scope

# Target
- <domain.com>
- <IP or CIDR>
- <username / email / account>

# Authorization
- Source: <written permission / bug bounty program URL / CTF / own asset>
- Granted by: <name + role>
- Reference: <ticket, PR, email subject — something a third party can verify>

# Dates
- Start: {today}
- End:   {today}

# Out of Scope
- <domains / IPs / actions explicitly not permitted>

# Contact
- Primary: <name + contact>
- Emergency stop signal: <phrase or channel>

# Notes
<anything else relevant: rate limits, maintenance windows, PII handling rules>
"""


def _load_template() -> str:
    if TEMPLATE_PATH.exists():
        return TEMPLATE_PATH.read_text(encoding="utf-8")
    return _template_fallback()


def _validate(text: str) -> list[str]:
    """Return a list of problems. Empty list = valid."""
    problems = []
    for section in REQUIRED_SECTIONS:
        if section not in text:
            problems.append(f"missing section: {section}")
    # At least one non-placeholder bullet under Target
    target_block = _section_text(text, "Target")
    if target_block and not _has_real_bullet(target_block):
        problems.append("Target section has no filled-in entries (only placeholders)")
    auth_block = _section_text(text, "Authorization")
    if auth_block and not _has_real_bullet(auth_block):
        problems.append("Authorization section has no filled-in entries")
    return problems


def _section_text(text: str, header: str) -> str:
    m = re.search(rf"#\s+{re.escape(header)}\s*\n(.*?)(?=\n#\s+|\Z)", text, re.S)
    return m.group(1) if m else ""


def _has_real_bullet(block: str) -> bool:
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("-"):
            continue
        payload = line[1:].strip()
        # Reject empty or placeholder bullets
        if not payload or payload.startswith("<") or payload.lower() == "none":
            continue
        return True
    return False


def cmd_init():
    if SCOPE_FILE.exists():
        print(json.dumps({
            "status": "exists",
            "path": str(SCOPE_FILE),
            "message": "scope.md already exists; not overwriting. Edit it directly.",
        }, indent=2))
        return
    SCOPE_FILE.write_text(_load_template(), encoding="utf-8")
    print(json.dumps({
        "status": "created",
        "path": str(SCOPE_FILE),
        "message": (
            "Edit scope.md to fill in Target, Authorization, and Dates. "
            "ht_run.py will refuse destructive tools until those are filled in."
        ),
    }, indent=2))


def cmd_check():
    if not SCOPE_FILE.exists():
        print(json.dumps({
            "status": "missing",
            "path": str(SCOPE_FILE),
            "message": "scope.md not found. Run `ht_scope.py init` to create one.",
        }, indent=2))
        sys.exit(1)
    text = SCOPE_FILE.read_text(encoding="utf-8")
    problems = _validate(text)
    if problems:
        print(json.dumps({
            "status": "invalid",
            "path": str(SCOPE_FILE),
            "problems": problems,
        }, indent=2))
        sys.exit(1)
    print(json.dumps({
        "status": "ok",
        "path": str(SCOPE_FILE),
        "message": "scope.md valid; destructive tools are unlocked for this session.",
    }, indent=2))


def cmd_show():
    if not SCOPE_FILE.exists():
        print(json.dumps({"status": "missing", "path": str(SCOPE_FILE)}, indent=2))
        sys.exit(1)
    print(SCOPE_FILE.read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("check")
    sub.add_parser("show")
    args = ap.parse_args()

    if args.cmd == "init":
        cmd_init()
    elif args.cmd == "check":
        cmd_check()
    elif args.cmd == "show":
        cmd_show()


if __name__ == "__main__":
    main()
