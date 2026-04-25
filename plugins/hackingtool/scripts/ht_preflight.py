#!/usr/bin/env python3
"""
ht_preflight.py — Capability check + user-facing setup recommendations.

Wraps `ht_env.describe()` and adds:
  - per-tool inventory (which canonical Linux pentest tools are available natively or via Docker)
  - disk-space check (Docker pulls are heavy)
  - internet reachability (image pulls + template fetches)
  - a `ready_score` (0–100) and `verdict` enum: ready | partial | blocked
  - a `recommendations` list: human-readable, ordered, ready to surface to the user

The skill is expected to call this ONCE at the start of every session and act on the
recommendations before doing any manual probing.

Output is JSON on stdout. Exit code is always 0 (the model parses the verdict).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Re-use the env detector.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ht_env  # noqa: E402


# Canonical tools the model should reach for first.
# Each entry: (logical_name, native_binary, has_docker_image)
_CORE_TOOLS = [
    ("nmap",         "nmap",        True),
    ("nuclei",       "nuclei",      True),
    ("subfinder",    "subfinder",   True),
    ("httpx",        "httpx",       True),
    ("amass",        "amass",       True),
    ("katana",       "katana",      True),
    ("ffuf",         "ffuf",        True),
    ("gobuster",     "gobuster",    True),
    ("sqlmap",       "sqlmap",      True),
    ("dnsx",         "dnsx",        True),
    ("naabu",        "naabu",       True),
    ("trufflehog",   "trufflehog",  True),
    ("gitleaks",     "gitleaks",    True),
    ("sherlock",     "sherlock",    True),
    ("holehe",       "holehe",      True),
    ("maigret",      "maigret",     True),
    ("theharvester", "theHarvester", True),
    ("masscan",      "masscan",     True),
    ("netexec",      "netexec",     True),
    ("impacket",     "impacket-secretsdump", True),
]


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _disk_free_gb(path: str = ".") -> float:
    try:
        usage = shutil.disk_usage(os.path.abspath(path))
        return round(usage.free / (1024 ** 3), 1)
    except OSError:
        return -1.0


def _internet_ok() -> bool:
    # 1.1.1.1:443 — Cloudflare. Avoids DNS so we don't double-test.
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            return True
    except (OSError, socket.timeout):
        return False


def _tool_inventory(env: dict[str, Any]) -> dict[str, dict[str, bool]]:
    """For each core tool, what's available right now?"""
    docker_ok = bool(env.get("docker"))
    native_ok = env.get("preferred_backend") in ("native", "wsl")
    inv: dict[str, dict[str, bool]] = {}
    for name, binary, has_image in _CORE_TOOLS:
        natively = native_ok and _has(binary)
        # We don't probe Docker Hub here (slow, network-dependent) — assume image exists if we mapped one.
        inv[name] = {
            "native": natively,
            "docker": docker_ok and has_image,
            "any": natively or (docker_ok and has_image),
        }
    return inv


def _make_recommendations(env: dict[str, Any], inv: dict[str, dict[str, bool]],
                          disk_gb: float, net_ok: bool) -> list[dict[str, str]]:
    """Ordered list of {priority, action, why} for the user."""
    recs: list[dict[str, str]] = []
    host = env["host"]
    backend = env["preferred_backend"]
    docker = env["docker"]
    wsl = env["wsl_distros"]

    if not net_ok:
        recs.append({
            "priority": "critical",
            "action": "Restore internet connectivity",
            "why": "Image pulls (Docker Hub) and template updates (nuclei-templates) require internet. Without it, you're limited to whatever's already cached.",
        })

    if backend == "fallback":
        if host == "windows":
            recs.append({
                "priority": "critical",
                "action": "Install Docker Desktop OR enable WSL2 with a Linux distro (`wsl --install -d Ubuntu`)",
                "why": "Without one of these, the skill cannot run any Linux-only pentest tools (nmap, nuclei, subfinder, etc.). It would fall back to manual curl/PowerShell probes — much slower and far less thorough.",
            })
        else:
            recs.append({
                "priority": "critical",
                "action": "Install Docker (or run on Linux/macOS where the tools are native)",
                "why": "Detected an unusual environment. The skill needs Docker or a real Linux/macOS shell to invoke its tool wrappers.",
            })
    elif backend == "docker" and not docker:
        recs.append({
            "priority": "high",
            "action": "Start Docker Desktop",
            "why": "Docker is installed but the daemon isn't responding. Tools that pull images can't run until it's up.",
        })
    elif backend == "wsl" and host == "windows" and not docker:
        recs.append({
            "priority": "medium",
            "action": "Optional: also start Docker Desktop",
            "why": f"WSL distro ({', '.join(wsl)}) detected — most tools will run natively. Docker is the fallback for tools you haven't installed inside WSL.",
        })

    if disk_gb >= 0 and disk_gb < 5 and (docker or backend == "fallback"):
        recs.append({
            "priority": "high",
            "action": f"Free up disk space (currently {disk_gb} GB free)",
            "why": "Pentest Docker images range from ~50 MB (httpx) to ~3 GB (kalilinux/kali-rolling). 5+ GB recommended for a comfortable buffer.",
        })

    # If Docker is up but the user is on Windows native, hint the perf trade-off
    if host == "windows" and backend == "docker":
        recs.append({
            "priority": "info",
            "action": "Consider enabling WSL2 alongside Docker for faster scans",
            "why": "WSL native binaries are 2–5× faster than Docker for short tools (subfinder, httpx). Docker is still fine for long-running scans.",
        })

    # Permission / sudo hints for native Linux/WSL
    if backend in ("native", "wsl") and host != "macos":
        try:
            sudo_test = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=3)
            sudo_passwordless = sudo_test.returncode == 0
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            sudo_passwordless = False
        if not sudo_passwordless:
            recs.append({
                "priority": "info",
                "action": "Configure passwordless sudo for nmap/masscan (`sudo visudo`)",
                "why": "Raw-socket scans (SYN scan, OS detect, masscan) need root. Without passwordless sudo, the wrapper falls back to TCP-connect scans — slower and noisier.",
            })

    return recs


def _ready_score(env: dict[str, Any], inv: dict[str, dict[str, bool]],
                 disk_gb: float, net_ok: bool) -> int:
    score = 0
    if net_ok:
        score += 20
    if env["preferred_backend"] in ("native", "wsl"):
        score += 50
    elif env["preferred_backend"] == "docker":
        score += 40
    if env["docker"]:
        score += 10
    if disk_gb < 0 or disk_gb >= 5:
        score += 10
    # Tool coverage
    available = sum(1 for v in inv.values() if v["any"])
    score += int((available / len(inv)) * 10)
    return min(score, 100)


def _verdict(score: int) -> str:
    if score >= 75:
        return "ready"
    if score >= 40:
        return "partial"
    return "blocked"


def _summary_for_model(env: dict[str, Any], inv: dict[str, dict[str, bool]],
                       verdict: str, recs: list[dict[str, str]]) -> str:
    """A short text the model can paraphrase to the user."""
    backend = env["preferred_backend"]
    available = sorted(name for name, v in inv.items() if v["any"])
    missing = sorted(name for name, v in inv.items() if not v["any"])

    if verdict == "ready":
        head = f"✅ Pentest skill ready — backend={backend}. {len(available)}/{len(inv)} core tools available."
    elif verdict == "partial":
        head = f"⚠️ Pentest skill partially ready — backend={backend}. {len(available)}/{len(inv)} core tools available. Some workflows will be limited."
    else:
        head = f"⛔ Pentest skill blocked — backend={backend}. The skill cannot run real tools in this environment."

    if recs:
        body = "Required setup steps:\n" + "\n".join(
            f"  [{r['priority']}] {r['action']}\n      → {r['why']}" for r in recs
        )
    else:
        body = "No setup actions required."

    if missing and verdict != "blocked":
        body += f"\n\nUnavailable in current backend: {', '.join(missing)}"

    return f"{head}\n\n{body}"


def main() -> int:
    env = ht_env.describe()
    disk_gb = _disk_free_gb()
    net_ok = _internet_ok()
    inv = _tool_inventory(env)
    recs = _make_recommendations(env, inv, disk_gb, net_ok)
    score = _ready_score(env, inv, disk_gb, net_ok)
    verdict = _verdict(score)
    summary = _summary_for_model(env, inv, verdict, recs)

    out = {
        "env": env,
        "disk_free_gb": disk_gb,
        "internet": net_ok,
        "tool_inventory": inv,
        "ready_score": score,
        "verdict": verdict,
        "recommendations": recs,
        "summary_for_user": summary,
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
