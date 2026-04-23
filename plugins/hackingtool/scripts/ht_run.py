#!/usr/bin/env python3
"""
ht_run.py — Non-interactive runner for hackingtool tools.

Given a tool id, checks capability flags and either (a) runs the command on
an appropriate backend (native bash, WSL, Docker) or (b) emits a structured
handoff block so Claude can tell the user to run it themselves.

Output is always JSON on stdout. Stderr is reserved for human-readable
diagnostics.

Example:
  python ht_run.py information_gathering.Sherlock --args 'johndoe'
  python ht_run.py information_gathering.Sherlock --install
  python ht_run.py web_attack.Nuclei --backend docker
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from ht_env import describe


DEFAULT_TIMEOUT = 180
DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "tools.json"


# ── Index loading ─────────────────────────────────────────────────────────────

def load_tools() -> dict:
    if not DATA_PATH.exists():
        sys.exit(json.dumps({
            "status": "error",
            "message": f"tools.json not found at {DATA_PATH}. Run ht_index.py first.",
        }))
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def find_tool(doc: dict, tool_id: str) -> dict | None:
    for t in doc["tools"]:
        if t["id"] == tool_id:
            return t
    return None


# ── Handoff formatting ────────────────────────────────────────────────────────

def handoff(tool: dict, reason: str, command: str, hint: str = "") -> dict:
    msg = (
        f"I can't run this from here ({reason}). Run it yourself, then paste "
        f"the output back:\n\n  {command}\n"
    )
    if hint:
        msg += f"\n{hint}\n"
    return {
        "status": "handoff",
        "reason": reason,
        "tool": tool["id"],
        "title": tool["title"],
        "command": command,
        "message": msg,
    }


# ── Backends ──────────────────────────────────────────────────────────────────

def _run_subprocess(argv: list[str], timeout: int, label: str, extra: dict | None = None) -> dict:
    try:
        r = subprocess.run(
            argv,
            capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "backend": label, "argv": argv,
                "message": f"Timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"status": "error", "backend": label, "argv": argv,
                "message": f"Backend executable not found: {e}"}

    def _decode(b: bytes) -> str:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.decode("utf-8", errors="replace")

    result = {
        "status": "ok" if r.returncode == 0 else "error",
        "backend": label,
        "returncode": r.returncode,
        "stdout": _decode(r.stdout),
        "stderr": _decode(r.stderr),
    }
    if extra:
        result.update(extra)
    return result


def run_native(command: str, timeout: int) -> dict:
    return _run_subprocess(
        ["bash", "-lc", command], timeout, "native", {"command": command},
    )


def run_wsl(command: str, timeout: int, distro: str | None) -> dict:
    argv = ["wsl"]
    if distro:
        argv += ["-d", distro]
    argv += ["--", "bash", "-lc", command]
    return _run_subprocess(
        argv, timeout, "wsl", {"command": command, "distro": distro},
    )


def run_docker(command: str, timeout: int, image: str) -> dict:
    cwd = os.getcwd().replace("\\", "/")
    # On Windows, Docker Desktop expects /c/... style paths
    if len(cwd) > 1 and cwd[1] == ":":
        cwd = "/" + cwd[0].lower() + cwd[2:]
    argv = [
        "docker", "run", "--rm",
        "-v", f"{cwd}:/work",
        "-w", "/work",
        image,
        "bash", "-lc", command,
    ]
    return _run_subprocess(
        argv, timeout, "docker", {"command": command, "image": image},
    )


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch(tool: dict, command: str, backend: str, timeout: int,
             distro: str | None, image: str) -> dict:
    if backend == "native":
        return run_native(command, timeout)
    if backend == "wsl":
        return run_wsl(command, timeout, distro)
    if backend == "docker":
        return run_docker(command, timeout, image)
    if backend == "handoff":
        return handoff(tool, "no execution backend available", command,
                       hint="Install WSL (`wsl --install`) or Docker Desktop, then retry.")
    return {"status": "error", "message": f"unknown backend: {backend}"}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Run a hackingtool tool or emit a handoff block.")
    ap.add_argument("tool_id", help="Tool id, e.g. information_gathering.Sherlock")
    ap.add_argument("--args", default="",
                    help="Extra args appended to the tool's run command")
    ap.add_argument("--install", action="store_true",
                    help="Run INSTALL_COMMANDS instead of RUN_COMMANDS")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--backend",
                    choices=["auto", "native", "wsl", "docker", "handoff"],
                    default="auto")
    ap.add_argument("--distro", default=None, help="WSL distro name (e.g. Ubuntu)")
    ap.add_argument("--image", default="kalilinux/kali-rolling",
                    help="Docker image for the docker backend")
    ap.add_argument("--force", action="store_true",
                    help="Run even if capability flags would normally block")
    args = ap.parse_args()

    doc = load_tools()
    tool = find_tool(doc, args.tool_id)
    if not tool:
        print(json.dumps({
            "status": "error",
            "message": f"tool not found: {args.tool_id}. Use ht_search.py to discover tool ids.",
        }, indent=2))
        sys.exit(2)

    cmds = tool["install_commands"] if args.install else tool["run_commands"]
    if not cmds:
        print(json.dumps({
            "status": "handoff",
            "reason": "no_command",
            "tool": tool["id"],
            "title": tool["title"],
            "message": (
                f"The index has no {'install' if args.install else 'run'}_commands for this tool. "
                f"See the project page: {tool.get('project_url') or '(none)'}"
            ),
        }, indent=2))
        return

    command = cmds[0]
    if not args.install and args.args:
        command = f"{command} {args.args}"

    caps = tool["capabilities"]

    # Capability gates
    if not args.force:
        if caps.get("interactive"):
            print(json.dumps(handoff(tool, "interactive prompts mid-run", command), indent=2))
            return
        if caps.get("requires_sudo"):
            print(json.dumps(handoff(tool, "requires sudo (password prompt)", command), indent=2))
            return
        if caps.get("requires_gui"):
            print(json.dumps(handoff(tool, "opens a GUI window", command), indent=2))
            return
        if caps.get("requires_hardware"):
            print(json.dumps(handoff(
                tool, "requires physical hardware (wifi adapter, SDR, etc.)", command,
            ), indent=2))
            return

    env = describe()
    backend = args.backend if args.backend != "auto" else env["preferred_backend"]
    distro = args.distro or (env["wsl_distros"][0] if env["wsl_distros"] else None)

    result = dispatch(tool, command, backend, args.timeout, distro, args.image)
    result["tool"] = tool["id"]
    result["title"] = tool["title"]
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
