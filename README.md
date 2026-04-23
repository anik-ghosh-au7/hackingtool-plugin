# hackingtool — Claude Code plugin

Gives Claude Code access to the **183+ pentesting & OSINT tools** from [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) as a single skill.

Claude auto-runs anything it can (non-interactive, no sudo, no GUI, no hardware). For the rest — interactive prompts, sudo, GUI windows, wifi adapters — Claude hands you the exact command to run yourself, then picks up with your output.

**For authorized security testing, bug bounty work, CTFs, and research only.** Destructive tools are gated behind a `scope.md` authorization file you fill in once per engagement.

Built by [ariacodez](https://github.com/AKCODEZ).

---

## Install

### 1. Add the marketplace

```
/plugin marketplace add AKCODEZ/hackingtool-plugin
```

(Replace with the actual repo path once you push it.)

### 2. Install the plugin

```
/plugin install hackingtool@hackingtool-marketplace
```

### 3. Verify

Ask Claude: *"search for all runnable OSINT tools"*. The skill should activate and list matching tools from the index.

---

## What it gives Claude

- **A tool index** (`data/tools.json`) with every hackingtool tool, parsed from upstream Python sources. Each entry has capability flags so Claude knows whether to run or hand off.
- **Four scripts** Claude calls at runtime:
  - `ht_search.py` — query the index by keyword, tag, category, or capability.
  - `ht_env.py` — detect OS, WSL distros, Docker availability; pick a backend.
  - `ht_run.py` — run a tool with gating, or return a structured handoff block.
  - `ht_scope.py` — manage the per-session `scope.md` authorization file.
- **Workflow playbooks** (`reference/workflows.md`) for common tasks: domain recon, username investigation, email pivot, web app recon, AD enumeration, cloud audit, mobile static analysis, wifi recon, RE, forensics.
- **Handoff templates** (`reference/handoff-patterns.md`) so Claude's output is consistent and copy-pasteable.
- **A scope template** (`reference/scope-template.md`) used by `ht_scope.py init` to bootstrap authorization paperwork.

---

## How Claude decides run vs. hand off

Every tool in the index has capability flags. The dispatcher checks them before executing:

| Flag | Behavior |
|---|---|
| `interactive` | Hand off — tool prompts mid-run. |
| `requires_sudo` | Hand off — can't type a password. |
| `requires_gui` | Hand off — no display. |
| `requires_hardware` | Hand off — needs wifi adapter / SDR / USB / etc. |
| `destructive` | Run only if `scope.md` is valid and the user confirms. |
| `long_running` | Run with a raised timeout, or hand off, by user preference. |
| none of the above | Claude runs directly. |

Current breakdown across the 183 tools: **~56 runnable by Claude**, 100 sudo, 25 interactive, 15 hardware, 5 GUI, 71 destructive, 17 long-running (flags overlap).

---

## OS support

The plugin picks a backend automatically:

| Host | Backend |
|---|---|
| Linux (native or WSL2 with a real distro) | `bash -lc <cmd>` |
| macOS | `bash -lc <cmd>` |
| Windows with a real WSL distro | `wsl -d <distro> -- bash -lc <cmd>` |
| Windows with Docker Desktop (no WSL) | `docker run --rm kalilinux/kali-rolling bash -lc <cmd>` |
| Windows with neither | Handoff with install hints |

Tools still need to be installed in the chosen backend. `ht_run.py <tool_id> --install` runs the tool's install commands (which may itself be a handoff if they need sudo).

---

## Authorization gate (`scope.md`)

Before Claude runs any tool flagged `destructive`, it requires a valid `scope.md` in the current working directory.

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/ht_scope.py init
# edit scope.md — fill in Target, Authorization, Dates, Out of Scope
python ${CLAUDE_PLUGIN_ROOT}/scripts/ht_scope.py check   # must return ok
```

Claude will not `--force` past this gate on your behalf. If you want to bypass it for a known-safe case, run `ht_run.py` yourself with `--force`.

---

## Refreshing the tool index

When upstream hackingtool adds tools, regenerate `data/tools.json`:

```
python ${CLAUDE_PLUGIN_ROOT}/scripts/ht_index.py --hackingtool-path /path/to/hackingtool
```

If hackingtool is a sibling directory of this repo, `--hackingtool-path` isn't needed — the script auto-detects.

The index ships with the plugin, so viewers don't need to run this — it's for when you (the plugin maintainer) want to publish an update.

---

## Directory layout

```
hackingtool-plugin/
├── .claude-plugin/
│   └── marketplace.json         # marketplace entry
├── README.md                    # this file
└── plugins/
    └── hackingtool/             # the actual plugin
        ├── .claude-plugin/
        │   └── plugin.json
        ├── data/
        │   └── tools.json       # generated index
        ├── scripts/
        │   ├── ht_index.py      # (dev only) regenerate tools.json
        │   ├── ht_search.py     # query index
        │   ├── ht_env.py        # detect backend
        │   ├── ht_run.py        # run or hand off
        │   └── ht_scope.py      # scope.md gate
        └── skills/
            └── pentest/
                ├── SKILL.md
                └── reference/
                    ├── workflows.md
                    ├── handoff-patterns.md
                    └── scope-template.md
```

---

## Limitations

- **Python 3.10+** required (for the scripts' type hint syntax).
- **No async tool streaming.** Long-running tools block until they finish or the timeout hits. For live output, run them yourself in a separate terminal.
- **Docker backend assumes `kalilinux/kali-rolling`** and pulls each time unless already cached. Custom images with pre-installed tools are on the roadmap.
- **Capability flags are heuristics.** If you find a mis-tagged tool, fix it in `data/tools.json` directly, or open an issue. (`data/capability_overrides.yaml` support is planned.)
- **Legal:** this plugin makes it easier to run pentesting tools. It does not grant authorization. You are responsible for every command that runs.

---

## License

MIT for the plugin code.
Upstream [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) is MIT-licensed — this plugin does not redistribute any of its source, only derives `tools.json` from public class metadata.
