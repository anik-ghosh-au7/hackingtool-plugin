# hackingtool — OpenClaw pentest bundle

Lean OpenClaw-first bundle wrapping 183 pentest and OSINT tools from [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool).

This fork is intentionally maintained only for our OpenClaw workflow. The repo itself is the installable bundle.

## What stays

Only the runtime surface we actually use in OpenClaw:
- `.claude-plugin/plugin.json`
- `data/tools.json`
- `scripts/ht_env.py`
- `scripts/ht_preflight.py`
- `scripts/ht_run.py`
- `scripts/ht_search.py`
- `skills/pentest/`

## What was removed

Anything not needed for day-to-day OpenClaw use:
- marketplace wrapper files
- nested packaging layout
- screenshots / logo assets
- generator scripts used only to build the checked-in index/docs
- repo marketing material and extra presentation clutter

## Install

Install directly from the repo root:

```bash
openclaw plugins install /path/to/hackingtool-plugin
```

## Layout

```text
hackingtool-plugin/
├── .claude-plugin/plugin.json
├── data/tools.json
├── scripts/
│   ├── ht_env.py
│   ├── ht_preflight.py
│   ├── ht_run.py
│   └── ht_search.py
└── skills/pentest/
    ├── SKILL.md
    └── reference/
        ├── workflows.md
        └── runtime-fallbacks.md
```

## Runtime behavior

`ht_run.py` is the entire execution shim:
- chooses native / WSL / Docker backend
- falls through to Docker automatically in `auto` mode when the preferred local backend is missing the binary
- maps common tools to purpose-built Docker images
- returns structured JSON for success, fallback, timeout, and diagnostics

`ht_preflight.py` reports the backend chain and whether the current environment is ready.

`data/tools.json` is treated as the stable checked-in runtime index for this fork.

If we ever need to refresh the upstream tool inventory again, that should be done as a deliberate maintenance action — not as part of the normal runtime surface of this repo.
