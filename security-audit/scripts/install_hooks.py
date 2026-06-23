#!/usr/bin/env python3
"""
install_hooks.py — configure security-audit's automatic checking.

Writes the chosen hooks into Claude Code's settings.json, merging carefully so
existing settings (other hooks, MCP servers, secrets, model, …) are preserved.

    python3 install_hooks.py --cadence session-start --enforcement warn
    python3 install_hooks.py --cadence per-call      --enforcement block
    python3 install_hooks.py --uninstall

Cadence:
  session-start   only the cheap once-per-session change nudge (SessionStart).
  per-call        also run the guard before EVERY skill/MCP call (PreToolUse).

Enforcement (per-call only):
  warn            inject a warning for the model; never block.
  block           deny a skill/MCP call that carries a Critical finding.

The choice is meant to be made interactively by the skill at setup time — see
SKILL.md ("Setup & enforcement").
"""

import argparse
import json
import os
import sys
from pathlib import Path

PRETOOL_MATCHER = "Skill|mcp__.*"


def scripts_dir():
    """Prefer the installed skill location (`~/.claude/skills/security-audit`,
    a symlink) for hook commands: it's stable across repo moves and usually
    space-free. Fall back to wherever this file actually lives."""
    base = os.environ.get("CLAUDE_HOME") or os.path.expanduser("~/.claude")
    installed = Path(base) / "skills" / "security-audit" / "scripts"
    if (installed / "scan.py").exists():
        return installed
    return Path(__file__).resolve().parent


SCRIPTS = scripts_dir()


def settings_path():
    base = os.environ.get("CLAUDE_HOME") or os.path.expanduser("~/.claude")
    return Path(base) / "settings.json"


def _is_ours(entry):
    """True if a hook group is one we manage (command points at our scripts)."""
    for h in entry.get("hooks", []):
        cmd = h.get("command", "")
        if "scan.py" in cmd or "guard.py" in cmd or "security-audit" in cmd:
            return True
    return False


def _strip_ours(hook_list):
    return [e for e in (hook_list or []) if not _is_ours(e)]


def session_start_entry(resolve_links=False):
    cmd = f'python3 "{SCRIPTS}/scan.py" scan --changed-only --quiet'
    if resolve_links:
        # Deterministically follow each due link's redirects at session start so a
        # repointed/hijacked destination is caught automatically (no model, but it
        # makes network calls). The nudge stays quiet unless something changed.
        cmd += " --resolve-urls"
    return {"hooks": [{"type": "command", "command": cmd}]}


def pretooluse_entry(enforcement):
    return {"matcher": PRETOOL_MATCHER, "hooks": [{
        "type": "command",
        "command": f'python3 "{SCRIPTS}/guard.py" --mode {enforcement}',
    }]}


def load_settings(p):
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            print(f"error: {p} is not valid JSON; refusing to touch it.", file=sys.stderr)
            sys.exit(1)
    return {}


def save_settings(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cadence", choices=["session-start", "per-call"], default="session-start")
    ap.add_argument("--enforcement", choices=["warn", "block"], default="warn")
    ap.add_argument("--link-check", choices=["off", "resolve"], default="off",
                    help="'resolve' makes the session-start hook follow due links "
                         "over the network to auto-detect a changed/hijacked "
                         "destination (deterministic, no model). Default off.")
    ap.add_argument("--uninstall", action="store_true")
    args = ap.parse_args()

    p = settings_path()
    data = load_settings(p)
    hooks = data.get("hooks", {}) or {}

    # Always start from a clean slate of *our* entries, preserving others.
    hooks["SessionStart"] = _strip_ours(hooks.get("SessionStart"))
    hooks["PreToolUse"] = _strip_ours(hooks.get("PreToolUse"))

    if args.uninstall:
        summary = "uninstalled (removed security-audit hooks)"
    else:
        resolve_links = args.link_check == "resolve"
        hooks["SessionStart"].append(session_start_entry(resolve_links))
        link_note = " + auto link-resolution" if resolve_links else ""
        if args.cadence == "per-call":
            hooks["PreToolUse"].append(pretooluse_entry(args.enforcement))
            summary = f"per-call ({args.enforcement}) + session-start nudge{link_note}"
        else:
            summary = f"session-start nudge only{link_note}"

    # Drop empty event lists; drop hooks key if fully empty.
    hooks = {k: v for k, v in hooks.items() if v}
    if hooks:
        data["hooks"] = hooks
    else:
        data.pop("hooks", None)

    save_settings(p, data)
    print(f"security-audit hooks → {summary}")
    print(f"  settings: {p}")
    print(f"  SessionStart: {len(hooks.get('SessionStart', []))} entry; "
          f"PreToolUse: {len(hooks.get('PreToolUse', []))} entry")


if __name__ == "__main__":
    main()
