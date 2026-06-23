#!/usr/bin/env python3
"""
guard.py — PreToolUse guard for security-audit.

Wired as a Claude Code PreToolUse hook with a matcher on the `Skill` tool and
`mcp__.*` (all MCP tools), this runs *before every skill / MCP invocation*. It
reads the hook payload on stdin, audits only the single item being called (fast),
and either:

  --mode warn   : injects a one-line warning for the model when the targeted
                  skill/MCP is new/changed or carries a Critical/High finding,
                  but always allows the call.
  --mode block  : DENIES the call when the targeted skill/MCP carries a Critical
                  finding; otherwise allows (and still warns on High/changed).

Design choices:
- It targets the specific item being invoked, so unrelated standing issues never
  block your work.
- It runs the deterministic engine only (no model, no network) — the deep review
  and live URL checks still happen when you run /security-audit.
- It FAILS OPEN: any error, or an unrecognized tool, results in "allow". A bug in
  the guard must never be able to wedge your session.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _emit(obj):
    print(json.dumps(obj))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["warn", "block"], default="warn")
    args = ap.parse_args()

    try:
        payload = json.load(sys.stdin)
    except Exception:
        return  # no/invalid payload → allow

    tool = payload.get("tool_name", "")
    tinput = payload.get("tool_input", {})
    project = payload.get("cwd") or os.getcwd()

    try:
        import scan
        res = scan.audit_target(tool, tinput, project)
    except Exception:
        return  # fail open — never break the session on a guard error

    if not res:
        return  # not a recognizable local skill/MCP → allow

    c = res["counts"]
    crit, high = c.get("critical", 0), c.get("high", 0)
    changed = res["status"] in ("new", "changed")
    label = res["key"]

    if args.mode == "block" and crit:
        reason = (f"security-audit blocked {label}: {crit} Critical finding(s) "
                  f"({res['status']}). Run /security-audit for the details and fix "
                  f"before invoking it.")
        _emit({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }})
        return

    # Otherwise allow, but surface context to the model when noteworthy.
    if crit or high or changed:
        bits = []
        if changed:
            bits.append(res["status"])
        if crit:
            bits.append(f"{crit} critical")
        if high:
            bits.append(f"{high} high")
        note = (f"⚠ security-audit: {label} is {', '.join(bits)} since last audit. "
                f"Consider running /security-audit before relying on it.")
        _emit({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": note,
        }})


if __name__ == "__main__":
    main()
