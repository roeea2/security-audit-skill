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

    # Self-terminate if the guard ever hangs, so it can never block a tool call.
    # On timeout we exit 0 (allow) — failing open, like every other guard error.
    try:
        import signal
        signal.signal(signal.SIGALRM, lambda *a: os._exit(0))
        signal.alarm(10)
    except Exception:
        pass

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
    status = res["status"]
    unaudited = status in ("new", "changed")  # not reviewed since this version
    label = res["key"]

    # Audit-gate framing: a skill/MCP shouldn't be trusted to run until a full
    # /security-audit has reviewed *this* version of it.
    gate = ("has not been audited yet" if status == "new"
            else "changed since your last audit" if status == "changed" else None)
    finding_note = ""
    if crit or high:
        parts = ([f"{crit} critical"] if crit else []) + ([f"{high} high"] if high else [])
        finding_note = f" ({', '.join(parts)} deterministic finding(s))"

    # block: deny anything unaudited (new/changed) or carrying a Critical, until
    # a full audit clears it. warn: never deny.
    if args.mode == "block" and (crit or unaudited):
        why = gate or f"has {crit} Critical finding(s)"
        _emit({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"security-audit blocked {label}: {why}{finding_note}. "
                f"Run /security-audit to review and clear it before invoking."),
        }})
        return

    # warn / allow: surface context to the model when noteworthy.
    if gate or crit or high:
        lead = gate or "has unresolved findings"
        _emit({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": (
                f"⚠ security-audit: {label} {lead}{finding_note}. "
                f"Run /security-audit before relying on it."),
        }})


if __name__ == "__main__":
    main()
