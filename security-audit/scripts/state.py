"""
state.py — machine-local change-detection cache for security-audit.

This is what makes the skill token-smart and what powers the URL time-of-check/
time-of-use (TOCTOU) defense. It lives OUTSIDE the repo (default
``~/.claude/.security-audit/state.json``) so it is never published and is
per-machine.

state.json shape:

    {
      "version": 1,
      "last_audit": "2026-06-23T19:40:00Z",
      "items": {                      # one entry per scanned skill/mcp/file
        "<key>": {"hash": "<sha256>", "kind": "skill", "last_seen": "<iso>"}
      },
      "urls": {                       # resolved-destination fingerprints
        "<url>": {
          "final_url":  "<resolved url after redirects>",
          "content_sha":"<sha256 of normalized body>",
          "chain":      ["<url>", "..."],
          "last_checked":"<iso>"
        }
      }
    }
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

STATE_VERSION = 1


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_path():
    override = os.environ.get("SECURITY_AUDIT_STATE")
    if override:
        return Path(override)
    base = os.environ.get("CLAUDE_HOME") or os.path.expanduser("~/.claude")
    return Path(base) / ".security-audit" / "state.json"


def load_state():
    p = state_path()
    if p.exists():
        try:
            data = json.loads(p.read_text())
            data.setdefault("items", {})
            data.setdefault("urls", {})
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return {"version": STATE_VERSION, "last_audit": None, "items": {}, "urls": {}}


def save_state(state):
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    state["version"] = STATE_VERSION
    p.write_text(json.dumps(state, indent=2, sort_keys=True))
    try:
        os.chmod(p, 0o600)  # the cache records URLs/paths; keep it private
    except OSError:
        pass


def sha256(text):
    if isinstance(text, str):
        text = text.encode("utf-8", "replace")
    return hashlib.sha256(text).hexdigest()


def normalized_body_sha(body):
    """Fingerprint web content with volatile bits (whitespace) collapsed so a
    cosmetic change doesn't look like a takeover, but real content changes do."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    collapsed = " ".join(body.split())
    return sha256(collapsed)


# --------------------------------------------------------------------------- #
# Item diffing (the token-saving core)
# --------------------------------------------------------------------------- #

def diff_items(state, current):
    """`current` = {key: hash}. Returns dict of new / changed / unchanged / removed
    key lists by comparing against the cached item hashes."""
    cached = {k: v.get("hash") for k, v in state.get("items", {}).items()}
    cur_keys, old_keys = set(current), set(cached)
    new = sorted(cur_keys - old_keys)
    removed = sorted(old_keys - cur_keys)
    changed = sorted(k for k in (cur_keys & old_keys) if current[k] != cached[k])
    unchanged = sorted(k for k in (cur_keys & old_keys) if current[k] == cached[k])
    return {"new": new, "changed": changed, "unchanged": unchanged, "removed": removed}


def record_items(state, current, kinds, findings_by_key=None):
    """Persist the current hashes and (optionally) the findings per item, so an
    unchanged item can carry its unresolved findings into the next audit.
    `kinds` = {key: kind}; `findings_by_key` = {key: [finding, ...]}."""
    findings_by_key = findings_by_key or {}
    items = {}
    ts = now_iso()
    for key, h in current.items():
        items[key] = {
            "hash": h,
            "kind": kinds.get(key, "file"),
            "last_seen": ts,
            "findings": findings_by_key.get(key, []),
        }
    state["items"] = items
    state["last_audit"] = ts


# --------------------------------------------------------------------------- #
# URL TOCTOU tracking
# --------------------------------------------------------------------------- #

def compare_url(state, url, final_url, content_sha):
    """Compare a freshly-resolved URL against the cached trusted record.
    Returns (status, detail):
      'new'        first time we've seen this URL
      'unchanged'  destination + fingerprint match the trusted record
      'redirect_changed'  final URL differs from last time  -> possible takeover
      'content_changed'   final URL same but body fingerprint differs
    """
    rec = state.get("urls", {}).get(url)
    if not rec:
        return "new", None
    if final_url and rec.get("final_url") and final_url != rec["final_url"]:
        return "redirect_changed", {"was": rec["final_url"], "now": final_url}
    if content_sha and rec.get("content_sha") and content_sha != rec["content_sha"]:
        return "content_changed", {"last_checked": rec.get("last_checked")}
    return "unchanged", None


def update_url(state, url, final_url=None, content_sha=None, chain=None):
    state.setdefault("urls", {})[url] = {
        "final_url": final_url,
        "content_sha": content_sha,
        "chain": chain or [],
        "last_checked": now_iso(),
    }
