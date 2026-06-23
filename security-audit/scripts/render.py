#!/usr/bin/env python3
"""
render.py — turn scan.py's JSON into the findings table the user sees.

Usage:
    python scan.py <mode> --json | python render.py
    python render.py results.json

The skill normally lets the model render the table (so it can weave in the live
URL-verification results from WebFetch), but this script guarantees a correct,
consistent table whenever you want it deterministically.
"""

import json
import sys

EMOJI = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🔵 Low",
    "info": "⚪ Info",
}
VERDICT_EMOJI = {"PASS": "✅ PASS", "FLAGGED": "⚠️ FLAGGED", "BLOCK": "⛔ BLOCK"}


def _cell(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def render(result):
    s = result["summary"]
    c = s["findings_by_severity"]
    lines = []

    scope = result.get("scope", "")
    lines.append(
        f"## 🔒 Security Audit — {result['mode']} · "
        f"{s['scanned']} scanned, {s.get('changed', 0)} changed · "
        f"Verdict: {VERDICT_EMOJI.get(s['verdict'], s['verdict'])}")
    lines.append("")
    lines.append(f"*Scope: {scope} · generated {result.get('generated_at','')}*")
    lines.append("")

    if result["mode"] != "deploy" and (s["new"] + s["changed"]) == 0:
        lines.append(f"✓ **No changes since last audit.** {s['unchanged']} item(s) "
                     "unchanged — nothing new to review. (Run `/security-audit full` "
                     "to force a complete re-scan.)")
        return "\n".join(lines)

    findings = result.get("findings", [])
    if not findings:
        lines.append("✅ **No findings.** Nothing exposed or suspicious in the reviewed items.")
    else:
        lines.append("| # | Severity | Finding | Location | Why it matters | How to fix |")
        lines.append("|---|----------|---------|----------|----------------|------------|")
        for i, f in enumerate(findings, 1):
            lines.append("| {} | {} | {} | `{}` | {} | {} |".format(
                i, EMOJI.get(f.get("severity"), f.get("severity")),
                _cell(f.get("title")), _cell(f.get("location")),
                _cell(f.get("why")), _cell(f.get("fix"))))
        # Evidence appendix (redacted) so the table stays scannable.
        lines.append("")
        lines.append("<details><summary>Evidence (redacted)</summary>\n")
        for i, f in enumerate(findings, 1):
            if f.get("evidence"):
                lines.append(f"- **{i}. {_cell(f.get('title'))}** — `{_cell(f.get('evidence'))}`")
        lines.append("\n</details>")

    lines.append("")
    summary = " · ".join(f"{c.get(k,0)} {EMOJI[k].split(' ',1)[1]}"
                         for k in ("critical", "high", "medium", "low", "info")
                         if c.get(k))
    lines.append(f"**Summary:** {summary or '0 findings'} — Verdict: "
                 f"{VERDICT_EMOJI.get(s['verdict'], s['verdict'])}")

    to_verify = result.get("urls_to_verify", [])
    if to_verify:
        lines.append("")
        lines.append(f"**{len(to_verify)} external URL(s) still need live verification** "
                     "(follow redirects with WebFetch, confirm the final destination is "
                     "safe and unchanged):")
        for u in to_verify[:20]:
            tag = u.get("status", "")
            cached = f" (last trusted → {u['cached_final']})" if u.get("cached_final") else ""
            lines.append(f"- `{_cell(u['url'])}` — at {_cell(u.get('where'))} [{tag}]{cached}")

    if s["verdict"] == "BLOCK":
        lines.append("")
        lines.append("> ⛔ **Do not publish / proceed** until the Critical/High items above "
                     "are resolved.")
    return "\n".join(lines)


def main():
    if len(sys.argv) > 1 and sys.argv[1] not in ("-",):
        with open(sys.argv[1]) as fh:
            result = json.load(fh)
    else:
        result = json.load(sys.stdin)
    print(render(result))


if __name__ == "__main__":
    main()
