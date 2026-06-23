---
name: security-audit
description: >-
  Security auditor for Claude skills, MCP servers, and pre-publish deployments.
  Use this skill PROACTIVELY — not only when asked. Trigger it whenever: a skill
  or MCP server is about to run, is newly installed, or has changed; it's the
  first time a given skill/MCP is used this session; an MCP config, settings.json,
  or .mcp.json is edited; OR the user is about to push / publish / deploy / "go
  live" / open-source / upload anything to GitHub, npm, a website, or any
  external/production surface. It vets skills & MCPs for hidden-instruction,
  exfiltration, and supply-chain risk (including following external links and
  re-checking that a previously-trusted redirect hasn't been repointed to
  something hostile), and runs an exposure gate that blocks secrets, API keys,
  tokens, PII, and EXIF from being published. It is token-cheap: a deterministic
  hash-diff runs first and stops immediately when nothing changed. Triggers on:
  "is this skill safe", "audit my MCPs", "check before I push", "security review
  of my skills", "did anything change", "scan for secrets before publishing".
argument-hint: "[scan | deploy | full]  (default: scan)"
metadata:
  version: "1.0.0"
  author: RoeeAI
  repo: https://github.com/roeea2/security-audit-skill
---

# Security Audit — skills, MCPs, and deployments

Skills and MCP servers are third-party instructions and code that the agent
loads and acts on. A malicious or compromised one can hide instructions from the
user, read credentials, exfiltrate data, or point at a link whose destination is
silently changed *after* you trusted it. Separately, it is easy to leak a secret,
token, personal email, or geotagged image when publishing. This skill defends
both fronts and reports every finding in one severity-ranked table with a clear
fix for each item.

## The golden rule: run the scanner first, always

The deterministic engine does the heavy lifting and keeps this cheap. **Always
start by running it** and let its JSON tell you whether there is anything to
review:

```bash
python3 scripts/scan.py <mode> --project "$PWD" --json
```

- If the engine reports **no new or changed items** (`summary.new == 0` and
  `summary.changed == 0` in `scan`/`full` against a populated cache), do **not**
  burn tokens re-reviewing. Print the short "nothing changed" verdict and stop.
- Otherwise, review only the items the engine flags as `new`/`changed` (they are
  in `review_items`), verify their external URLs live (below), then render the
  table and let the engine update its cache.

This change-awareness is the whole point: the engine hashes every skill/MCP and
diffs against a machine-local cache at `~/.claude/.security-audit/state.json`, so
re-audits are near-free until something actually changes.

## Modes

| Mode | When | What it does |
|------|------|--------------|
| `scan` (default) | A skill/MCP ran, was installed, or changed; start of session | Change-aware audit of skills + MCP configs. Short-circuits if nothing changed. |
| `deploy` | Before any push / publish / deploy / going public | Exposure gate over the working tree: secrets, tokens, PII, EXIF, git author email. Never short-circuits. |
| `full` | "audit everything", periodic deep check | Re-scans every skill + MCP ignoring the change cache. |

Run a mode explicitly with `/security-audit deploy`, etc. With no argument, use
`scan`.

## Workflow — `scan` / `full` (auditing skills & MCPs)

1. **Run the engine** with `--json` (above). Read `summary`.
2. **Short-circuit check.** In `scan` mode, if `summary.new + summary.changed == 0`,
   report: `✓ No changes since last audit (<last_audit>). N items unchanged —
   nothing to review.` and stop. (Suggest `/security-audit full` if they want a
   forced deep pass.)
3. **Review changed items.** For each entry in `review_items`, look at its
   `findings`. The engine already classifies the obvious things (plaintext
   secrets in MCP env, unpinned `npx -y` packages, hidden-instruction phrasing,
   credential reads, obfuscation, shorteners/IP-literal hosts). Add your own
   judgement: read the actual `SKILL.md`/scripts of a flagged item if a finding
   is ambiguous, and decide whether it is a real risk or a false positive.
4. **Verify external links live (the TOCTOU step).** For each URL in
   `urls_to_verify`, use **WebFetch** to follow it and confirm the final
   destination is what it claims and is not hostile. The engine records each
   URL's resolved destination + a content fingerprint in the cache; if a URL it
   had seen before now resolves somewhere new, it emits a **Critical
   `URL_REDIRECT_CHANGED`** finding — treat that as a likely takeover and do not
   follow the link. (For a deeper scripted check you may re-run the engine with
   `--resolve-urls`, which follows redirects itself when the network allows.)
5. **Render the findings table** (template below).
6. **Let the engine update its cache.** A normal (non-`--no-update`) run records
   the new hashes so the next audit is cheap. Re-run without `--json` if you only
   need the cache write, or trust the run you already did (it updates unless you
   passed `--no-update`).

## Workflow — `deploy` (pre-publish exposure gate)

This is the hard gate before anything goes public — it mirrors the user's global
publish rules.

1. Run `python3 scripts/scan.py deploy --project "<repo>" --json`.
2. Review every finding. Exposure findings (real secrets, tokens, private keys,
   presigned URLs, personal emails, a personal git commit email, EXIF GPS) are
   what matter here.
3. **Verdict is a gate:** if the engine returns **BLOCK** (any Critical, or any
   High in deploy mode), tell the user clearly: *do not publish until these are
   fixed.* Offer to remediate (move secrets to env vars, switch git email to a
   `noreply`, strip EXIF, add `.gitignore` rules), then re-run until **PASS**.
4. Only after **PASS** should the push/publish proceed. If a real secret was
   found, remind the user to **rotate** it — removing it from the file is not
   enough once it has existed.

## Output: the findings table (use this exact shape)

```
## 🔒 Security Audit — <mode> · <N> scanned, <M> changed · Verdict: <✅ PASS | ⚠️ FLAGGED | ⛔ BLOCK>

| # | Severity | Finding | Location | Why it matters | How to fix |
|---|----------|---------|----------|----------------|------------|
| 1 | 🔴 Critical | <title> | `<path:line>` | <one sentence> | <one action> |

**Summary:** <X 🔴> · <Y 🟠> · <Z 🟡> … — Verdict: <…>
```

- Severity scale: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · ⚪ Info.
- Keep evidence **redacted** (the engine already masks it, e.g. `AQ.Ab8…HsY6`) so
  the report itself never leaks a secret. Put redacted evidence in a collapsible
  appendix, not the main table.
- End a `deploy` BLOCK with an explicit "do not publish yet" line.
- `scripts/render.py` produces exactly this table from the engine's JSON
  (`scan.py <mode> --json | python3 render.py -`). Use it when you want a
  guaranteed-consistent render; weave in your live WebFetch URL results around it.

## How severity is assigned

Briefly: Critical = active compromise or a live exposed credential (plaintext
secret in config, reverse shell, a redirect that now lands somewhere new). High =
strong exfiltration/hidden-instruction signal or a real exposed token before
publish. Medium = supply-chain weakness or risky-but-common patterns (unpinned
package, remote-installer-piped-to-shell). Low/Info = hygiene. The full rubric and
the complete rule catalog (ids, patterns, fixes) are in `references/`.

## Suppressing a false positive

If a flagged line is an intentional example, a detector definition, or a vetted
exception, add an inline marker on that line and it will be ignored on future
runs: `# security-audit: ignore` (also accepts `pragma: allowlist secret` /
`nosec`). Use this sparingly and only when you are sure.

## Reference files

Read these when you need detail beyond the summary:

- `references/severity-model.md` — how each severity is decided, and the verdict
  gate (PASS / FLAGGED / BLOCK).
- `references/detection-rules.md` — the full catalog: every rule id, what it
  matches, its severity, why it matters, and how to fix it.
- `references/url-verification.md` — the redirect / time-of-check-time-of-use
  methodology and how the URL fingerprint cache detects a repointed link.

## Notes

- Network is only needed for live URL verification (WebFetch, or `--resolve-urls`).
  Everything else is fully offline and deterministic.
- The cache and any resolved-URL fingerprints live under `~/.claude/.security-audit/`,
  outside any repo, and must never be published.
