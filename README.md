```
 ____                    _    ___
|  _ \ ___   ___  ___   / \  |_ _|
| |_) / _ \ / _ \/ _ \ / _ \  | |
|  _ < (_) |  __/  __// ___ \ | |
|_| \_\___/ \___|\___/_/   \_\___|

        s e c u r i t y - a u d i t   s k i l l
```

# security-audit

A Claude skill that **protects you from bad skills, bad MCP servers, and risky
deployments** — and reports everything in one severity-ranked table with a fix
for every finding.

Skills and MCP servers are third-party instructions and code that an AI agent
loads and *acts on*. A malicious or compromised one can hide instructions from
you, read your credentials, exfiltrate data, or point at a link whose
destination is quietly changed **after** you trusted it. And it's easy to leak a
secret, token, email, or geotagged image the moment you publish. `security-audit`
defends both fronts.

> Built by **RoeeAI**. MIT-licensed.

---

## What it does

**1. Audits skills & MCP servers** for what they could do to you:
- Plaintext secrets/keys in MCP config (`env`), unpinned `npx -y` / remote-install
  packages, and launch commands that pipe remote code through a shell.
- Hidden-instruction / prompt-injection text ("ignore previous instructions",
  "don't tell the user"), zero-width & bidi unicode, instructions buried in HTML
  comments.
- Code that reads SSH/cloud credentials, exfiltrates data, opens reverse shells,
  or hides payloads behind base64/hex/`eval`.

**2. Verifies external links — and re-checks them over time.** It follows each
link's redirect chain, fingerprints the final destination, and remembers it. If a
link you trusted last week now resolves **somewhere new**, that's flagged
**Critical** — the classic sign of a hijacked domain or repointed shortener
(a time-of-check/time-of-use attack). See
[url-verification.md](security-audit/references/url-verification.md).

**3. Gates your deployments.** Before you push/publish/go-live, it scans the
working tree for exposed secrets, API keys, tokens, private keys, presigned URLs,
personal emails, a personal git commit email, and image EXIF (GPS/camera/author).
If anything Critical/High is exposed, the verdict is **BLOCK** — don't publish
until it's clean.

**4. It's token-cheap.** A deterministic hash-diff runs first and **stops
immediately when nothing changed**. The expensive review only happens on the
skills/MCPs that are new or have actually changed since the last audit.

## The output

```
## 🔒 Security Audit — scan · 67 scanned, 1 changed · Verdict: ⛔ BLOCK

| # | Severity | Finding | Location | Why it matters | How to fix |
|---|----------|---------|----------|----------------|------------|
| 1 | 🔴 Critical | Plaintext secret in MCP env (GOOGLE_AI_API_KEY) | `settings.json` | Any local process/skill can read it; it travels with backups | Move to a secret store; rotate the key |
| 2 | 🟡 Medium | Unpinned MCP package via npx -y | `settings.json` | Latest version runs every launch with no pin/checksum | Pin an exact version or vendor it |

**Summary:** 1 🔴 Critical · 1 🟡 Medium — Verdict: ⛔ BLOCK
```

Severity scale: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low · ⚪ Info. Evidence in
the report is always **redacted** (e.g. `AQ.Ab8…HsY6`) so the audit never leaks a
secret itself.

## Install

This is a [Claude Code](https://claude.com/claude-code) skill.

```bash
git clone https://github.com/roeea2/security-audit-skill.git
ln -s "$PWD/security-audit-skill/security-audit" ~/.claude/skills/security-audit
```

Then just talk to Claude: *"audit my skills"*, *"is this MCP safe?"*, *"scan for
secrets before I push"* — or run a mode directly:

```
/security-audit          # change-aware audit of skills + MCPs (default)
/security-audit deploy   # pre-publish exposure gate over the current repo
/security-audit full     # force a complete re-scan, ignore the change cache
```

### Optional: automatic checking

Decide **how often** the check runs and **how strict** it is, then let the
installer wire it into `settings.json` (it merges, preserving your other settings):

```bash
# once per session: a near-instant change-nudge (no model tokens)
python3 security-audit/scripts/install_hooks.py --cadence session-start --enforcement warn

# before EVERY skill/MCP call: warn on issues, never block
python3 security-audit/scripts/install_hooks.py --cadence per-call --enforcement warn

# before EVERY skill/MCP call: DENY a call that carries a Critical finding
python3 security-audit/scripts/install_hooks.py --cadence per-call --enforcement block

# turn automatic checking off
python3 security-audit/scripts/install_hooks.py --uninstall
```

| Cadence | Mechanism | Cost | Catches |
|---------|-----------|------|---------|
| `session-start` | `SessionStart` hook | once/session, ~0 | changes & due links since last audit |
| `per-call` | `PreToolUse` hook on `Skill` + `mcp__.*` | ~100–300 ms/call | the specific skill/MCP **before** it runs |

The hook runs only the deterministic engine (no model, no network); the deep
review and live URL verification happen when you run `/security-audit`. The
per-call guard targets just the item being invoked and **fails open** on any
error, so it can never wedge your session.

## How it works

```
security-audit/
├── SKILL.md                     # how Claude drives the audit (modes, workflow, output)
├── scripts/
│   ├── scan.py                  # engine: enumerate → hash-diff → static checks → URL extract → JSON
│   ├── checks.py                # the detection rule catalog
│   ├── state.py                 # machine-local change/URL cache
│   └── render.py                # JSON → the markdown findings table
└── references/
    ├── detection-rules.md       # every rule: id, match, severity, fix
    ├── severity-model.md        # how severity & the PASS/FLAGGED/BLOCK verdict are decided
    └── url-verification.md       # the redirect / TOCTOU methodology
```

Run the engine standalone any time:

```bash
python3 security-audit/scripts/scan.py full --json | python3 security-audit/scripts/render.py -
```

The change-detection cache and resolved-URL fingerprints live in
`~/.claude/.security-audit/` — **machine-local, never published.**

## Design notes

- **Offline by default.** Everything except live link verification is
  deterministic and needs no network. Link verification uses Claude's WebFetch
  (or `--resolve-urls` for unattended runs).
- **Low-noise.** It de-duplicates across plugin versions, skips authors' own PII
  when auditing third-party skills, and supports inline `# security-audit: ignore`
  to allowlist a line.
- **Self-aware.** A security tool's catalog necessarily contains the signatures it
  hunts for, so it excludes its own directory from skill auditing (the code stays
  fully auditable here on GitHub).

## License

[MIT](LICENSE) © RoeeAI
