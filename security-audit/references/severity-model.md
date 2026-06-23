# Severity model & verdict gate

Every finding carries one severity. Severity drives the **verdict**, which is the
single most important output — it tells the user whether it is safe to proceed.

## Severity levels

| Level | Emoji | Meaning | Examples |
|-------|-------|---------|----------|
| Critical | 🔴 | Active compromise, or a **live** credential exposed right now. Acting on it can directly harm you. | Plaintext API key/secret in MCP `env`; reverse-shell / raw-socket pattern; a trusted link's redirect now lands on a **different** destination (likely takeover); an AWS/GitHub/Stripe key in a file about to be published. |
| High | 🟠 | Strong signal of exfiltration, hidden intent, or a real exposure that should block a publish. | Prompt-injection / "don't tell the user" phrasing; reads SSH/cloud credential files; uploads file/env contents to a remote host; presigned URL or bearer token in tracked source. |
| Medium | 🟡 | Supply-chain weakness or a risky-but-common pattern that deserves a look. | Unpinned `npx -y` / remote-install MCP package; remote installer piped into a shell; hidden instruction inside an HTML comment; URL shortener / IP-literal / punycode host; a personal email being published. |
| Low | 🔵 | Hygiene; unlikely to be exploited on its own. | Dynamic `eval`/`exec`; absolute `/Users/<name>/…` paths in your repo; missing `.gitignore` rules. |
| Info | ⚪ | Context worth noting, not a problem. | A remote MCP endpoint exists (verify you trust it). |

## How the engine decides

The engine assigns severity from the rule that fired (see `detection-rules.md`).
A few rules adjust dynamically:

- **Secrets in MCP `env`** are Critical because the value is sitting in plaintext
  in a config that any local process or skill can read.
- **Generic "secret-looking name = high-entropy value"** is only Medium — it is a
  lower-confidence heuristic, and placeholders / `process.env.X` references /
  `<your-token>` style values are filtered out before it fires.
- **URL findings** escalate over time: a brand-new external URL is just something
  to verify, but a URL whose **resolved destination changed** since the last audit
  is Critical, and one whose **page content changed** is High.

## Verdict gate

The verdict is computed from the severity counts and the mode:

```
BLOCK    if any Critical
BLOCK    if mode == deploy and any High
FLAGGED  if any High / Medium / Low (and not already BLOCK)
PASS     if nothing above Info
```

- **`deploy` mode is strict on purpose.** Before publishing, a single High
  exposure (a real token, a presigned URL) is enough to BLOCK — it is far cheaper
  to fix before the push than to rotate-and-scrub after.
- **`scan` / `full` modes** BLOCK only on Critical, because a skill audit surfaces
  many Medium/Low items that are informational caution rather than stop-the-world.

When the verdict is **BLOCK**, say so explicitly and do not let the action
(running the skill, or publishing) proceed until the Critical/High items are
resolved. When a real secret was exposed, removing it is not enough — it must be
**rotated**, because it may already have been read or backed up.
