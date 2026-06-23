# URL & redirect verification (the TOCTOU defense)

A link that is safe today can betray you tomorrow. The domain behind a URL
shortener can be repointed; an expired domain can be re-registered by an
attacker; a CDN path can start serving a different file. This is a **time-of-check
/ time-of-use (TOCTOU)** problem: you verified the destination once, trusted it,
and the destination changed underneath you. This skill defends against it by
remembering where each link *used to* resolve and flagging when that changes.

## What gets checked

For every external URL found in a skill, MCP config, or (in deploy mode) repo
file, the engine first runs **offline static checks** (`URL_SHORTENER`,
`URL_IP_LITERAL`, `URL_PUNYCODE`, `URL_USERINFO` — see `detection-rules.md`).
Those need no network.

The **live** checks resolve the URL and compare it to what was trusted before:

1. **Follow the redirect chain.** From the starting URL, follow each `3xx`
   `Location` hop (up to 8) and record the full chain and the **final URL**.
2. **Fingerprint the destination.** Hash the final page's body with whitespace
   collapsed (`normalized_body_sha`) so cosmetic edits don't look like an attack
   but real content changes do.
3. **Compare against the cache** (`state.json → urls[url]`):
   - **new** — first time seen. Record it; nothing to flag yet.
   - **unchanged** — final URL and fingerprint match the trusted record. ✅
   - **`URL_REDIRECT_CHANGED`** (🔴 Critical) — the final URL differs from last
     time. This is the takeover signal: a previously-trusted link now lands
     somewhere new. Do **not** follow it until the new destination is verified.
   - **`URL_CONTENT_CHANGED`** (🟠 High) — same final URL, but the page content
     changed materially since you trusted it. Re-review before relying on it.
4. **Update the trusted record** after a clean verification, so the next audit
   has a fresh baseline.

## Two ways to run the live check

**Preferred — model-driven with WebFetch.** The engine lists every URL needing
verification in `urls_to_verify`. For each, use **WebFetch** to follow the link
and judge the destination with real understanding (Is this the domain it claims?
Is it a login/credential-harvest page? Does the content match the skill's stated
purpose?). WebFetch returns cross-host redirects to you rather than following them
blindly, which is itself a useful signal — re-fetch the redirect target and look.
This is the smart layer: a fingerprint diff tells you *that* something changed; a
model reading the page tells you *whether it's dangerous*.

**Scripted — `--resolve-urls`.** Running `scripts/scan.py <mode> --resolve-urls`
makes the engine follow redirects itself (via `urllib`) and do the cache
comparison automatically, emitting `URL_REDIRECT_CHANGED` / `URL_CONTENT_CHANGED`
findings without a model in the loop. It degrades gracefully when the network is
blocked (the URL is simply reported as needing manual verification). Use this for
unattended / CI-style runs.

## Why the cache matters here

The same `state.json` that makes audits token-cheap is what makes this defense
possible. Without a remembered baseline, "the redirect changed" is unanswerable —
changed *from what?* The cache stores, per URL: the resolved `final_url`, the
`content_sha`, the redirect `chain`, and `last_checked`. It lives under
`~/.claude/.security-audit/` (machine-local, never published), so each machine
builds its own trust baseline over time.

## Practical guidance

- Treat a `URL_REDIRECT_CHANGED` on a link the agent was about to act on as
  **stop-and-confirm**, not a warning to scroll past.
- Shorteners and IP-literal hosts are flagged statically *and* should always be
  resolved live — their whole risk is that the visible URL tells you nothing.
- If a skill's external link points somewhere unrelated to its stated purpose
  (e.g. a "documentation" link that resolves to a credential form), that mismatch
  is a strong malicious signal even if the fingerprint hasn't changed yet.
