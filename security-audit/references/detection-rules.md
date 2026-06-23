# Detection rule catalog

Every rule the engine (`scripts/checks.py`) can emit, grouped by category. Each
has a stable `id` so findings are dedupable and traceable. Example tokens below
are deliberately truncated (`…`) so this document does not itself trip the
scanner.

Contents: [Secrets](#secrets) · [PII / exposure](#pii--exposure) ·
[Behavioral](#behavioral) · [Prompt-injection](#prompt-injection) ·
[Obfuscation](#obfuscation) · [URLs](#urls) · [MCP config](#mcp-config) ·
[Deploy-only](#deploy-only)

---

## Secrets

High-confidence, known-format credential detectors. These fire wherever they
appear (skill text, scripts, configs, repo files).

| id | sev | Matches (example, truncated) | Fix |
|----|-----|------------------------------|-----|
| `SECRET_GITHUB_TOKEN` | 🔴 | `ghp_…`, `gho_…`, `github_pat_…` | Revoke in GitHub → Developer settings; load from env. |
| `SECRET_AWS_ACCESS_KEY` | 🔴 | `AKIA…`, `ASIA…` (+16 chars) | Deactivate in IAM, rotate, use a credentials provider. |
| `SECRET_OPENAI_KEY` | 🔴 | `sk-…`, `sk-proj-…` | Rotate with the provider; read from env. |
| `SECRET_GOOGLE_API_KEY` | 🔴 | `AIza…`, `AQ.…` | Rotate in Google Cloud / AI Studio; inject at runtime. |
| `SECRET_SLACK_TOKEN` | 🟠 | `xoxb-…`, `xoxp-…` | Revoke in the Slack app config. |
| `SECRET_STRIPE_KEY` | 🔴 | `sk_live_…`, `rk_live_…` | Roll the key in the Stripe dashboard. |
| `SECRET_PRIVATE_KEY` | 🔴 | a PEM `-----BEGIN … PRIVATE KEY-----` header | Remove and rotate the credential. |
| `SECRET_BEARER` | 🟠 | `Authorization: Bearer …` | Send the header from an env value at request time. |
| `SECRET_GENERIC_ASSIGNMENT` | 🟡 | `api_key = "<20+ high-entropy chars>"` | Confirm if live; rotate and move to env. Lower confidence — placeholders/`process.env.X`/`<your-token>` are filtered out. |

## PII / exposure

Personal-information detectors. **Skill audits skip these** (a skill author's own
email is not your problem); they run in the **deploy** gate over your own repo.

| id | sev | Matches | Fix |
|----|-----|---------|-----|
| `PII_EMAIL` | 🟡 | A personal email (noreply / example.com excluded) | Use `<user>@users.noreply.github.com` or remove. |
| `PII_HOME_PATH` | 🔵 | Absolute `/Users/<name>/…` or `/home/<name>/…` | Use a relative path, `~`, or an env var. |
| `PII_PRESIGNED_URL` | 🟠 | Signed URL / token query param / AWS signature param | Remove; generate short-lived URLs at runtime. <!-- security-audit: ignore (rule example) --> |

## Behavioral

What the skill/script could *do* — the part that distinguishes a useful skill
from a dangerous one.

| id | sev | Matches | Why |
|----|-----|---------|-----|
| `BEHAV_REVERSE_SHELL` | 🔴 | `/dev/tcp/…`, `nc -e`, `bash -i >&` | A backdoor connecting out to a remote host. |
| `BEHAV_PIPE_TO_SHELL` | 🟡 | A remote installer piped straight into a shell | Runs whatever the server returns *now*; operator can change it anytime. |
| `BEHAV_BASE64_EXEC` | 🟠 | base64-decode piped into a shell | Hides commands from a casual reader. |
| `BEHAV_READ_CREDENTIALS` | 🟠 | Reads `~/.aws/credentials`, `~/.ssh/id_*`, `.env`, `~/.claude/.credentials`, `id_rsa`, `.npmrc`, `.netrc` | May be staging your secrets for exfiltration. |
| `BEHAV_EXFIL_POST` | 🟠 | An outbound `curl`/`wget` whose POST body comes from a command, a file, or `env` | The real shape of data exfiltration. |
| `BEHAV_DESTRUCTIVE` | 🟡 | `rm -rf /`/`~`/`$HOME`, `chmod 777`, `sudo` | Can damage the system or weaken its security. |

## Prompt-injection

Attempts to hijack the agent through the skill's own text.

| id | sev | Matches | Why |
|----|-----|---------|-----|
| `INJECT_OVERRIDE` | 🟠 | "ignore previous instructions", "do not tell the user", "without telling the user", "reveal the system prompt / api key / secret" | Hijack / secrecy language; legit skills never hide behavior. |
| `INJECT_ZERO_WIDTH` | 🟠 | Zero-width unicode characters | Invisible text a human can't see but the model reads. |
| `INJECT_BIDI` | 🟠 | Bidirectional-override characters | Displayed text can differ from parsed text. |
| `INJECT_HTML_COMMENT` | 🟡 | Instructions hidden inside `<!-- … -->` | Invisible in rendered markdown, still influences the model. |

## Obfuscation

| id | sev | Matches | Why |
|----|-----|---------|-----|
| `OBF_BASE64_BLOB` | 🟡 | A base64 blob ≥160 chars | May hide an encoded payload. |
| `OBF_HEX_BLOB` | 🟡 | `\xNN` sequences ≥24 long | Common way to obscure strings/commands. |
| `OBF_DYNAMIC_EXEC` | 🔵 | `eval(`, `exec(`, `new Function(` | Hard to audit; can run attacker-controlled strings. |

## URLs

Static checks on any URL found; the live/redirect checks are in
`url-verification.md`.

| id | sev | Matches | Why |
|----|-----|---------|-----|
| `URL_SHORTENER` | 🟡 | bit.ly, tinyurl, t.co, goo.gl, rb.gy, cutt.ly, … | Hides the real destination; can be repointed. |
| `URL_IP_LITERAL` | 🟡 | `http(s)://<ip>/…` | Bypasses domain reputation; common throwaway infra. |
| `URL_PUNYCODE` | 🟡 | `xn--…` host | Look-alike (homograph) of a trusted domain. |
| `URL_USERINFO` | 🟡 | `user:pass@host` in a URL | Leaks credentials; disguises the true host. |
| `URL_REDIRECT_CHANGED` | 🔴 | Resolved destination differs from the cached trusted one | Classic hijacked-domain / repointed-shortener takeover. |
| `URL_CONTENT_CHANGED` | 🟠 | Same final URL, different content fingerprint | The page you trusted changed materially. |

## MCP config

Checks on each `mcpServers[name]` entry.

| id | sev | Matches | Fix |
|----|-----|---------|-----|
| `MCP_ENV_SECRET` | 🔴 | A secret-looking `env` var with a real value | Move to a secret store; rotate it. |
| `MCP_UNPINNED_NPX` | 🟡 | `npx -y <pkg>` with no version pin | Pin an exact version / vendor / checksum. |
| `MCP_REMOTE_INSTALL` | 🟡 | `uvx` / `pip install` at launch | Pin versions; prefer a vetted local package. |
| `MCP_SHELL_PIPE` | 🟠 | Launch command pipes remote code through a shell | Use a pinned, inspected executable. |
| `MCP_REMOTE_URL` | ⚪ | A remote MCP endpoint | Confirm you trust it and it is HTTPS. |

## Deploy-only

| id | sev | Matches | Fix |
|----|-----|---------|-----|
| `META_ENV_FILE` | 🟠 | A `.env` / credentials-style file in the tree | Remove; `.gitignore` it; ship `.env.example` with no real values. |
| `META_GIT_EMAIL` | 🟡 | `git config user.email` is a personal address | `git config user.email '<user>@users.noreply.github.com'`. |
| `META_GITIGNORE` | 🔵 | No `.gitignore`, or it doesn't block `.env` | Add ignore rules for `.env*`, keys, media. |
| `META_EXIF` | 🟠/🟡 | Image EXIF: GPS (High) / camera, author, timestamp (Medium) | Strip metadata before publishing (`exiftool -all=`). |

---

### Suppressing a rule on a line

Add `# security-audit: ignore` (or `pragma: allowlist secret`, `nosec`) to a line
to drop any finding on it — used for rule definitions, doc examples, and vetted
exceptions.
