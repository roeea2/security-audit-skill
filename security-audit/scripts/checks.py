"""
checks.py — the detection rule catalog for security-audit.

Every detector is a pure function over text (or a parsed config object) that
yields *finding* dicts. A finding is intentionally small and stable so the
cache, the renderer, and the model layer can all rely on the same shape:

    {
      "id":       "SECRET_GITHUB_TOKEN",   # stable rule id (dedupe key)
      "severity": "critical",              # critical|high|medium|low|info
      "category": "secret",                # secret|supply-chain|behavioral
                                           #   |prompt-injection|obfuscation
                                           #   |url|pii|metadata|config
      "title":    "GitHub token",
      "line":     18,                      # 1-based line, or None
      "evidence": "ghp_****…**a1",         # ALWAYS redacted
      "why":      "Why it matters …",
      "fix":      "How to fix …",
    }

Design rules:
- Detectors never raise on weird input; they degrade to "no finding".
- Evidence is redacted at the source so the report itself never leaks a secret.
- Regexes are kept simple/linear to avoid catastrophic backtracking.
"""

import math
import re

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- #
# Redaction helpers
# --------------------------------------------------------------------------- #

def redact(value, keep_start=4, keep_end=2):
    """Mask the middle of a sensitive value: 'AQ.Ab8RN6…HsY6' style."""
    if value is None:
        return ""
    s = str(value).strip().strip("'\"")
    if len(s) <= keep_start + keep_end:
        return "*" * len(s)
    return f"{s[:keep_start]}…{s[-keep_end:]}"


def _line_of(text, idx):
    """1-based line number of character offset `idx`."""
    return text.count("\n", 0, idx) + 1


# Inline suppression — same idea as `# nosec` / gitleaks allowlists. A finding is
# dropped if its own source line carries one of these markers. This is how rule
# definitions, examples in docs, and intentional test fixtures avoid self-tripping
# the scanner (so the audit's own repo can pass its own deploy gate).
_IGNORE_MARKERS = ("security-audit: ignore", "security-audit:ignore",
                   "pragma: allowlist secret", "nosec")


def filter_ignored(findings, text):
    if not findings:
        return findings
    lines = text.split("\n")
    kept = []
    for f in findings:
        ln = f.get("line")
        if ln and 1 <= ln <= len(lines):
            src = lines[ln - 1].lower()
            if any(m in src for m in _IGNORE_MARKERS):
                continue
        kept.append(f)
    return kept


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------- #
# 1. Secrets / tokens / credentials
# --------------------------------------------------------------------------- #
# (id, severity, title, compiled-regex, why, fix)
SECRET_RULES = [
    (
        "SECRET_GITHUB_TOKEN", "critical", "GitHub token",
        re.compile(r"\b(gh[opsu]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b"),
        "A GitHub token grants API/repo access under your identity; if published it can be used to push, read private repos, or exfiltrate data.",
        "Revoke the token immediately (GitHub → Settings → Developer settings), remove it from the file, and load it from an environment variable or secret manager instead.",
    ),
    (
        "SECRET_AWS_ACCESS_KEY", "critical", "AWS access key id",
        re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
        "An AWS access key id (paired with a secret) lets an attacker call AWS APIs and run up cost or exfiltrate data.",
        "Deactivate/delete the key in IAM, rotate it, and use a credentials provider (env, SSO, instance role) rather than hardcoding.",
    ),
    (
        "SECRET_OPENAI_KEY", "critical", "OpenAI / sk- API key",
        re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b"),
        "An `sk-` key bills to your account and can be abused at scale if leaked.",
        "Rotate the key with the provider, remove it from source, and read it from an environment variable.",
    ),
    (
        "SECRET_GOOGLE_API_KEY", "critical", "Google API key",
        re.compile(r"\b(AIza[A-Za-z0-9_\-]{35}|AQ\.[A-Za-z0-9_\-]{30,})\b"),
        "A Google AI / API key grants billable access to the associated project; in plaintext config it can be copied by anything that reads the file.",
        "Rotate the key in Google Cloud / AI Studio, then inject it at runtime from a secret store instead of committing it.",
    ),
    (
        "SECRET_SLACK_TOKEN", "high", "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "A Slack token can read/post messages and access workspace data.",
        "Revoke the token in the Slack app config and store it as a secret.",
    ),
    (
        "SECRET_STRIPE_KEY", "critical", "Stripe live key",
        re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b"),
        "A live Stripe key can move real money and read customer/payment data.",
        "Roll the key in the Stripe dashboard immediately and never commit live keys.",
    ),
    (
        "SECRET_PRIVATE_KEY", "critical", "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "An embedded private key allows impersonation, decryption, or SSH/login as you.",
        "Remove the key, rotate the corresponding credential, and keep private keys out of any tracked file.",
    ),
    (
        "SECRET_BEARER", "high", "Bearer token / Authorization header",
        re.compile(r"(?i)\b(?:authorization\s*:\s*bearer|bearer)\s+[A-Za-z0-9._\-]{20,}"),
        "A bearer token in source is a ready-to-use credential for whatever API it targets.",
        "Remove it, rotate it, and send the header from an env-sourced value at request time.",
    ),
]


def scan_secrets(text):
    findings = []
    for rid, sev, title, rx, why, fix in SECRET_RULES:
        for m in rx.finditer(text):
            findings.append({
                "id": rid, "severity": sev, "category": "secret", "title": title,
                "line": _line_of(text, m.start()),
                "evidence": redact(m.group(0)),
                "why": why, "fix": fix,
            })
    # Generic "name = high-entropy value" assignments (lower confidence, medium).
    for m in _GENERIC_ASSIGN.finditer(text):
        name, val = m.group(1), m.group(2)
        if _is_placeholder(val) or shannon_entropy(val) < 3.6:
            continue
        findings.append({
            "id": "SECRET_GENERIC_ASSIGNMENT", "severity": "medium", "category": "secret",
            "title": f"Possible hardcoded secret ({name})",
            "line": _line_of(text, m.start()),
            "evidence": f"{name}={redact(val)}",
            "why": "A high-entropy value assigned to a secret-looking name may be a real credential rather than a placeholder.",
            "fix": "Confirm whether it is a live secret; if so rotate it and move it to an environment variable / secret manager.",
        })
    return findings


_GENERIC_ASSIGN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)[A-Z0-9_]*)"
    r"\s*[:=]\s*['\"]?([^\s'\"]{20,})"
)
# Markers that mean a value is documentation/placeholder/env-reference, not a real secret.
_PLACEHOLDER_MARKERS = (
    "your", "example", "placeholder", "redacted", "changeme", "change_me", "dummy",
    "sample", "fake", "todo", "replace", "insert", "my-", "my_", "<", ">", "{{", "}}",
    "${", "process.env", "os.environ", "import.meta", "getenv", "config.", "settings.",
    "xxxx", "...", "***", "abc123", "1234567", "n/a",
)


def _is_placeholder(val):
    v = val.strip("'\"")
    if not v:
        return True
    low = v.lower()
    if any(tok in low for tok in _PLACEHOLDER_MARKERS):
        return True
    # Bare ENV_VAR_NAME reference (all caps + underscores) is not a literal secret.
    if re.fullmatch(r"[A-Z][A-Z0-9_]+", v):
        return True
    # Looks like a dotted/pathy identifier (e.g. a code expression), not a key.
    if re.fullmatch(r"[A-Za-z_][\w.]*\([^)]*\)?", v):
        return True
    return False


# --------------------------------------------------------------------------- #
# 2. PII / personal exposure
# --------------------------------------------------------------------------- #

EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
HOME_PATH_RX = re.compile(r"/(?:Users|home)/[A-Za-z0-9._\-]+/")
PRESIGNED_RX = re.compile(r"(?i)(X-Amz-Signature|AWSAccessKeyId|[?&](?:sig|signature|token)=)[^\s\"']*")  # security-audit: ignore (rule definition)


def scan_pii(text):
    findings = []
    for m in EMAIL_RX.finditer(text):
        email = m.group(0)
        low = email.lower()
        if "noreply" in low or low.endswith("users.noreply.github.com") or "example.com" in low:
            continue  # noreply / placeholder addresses are intended-safe
        findings.append({
            "id": "PII_EMAIL", "severity": "medium", "category": "pii",
            "title": "Personal email address",
            "line": _line_of(text, m.start()),
            "evidence": redact(email, keep_start=3, keep_end=4),
            "why": "Publishing a personal email exposes you to spam/phishing and ties the repo to a real identity.",
            "fix": "Replace with a noreply address (e.g. <username>@users.noreply.github.com) or remove it.",
        })
    for m in HOME_PATH_RX.finditer(text):
        findings.append({
            "id": "PII_HOME_PATH", "severity": "low", "category": "pii",
            "title": "Absolute home-directory path",
            "line": _line_of(text, m.start()),
            "evidence": m.group(0),
            "why": "Absolute /Users/<name>/ paths leak your OS username and local layout, and break for anyone else.",
            "fix": "Use a relative path, ~, or an environment variable instead of the absolute path.",
        })
    for m in PRESIGNED_RX.finditer(text):
        findings.append({
            "id": "PII_PRESIGNED_URL", "severity": "high", "category": "pii",
            "title": "Presigned / signed URL or embedded credential param",
            "line": _line_of(text, m.start()),
            "evidence": redact(m.group(0), keep_start=6, keep_end=2),
            "why": "Signed URLs and token query params grant temporary access to private storage and are often still live.",
            "fix": "Remove the signed URL; generate fresh, short-lived URLs at runtime instead of committing them.",
        })
    return findings


# --------------------------------------------------------------------------- #
# 3. Behavioral risk (dangerous actions in skill text / scripts)
# --------------------------------------------------------------------------- #

BEHAVIORAL_RULES = [
    (
        "BEHAV_PIPE_TO_SHELL", "medium", "Remote code piped to a shell",
        re.compile(r"(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?)\b"),
        "`curl … | bash` runs whatever the server returns right now — the operator can change it at any time to run arbitrary code on your machine. Common in install steps, but it is an unverified-code-execution risk.",
        "Download to a file, inspect it, pin a checksum, then run it — never pipe a live URL straight into a shell.",
    ),
    (
        "BEHAV_BASE64_EXEC", "high", "Base64-decoded content executed",
        re.compile(r"(?i)base64\s+(?:-d|--decode|-D)[^\n|]*\|\s*(?:bash|sh|python3?)"),
        "Decoding base64 and piping it to a shell is a classic way to hide malicious commands from a casual reader.",
        "Decode to a file and inspect the result before running anything; treat hidden/encoded commands as untrusted.",
    ),
    (
        "BEHAV_READ_CREDENTIALS", "high", "Reads credential / key files",
        re.compile(r"(?i)(~|\$HOME|/Users/[^/\s]+|/home/[^/\s]+)?/?\.(?:aws/credentials|ssh/id_[a-z0-9]+|claude/\.credentials|netrc|npmrc|docker/config\.json)\b|\bid_rsa\b"),
        "A skill/script that reads your SSH keys, cloud credentials, or token files may be staging them for exfiltration.",
        "Confirm the skill genuinely needs those files; if not, this is a strong red flag — do not run it.",
    ),
    (
        "BEHAV_EXFIL_POST", "high", "Posts captured data to an external host",
        # Tight: an outbound curl/wget whose POST body is sourced from a command
        # substitution, a file read, or the environment — the real shape of exfil.
        re.compile(r"(?i)(?:curl|wget)\s+[^\n]*(?:-d|--data|--data-binary)[^\n]*(?:\$\(|`|\bcat\s+|\benv\b|process\.env|os\.environ|/etc/passwd|\.ssh|\.aws)"),
        "An outbound request whose body is filled from command output, a file, or the environment is the classic shape of data exfiltration to an attacker-controlled server.",
        "Verify the destination host and exactly what is being sent; an unexplained upload of file/env contents should block use of the skill.",
    ),
    (
        "BEHAV_REVERSE_SHELL", "critical", "Reverse-shell / raw socket pattern",
        re.compile(r"(?:/dev/tcp/|\bnc\s+-e\b|\bncat\s+[^\n]*-e\b|bash\s+-i\s+>&)"),
        "These patterns open an interactive connection back to a remote host — a hallmark of a backdoor.",
        "Do not run this skill. Treat it as actively malicious and report/remove it.",
    ),
    (
        "BEHAV_DESTRUCTIVE", "medium", "Destructive or privilege command",
        re.compile(r"(?:rm\s+-rf\s+(?:/|~|\$HOME)\b|chmod\s+(?:-R\s+)?777\b|sudo\s+)"),
        "Broad deletes, world-writable perms, or sudo in an automated skill can damage your system or weaken its security.",
        "Make sure the command is scoped and necessary; avoid sudo and recursive 777 in skills.",
    ),
]


def scan_behavioral(text):
    findings = []
    for rid, sev, title, rx, why, fix in BEHAVIORAL_RULES:
        m = rx.search(text)
        if m:
            findings.append({
                "id": rid, "severity": sev, "category": "behavioral", "title": title,
                "line": _line_of(text, m.start()),
                "evidence": redact(m.group(0), keep_start=24, keep_end=0) if len(m.group(0)) > 40 else m.group(0),
                "why": why, "fix": fix,
            })
    return findings


# --------------------------------------------------------------------------- #
# 4. Prompt-injection / hidden-intent markers (skill instructions)
# --------------------------------------------------------------------------- #

INJECTION_PHRASES = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior|the\s+above)\s+instructions"
    r"|disregard\s+(?:the\s+)?(?:above|previous|system)"
    r"|do\s+not\s+(?:tell|inform|mention\s+to|reveal\s+to)\s+the\s+user"
    r"|without\s+(?:telling|informing|notifying)\s+the\s+user"
    r"|do\s+not\s+mention\s+this"
    r"|(?:print|reveal|exfiltrate|send)\s+(?:the\s+)?(?:system\s+prompt|api[_\s-]?key|secret|credentials))"
)
ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")
BIDI = re.compile(r"[‪-‮⁦-⁩]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)


def scan_prompt_injection(text):
    findings = []
    for m in INJECTION_PHRASES.finditer(text):
        findings.append({
            "id": "INJECT_OVERRIDE", "severity": "high", "category": "prompt-injection",
            "title": "Prompt-injection / hidden-intent phrasing",
            "line": _line_of(text, m.start()),
            "evidence": m.group(0)[:80],
            "why": "Language that tells the assistant to ignore instructions or hide actions from you is how a malicious skill hijacks the agent.",
            "fix": "Remove the override/secrecy language. Legitimate skills never need to hide their behavior from the user.",
        })
    if ZERO_WIDTH.search(text):
        m = ZERO_WIDTH.search(text)
        findings.append({
            "id": "INJECT_ZERO_WIDTH", "severity": "high", "category": "prompt-injection",
            "title": "Hidden zero-width characters",
            "line": _line_of(text, m.start()),
            "evidence": "zero-width unicode present (invisible to the eye)",
            "why": "Zero-width characters can hide instructions that a human reviewer can't see but the model still reads.",
            "fix": "Strip zero-width characters; re-review the file for concealed instructions.",
        })
    if BIDI.search(text):
        m = BIDI.search(text)
        findings.append({
            "id": "INJECT_BIDI", "severity": "high", "category": "prompt-injection",
            "title": "Bidirectional-override characters",
            "line": _line_of(text, m.start()),
            "evidence": "Unicode bidi override present",
            "why": "Bidi overrides can make displayed text differ from what the model actually parses (a known supply-chain trick).",
            "fix": "Remove bidi control characters and verify the literal text matches what is shown.",
        })
    for m in HTML_COMMENT.finditer(text):
        body = m.group(1)
        if INJECTION_PHRASES.search(body) or re.search(r"(?i)(instruction|api[_\s-]?key|secret|do\s+not)", body):
            findings.append({
                "id": "INJECT_HTML_COMMENT", "severity": "medium", "category": "prompt-injection",
                "title": "Suspicious instruction inside HTML comment",
                "line": _line_of(text, m.start()),
                "evidence": body.strip()[:80],
                "why": "Instructions tucked into HTML comments are invisible in rendered markdown but still influence the model.",
                "fix": "Move any real guidance into visible text; delete hidden instruction comments.",
            })
    return findings


# --------------------------------------------------------------------------- #
# 5. Obfuscation
# --------------------------------------------------------------------------- #

B64_BLOB = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")
HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){24,}")
DYNAMIC_EXEC = re.compile(r"(?<![A-Za-z_])(?:eval|exec)\s*\(|new\s+Function\s*\(")


def scan_obfuscation(text):
    findings = []
    m = B64_BLOB.search(text)
    if m:
        findings.append({
            "id": "OBF_BASE64_BLOB", "severity": "medium", "category": "obfuscation",
            "title": "Large base64 blob",
            "line": _line_of(text, m.start()),
            "evidence": redact(m.group(0), keep_start=12, keep_end=4),
            "why": "A large opaque base64 blob can hide an encoded payload or data that won't be reviewed.",
            "fix": "Decode and inspect the blob; if it isn't a legitimate asset, remove it.",
        })
    m = HEX_BLOB.search(text)
    if m:
        findings.append({
            "id": "OBF_HEX_BLOB", "severity": "medium", "category": "obfuscation",
            "title": "Hex-escaped byte sequence",
            "line": _line_of(text, m.start()),
            "evidence": redact(m.group(0), keep_start=12, keep_end=4),
            "why": "Long \\xNN sequences are a common way to obscure strings/commands from review.",
            "fix": "Decode the sequence and confirm it is benign, or remove it.",
        })
    m = DYNAMIC_EXEC.search(text)
    if m:
        findings.append({
            "id": "OBF_DYNAMIC_EXEC", "severity": "low", "category": "obfuscation",
            "title": "Dynamic code execution (eval/exec/Function)",
            "line": _line_of(text, m.start()),
            "evidence": m.group(0),
            "why": "Dynamic execution makes behavior hard to audit and can run attacker-controlled strings.",
            "fix": "Replace eval/exec with explicit code paths where feasible; if required, ensure inputs are fully trusted.",
        })
    return findings


# --------------------------------------------------------------------------- #
# 6. URL extraction + static URL checks
# --------------------------------------------------------------------------- #

URL_RX = re.compile(r"https?://[^\s\)\]\}\"'>`]+")
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "lnkd.in", "tiny.cc",
}
IP_HOST_RX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def extract_urls(text):
    """Return de-duplicated list of (url, line) tuples."""
    seen = {}
    for m in URL_RX.finditer(text):
        url = m.group(0).rstrip(".,;")
        if url not in seen:
            seen[url] = _line_of(text, m.start())
    return [(u, ln) for u, ln in seen.items()]


def _host(url):
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def scan_url_static(url, line=None):
    """Cheap, offline checks on a single URL string (no network)."""
    findings = []
    host = _host(url)
    # Note: plain http:// is intentionally NOT flagged here — in third-party docs
    # it is almost always localhost/example/license URLs (pure noise). Destination
    # safety is covered by the live WebFetch verification + the TOCTOU diff.
    if host in SHORTENERS:
        findings.append({
            "id": "URL_SHORTENER", "severity": "medium", "category": "url",
            "title": f"URL shortener ({host})", "line": line, "evidence": url,
            "why": "A shortener hides the real destination, which the owner can repoint at any time to a malicious page.",
            "fix": "Replace with the expanded final URL after verifying where it actually lands.",
        })
    if IP_HOST_RX.match(host):
        findings.append({
            "id": "URL_IP_LITERAL", "severity": "medium", "category": "url",
            "title": "IP-literal host", "line": line, "evidence": url,
            "why": "A raw IP bypasses domain reputation and is common in throwaway malicious infrastructure.",
            "fix": "Confirm the IP is an expected, trusted endpoint; prefer a named, verifiable host.",
        })
    if host.startswith("xn--") or "xn--" in host:
        findings.append({
            "id": "URL_PUNYCODE", "severity": "medium", "category": "url",
            "title": "Punycode / possible homograph host", "line": line, "evidence": url,
            "why": "Punycode hosts can visually mimic a trusted domain (homograph attack).",
            "fix": "Decode the host and confirm it is the domain you expect, not a look-alike.",
        })
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        findings.append({
            "id": "URL_USERINFO", "severity": "medium", "category": "url",
            "title": "Credentials/userinfo embedded in URL", "line": line, "evidence": redact(url, 10, 4),
            "why": "A user:pass@host URL leaks credentials and can disguise the true host before the @.",
            "fix": "Remove the userinfo portion; pass credentials out-of-band.",
        })
    return findings


# --------------------------------------------------------------------------- #
# 7. MCP config checks (parsed JSON object)
# --------------------------------------------------------------------------- #

SECRET_ENV_NAME = re.compile(r"(?i)(key|token|secret|password|passwd|pwd|credential|auth)")


def scan_mcp_server(name, cfg, location):
    """`cfg` is one mcpServers[name] object. `location` is where it lives."""
    findings = []
    if not isinstance(cfg, dict):
        return findings

    # 7a. Secrets stored plaintext in env
    env = cfg.get("env") or {}
    if isinstance(env, dict):
        for k, v in env.items():
            if SECRET_ENV_NAME.search(str(k)) and isinstance(v, str) and len(v) >= 12 \
                    and not v.startswith("${"):
                findings.append({
                    "id": "MCP_ENV_SECRET", "severity": "critical", "category": "secret",
                    "title": f"Plaintext secret in MCP env ({name}.{k})",
                    "line": None, "evidence": f"{k}={redact(v)}",
                    "why": "Secrets stored directly in MCP config are readable by any process or skill that can read the config file, and travel with backups.",
                    "fix": "Move the value to an OS secret store / env var and reference it; rotate the secret since it has been sitting in plaintext.",
                    "location": location,
                })

    # 7b. Unpinned / remote package execution
    command = str(cfg.get("command") or "")
    args = cfg.get("args") or []
    argline = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)
    full = f"{command} {argline}".strip()
    if re.search(r"\bnpx\b", command) or re.search(r"\bnpx\b", argline):
        if re.search(r"-y\b|--yes\b", argline) and not re.search(r"@\d+\.\d+|@\^|@~|@\d", argline):
            pkg = next((a for a in (args if isinstance(args, list) else []) if str(a).startswith("@") or (str(a) and not str(a).startswith("-"))), "package")
            findings.append({
                "id": "MCP_UNPINNED_NPX", "severity": "medium", "category": "supply-chain",
                "title": f"Unpinned MCP package via npx -y ({name})",
                "line": None, "evidence": f"npx -y {pkg}",
                "why": "`npx -y` fetches and runs the latest published version every launch with no version pin or checksum — a compromised release would execute automatically.",
                "fix": "Pin an exact version (e.g. pkg@1.2.3), vendor the package, or verify a checksum before each upgrade.",
                "location": location,
            })
    if re.search(r"\buvx\b|pip\s+install", full):
        findings.append({
            "id": "MCP_REMOTE_INSTALL", "severity": "medium", "category": "supply-chain",
            "title": f"Remote install at launch ({name})",
            "line": None, "evidence": full[:80],
            "why": "Installing from a remote index at launch means the executed code can change between runs without review.",
            "fix": "Pin versions and prefer a vetted, locally installed package.",
            "location": location,
        })
    # 7c. Shell-through-command
    if re.search(r"(?i)(curl|wget)[^\n]*\|\s*(bash|sh)|/dev/tcp/", full):
        findings.append({
            "id": "MCP_SHELL_PIPE", "severity": "high", "category": "behavioral",
            "title": f"MCP command pipes remote code to a shell ({name})",
            "line": None, "evidence": full[:80],
            "why": "The MCP launches by running live remote code through a shell, which the operator can change at any time.",
            "fix": "Replace with a pinned, inspected executable; never bootstrap an MCP via curl|bash.",
            "location": location,
        })

    # 7d. Remote URL transport (worth verifying the endpoint)
    url = cfg.get("url") or cfg.get("serverUrl")
    if isinstance(url, str) and url.startswith(("http://", "https://")):
        for f in scan_url_static(url):
            f["location"] = location
            findings.append(f)
        findings.append({
            "id": "MCP_REMOTE_URL", "severity": "info", "category": "supply-chain",
            "title": f"Remote MCP endpoint ({name})",
            "line": None, "evidence": url,
            "why": "A remote MCP server can change its behavior server-side; the endpoint should be verified and trusted.",
            "fix": "Confirm you control/trust this endpoint and that it is reached over HTTPS.",
            "location": location,
        })
    return findings


# --------------------------------------------------------------------------- #
# Convenience: run the text-based detectors appropriate to a file kind
# --------------------------------------------------------------------------- #

def scan_text(text, kinds=("secret", "pii", "behavioral", "prompt-injection", "obfuscation", "url")):
    """Run the selected text detectors and return all findings (no location set)."""
    out = []
    if "secret" in kinds:
        out += scan_secrets(text)
    if "pii" in kinds:
        out += scan_pii(text)
    if "behavioral" in kinds:
        out += scan_behavioral(text)
    if "prompt-injection" in kinds:
        out += scan_prompt_injection(text)
    if "obfuscation" in kinds:
        out += scan_obfuscation(text)
    if "url" in kinds:
        for url, line in extract_urls(text):
            out += scan_url_static(url, line)
    return filter_ignored(out, text)
