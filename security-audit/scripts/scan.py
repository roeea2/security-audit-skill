#!/usr/bin/env python3
"""
scan.py — the deterministic front door of the security-audit skill.

It is always run *first*. It enumerates the things worth auditing, hashes them,
diffs against the machine-local cache, runs cheap static checks, and emits a
single JSON document. The expensive model-level review then happens only on the
new/changed items the JSON points at — that is the whole token-saving idea.

Modes:
  scan     (default)  change-aware audit of skills + MCP configs
  full                 audit everything, ignore the change cache
  deploy               pre-publish exposure gate over a directory (no cache)

Useful flags:
  --project PATH       project root to include (default: cwd)
  --json               print the full JSON document (default human summary)
  --changed-only       print only a one-line nudge if something changed (hooks)
  --quiet              suppress the nudge when nothing changed (hooks)
  --resolve-urls       best-effort follow redirects offline-permitting (TOCTOU)
  --no-update          do not write the cache (dry run)
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import checks  # noqa: E402
import state as st  # noqa: E402

HOME = Path(os.environ.get("CLAUDE_HOME") or os.path.expanduser("~/.claude"))
# This skill's own directory. A security tool's rule catalog necessarily contains
# the very signatures it hunts for (reverse-shell regexes, credential paths, …),
# so it must exclude itself from skill auditing — exactly like antivirus excludes
# its own signature database. The code stays open-source and auditable by reading
# the repo directly; the deploy gate's secret scan still applies everywhere.
SELF_DIR = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
             ".next", "upstream"}
TEXT_EXT = {".md", ".py", ".js", ".ts", ".json", ".sh", ".bash", ".zsh", ".txt",
            ".yml", ".yaml", ".toml", ".cfg", ".ini", ".env", ".rb", ".go", ".rs"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".tiff", ".heic", ".webp"}
MAX_BYTES = 512 * 1024


# --------------------------------------------------------------------------- #
# IO helpers
# --------------------------------------------------------------------------- #

def read_text(path):
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def add_location(findings, path, fallback=None):
    out = []
    for f in findings:
        if "location" not in f:
            line = f.get("line")
            f["location"] = f"{path}:{line}" if line else (path or fallback or "")
        out.append(f)
    return out


# --------------------------------------------------------------------------- #
# Enumeration: skills
# --------------------------------------------------------------------------- #

def skill_dirs(project):
    """Enumerate installed skills, de-duplicated by name. A skill name can appear
    under several roots (user dir, project dir, and multiple plugin versions);
    we keep one: user > project > plugin, and for plugins the newest path wins
    (e.g. vercel/0.44.0 over 0.43.0). This stops the same skill being audited
    several times and collapses stale plugin caches."""
    roots = []  # (priority, root)
    g = HOME / "skills"
    if g.is_dir():
        roots.append((0, g))
    if project:
        ps = Path(project) / ".claude" / "skills"
        if ps.is_dir():
            roots.append((1, ps))
    plugins = HOME / "plugins"
    if plugins.is_dir():
        for sk in sorted(plugins.rglob("skills")):
            roots.append((2, sk))

    chosen = {}  # name -> (priority, path_str, target)
    for pri, root in roots:
        for child in sorted(root.iterdir()):
            target = child.resolve()
            if not (target.is_dir() and (target / "SKILL.md").exists()):
                continue
            if target == SELF_DIR:
                continue  # don't audit our own signature catalog
            name = child.name
            prev = chosen.get(name)
            if prev is None or pri < prev[0] or (pri == prev[0] and str(target) > prev[1]):
                chosen[name] = (pri, str(target), target)

    out, seen_paths = [], set()
    for name, (_, _, target) in sorted(chosen.items()):
        rp = str(target.resolve())
        if rp in seen_paths:
            continue
        seen_paths.add(rp)
        out.append((name, target))
    return out


def hash_skill(skill_dir):
    """Hash all text files in the skill, return (hash, joined_text, file_list)."""
    parts, texts, files = [], [], []
    for p in sorted(skill_dir.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in TEXT_EXT:
            continue
        if any(d in p.parts for d in SKIP_DIRS):
            continue
        t = read_text(p)
        if t is None:
            continue
        rel = p.relative_to(skill_dir)
        parts.append(f"{rel}\0{st.sha256(t)}")
        texts.append((str(rel), t))
        files.append(p)
    return st.sha256("\n".join(parts)), texts, files


# When auditing third-party skills we care about what the skill could *do to you*
# (secrets it ships, code it runs, instructions it hides, links it points at) —
# not the author's own emails or home paths. Those PII checks belong to the
# deploy gate over your own repo, so they are intentionally excluded here.
SKILL_KINDS = ("secret", "behavioral", "prompt-injection", "obfuscation", "url")


def scan_skill_item(name, skill_dir):
    h, texts, _ = hash_skill(skill_dir)
    findings, urls = [], []
    for rel, text in texts:
        loc = f"{skill_dir.name}/{rel}"
        findings += add_location(checks.scan_text(text, kinds=SKILL_KINDS), loc)
        for url, line in checks.extract_urls(text):
            urls.append({"url": url, "where": f"{loc}:{line}"})
    return h, findings, urls


# --------------------------------------------------------------------------- #
# Enumeration: MCP servers
# --------------------------------------------------------------------------- #

def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def mcp_sources(project):
    """Return list of (source_label, location_string, {name: cfg})."""
    out = []

    def collect(obj, label, location):
        if isinstance(obj, dict):
            servers = obj.get("mcpServers")
            if isinstance(servers, dict) and servers:
                out.append((label, location, servers))

    collect(_load_json(HOME / "settings.json"), "global-settings", str(HOME / "settings.json"))
    dotclaude = _load_json(Path(os.path.expanduser("~/.claude.json")))
    if isinstance(dotclaude, dict):
        collect(dotclaude, "global-claude.json", os.path.expanduser("~/.claude.json"))
        projects = dotclaude.get("projects") or {}
        if project and isinstance(projects, dict):
            pj = projects.get(str(project))
            if isinstance(pj, dict):
                collect(pj, "project-claude.json", f"~/.claude.json → projects[{project}]")
    if project:
        collect(_load_json(Path(project) / ".mcp.json"), "project-.mcp.json", str(Path(project) / ".mcp.json"))
        collect(_load_json(Path(project) / ".claude" / "settings.json"), "project-settings", str(Path(project) / ".claude/settings.json"))
    return out


def scan_mcp_item(name, cfg, location):
    h = st.sha256(json.dumps(cfg, sort_keys=True))
    findings = checks.scan_mcp_server(name, cfg, location)
    urls = []
    url = cfg.get("url") or cfg.get("serverUrl") if isinstance(cfg, dict) else None
    if isinstance(url, str) and url.startswith("http"):
        urls.append({"url": url, "where": f"{location} ({name})"})
    return h, findings, urls


# --------------------------------------------------------------------------- #
# Deploy mode: exposure gate over a directory
# --------------------------------------------------------------------------- #

def git_listed_files(root):
    import subprocess
    try:
        tracked = subprocess.run(["git", "-C", str(root), "ls-files"],
                                 capture_output=True, text=True, timeout=20)
        others = subprocess.run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"],
                                capture_output=True, text=True, timeout=20)
        if tracked.returncode == 0:
            files = tracked.stdout.split("\n") + others.stdout.split("\n")
            return [root / f for f in files if f.strip()]
    except Exception:
        pass
    return None


def walk_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            out.append(Path(dirpath) / fn)
    return out


def git_author_email(root):
    import subprocess
    try:
        r = subprocess.run(["git", "-C", str(root), "config", "user.email"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or None
    except Exception:
        return None


def exif_findings(path):
    try:
        from PIL import Image, ExifTags
    except Exception:
        return []
    try:
        img = Image.open(path)
        exif = img._getexif() or {}
    except Exception:
        return []
    if not exif:
        return []
    tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    flagged = []
    for key in ("GPSInfo", "Make", "Model", "Artist", "XPAuthor", "DateTimeOriginal", "Software"):
        if key in tags and tags[key]:
            flagged.append(key)
    if not flagged:
        return []
    sev = "high" if "GPSInfo" in flagged else "medium"
    return [{
        "id": "META_EXIF", "severity": sev, "category": "metadata",
        "title": "Image EXIF metadata present",
        "location": str(path), "line": None,
        "evidence": ", ".join(flagged),
        "why": "EXIF can embed GPS location, device make/model, author name and timestamps — publishing it leaks where/when/by whom the photo was taken.",
        "fix": "Strip metadata before publishing (e.g. exiftool -all= file, or re-export without metadata).",
    }]


def scan_deploy(root):
    root = Path(root)
    files = git_listed_files(root) or walk_files(root)
    findings, urls = [], []
    for p in files:
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        rel = p.relative_to(root) if str(p).startswith(str(root)) else p
        if ext in IMAGE_EXT:
            findings += exif_findings(p)
            continue
        if ext and ext not in TEXT_EXT and p.name not in (".env", ".npmrc", ".netrc"):
            continue
        text = read_text(p)
        if text is None:
            continue
        # Deploy gate cares about exposure: secrets, pii, presigned urls, metadata.
        fs = checks.filter_ignored(checks.scan_secrets(text) + checks.scan_pii(text), text)
        findings += add_location(fs, str(rel))
        # A committed .env / credentials file is itself a finding.
        if p.name == ".env" or "credential" in p.name.lower():
            findings.append({
                "id": "META_ENV_FILE", "severity": "high", "category": "metadata",
                "title": f"Credentials-style file present ({p.name})",
                "location": str(rel), "line": None, "evidence": p.name,
                "why": "Shipping a .env / credentials file publishes whatever secrets it holds.",
                "fix": "Remove it from the tree and add it to .gitignore; provide a .env.example with no real values instead.",
            })
        for url, line in checks.extract_urls(text):
            urls.append({"url": url, "where": f"{rel}:{line}"})

    # Git author identity check
    email = git_author_email(root)
    if email and "noreply" not in email.lower() and not email.lower().endswith("users.noreply.github.com"):
        findings.append({
            "id": "META_GIT_EMAIL", "severity": "medium", "category": "pii",
            "title": "Git commit email is a personal address",
            "location": "git config user.email", "line": None,
            "evidence": checks.redact(email, 3, 4),
            "why": "Every commit will permanently embed your personal email in public history.",
            "fix": "Set a noreply address: git config user.email '<username>@users.noreply.github.com'.",
        })
    # .gitignore coverage hint
    gi = root / ".gitignore"
    gi_text = read_text(gi) if gi.exists() else ""
    if not gi.exists() or (".env" not in (gi_text or "")):
        findings.append({
            "id": "META_GITIGNORE", "severity": "low", "category": "metadata",
            "title": ".gitignore missing or doesn't block .env / media",
            "location": ".gitignore", "line": None, "evidence": "no .env rule",
            "why": "Without ignore rules, secret files and real media can be committed by accident.",
            "fix": "Add a .gitignore that blocks .env*, credentials, keys, and working media.",
        })
    return findings, urls


# --------------------------------------------------------------------------- #
# URL resolution (best-effort, opt-in) — feeds the TOCTOU comparison
# --------------------------------------------------------------------------- #

def resolve_url(url, timeout=8, max_hops=8):
    """Follow redirects one hop at a time so we capture the full chain and the
    final body. Returns (final_url, content_sha, chain, error). Any network
    failure (blocked/DNS/timeout) degrades to a non-fatal error string."""
    import urllib.error
    import urllib.request
    from urllib.parse import urljoin

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # surface the 3xx instead of auto-following

    opener = urllib.request.build_opener(_NoRedirect())
    chain, current = [url], url
    try:
        for _ in range(max_hops):
            req = urllib.request.Request(
                current, method="GET",
                headers={"User-Agent": "security-audit/1.0"})
            try:
                resp = opener.open(req, timeout=timeout)
                status = getattr(resp, "status", 200)
            except urllib.error.HTTPError as e:
                resp, status = e, e.code
            if status in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location")
                if not loc:
                    break
                current = urljoin(current, loc)
                chain.append(current)
                continue
            body = resp.read(200_000)
            return current, st.normalized_body_sha(body), chain, None
        return current, None, chain, "too many redirects"
    except Exception as e:  # network blocked / dns / timeout — degrade gracefully
        return None, None, chain, str(e)


def verify_urls(state, url_entries, resolve):
    """Compare each URL against the cached trusted record. Returns findings +
    the list of urls the model should verify live with WebFetch."""
    findings, to_verify, seen = [], [], set()
    for entry in url_entries:
        url = entry["url"]
        if url in seen:
            continue
        seen.add(url)
        rec = state.get("urls", {}).get(url)
        if resolve:
            final_url, content_sha, chain, err = resolve_url(url)
            if err is None:
                status, detail = st.compare_url(state, url, final_url, content_sha)
                if status == "redirect_changed":
                    findings.append({
                        "id": "URL_REDIRECT_CHANGED", "severity": "critical", "category": "url",
                        "title": "Redirect destination changed since last audit",
                        "location": entry["where"], "line": None,
                        "evidence": f"{detail['was']} → {detail['now']}",
                        "why": "A previously-trusted link now lands somewhere new — the classic sign of a hijacked/expired domain or repointed shortener serving something hostile.",
                        "fix": "Do NOT follow the link until you confirm the new destination is legitimate; update or remove it.",
                    })
                elif status == "content_changed":
                    findings.append({
                        "id": "URL_CONTENT_CHANGED", "severity": "high", "category": "url",
                        "title": "Linked page content changed since last audit",
                        "location": entry["where"], "line": None,
                        "evidence": f"final={final_url}",
                        "why": "The destination resolves to the same URL but its content changed materially since you last trusted it.",
                        "fix": "Re-review the page content before relying on it; confirm the change is expected.",
                    })
                st.update_url(state, url, final_url, content_sha, chain)
            else:
                to_verify.append({**entry, "status": "unresolved", "error": err,
                                  "cached_final": (rec or {}).get("final_url")})
        else:
            to_verify.append({**entry, "status": "known" if rec else "new",
                              "cached_final": (rec or {}).get("final_url")})
    return findings, to_verify


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #

def severity_counts(findings):
    counts = {s: 0 for s in checks.SEVERITY_ORDER}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    return counts


def verdict(counts, mode):
    if counts.get("critical"):
        return "BLOCK"
    if mode == "deploy" and counts.get("high"):
        return "BLOCK"
    if any(counts.get(s) for s in ("high", "medium", "low")):
        return "FLAGGED"
    return "PASS"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def run(mode, project, resolve, update):
    state = st.load_state()
    items, all_findings, url_entries, current_hashes, kinds = [], [], [], {}, {}

    if mode == "deploy":
        findings, url_entries = scan_deploy(project or os.getcwd())
        all_findings += findings
        diff = {"new": [], "changed": [], "unchanged": [], "removed": []}
        scanned = 1
    else:
        # Skills
        for name, sdir in skill_dirs(project):
            key = f"skill:{name}"
            h, findings, urls = scan_skill_item(name, sdir)
            current_hashes[key] = h
            kinds[key] = "skill"
            items.append({"key": key, "kind": "skill", "path": str(sdir),
                          "_findings": findings, "_urls": urls})
        # MCP servers
        for label, location, servers in mcp_sources(project):
            for name, cfg in servers.items():
                key = f"mcp:{label}:{name}"
                h, findings, urls = scan_mcp_item(name, cfg, location)
                current_hashes[key] = h
                kinds[key] = "mcp"
                items.append({"key": key, "kind": "mcp", "path": location,
                              "_findings": findings, "_urls": urls})

        diff = st.diff_items(state, current_hashes)
        changed_set = set(diff["new"]) | set(diff["changed"])
        scanned = len(items)
        prev = state.get("items", {})
        review = items if mode == "full" else [it for it in items if it["key"] in changed_set]
        for it in review:
            it["status"] = ("new" if it["key"] in diff["new"] else
                            "changed" if it["key"] in diff["changed"] else "unchanged")
            all_findings += it["_findings"]
            url_entries += it["_urls"]
        # Carry forward unresolved findings on UNCHANGED items so a pre-existing
        # Critical/High doesn't get buried once the cache is populated. Content is
        # identical to last audit, so the cached findings still hold — surfacing
        # them costs no model tokens but keeps the verdict honest.
        carried = 0
        if mode == "scan":
            for it in items:
                if it["key"] not in changed_set:
                    cf = prev.get(it["key"], {}).get("findings", [])
                    all_findings += cf
                    carried += len(cf)

    # URL TOCTOU comparison
    url_findings, urls_to_verify = verify_urls(state, url_entries, resolve)
    all_findings += url_findings

    # URL findings belong to the items whose URLs they came from; for caching we
    # keep them out of per-item findings (they live in the URL cache) and just
    # show them this run.
    all_findings = _dedupe(all_findings)
    counts = severity_counts(all_findings)
    result = {
        "mode": mode,
        "scope": _scope_label(mode, project),
        "generated_at": st.now_iso(),
        "summary": {
            "scanned": scanned,
            "new": len(diff["new"]), "changed": len(diff["changed"]),
            "unchanged": len(diff["unchanged"]), "removed": len(diff["removed"]),
            "carried": locals().get("carried", 0),
            "findings_by_severity": counts,
            "verdict": verdict(counts, mode),
        },
        "diff": diff,
        "review_items": [{"key": it["key"], "kind": it["kind"], "path": it["path"],
                          "status": it.get("status"), "findings": it["_findings"]}
                         for it in items if it.get("status")],
        "urls_to_verify": urls_to_verify,
        "findings": _sorted(all_findings),
    }

    if update and mode != "deploy":
        # Persist per-item findings so unchanged items can carry their unresolved
        # issues forward to the next audit (fresh for reviewed items, cached
        # otherwise).
        prev_items = state.get("items", {})
        findings_by_key = {}
        for it in items:
            if mode == "full" or it["key"] in changed_set:
                findings_by_key[it["key"]] = it["_findings"]
            else:
                findings_by_key[it["key"]] = prev_items.get(it["key"], {}).get("findings", [])
        st.record_items(state, current_hashes, kinds, findings_by_key)
        st.save_state(state)
    elif update and resolve:
        st.save_state(state)  # persist refreshed URL fingerprints even in deploy

    return result


def _scope_label(mode, project):
    if mode == "deploy":
        return f"deploy gate: {project or os.getcwd()}"
    return f"global (~/.claude) + project ({project or os.getcwd()})"


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f.get("id"), f.get("location"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _sorted(findings):
    rank = {s: i for i, s in enumerate(checks.SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (rank.get(f.get("severity"), 9), f.get("id", "")))


def main():
    ap = argparse.ArgumentParser(description="security-audit scanner")
    ap.add_argument("mode", nargs="?", default="scan",
                    choices=["scan", "full", "deploy"])
    ap.add_argument("--project", default=os.getcwd())
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--changed-only", action="store_true",
                    help="print a one-line nudge only if something changed (for hooks)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--resolve-urls", action="store_true")
    ap.add_argument("--no-update", action="store_true")
    args = ap.parse_args()

    # The hook nudge must never update the baseline — otherwise it would
    # silently "acknowledge" a change before you've actually reviewed it. Only a
    # real audit run advances the cache.
    update = not args.no_update and not args.changed_only
    result = run(args.mode, args.project, args.resolve_urls, update=update)
    s = result["summary"]

    c = s["findings_by_severity"]
    unresolved = c.get("critical", 0) + c.get("high", 0)

    if args.changed_only:
        n = s["new"] + s["changed"] + s["removed"]
        if n:
            bits = []
            if s["new"]:
                bits.append(f"{s['new']} new")
            if s["changed"]:
                bits.append(f"{s['changed']} changed")
            if s["removed"]:
                bits.append(f"{s['removed']} removed")
            print(f"⚠ security-audit: {', '.join(bits)} skill/MCP item(s) since last audit — run /security-audit to review")
        elif unresolved:
            print(f"⚠ security-audit: no changes, but {unresolved} unresolved "
                  f"critical/high finding(s) remain — run /security-audit full")
        elif not args.quiet:
            print("✓ security-audit: nothing changed since last audit")
        return

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # Human summary (the skill normally consumes --json; this is for direct use)
    if args.mode != "deploy" and (s["new"] + s["changed"]) == 0 and not result["findings"]:
        print(f"✓ No changes since last audit ({st.load_state().get('last_audit')}). "
              f"{s['unchanged']} items unchanged — nothing to review.")
        return
    print(f"🔒 security-audit [{result['mode']}] — {result['scope']}")
    print(f"   scanned={s['scanned']} new={s['new']} changed={s['changed']} "
          f"unchanged={s['unchanged']} removed={s['removed']}")
    print(f"   findings: {c['critical']}C {c['high']}H {c['medium']}M {c['low']}L {c['info']}I "
          f"→ verdict {s['verdict']}")
    for f in result["findings"]:
        print(f"   [{f['severity'].upper():8}] {f['title']} @ {f.get('location','')}")
    if result["urls_to_verify"]:
        print(f"   {len(result['urls_to_verify'])} URL(s) need live verification (WebFetch).")


if __name__ == "__main__":
    main()
