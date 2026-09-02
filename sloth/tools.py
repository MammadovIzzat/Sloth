"""The non-host task formats: shodan, web-archive, header-check, source-enum.

Each runner takes the task's target + params and returns a JSON-serialisable
result dict that its result template renders. A `log` callback streams progress
lines to the task page. Network fetches use the stdlib so there is no extra
dependency, with TLS verification relaxed because engagement targets routinely
present self-signed or mismatched certificates.
"""
import json
import os
import re
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from .config import DATA_DIR
from .engine import ScanError

# The Shodan API key lives in its own file, not the shared results DB. Passed to
# the shodan CLI via SHODAN_API_KEY, which it reads before its own config.
SHODAN_KEY_FILE = os.path.join(DATA_DIR, "shodan_api.key")


def get_shodan_key():
    try:
        with open(SHODAN_KEY_FILE) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def set_shodan_key(key):
    """Store the key and configure the shodan CLI with it.

    The CLI reads its own config file (written by `shodan init`), not
    SHODAN_API_KEY, so saving the key has to run init for the user — which also
    validates the key against Shodan. Raises ScanError if init fails."""
    key = (key or "").strip()
    if not key:
        try:
            os.remove(SHODAN_KEY_FILE)
        except OSError:
            pass
        return
    if shutil.which("shodan") is None:
        raise ScanError("The shodan CLI is not installed. `pipx install shodan`.")
    try:
        proc = subprocess.run(["shodan", "init", key], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise ScanError("shodan init timed out — no network to Shodan?")
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise ScanError("shodan init rejected the key: " + (err[-1] if err else "unknown error"))
    with open(SHODAN_KEY_FILE, "w") as fh:
        fh.write(key)
    try:
        os.chmod(SHODAN_KEY_FILE, 0o600)
    except OSError:
        pass


def shodan_key_configured():
    return bool(get_shodan_key())

USER_AGENT = "sloth/2.4 (+security-testing)"
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _get(url, timeout=20, method="GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout, context=_CTX)


def _noop(_):
    pass


# ── web archive ────────────────────────────────────────────────────────────
_INTERESTING = re.compile(
    r"(admin|login|config|backup|\.sql|\.bak|\.old|\.zip|\.tar|\.git|\.env|"
    r"api|token|secret|password|upload|phpinfo|swagger|graphql|\.json|\.xml)", re.I)


def archive_urls(domain, params=None, log=_noop):
    """Every URL the Wayback CDX index has for a domain, via the user's URL:
    https://web.archive.org/cdx/search/cdx?url=*.<domain>/*&output=txt&fl=original&collapse=urlkey
    """
    domain = (domain or "").strip().lstrip("*.").rstrip("/")
    if not domain:
        raise ScanError("A domain is required.")
    cdx = ("https://web.archive.org/cdx/search/cdx?url=*."
           + urllib.parse.quote(domain) + "/*&output=txt&fl=original&collapse=urlkey")
    log(f"GET {cdx}")
    try:
        with _get(cdx, timeout=90) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise ScanError(f"Wayback request failed: {exc}")
    urls = [u.strip() for u in body.splitlines() if u.strip()]
    # collapse=urlkey already dedupes most; be safe.
    seen, uniq = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    with_query = sum(1 for u in uniq if "?" in u)
    interesting = [u for u in uniq if _INTERESTING.search(u)]
    log(f"{len(uniq)} unique URLs, {len(interesting)} look interesting")
    rows = [{"url": u, "interesting": bool(_INTERESTING.search(u)), "query": "?" in u}
            for u in uniq]
    return {
        "rows": rows,
        "metrics": [
            {"v": len(uniq), "label": "unique URLs", "hue": "#8ab2f5"},
            {"v": with_query, "label": "with query strings", "hue": "#f0c076"},
            {"v": len(interesting), "label": "look interesting", "hue": "#ffb4b6"},
        ],
        "count": len(uniq),
    }


# ── shodan ───────────────────────────────────────────────────────────────
def shodan_domain(domain, params=None, log=_noop):
    """`shodan search` for a domain. Uses the shodan CLI and its stored key."""
    params = params or {}
    domain = (domain or "").strip()
    if not domain:
        raise ScanError("A domain is required.")
    if shutil.which("shodan") is None:
        raise ScanError("The shodan CLI is not installed. `pipx install shodan`.")
    key = get_shodan_key()
    if not key and not os.environ.get("SHODAN_API_KEY"):
        raise ScanError("No Shodan API key configured. Add it under Account → Shodan API key.")
    limit = 100
    try:
        limit = max(1, min(1000, int(params.get("max_pages") or 5) * 100))
    except (TypeError, ValueError):
        limit = 500
    fields = "ip_str,port,org,hostnames,location.country_code,product"
    query = f"hostname:{domain}"
    cmd = ["shodan", "search", "--fields", fields, "--limit", str(limit), query]
    log("$ " + " ".join(cmd))
    env = os.environ.copy()
    if key:
        env["SHODAN_API_KEY"] = key
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        raise ScanError("shodan timed out.")
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise ScanError("shodan failed: " + (err[-1] if err else "unknown error"))

    hosts = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t") if "\t" in line else line.split()
        ip = cols[0]
        port = cols[1] if len(cols) > 1 else ""
        org = cols[2] if len(cols) > 2 else ""
        host = cols[3] if len(cols) > 3 else ""
        cc = cols[4] if len(cols) > 4 else ""
        product = " ".join(cols[5:]) if len(cols) > 5 else ""
        h = hosts.setdefault(ip, {"ip": ip, "host": host, "org": org, "cc": cc,
                                  "product": product, "ports": []})
        if port and port not in h["ports"]:
            h["ports"].append(port)
        if not h["host"] and host:
            h["host"] = host
        if not h["product"] and product:
            h["product"] = product
    rows = sorted(hosts.values(), key=lambda r: r["ip"])
    orgs = {r["org"] for r in rows if r["org"]}
    countries = {r["cc"] for r in rows if r["cc"]}
    log(f"{len(rows)} hosts, {len(orgs)} organisations")
    return {
        "rows": rows,
        "metrics": [
            {"v": len(rows), "label": "hosts known", "hue": "#cbb0f5"},
            {"v": sum(len(r["ports"]) for r in rows), "label": "with open services", "hue": "#8ab2f5"},
            {"v": len(orgs), "label": "organisations", "hue": "#7fd8b0"},
            {"v": len(countries), "label": "countries", "hue": "#f0c076"},
        ],
        "count": len(rows),
    }


# ── header check ───────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "XFO"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "Referrer"),
    ("permissions-policy", "Permissions"),
]
_GRADES = ["F", "E", "D", "C", "B", "A", "A"]   # index by count present (0..6)


def header_check(endpoints, params=None, log=_noop):
    """Fetch each endpoint and grade its security headers."""
    urls = []
    for u in (endpoints or []):
        u = u.strip()
        if not u:
            continue
        # A bare domain (megasec.az) is not a URL — default it to https so the
        # fetch actually hits the site instead of failing with "no headers".
        if not re.match(r"^https?://", u, re.I):
            u = "https://" + u
        urls.append(u)
    if not urls:
        raise ScanError("No web endpoints to check. Add some URLs, or run a host "
                        "scan first so this project has 443/8080 hosts to derive them from.")
    cols = [label for _, label in SECURITY_HEADERS]
    rows, gradeA, missing_hsts, no_csp = [], 0, 0, 0
    for url in urls[:200]:
        log(f"HEAD {url}")
        server, present = "", {}
        try:
            with _get(url, timeout=12) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:                       # noqa: BLE001 - reported per row
            rows.append({"url": url, "server": f"unreachable — {exc}",
                         "cells": [{"mark": "—", "ok": False} for _ in SECURITY_HEADERS],
                         "grade": "—", "gradeHue": "rgba(233,233,237,.4)"})
            continue
        server = headers.get("server", "")
        n = 0
        cells = []
        for key, _label in SECURITY_HEADERS:
            ok = key in headers
            if ok:
                n += 1
            cells.append({"mark": "✓" if ok else "✗", "ok": ok, "title": headers.get(key, "missing")})
        grade = _GRADES[n]
        if grade == "A":
            gradeA += 1
        if "strict-transport-security" not in headers:
            missing_hsts += 1
        if "content-security-policy" not in headers:
            no_csp += 1
        hue = {"A": "#7fd8b0", "B": "#8ab2f5", "C": "#f0c076"}.get(grade, "#ffb4b6")
        rows.append({"url": url, "server": server or "—", "cells": cells,
                     "grade": grade, "gradeHue": hue})
    leak = sum(1 for r in rows if re.search(r"\d", r["server"] or ""))
    return {
        "rows": rows, "cols": cols,
        "metrics": [
            {"v": len(rows), "label": "endpoints checked", "hue": "#f0c076"},
            {"v": gradeA, "label": "grade A", "hue": "#7fd8b0"},
            {"v": missing_hsts, "label": "missing HSTS", "hue": "#ffb4b6"},
            {"v": no_csp, "label": "no CSP at all", "hue": "#ffb4b6"},
            {"v": leak, "label": "leak server version", "hue": "#f0c076"},
        ],
        "count": len(rows),
    }


# ── source enumeration ───────────────────────────────────────────────────
_RULES = {
    "secrets": (re.compile(
        r"""(?ix)(?:api[_-]?key|secret|token|passwd|password|aws_access_key_id|
        authorization|bearer)\s*[:=]\s*['"][^'"]{8,}['"]"""), "high"),
    "endpoints": (re.compile(r"""(?i)['"](/[a-z0-9_\-./]{2,}(?:\?[^'"]*)?)['"]"""), "info"),
    "urls": (re.compile(r"""https?://[a-z0-9.\-]+[a-z0-9/_\-.?=&%]*""", re.I), "info"),
}
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.I)
_SRCMAP = re.compile(r"sourceMappingURL=([^\s*]+)")


def source_enum(url, params=None, log=_noop):
    """Crawl a URL's page + its scripts, grep every asset for the chosen rules."""
    params = params or {}
    url = (url or "").strip()
    if not url:
        raise ScanError("A start URL is required.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    custom = (params.get("regex") or "").strip()
    rules = []
    for name in (params.get("rules") or "secrets,endpoints").replace(" ", "").split(","):
        if name in _RULES:
            rules.append((name, _RULES[name][0], _RULES[name][1]))
    if custom:
        try:
            rules.append(("custom", re.compile(custom), "high"))
        except re.error as exc:
            raise ScanError(f"Bad custom regex: {exc}")

    def fetch(u):
        with _get(u, timeout=15) as resp:
            return resp.read().decode("utf-8", "replace")

    log(f"GET {url}")
    try:
        html = fetch(url)
    except Exception as exc:                            # noqa: BLE001
        raise ScanError(f"Could not fetch {url}: {exc}")

    base = urllib.parse.urljoin(url, "/")
    assets = [("(page)", html)]
    srcmaps = 0
    for src in _SCRIPT_SRC.findall(html)[:40]:
        full = urllib.parse.urljoin(url, src)
        try:
            log(f"GET {full}")
            body = fetch(full)
            assets.append((full, body))
            if _SRCMAP.search(body):
                srcmaps += 1
        except Exception:                               # noqa: BLE001
            continue

    matches, seen = [], set()
    endpoints = set()
    for asset, body in assets:
        for name, rx, sev in rules:
            for m in rx.finditer(body):
                val = (m.group(1) if m.groups() else m.group(0))[:200]
                if name in ("endpoints", "urls"):
                    endpoints.add(val)
                key = (name, val)
                if key in seen:
                    continue
                seen.add(key)
                matches.append({"asset": asset, "rule": name, "severity": sev, "match": val})
    high = sum(1 for m in matches if m["severity"] == "high")
    log(f"{len(assets)} assets, {len(matches)} matches, {high} high")
    return {
        "rows": matches[:1000],
        "metrics": [
            {"v": len(assets), "label": "assets fetched", "hue": "#7fd8b0"},
            {"v": len(matches), "label": "regex matches", "hue": "#8ab2f5"},
            {"v": high, "label": "high severity", "hue": "#ffb4b6"},
            {"v": len(endpoints), "label": "endpoints found", "hue": "#f0c076"},
            {"v": srcmaps, "label": "source maps found", "hue": "#cbb0f5"},
        ],
        "count": len(matches),
    }


RUNNERS = {
    "shodan": shodan_domain,
    "archive": archive_urls,
    "headers": header_check,
    "source": source_enum,
}
