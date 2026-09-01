#!/usr/bin/env python3
"""Builds a clean source archive — code only, none of your engagement data.

    ./make-source-zip.py                 → dist/sloth-<version>-src.zip
    ./make-source-zip.py --out /tmp/x.zip

Files are chosen from an explicit **allowlist**. That is the whole point: a
denylist quietly ships whatever you add later that nobody remembered to exclude,
and in this repository the things worth excluding are scan results, screenshots
of client systems, password hashes and the session signing key.

Everything staged is then scanned for credentials and for addresses that look
like real targets rather than documentation examples, and the archive is not
written if anything trips.
"""
import argparse
import fnmatch
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))

# (directory, glob) pairs. Nothing outside this list is ever archived.
ALLOW = [
    (".", "scanner.py"),
    (".", "build-deb.sh"),
    (".", "make-source-zip.py"),
    (".", "README.md"),
    ("sloth", "**/*.py"),
    ("templates", "**/*.html"),
    ("static", "**/*.js"),
    ("static", "**/*.css"),
    # Nocturne's webfonts — without these the interface has no type and no icons.
    ("static", "**/*.woff2"),
    ("static", "**/*.woff"),
    ("static", "**/*.ttf"),
    ("static", "**/*.svg"),
    # The interface logo and favicon — the app's own artwork, not client data,
    # so exempt from the blanket .png ban below.
    ("static/img", "*.png"),
    ("packaging", "*"),
    (".", "make-screenshots.py"),
]

# Extensions and names that must never appear, whatever the allowlist says.
FORBIDDEN_NAMES = {
    ".secret", "paused.conf", "scans.db", ".cls",
    "legacy_scans_backup.json", "restore_legacy_scans.py",
}
FORBIDDEN_SUFFIXES = (
    ".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3",
    ".png", ".jpg", ".jpeg", ".gif", ".pcap",
    ".pem", ".key", ".p12", ".pfx",
    ".pyc", ".pyo", ".deb", ".list", ".xml", ".log",
)

# Content that would mean a credential slipped in.
SECRET_PATTERNS = [
    (re.compile(r"scrypt:\d+:\d+:\d+\$"), "a password hash"),
    (re.compile(r"pbkdf2:sha\d+"), "a password hash"),
    (re.compile(r"sloth_[A-Za-z0-9_\-]{30,}"), "an API token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(r"resume-index\s*=", re.I), "a masscan resume file"),
    (re.compile(r"adapter-ip\s*=", re.I), "a masscan adapter config"),
]

# Addresses that legitimately appear in code and docs as examples or as fixed
# infrastructure. Anything else is flagged for you to eyeball.
ALLOWED_IPS = {
    "0.0.0.0", "255.255.255.255", "8.8.8.8", "1.1.1.1",
    "192.168.1.0", "192.168.1.5", "10.0.0.0", "10.0.0.1", "10.0.0.2",
    "10.0.0.5", "10.0.0.9", "10.0.0.24", "10.0.0.90", "1.2.3.4",
}
# 10.0.x is the documentation range used in examples and demo data.
ALLOWED_IP_PREFIXES = ("127.", "10.0.", "192.168.1.", "172.16.0.")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

TEXT_SUFFIXES = (".py", ".html", ".js", ".css", ".md", ".sh", ".conf",
                 ".service", ".launcher", "")


def collect():
    patterns = list(ALLOW)
    found = []
    for base, glob in patterns:
        root = os.path.join(HERE, base)
        if "**" in glob:
            tail = glob.split("**/", 1)[1]
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d != "__pycache__"]
                for name in filenames:
                    if fnmatch.fnmatch(name, tail):
                        found.append(os.path.join(dirpath, name))
        else:
            for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
                if fnmatch.fnmatch(name, glob):
                    path = os.path.join(root, name)
                    if os.path.isfile(path):
                        found.append(path)
            direct = os.path.join(root, glob)
            if os.path.isfile(direct):
                found.append(direct)
    # De-duplicate while keeping a stable order for reproducible archives.
    return sorted({os.path.relpath(p, HERE) for p in found})


# PNGs are forbidden because client screenshots are PNGs — except the app's own
# interface art, permitted by exact path.
ALLOWED_BINARIES = {
    "static/img/logo.png", "static/img/logo-small.png", "static/img/favicon.png",
}


def check(paths):
    """Returns (errors, warnings). Errors block the build."""
    errors, warnings = [], []
    for rel in paths:
        name = os.path.basename(rel)
        if rel in ALLOWED_BINARIES:
            continue
        if name in FORBIDDEN_NAMES:
            errors.append(f"{rel}: excluded by name")
            continue
        if name.endswith(FORBIDDEN_SUFFIXES):
            errors.append(f"{rel}: excluded file type")
            continue
        if "__pycache__" in rel.split(os.sep):
            errors.append(f"{rel}: compiled bytecode")
            continue

        if not rel.endswith(TEXT_SUFFIXES):
            continue
        try:
            with open(os.path.join(HERE, rel), encoding="utf-8") as fh:
                body = fh.read()
        except (OSError, UnicodeDecodeError):
            continue

        for pattern, what in SECRET_PATTERNS:
            if pattern.search(body):
                errors.append(f"{rel}: looks like it contains {what}")

        for ip in set(IP_RE.findall(body)):
            if ip in ALLOWED_IPS or ip.startswith(ALLOWED_IP_PREFIXES):
                continue
            warnings.append(f"{rel}: contains {ip} — a real target address?")
    return errors, warnings


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", help="output path for the zip")
    args = ap.parse_args()

    sys.path.insert(0, HERE)
    try:
        from sloth import __version__ as version
    except Exception:
        version = "dev"

    paths = collect()
    if not paths:
        sys.exit("[!] Nothing matched the allowlist — run this from the project directory.")

    errors, warnings = check(paths)
    if errors:
        print("[!] Refusing to build — these would have been included:", file=sys.stderr)
        for line in errors:
            print(f"      {line}", file=sys.stderr)
        return 1

    out = args.out or os.path.join(HERE, "dist", f"sloth-{version}-src.zip")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)

    top = f"sloth-{version}"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in paths:
            # Fixed timestamp and permissions so the same source always produces
            # the same archive.
            info = zipfile.ZipInfo(f"{top}/{rel}", date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = (0o755 if rel.endswith((".sh", ".py")) else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(HERE, rel), "rb") as fh:
                zf.writestr(info, fh.read())

    print(f"Included {len(paths)} file(s):")
    for group in ("sloth/", "templates/", "static/", "packaging/"):
        n = sum(1 for p in paths if p.startswith(group))
        if n:
            print(f"    {group:<16} {n}")
    for p in paths:
        if os.sep not in p:
            print(f"    {p}")

    print("\nDeliberately excluded: scans.db (projects, findings, password and "
          "token hashes), runs/ (session key, scan logs, masscan resume files), "
          "screenshots/ (captured client systems), dist/, __pycache__.")

    if warnings:
        print("\n[!] Worth a look before you share this:")
        for line in warnings:
            print(f"      {line}")

    size = os.path.getsize(out)
    print(f"\n→ {out}  ({size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
