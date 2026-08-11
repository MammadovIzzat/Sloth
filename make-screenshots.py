#!/usr/bin/env python3
"""Renders the interface to PNGs for the README.

    ./make-screenshots.py            → docs/screenshots/

Pages are rendered by the real app against a throwaway database of invented
data, written to temporary HTML with the stylesheet and scripts pointed at
absolute paths, then photographed with headless Firefox. The page's own
JavaScript runs, so status badges and per-host controls appear exactly as they
do in the running tool.

Nothing here touches your real database. The demo content is fictional and
deliberately so — these images end up in a public repository.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    from PIL import Image
except ImportError:                      # cropping is a nicety, not a requirement
    Image = None

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "docs", "screenshots")
WIDTH, HEIGHT = 1440, 940
STATIC = os.path.join(HERE, "static")


def main():
    browser = shutil.which("firefox") or shutil.which("firefox-esr")
    if not browser:
        sys.exit("[!] firefox not found — needed to render the screenshots.")

    work = tempfile.mkdtemp(prefix="sloth-shots-")
    os.environ.update(SLOTH_DATA=work, SLOTH_DB=os.path.join(work, "demo.db"),
                      SLOTH_RUNS=os.path.join(work, "runs"),
                      SLOTH_SHOTS=os.path.join(work, "shots"))
    sys.path.insert(0, HERE)

    from sloth import auth, create_app, store
    from sloth.engine import log_path

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    ids = seed(auth, store, log_path)
    with client.session_transaction() as sess:
        sess[auth.SESSION_KEY] = ids["user"]

    os.makedirs(OUT, exist_ok=True)
    pages = [
        ("dashboard", "/", None),
        ("project", f"/projects/{ids['project']}", None),
        ("task", f"/tasks/{ids['done']}", None),
        # Opened via the dialog's own trigger, so the shot shows the real thing.
        ("new-task", f"/projects/{ids['project']}", "dlg-task"),
        ("nmap-report", f"/nmap-result/{ids['scan']}", None),
    ]

    made = []
    for name, url, dialog in pages:
        html = client.get(url).get_data(as_text=True)
        page = localise(html, dialog)
        src = os.path.join(work, name + ".html")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(page)
        dest = os.path.join(OUT, name + ".png")
        shoot(browser, src, dest)
        trim(dest)
        made.append((name, dest))

    shutil.rmtree(work, ignore_errors=True)

    print(f"Wrote {len(made)} screenshot(s) → docs/screenshots/")
    for name, path in made:
        size = os.path.getsize(path) // 1024 if os.path.exists(path) else 0
        print(f"    {name + '.png':<20} {size:>4} KB"
              + ("" if size else "   ← EMPTY, render failed"))
    return 0 if all(os.path.getsize(p) for _, p in made) else 1


def localise(html, dialog):
    """Points assets at absolute paths and, optionally, opens a dialog."""
    html = re.sub(r'(href|src)="/static/([^"?]+)(\?[^"]*)?"',
                  lambda m: f'{m.group(1)}="file://{STATIC}/{m.group(2)}"', html)
    if dialog:
        # Show the dialog and hide the page behind it, so the shot is the dialog.
        html = html.replace('id="%s" class="dialog-backdrop hidden"' % dialog,
                            'id="%s" class="dialog-backdrop"' % dialog)
        html = html.replace('class="dialog-backdrop hidden" id="%s"' % dialog,
                            'class="dialog-backdrop" id="%s"' % dialog)
    return html


def shoot(browser, src, dest):
    profile = tempfile.mkdtemp(prefix="ff-shot-")
    try:
        subprocess.run(
            [browser, "--headless", "--new-instance", "--profile", profile,
             "--window-size", f"{WIDTH},{HEIGHT}", "--screenshot", dest,
             "file://" + src],
            capture_output=True, timeout=90, check=False,
            env={**os.environ, "MOZ_HEADLESS": "1"})
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"    [!] {os.path.basename(dest)}: {exc}")
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def trim(path, sidebar=250):
    """Crops the dead background off the bottom of a short page.

    Only the content column is measured. The sidebar runs the full height of the
    window, so a whole-row test never finds a uniform row and would crop nothing.
    """
    if Image is None or not os.path.exists(path):
        return
    img = Image.open(path).convert("RGB")
    width, height = img.size
    content = img.crop((sidebar, 0, width, height))
    bbox = content.getbbox() if content.getextrema() else None
    # getbbox() works off black; the page background is not black, so difference
    # against a solid background image is the reliable way to find real content.
    bg = Image.new("RGB", content.size, content.getpixel((content.width - 4, height - 4)))
    from PIL import ImageChops
    bbox = ImageChops.difference(content, bg).getbbox()
    if not bbox:
        return
    last = min(height, bbox[3] + 28)      # a little breathing room
    if last < height - 8:
        img.crop((0, 0, width, last)).save(path, optimize=True)


def seed(auth, store, log_path):
    """Entirely invented content — no real client, host or range appears here."""
    user = auth.create_user("analyst", "demo password 1234")

    pid = store.create_project(
        "Acme Corp — internal", client="Acme Corp",
        description="Internal range assessment. Scope agreed 2026-03-02.")
    store.create_project("Quick scans",
                         description="Ad-hoc scans started from the dashboard.")

    done = store.create_task(pid, "10.0.0.0/24", name="10.0.0.0/24 (256 hosts)",
                             scan_type="full", engine="rustscan",
                             tcp_ports="1-65535", rate=1000, retries=3,
                             discovery="fping_sweep",
                             notes="Servers VLAN. Avoid the printers on .200+.")
    store.update_task(done, status="completed", progress=100.0,
                      started_at="2026-03-04 09:12:00",
                      finished_at="2026-03-04 09:19:41")

    hosts = {
        "10.0.0.5":  [(22, "tcp", "ssh (OpenSSH 9.8p1)"),
                      (445, "tcp", "microsoft-ds"),
                      (3389, "tcp", "ms-wbt-server"),
                      (5985, "tcp", "http (Microsoft HTTPAPI 2.0)")],
        "10.0.0.9":  [(80, "tcp", "http (nginx 1.24.0)"), (443, "tcp", "https"),
                      (3000, "tcp", "http (Golang net/http)"),
                      (8080, "tcp", "http-proxy")],
        "10.0.0.24": [(22, "tcp", "ssh (OpenSSH 9.2p1)"),
                      (5432, "tcp", "postgresql 15.4")],
        "10.0.0.90": [],
    }
    for ip, ports in hosts.items():
        store.add_hosts(done, [{"ip": ip, "state": "up", "reason": "echo-reply",
                                "hostname": "gw.internal" if ip.endswith(".90") else None}],
                        method="fping_sweep")
        if ports:
            store.add_findings(done, ip, [{"port": p, "proto": pr, "state": "open",
                                           "service": s} for p, pr, s in ports],
                               source="nmap")
    store.add_findings(done, "10.0.0.9", [{"port": 161, "proto": "udp",
                                           "state": "open|filtered",
                                           "service": "snmp"}], source="nmap")

    run = store.create_task(pid, "10.0.1.0/24", name="10.0.1.0/24 (256 hosts)",
                            scan_type="full", engine="masscan",
                            tcp_ports="1-65535", rate=2000, retries=3,
                            discovery="nmap_default")
    store.update_task(run, status="running", progress=64.2)
    store.create_task(pid, "10.0.2.0/24", name="10.0.2.0/24 · host discovery",
                      scan_type="discovery", discovery="nmap_thorough")

    scan = "a1b2c3d4e5f6"
    store.save_nmap_scan(
        scan, "10.0.0.9", "nmap_deep",
        "nmap -sC -sV -Pn -T4 -p 80,443,3000,8080 10.0.0.9 -oX nmap.xml -oN -",
        NMAP_OUTPUT,
        [{"port": 80, "proto": "tcp", "state": "open", "service": "http (nginx 1.24.0)"},
         {"port": 443, "proto": "tcp", "state": "open", "service": "ssl/https (nginx 1.24.0)"},
         {"port": 3000, "proto": "tcp", "state": "open", "service": "http (Golang net/http)"},
         {"port": 8080, "proto": "tcp", "state": "open", "service": "http-proxy"}],
        [], task_id=done, project_id=pid)

    os.makedirs(os.path.dirname(log_path(done)), exist_ok=True)
    with open(log_path(done), "w", encoding="utf-8") as fh:
        fh.write(LOG)
    return {"user": user, "project": pid, "done": done, "scan": scan}


NMAP_OUTPUT = """# TCP service/script scan on ports: 80,443,3000,8080
# Nmap 7.99 scan initiated Wed Mar  4 09:22:10 2026
Nmap scan report for 10.0.0.9
Host is up (0.0021s latency).

PORT     STATE SERVICE   VERSION
80/tcp   open  http      nginx 1.24.0
|_http-title: Did not follow redirect to https://intranet.acme.internal/
|_http-server-header: nginx/1.24.0
443/tcp  open  ssl/https nginx 1.24.0
| ssl-cert: Subject: commonName=intranet.acme.internal
| Not valid before: 2026-01-14T08:11:02
|_Not valid after:  2027-01-14T08:11:02
3000/tcp open  http      Golang net/http server
|_http-title: Grafana
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests

Service detection performed. Please report any incorrect results at
https://nmap.org/submit/ .
# Nmap done -- 1 IP address (1 host up) scanned in 107.20 seconds
"""

LOG = """══ 2026-03-04 09:12:00 · Full port scan · rustscan · discovery: fping_sweep · TCP 1-65535 ══
[discovery] fping ICMP sweep (-a -g) over 10.0.0.0/24
$ fping -a -q -r 1 -t 300 -g 10.0.0.0/24
[discovery] 4 host(s) up out of 256 address(es).
$ rustscan -a 10.0.0.5,10.0.0.9,10.0.0.24,10.0.0.90 -r 1-65535 --ulimit 5000
10.0.0.5 -> [22,445,3389,5985]
10.0.0.9 -> [80,443,3000,8080]
10.0.0.24 -> [22,5432]
Finished: completed — 4 host(s), 11 port(s).
Rescan of 10.0.0.9 (nmap_deep) finished: 4 port(s)
"""

if __name__ == "__main__":
    raise SystemExit(main())
