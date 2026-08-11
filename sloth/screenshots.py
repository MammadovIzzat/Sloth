"""Headless-browser screenshots of discovered web services."""
import os
import shutil
import subprocess
import tempfile

from .config import SHOTS_DIR, WEB_PORTS, SCREENSHOT_TIMEOUT
from .netutil import web_url_for


def find_browser():
    """Returns (path, kind) for a screenshot-capable browser, or (None, None)."""
    for name in ("chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable", "chrome"):
        path = shutil.which(name)
        if path:
            return path, "chromium"
    for name in ("firefox", "firefox-esr"):
        path = shutil.which(name)
        if path:
            return path, "firefox"
    return None, None


def capture(ip, ports, scan_id, spawn=None, cancelled=None):
    """Screenshots every web port on a host. Returns (shots, note).

    `spawn` launches each browser; passing the process registry's spawn makes the
    captures stoppable, which matters because a headless browser aimed at an
    unresponsive host sits there for the whole timeout. `cancelled` is checked
    between hosts so a stop takes effect promptly instead of after every port.
    """
    cancelled = cancelled or (lambda: False)
    browser, kind = find_browser()
    if not browser:
        return [], "No headless browser found (install chromium or firefox) — screenshots skipped."

    targets = [(p, web_url_for(ip, p, WEB_PORTS)) for p in ports]
    targets = [(p, url) for p, url in targets if url]
    if not targets:
        return [], "No web services detected on this host."

    shots = []
    failed = []
    stopped = False
    for p, url in targets:
        if cancelled():
            stopped = True
            break
        fname = f"{scan_id}_{p['proto']}_{p['port']}.png"
        out = os.path.join(SHOTS_DIR, fname)
        profile = None
        try:
            if kind == "chromium":
                cmd = [browser, "--headless", "--disable-gpu", "--no-sandbox",
                       "--hide-scrollbars", "--ignore-certificate-errors",
                       "--virtual-time-budget=6000", "--window-size=1280,900",
                       f"--screenshot={out}", url]
                env = None
            else:
                # Throwaway profile so this never clashes with the user's own Firefox.
                profile = tempfile.mkdtemp(prefix="ff-shot-")
                cmd = [browser, "--headless", "--new-instance", "--profile", profile,
                       "--window-size=1280,900", "--screenshot", out, url]
                env = {**os.environ, "MOZ_HEADLESS": "1"}
            _run_browser(cmd, env, spawn)
        except (subprocess.TimeoutExpired, OSError):
            failed.append(url)
            continue
        finally:
            if profile:
                shutil.rmtree(profile, ignore_errors=True)

        if os.path.exists(out) and os.path.getsize(out) > 0:
            shots.append({"port": p["port"], "proto": p["proto"], "url": url, "file": fname})
        else:
            failed.append(url)

    note = ""
    if stopped:
        note = f"stopped after {len(shots)} of {len(targets)} screenshot(s)"
    elif failed:
        note = f"{len(failed)} web service(s) could not be captured: " + ", ".join(failed[:5])
    return shots, note


def _run_browser(cmd, env, spawn):
    """Runs one headless capture, through the registry when one is supplied."""
    if spawn is None:
        subprocess.run(cmd, capture_output=True, timeout=SCREENSHOT_TIMEOUT,
                       check=False, env=env)
        return
    kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if env is not None:
        kwargs["env"] = env
    proc = spawn(cmd, **kwargs)
    try:
        proc.communicate(timeout=SCREENSHOT_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
