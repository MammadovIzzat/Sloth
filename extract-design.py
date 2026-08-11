#!/usr/bin/env python3
"""Unpacks the Nocturne design system out of Sloth.html into static/.

    ./extract-design.py

Sloth.html is a bundler export: the stylesheet and its webfonts live inside a
gzipped base64 manifest, referenced by uuid. This writes them out as ordinary
files and rewrites the font urls to match, so the app serves the design system
itself with no CDN and no build step — which is what lets the interface render
on a client network with no route out.
"""
import base64
import gzip
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, "Sloth.html")
CSS_DIR = os.path.join(HERE, "static", "css")
FONT_DIR = os.path.join(HERE, "static", "fonts")

EXT = {"font/woff2": ".woff2", "font/woff": ".woff", "font/ttf": ".ttf",
       "image/svg+xml": ".svg", "text/javascript": ".js"}


def main():
    if not os.path.exists(BUNDLE):
        sys.exit(f"[!] {BUNDLE} not found.")
    html = open(BUNDLE, encoding="utf-8", errors="replace").read()

    manifest = json.loads(_tag(html, "manifest"))
    template = json.loads(_tag(html, "template"))
    if isinstance(template, dict):
        template = next(iter(template.values()))

    os.makedirs(CSS_DIR, exist_ok=True)
    os.makedirs(FONT_DIR, exist_ok=True)

    # Fonts first, so the stylesheet can be rewritten to point at them. The
    # Phosphor icon set ships as an SVG font, so image/svg+xml counts here too —
    # skipping it leaves every icon in the interface blank.
    fonts = {}
    referenced = set(re.findall(r'url\("([0-9a-f-]{36})(?:#[^"]*)?"\)', template))
    for uuid, entry in manifest.items():
        mime = entry.get("mime", "")
        if not (mime.startswith("font/")
                or (mime == "image/svg+xml" and uuid in referenced)):
            continue
        raw = base64.b64decode(entry["data"])
        if entry.get("compressed"):
            raw = gzip.decompress(raw)
        name = uuid + EXT.get(mime, "")
        with open(os.path.join(FONT_DIR, name), "wb") as fh:
            fh.write(raw)
        fonts[uuid] = name

    css = "\n".join(m.group(1) for m in
                    re.finditer(r"<style>(.*?)</style>", template, re.S))
    # url("<uuid>#fragment") → url("../fonts/<uuid>.woff2#fragment")
    css = re.sub(
        r'url\("([0-9a-f-]{36})(#[^"]*)?"\)',
        lambda m: f'url("../fonts/{fonts.get(m.group(1), m.group(1))}{m.group(2) or ""}")',
        css)

    unresolved = re.findall(r'url\("([0-9a-f-]{36})(?:#[^"]*)?"\)', css)
    css_path = os.path.join(CSS_DIR, "nocturne.css")
    with open(css_path, "w", encoding="utf-8") as fh:
        fh.write(HEADER + css)

    print(f"Wrote {len(fonts)} font(s) → static/fonts/")
    print(f"Wrote {os.path.getsize(css_path) // 1024} KB → static/css/nocturne.css")
    if unresolved:
        print(f"[!] {len(unresolved)} font reference(s) could not be resolved")
    remaining = re.findall(r"https?://", css)
    print(f"External references in the stylesheet: {len(remaining)}"
          + ("  ← self-contained" if not remaining else ""))
    return 0


def _tag(html, kind):
    m = re.search(rf'<script type="__bundler/{kind}">(.*?)</script>', html, re.S)
    if not m:
        sys.exit(f"[!] no __bundler/{kind} block in {BUNDLE}")
    return m.group(1)


HEADER = """/* Nocturne — extracted from Sloth.html by extract-design.py. Do not edit here:
   re-export the bundle and re-run the script. Fonts are served from
   static/fonts/, so nothing is fetched at runtime. */

"""

if __name__ == "__main__":
    raise SystemExit(main())
