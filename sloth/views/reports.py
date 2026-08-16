"""Saved nmap reports, screenshots, and exports.

The old export dumped whatever masscan happened to have in memory. These pull
from the database instead, so an export covers everything a task or project ever
found: masscan ports, nmap-detected services, the raw nmap output and the
screenshots, embedded so the HTML file stands alone.
"""
import base64
import json
import os

from flask import (Blueprint, abort, flash, jsonify, make_response, redirect,
                   render_template, request, send_file, url_for)

from .. import store, transfer
from ..config import SHOTS_DIR

bp = Blueprint("reports", __name__)


@bp.route("/screenshot/<path:fname>")
def screenshot(fname):
    # basename() keeps a crafted name from escaping the screenshots directory.
    path = os.path.join(SHOTS_DIR, os.path.basename(fname))
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, mimetype="image/png")


SCANS_PAGE_SIZE = 200


@bp.route("/scans")
def list_scans():
    # Search runs in SQL so it reaches every saved scan, not just the page shown.
    search = (request.args.get("q") or "").strip()
    project_id = (request.args.get("project") or "").strip() or None
    matched = store.list_nmap_scans(project_id=project_id, search=search or None)

    limit = SCANS_PAGE_SIZE
    if request.args.get("all"):
        limit = len(matched)

    # Only projects that actually have a report — offering empty ones is just a
    # list of dead ends.
    projects = [p for p in store.list_projects()
                if store.list_nmap_scans(project_id=p["id"])]

    return render_template(
        "scans.html", nav_section="scans", scans=matched[:limit],
        total=len(matched), truncated=len(matched) > limit,
        grand_total=len(store.list_nmap_scans()),
        search=search, project_id=project_id or "", projects=projects)


@bp.route("/nmap-result/<scan_id>")
def nmap_result(scan_id):
    row = store.get_nmap_scan(scan_id)
    if row is None:
        abort(404)
    return render_template(
        "nmap_result.html",
        nav_section="scans",
        scan=row,
        ports=_loads(row["ports_json"]),
        shots=_loads(row["screenshots_json"]),
    )


@bp.route("/export/task/<task_id>")
def export_task(task_id):
    task = store.get_task(task_id)
    if task is None:
        abort(404)
    bundle = _task_bundle(task)
    return _render_export(request.args.get("format", "html"),
                          title=f"{task['project_name']} · {task['name']}",
                          slug=f"task-{task_id}",
                          sections=[bundle])


@bp.route("/export/project/<project_id>")
def export_project(project_id):
    project = store.get_project(project_id)
    if project is None:
        abort(404)
    sections = [_task_bundle(t) for t in store.list_tasks(project_id)]
    return _render_export(request.args.get("format", "html"),
                          title=project["name"],
                          slug=f"project-{project_id}",
                          sections=sections,
                          project=project)


@bp.route("/import", methods=["POST"])
def import_bundle():
    """Loads a JSON export from another install.

    Always lands in a project — a new one by default, or an existing one when
    two people are splitting the same engagement between them.
    """
    back = request.form.get("project_id")
    home = (url_for("projects.project_detail", project_id=back) if back
            else url_for("projects.index"))

    upload = request.files.get("bundle")
    if upload is None or not upload.filename:
        flash("Choose a .json export to import.", "error")
        return redirect(home)

    try:
        data = transfer.read_bundle(upload.read())
        tally = transfer.import_bundle(data, project_id=back or None)
    except transfer.BundleError as exc:
        flash(str(exc), "error")
        return redirect(home)

    counts = " · ".join(
        f"{tally[k]} {label}"
        for k, label in (("tasks", "task(s)"), ("hosts", "host(s)"),
                         ("ports", "port(s)"), ("scans", "nmap scan(s)"),
                         ("shots", "screenshot(s)")) if tally[k])
    where = "into a new project" if tally["created"] else "into this project"
    flash(f"Imported {counts or 'nothing — the file had no results'} {where}.",
          "ok")
    if tally["skipped"]:
        flash(f"{tally['skipped']} entr(y/ies) in the file were malformed and "
              f"were skipped.", "error")
    return redirect(url_for("projects.project_detail",
                            project_id=tally["project"]))


def _task_bundle(task):
    """Everything one task knows, ready for rendering or serialising."""
    hosts = store.task_hosts(task["id"])
    scans = {}
    for row in store.list_nmap_scans(task_id=task["id"]):
        full = store.get_nmap_scan(row["id"])
        scans.setdefault(row["ip"], []).append({
            "id": full["id"],
            "tool": full["tool"],
            "created_at": full["created_at"],
            "command": full["command"],
            "raw_output": full["raw_output"],
            "screenshots": _loads(full["screenshots_json"]),
        })
    return {"task": dict(task), "hosts": hosts, "scans": scans}


def _render_export(fmt, title, slug, sections, project=None):
    if fmt == "json":
        # The JSON export is also the import format, so it carries a version
        # header and the screenshots themselves rather than filenames that mean
        # nothing on another machine.
        from .. import __version__
        payload = transfer.envelope(title, sections, project, version=__version__)
        resp = make_response(json.dumps(payload, indent=2, default=str))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = f"attachment; filename={slug}.json"
        return resp

    if fmt == "txt":
        resp = make_response(_render_text(title, sections, project))
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename={slug}.txt"
        return resp

    # HTML: self-contained, screenshots inlined as data URIs.
    for sec in sections:
        for scan_list in sec["scans"].values():
            for scan in scan_list:
                for shot in scan["screenshots"]:
                    shot["data_uri"] = _inline_png(shot.get("file"))
    html = render_template("export.html", title=title, sections=sections,
                           project=project)
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={slug}.html"
    return resp


def _scan_config(t):
    """The one-line description of how a task was run, as the pages show it."""
    bits = [t["scan_type"] or "full"]
    for label, key in (("", "engine"), ("discovery ", "discovery"),
                       ("TCP ", "tcp_ports"), ("UDP ", "udp_ports"),
                       ("top ", "top_ports")):
        if t[key]:
            bits.append(f"{label}{t[key]}")
    if t["rate"]:
        bits.append(f"{t['rate']} pkts/s")
    return " · ".join(bits)


def _render_text(title, sections, project):
    """Plain text, carrying what the HTML report carries.

    The finding lines keep the shape 'ip:port (proto/state)  service' — this is
    the format people pipe into grep and cut, so it stays stable even as the
    surrounding report grows.
    """
    out = [f"# {title}"]
    if project:
        if project["client"]:
            out.append(f"client: {project['client']}")
        out.append(f"project created {project['created_at']}")
        if project["description"]:
            out.append(project["description"])

    hosts = sum(len(s["hosts"]) for s in sections)
    ports = sum(len(h["ports"]) for s in sections for h in s["hosts"])
    out += ["", f"{len(sections)} task(s) · {hosts} host(s) · "
                f"{ports} open/filtered port(s)"]

    for sec in sections:
        t = sec["task"]
        out += ["", "=" * 72, f"## {t['name']}", ""]
        meta = [("target", t["target"]), ("status", t["status"]),
                ("scan", _scan_config(t)), ("started", t["started_at"]),
                ("finished", t["finished_at"]), ("notes", t["notes"]),
                ("error", t["error"])]
        out += [f"   {k:<10} {v}" for k, v in meta if v]
        out.append("")

        if not sec["hosts"]:
            out.append("   (no hosts with open ports were found by this task)")
            continue

        for host in sec["hosts"]:
            if not host["ports"]:
                out.append(f"{host['ip']}  (up — no open ports recorded)")
            for p in host["ports"]:
                svc = f"  {p['service']}" if p.get("service") else ""
                out.append(
                    f"{host['ip']}:{p['port']} ({p['proto']}/{p['state']}){svc}")

            for scan in sec["scans"].get(host["ip"], []):
                out += ["", f"   nmap · {scan['tool']} · {scan['created_at']}",
                        f"   $ {scan['command']}"]
                for shot in scan["screenshots"]:
                    out.append(f"   screenshot: {shot.get('url', '')}")
                out += ["   " + "-" * 60]
                out += ["   " + ln for ln in
                        (scan["raw_output"] or "").rstrip().splitlines()]
                out += ["   " + "-" * 60, ""]
    return "\n".join(out) + "\n"


def _inline_png(fname):
    if not fname:
        return None
    path = os.path.join(SHOTS_DIR, os.path.basename(fname))
    try:
        with open(path, "rb") as fh:
            return "data:image/png;base64," + base64.b64encode(fh.read()).decode()
    except OSError:
        return None


def _loads(value):
    try:
        return json.loads(value or "[]")
    except (ValueError, TypeError):
        return []
