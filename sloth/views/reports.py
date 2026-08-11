"""Saved nmap reports, screenshots, and exports.

The old export dumped whatever masscan happened to have in memory. These pull
from the database instead, so an export covers everything a task or project ever
found: masscan ports, nmap-detected services, the raw nmap output and the
screenshots, embedded so the HTML file stands alone.
"""
import base64
import json
import os

from flask import (Blueprint, abort, jsonify, make_response, render_template,
                   request, send_file)

from .. import store
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
    # Capped so a long-running install doesn't render thousands of rows at once.
    all_scans = store.list_nmap_scans()
    limit = SCANS_PAGE_SIZE
    if request.args.get("all"):
        limit = len(all_scans)
    return render_template("scans.html", nav_section="scans", scans=all_scans[:limit],
                           total=len(all_scans), truncated=len(all_scans) > limit)


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
        payload = {"title": title, "project": dict(project) if project else None,
                   "tasks": sections}
        resp = make_response(json.dumps(payload, indent=2, default=str))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = f"attachment; filename={slug}.json"
        return resp

    if fmt == "txt":
        lines = [f"# {title}", ""]
        for sec in sections:
            t = sec["task"]
            lines.append(f"## Task: {t['name']}  [{t['target']}]  status={t['status']}")
            if not sec["hosts"]:
                lines.append("   (no hosts found)")
            for host in sec["hosts"]:
                for p in host["ports"]:
                    svc = f"  {p['service']}" if p.get("service") else ""
                    lines.append(
                        f"{host['ip']}:{p['port']} ({p['proto']}/{p['state']}){svc}")
            lines.append("")
        resp = make_response("\n".join(lines))
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
