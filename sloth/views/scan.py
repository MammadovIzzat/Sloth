"""Running a task: live SSE stream, pause/resume/stop, per-host rescans."""
import json
import os
import queue

from flask import (Blueprint, Response, abort, jsonify, render_template,
                   request, stream_with_context)

from .. import store
from ..discovery import get_profile, profiles_for_ui
from ..engine import (ScanBusy, ScanError, manager, paused_conf_path, read_log,
                      rescan_tools_for_ui)
from ..netutil import count_targets, is_valid_ip
from ..procs import registry
from ..scanconfig import ENGINES, QUICK_PROTOCOLS, SCAN_TYPES, parse_scan_config

bp = Blueprint("scan", __name__)


@bp.route("/tasks/<task_id>")
def task_detail(task_id):
    task = store.get_task(task_id)
    if task is None:
        abort(404)
    return render_template(
        "task.html",
        nav_section="projects",
        current_project_id=task["project_id"],
        task=task,
        hosts=store.task_hosts(task_id),
        nmap_scans=store.list_nmap_scans(task_id=task_id),
        host_count=count_targets(task["target"]),
        is_active=(manager.active_task == task_id),
        is_paused=registry.is_paused(task_id),
        can_resume=os.path.exists(paused_conf_path(task_id)),
        scan_log=read_log(task_id),
        rescanning=manager.active_rescans(task_id),
        rescan_tools=rescan_tools_for_ui(),
        discovery_label=(profile.label if (profile := get_profile(task["discovery"]))
                         else None),
        scan_types=SCAN_TYPES,
        engines=ENGINES,
        quick_protocols=QUICK_PROTOCOLS,
        discovery_profiles=profiles_for_ui(),
        autostart=bool(request.args.get("autostart")),
    )


@bp.route("/tasks/<task_id>/start", methods=["POST"])
def start_task(task_id):
    """Runs the task, optionally with different scan settings than last time.

    A task is a target, not a single fixed scan: you can sweep the top ports with
    nmap, then come back and run a full masscan over the same host, and both sets
    of findings accumulate against it.
    """
    task = store.get_task(task_id)
    if task is None:
        abort(404)

    payload = request.get_json(silent=True) or {}
    resume = (request.args.get("resume") or "").lower() in ("1", "true", "yes")
    resume = resume or bool(payload.get("resume"))

    if not resume and payload:
        # Persist the chosen settings so the page, the log and a later re-run all
        # agree on what this task is currently configured to do.
        try:
            config = parse_scan_config(payload, task["target"], defaults=dict(task))
        except ScanError as exc:
            return jsonify({"error": str(exc)}), 400
        store.update_task(task_id, **config)

    try:
        manager.start(task_id, resume=resume)
    except ScanBusy as exc:
        return jsonify({"error": str(exc), "busy": True}), 409
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"status": "started", "task_id": task_id, "resumed": resume})


@bp.route("/tasks/<task_id>/pause", methods=["POST"])
def pause_task(task_id):
    signalled = manager.pause(task_id)
    return jsonify({"status": _status(task_id), "signalled": signalled})


@bp.route("/tasks/<task_id>/resume", methods=["POST"])
def resume_task(task_id):
    signalled = manager.resume(task_id)
    return jsonify({"status": _status(task_id), "signalled": signalled})


@bp.route("/tasks/<task_id>/stop", methods=["POST"])
def stop_task(task_id):
    manager.stop(task_id)
    return jsonify({"status": _status(task_id),
                    "resumable": os.path.exists(paused_conf_path(task_id))})


def _status(task_id):
    """The status actually recorded, so the UI never shows a stale badge."""
    task = store.get_task(task_id)
    return task["status"] if task else "unknown"


@bp.route("/tasks/<task_id>/state")
def task_state(task_id):
    task = store.get_task(task_id)
    if task is None:
        abort(404)
    net = manager.network_state()
    return jsonify({
        "status": task["status"],
        "progress": task["progress"],
        "error": task["error"],
        "is_active": manager.active_task == task_id,
        "is_paused": registry.is_paused(task_id),
        "can_resume": os.path.exists(paused_conf_path(task_id)),
        "rescanning": manager.active_rescans(task_id),
        "network": net,
    })


@bp.route("/tasks/<task_id>/stream")
def task_stream(task_id):
    """Server-sent events for a running task.

    The page renders whatever is already in the database first, then subscribes
    here for updates — so reloading mid-scan shows everything found so far
    instead of starting from a blank list like the old build did.
    """
    if store.get_task(task_id) is None:
        abort(404)
    q = manager.subscribe(task_id)

    @stream_with_context
    def generate():
        try:
            yield ": connected\n\n"
            # Open with everything found so far. The browser subscribes a moment
            # after the scan starts, so without this the first discoveries could
            # slip through the gap and only appear on a manual reload.
            yield "data: " + json.dumps({
                "type": "snapshot",
                "hosts": store.task_hosts(task_id),
                "status": _status(task_id),
            }) + "\n\n"
            while True:
                try:
                    event = q.get(timeout=15)
                except queue.Empty:
                    # Stay open even when idle: rescans can start at any time and
                    # need somewhere to report back to.
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            manager.unsubscribe(task_id, q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@bp.route("/tasks/<task_id>/rescan", methods=["POST"])
def rescan(task_id):
    """Kicks off a per-host rescan and returns immediately.

    The result arrives over the task's event stream, so a long nmap run no
    longer holds the request open until the browser gives up on it.
    """
    task = store.get_task(task_id)
    if task is None:
        abort(404)
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    tool = data.get("tool") or "nmap_deep"

    if not ip:
        return jsonify({"error": "IP missing"}), 400
    if not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400
    if tool not in ("nmap_deep", "masscan_tcp", "masscan_udp"):
        return jsonify({"error": f"Unknown tool: {tool}"}), 400

    try:
        manager.start_rescan(ip=ip, tool=tool, task_id=task_id,
                             project_id=task["project_id"])
    except ScanBusy as exc:
        return jsonify({"error": str(exc), "busy": True}), 409
    except ScanError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"status": "started", "ip": ip, "tool": tool}), 202


@bp.route("/tasks/<task_id>/rescan/stop", methods=["POST"])
def stop_rescan(task_id):
    """Stops one host's rescan without touching the sweep or the other hosts."""
    if store.get_task(task_id) is None:
        abort(404)
    ip = (request.get_json(silent=True) or {}).get("ip")
    if not ip or not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP"}), 400
    if not manager.stop_rescan(task_id, ip):
        return jsonify({"error": f"No rescan of {ip} is running.",
                        "running": False}), 409
    return jsonify({"status": "stopping", "ip": ip})


@bp.route("/check-network")
def check_network():
    state = manager.network_state()
    return jsonify({
        "internet_error": state["error"],
        "disconnected_time": state["disconnected_at"],
        "connected_time": state["reconnected_at"],
    })
