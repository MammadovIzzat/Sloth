"""Project and task management: the entry point into the tool."""
from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)

from .. import store
from ..config import (DEFAULT_DISCOVERY, DEFAULT_ENGINE, DEFAULT_RATE,
                      DEFAULT_RETRIES, DEFAULT_TCP_PORTS, DEFAULT_TOP_PORTS,
                      DEFAULT_UDP_PORTS)
from ..discovery import profiles_for_ui
from ..engine import ScanError, manager
from ..netutil import apply_start_ip, count_targets, normalize_target
from ..scanconfig import ENGINES, SCAN_TYPES, parse_scan_config

bp = Blueprint("projects", __name__)

QUICK_PROJECT = "Quick scans"


@bp.route("/")
def index():
    # Archived projects are hidden by default — the status used to be cosmetic,
    # leaving finished engagements cluttering the dashboard forever.
    show = request.args.get("show", "active")
    status = None if show == "all" else ("archived" if show == "archived" else "active")
    projects = store.list_projects(status=status)
    return render_template(
        "projects.html",
        nav_section="projects",
        projects=projects,
        show=show,
        archived_count=len(store.list_projects(status="archived")),
        active_task=manager.active_task,
    )


@bp.route("/projects", methods=["POST"])
def create_project():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("A project needs a name.", "error")
        return redirect(url_for("projects.index"))
    pid = store.create_project(name,
                               client=request.form.get("client"),
                               description=request.form.get("description"))
    return redirect(url_for("projects.project_detail", project_id=pid))


@bp.route("/projects/<project_id>")
def project_detail(project_id):
    project = store.get_project(project_id)
    if project is None:
        abort(404)
    return render_template(
        "project.html",
        nav_section="projects",
        current_project_id=project_id,
        project=project,
        tasks=store.list_tasks(project_id),
        hosts=store.project_hosts(project_id),
        nmap_scans=store.list_nmap_scans(project_id=project_id),
        active_task=manager.active_task,
        scan_types=SCAN_TYPES,
        engines=ENGINES,
        discovery_profiles=profiles_for_ui(),
        defaults={"tcp": DEFAULT_TCP_PORTS, "udp": DEFAULT_UDP_PORTS,
                  "rate": DEFAULT_RATE, "top_ports": DEFAULT_TOP_PORTS,
                  "discovery": DEFAULT_DISCOVERY, "retries": DEFAULT_RETRIES,
                  "engine": DEFAULT_ENGINE},
    )


@bp.route("/projects/<project_id>/edit", methods=["POST"])
def edit_project(project_id):
    if store.get_project(project_id) is None:
        abort(404)
    store.update_project(project_id,
                         name=(request.form.get("name") or "").strip() or None,
                         client=request.form.get("client"),
                         description=request.form.get("description"),
                         status=request.form.get("status"))
    return redirect(url_for("projects.project_detail", project_id=project_id))


@bp.route("/projects/<project_id>/delete", methods=["POST"])
def delete_project(project_id):
    store.delete_project(project_id)
    flash("Project deleted.", "ok")
    return redirect(url_for("projects.index"))


@bp.route("/projects/<project_id>/tasks", methods=["POST"])
def create_task(project_id):
    if store.get_project(project_id) is None:
        abort(404)
    try:
        task_id = _create_task_from_form(project_id, request.form)
    except (ScanError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("projects.project_detail", project_id=project_id))

    if request.form.get("start_now"):
        return redirect(url_for("scan.task_detail", task_id=task_id, autostart=1))
    return redirect(url_for("scan.task_detail", task_id=task_id))


@bp.route("/quick-scan", methods=["POST"])
def quick_scan():
    """Old-style one-shot scan: files itself under a 'Quick scans' project."""
    project_id = store.get_or_create_project(
        QUICK_PROJECT, description="Ad-hoc scans started from the dashboard.")
    try:
        task_id = _create_task_from_form(project_id, request.form)
    except (ScanError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("projects.index"))
    return redirect(url_for("scan.task_detail", task_id=task_id, autostart=1))


@bp.route("/tasks/<task_id>/delete", methods=["POST"])
def delete_task(task_id):
    task = store.get_task(task_id)
    if task is None:
        abort(404)
    project_id = task["project_id"]
    store.delete_task(task_id)
    flash("Task deleted.", "ok")
    return redirect(url_for("projects.project_detail", project_id=project_id))


def _create_task_from_form(project_id, form):
    """Shared by the project page and the dashboard quick-scan box."""
    target = normalize_target(form.get("target") or "")
    target = apply_start_ip(target, (form.get("start_octet") or "").strip())
    config = parse_scan_config(form, target)

    hosts = count_targets(target)
    # The name describes the target, not the first scan run against it — the
    # same task can later be re-run with a different engine or scan type.
    default_name = target + (f" ({hosts} hosts)" if hosts and hosts > 1 else "")

    return store.create_task(
        project_id, target,
        name=(form.get("name") or "").strip() or default_name,
        notes=(form.get("notes") or "").strip() or None,
        **config,
    )
