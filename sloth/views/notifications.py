"""The notification log, its actions, and the global toast stream."""
import json
import queue

from flask import (Blueprint, Response, redirect, render_template, request,
                   stream_with_context, url_for)

from .. import notify

bp = Blueprint("notifications", __name__)


@bp.route("/notifications")
def log():
    rows = notify.list_notifications(limit=200)
    # Opening the log is reading it, so the badge clears — the entries stay.
    notify.mark_seen(None)
    return render_template("notifications.html", nav_section="notifications",
                           notifications=rows)


@bp.route("/notifications/seen", methods=["POST"])
def seen():
    notify.mark_seen(request.form.get("id") or None)
    return redirect(url_for("notifications.log"))


@bp.route("/notifications/clear", methods=["POST"])
def clear():
    notify.clear()
    return redirect(url_for("notifications.log"))


@bp.route("/notifications/stream")
def stream():
    """Server-sent events for toasts, across every page.

    Unlike the per-task scan stream, this is global: a notification should reach
    you wherever you are. The unread count rides along so the sidebar badge can
    update without a second request.
    """
    q = notify.subscribe()

    @stream_with_context
    def generate():
        try:
            yield ": connected\n\n"
            yield "data: " + json.dumps(
                {"type": "count", "unseen": notify.unseen_count()}) + "\n\n"
            while True:
                try:
                    row = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                yield "data: " + json.dumps(
                    {"type": "notification", "notification": row,
                     "unseen": notify.unseen_count()}) + "\n\n"
        finally:
            notify.unsubscribe(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})
