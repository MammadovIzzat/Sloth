"""Scan notifications, and the log that outlives them.

A sweep can run for an hour, and sitting on the task page watching it is not how
anyone works. The interesting moments — it started, discovery found this many
hosts, it finished with this many ports, a rescan turned up something new, the
network dropped — are raised wherever you happen to be.

Every one is written to the database first and shown second, so dismissing a
toast hides it without destroying the record. Notifications are derived from the
events the engine already publishes, through a single event tap, rather than
raised by hand at each call site — so a new event cannot quietly go unreported
and the engine keeps knowing nothing about the interface.
"""
import queue
import threading

from . import store
from .db import connect, now

_LEVELS = {"info", "good", "warn", "bad"}

# Global pub/sub for the notification SSE stream. Not per-task like the scan
# stream: a toast should reach you whatever page you are on.
_lock = threading.Lock()
_subs = []


def subscribe():
    q = queue.Queue(maxsize=500)
    with _lock:
        _subs.append(q)
    return q


def unsubscribe(q):
    with _lock:
        if q in _subs:
            _subs.remove(q)


def _broadcast(row):
    with _lock:
        subs = list(_subs)
    for q in subs:
        try:
            q.put_nowait(row)
        except queue.Full:
            pass


# --- storage -------------------------------------------------------------

def record(level, title, message=None, task_id=None, project_id=None):
    """Writes one notification and announces it. Returns the stored row."""
    level = level if level in _LEVELS else "info"
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO notifications (created_at, level, title, message, task_id,"
            " project_id, seen) VALUES (?,?,?,?,?,?,0)",
            (now(), level, str(title), message, task_id, project_id))
        conn.commit()
        row = conn.execute("SELECT * FROM notifications WHERE id = ?",
                           (cur.lastrowid,)).fetchone()
    finally:
        conn.close()
    _broadcast(dict(row))
    return row


def list_notifications(limit=200, unseen_only=False):
    conn = connect()
    try:
        sql = "SELECT * FROM notifications"
        if unseen_only:
            sql += " WHERE seen = 0"
        sql += " ORDER BY id DESC LIMIT ?"
        return conn.execute(sql, (limit,)).fetchall()
    finally:
        conn.close()


def unseen_count():
    conn = connect()
    try:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM notifications WHERE seen = 0").fetchone()["n"]
    finally:
        conn.close()


def mark_seen(notification_id=None):
    """Marking as seen only clears the badge — the entry stays in the log."""
    conn = connect()
    try:
        if notification_id is None:
            conn.execute("UPDATE notifications SET seen = 1")
        else:
            conn.execute("UPDATE notifications SET seen = 1 WHERE id = ?",
                        (notification_id,))
        conn.commit()
    finally:
        conn.close()
    return unseen_count()


def clear():
    """Deletes history. Separate from mark_seen because they differ in intent."""
    conn = connect()
    try:
        conn.execute("DELETE FROM notifications")
        conn.commit()
    finally:
        conn.close()
    return 0


# --- deriving notifications from scan events ------------------------------

def _label(task_id):
    if not task_id:
        return None, None
    task = store.get_task(task_id)
    return (task["name"], task["project_id"]) if task else (None, None)


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def from_scan_event(task_id, event):
    """Translates one engine event into a notification, or nothing.

    Deliberately quiet: log lines, progress ticks and per-port discoveries are
    far too frequent to raise. A notification that arrives hundreds of times an
    hour trains you to ignore all of them, including the one that mattered.
    """
    if not isinstance(event, dict):
        return None
    etype = event.get("type")
    name, project_id = _label(task_id)
    name = name or "a task"
    where = {"task_id": task_id, "project_id": project_id}

    if etype == "phase":
        phase = event.get("phase")
        if phase == "discovery":
            return record("info", f"Scan started — {name}",
                          f"Host discovery with {event.get('label') or event.get('tool')}.",
                          **where)
        if phase == "portscan":
            return record("info", f"Port scan started — {name}",
                          f"Scanning with {event.get('tool')}.", **where)
        return None

    if etype == "discovery_done":
        count = event.get("count") or 0
        return record("good" if count else "warn", f"Discovery finished — {name}",
                      f"{_plural(count, 'host')} answered." if count
                      else "No hosts answered. The port scan will cover the whole range.",
                      **where)

    if etype == "done":
        status = event.get("status")
        good = status == "completed"
        level = "good" if good else ("bad" if status == "error" else "warn")
        msg = (f"{_plural(event.get('hosts') or 0, 'host')}, "
               f"{_plural(event.get('ports') or 0, 'open port')}." if good
               else (event.get("error") or f"Finished as {status}."))
        return record(level, f"Scan {status} — {name}", msg, **where)

    if etype == "rescan":
        state = event.get("state")
        if state == "done":
            fresh = event.get("new_ports") or 0
            shots = event.get("screenshots") or 0
            body = (f"{_plural(fresh, 'new port')} found by {event.get('tool')}."
                    if fresh else
                    f"No new ports; {event.get('tool')} confirmed "
                    f"{_plural(len(event.get('ports') or []), 'port')}.")
            if shots:
                body += f" {_plural(shots, 'screenshot')}."
            return record("good" if fresh else "info",
                          f"Rescan finished — {event.get('ip')}", body, **where)
        if state == "error":
            return record("bad", f"Rescan failed — {event.get('ip')}",
                          event.get("error"), **where)
        return None      # 'running' and 'cancelled' are visible on the page

    if etype == "network":
        connected = event.get("connected")
        return record("good" if connected else "warn",
                      "Network restored" if connected else "Waiting — network lost",
                      event.get("message"), **where)

    if etype == "status" and event.get("status") == "interrupted":
        return record("warn", f"Scan interrupted — {name}", event.get("message"),
                      **where)

    return None


def attach(manager):
    """Wires the tap so every scan event becomes a notification where apt."""
    manager.add_event_tap(from_scan_event)
