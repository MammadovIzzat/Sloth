"""Query layer for projects, tasks and findings.

Every function opens and closes its own connection, so these are safe to call
from the scan worker threads as well as from request handlers.
"""
import json
import os
import shutil

from .config import RUNS_DIR, SHOTS_DIR
from .db import connect, new_id, now


def _purge_files(task_ids):
    """Deletes the on-disk artefacts of tasks whose rows are going away.

    Row deletion cascades, but the run directories and captured screenshots used
    to be left behind forever, so a busy install slowly filled up with orphans.
    """
    for task_id in task_ids:
        conn = connect()
        try:
            rows = conn.execute(
                "SELECT screenshots_json FROM nmap_scans WHERE task_id = ?",
                (task_id,)).fetchall()
        finally:
            conn.close()
        for row in rows:
            try:
                shots = json.loads(row["screenshots_json"] or "[]")
            except (ValueError, TypeError):
                continue
            for shot in shots:
                name = os.path.basename(shot.get("file") or "")
                if name:
                    try:
                        os.remove(os.path.join(SHOTS_DIR, name))
                    except OSError:
                        pass
        run_dir = os.path.join(RUNS_DIR, task_id)
        if os.path.isdir(run_dir):
            shutil.rmtree(run_dir, ignore_errors=True)


# --- projects ------------------------------------------------------------

def create_project(name, client=None, description=None):
    pid = new_id()
    ts = now()
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO projects (id, name, client, description, status, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (pid, name.strip(), (client or "").strip() or None,
             (description or "").strip() or None, "active", ts, ts),
        )
        conn.commit()
    finally:
        conn.close()
    return pid


def update_project(project_id, **fields):
    allowed = {"name", "client", "description", "status"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    sets["updated_at"] = now()
    clause = ", ".join(f"{k} = ?" for k in sets)
    conn = connect()
    try:
        conn.execute(f"UPDATE projects SET {clause} WHERE id = ?",
                     (*sets.values(), project_id))
        conn.commit()
    finally:
        conn.close()


def delete_project(project_id):
    conn = connect()
    try:
        task_ids = [r["id"] for r in conn.execute(
            "SELECT id FROM tasks WHERE project_id = ?", (project_id,))]
    finally:
        conn.close()
    _purge_files(task_ids)
    conn = connect()
    try:
        conn.execute("DELETE FROM nmap_scans WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        conn.commit()
    finally:
        conn.close()


def get_project(project_id):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    finally:
        conn.close()


def list_projects(status=None):
    """Projects with rolled-up task/host/port counts for the dashboard."""
    sql = """
        SELECT p.*,
               (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count,
               (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id
                                               AND t.status = 'running') AS running_count,
               (SELECT COUNT(*) FROM (
                    SELECT f.ip FROM findings f JOIN tasks t ON t.id = f.task_id
                      WHERE t.project_id = p.id
                    UNION
                    SELECT h.ip FROM hosts h JOIN tasks t ON t.id = h.task_id
                      WHERE t.project_id = p.id
                )) AS host_count,
               -- Distinct host/port/proto: one port found by both masscan and
               -- nmap is two rows but one finding, and must not be counted twice.
               (SELECT COUNT(DISTINCT f.ip || '/' || f.proto || '/' || f.port) FROM findings f
                  JOIN tasks t ON t.id = f.task_id WHERE t.project_id = p.id) AS finding_count
        FROM projects p
    """
    params = ()
    if status:
        sql += " WHERE p.status = ?"
        params = (status,)
    sql += " ORDER BY p.updated_at DESC"
    conn = connect()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def get_or_create_project(name, description=None):
    conn = connect()
    try:
        row = conn.execute("SELECT id FROM projects WHERE name = ?", (name,)).fetchone()
        if row:
            return row["id"]
    finally:
        conn.close()
    return create_project(name, description=description)


# --- tasks ---------------------------------------------------------------

def create_task(project_id, target, name=None, tcp_ports=None, udp_ports=None,
                rate=None, notes=None, scan_type="full", discovery=None,
                top_ports=None, retries=None, wait=None, engine="masscan"):
    tid = new_id()
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO tasks (id, project_id, name, target, tcp_ports, udp_ports, rate,"
            " status, created_at, notes, scan_type, discovery, top_ports, retries, wait,"
            " engine) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, project_id, (name or "").strip() or target, target,
             tcp_ports, udp_ports, rate, "pending", now(), notes,
             scan_type, discovery, top_ports, retries, wait, engine),
        )
        conn.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now(), project_id))
        conn.commit()
    finally:
        conn.close()
    return tid


def update_task(task_id, **fields):
    allowed = {"name", "status", "progress", "started_at", "finished_at",
               "error", "notes", "resumable", "tcp_ports", "udp_ports", "rate",
               "scan_type", "discovery", "top_ports", "retries", "wait", "engine"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    clause = ", ".join(f"{k} = ?" for k in sets)
    conn = connect()
    try:
        conn.execute(f"UPDATE tasks SET {clause} WHERE id = ?", (*sets.values(), task_id))
        conn.execute(
            "UPDATE projects SET updated_at = ?"
            " WHERE id = (SELECT project_id FROM tasks WHERE id = ?)", (now(), task_id))
        conn.commit()
    finally:
        conn.close()


def delete_task(task_id):
    _purge_files([task_id])
    conn = connect()
    try:
        conn.execute("DELETE FROM nmap_scans WHERE task_id = ?", (task_id,))
        conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
    finally:
        conn.close()


def get_task(task_id):
    conn = connect()
    try:
        return conn.execute(
            "SELECT t.*, p.name AS project_name FROM tasks t"
            " JOIN projects p ON p.id = t.project_id WHERE t.id = ?", (task_id,)).fetchone()
    finally:
        conn.close()


def list_tasks(project_id):
    conn = connect()
    try:
        return conn.execute("""
            SELECT t.*,
                   -- Hosts with open ports plus any discovery found alive.
                   (SELECT COUNT(*) FROM (
                        SELECT ip FROM findings WHERE task_id = t.id
                        UNION SELECT ip FROM hosts WHERE task_id = t.id
                    )) AS host_count,
                   -- Distinct host/port/proto, so a masscan hit later confirmed
                   -- by nmap counts once rather than twice.
                   (SELECT COUNT(DISTINCT f.ip || '/' || f.proto || '/' || f.port)
                      FROM findings f WHERE f.task_id = t.id) AS finding_count
            FROM tasks t WHERE t.project_id = ? ORDER BY t.created_at DESC
        """, (project_id,)).fetchall()
    finally:
        conn.close()


def running_tasks():
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM tasks WHERE status IN ('running','paused')").fetchall()
    finally:
        conn.close()


def reset_stale_tasks():
    """Called at startup: a task marked running can't have survived a restart."""
    conn = connect()
    try:
        conn.execute(
            "UPDATE tasks SET status = 'interrupted', error = ?"
            " WHERE status IN ('running','paused')",
            ("Server restarted while this task was running.",))
        conn.commit()
    finally:
        conn.close()


# --- discovered hosts ----------------------------------------------------

def add_hosts(task_id, hosts, method=None):
    """Records hosts a discovery probe found alive. Returns the new ones."""
    if not hosts:
        return []
    ts = now()
    fresh = []
    conn = connect()
    try:
        for h in hosts:
            ip = h.get("ip")
            if not ip:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO hosts"
                " (task_id, ip, state, method, reason, hostname, latency, found_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (task_id, ip, h.get("state") or "up", method, h.get("reason"),
                 h.get("hostname"), h.get("latency"), ts),
            )
            if cur.rowcount:
                fresh.append(h)
        conn.commit()
    finally:
        conn.close()
    return fresh


def live_hosts(task_id):
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM hosts WHERE task_id = ? AND state = 'up'",
            (task_id,)).fetchall()
    finally:
        conn.close()
    return sorted((dict(r) for r in rows), key=lambda r: _ip_sort_key(r["ip"]))


def clear_hosts(task_id):
    conn = connect()
    try:
        conn.execute("DELETE FROM hosts WHERE task_id = ?", (task_id,))
        conn.commit()
    finally:
        conn.close()


def host_count(task_id):
    conn = connect()
    try:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM hosts WHERE task_id = ?",
            (task_id,)).fetchone()["n"]
    finally:
        conn.close()


# --- findings ------------------------------------------------------------

def add_findings(task_id, ip, ports, source="masscan"):
    """Insert ports for a host. Returns the rows that were actually new."""
    if not ports:
        return []
    ts = now()
    fresh = []
    conn = connect()
    try:
        for p in ports:
            try:
                port = int(p["port"])
            except (KeyError, TypeError, ValueError):
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO findings"
                " (task_id, ip, port, proto, state, service, source, found_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (task_id, ip, port, p.get("proto") or "tcp", p.get("state") or "open",
                 p.get("service"), source, ts),
            )
            if cur.rowcount:
                fresh.append(p)
            elif p.get("service"):
                # Same port seen again but now with service detail — keep the richer row.
                conn.execute(
                    "UPDATE findings SET service = ?, state = ? WHERE task_id = ?"
                    " AND ip = ? AND port = ? AND proto = ? AND source = ?",
                    (p.get("service"), p.get("state") or "open", task_id, ip, port,
                     p.get("proto") or "tcp", source),
                )
        conn.commit()
    finally:
        conn.close()
    return fresh


def replace_findings(task_id, ip, ports, source):
    """Swap out one source's findings for a host (used by rescans)."""
    conn = connect()
    try:
        conn.execute("DELETE FROM findings WHERE task_id = ? AND ip = ? AND source = ?",
                     (task_id, ip, source))
        conn.commit()
    finally:
        conn.close()
    return add_findings(task_id, ip, ports, source=source)


def task_findings(task_id):
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM findings WHERE task_id = ?"
            " ORDER BY ip, proto, port", (task_id,)).fetchall()
    finally:
        conn.close()


def task_hosts(task_id):
    """Hosts for a task, with their ports.

    Includes addresses that discovery proved alive but which have no open ports,
    so a discovery-only run still has something to show.
    """
    rows = task_findings(task_id)
    hosts = {}
    for r in rows:
        hosts.setdefault(r["ip"], []).append(dict(r))

    discovered = {h["ip"]: h for h in live_hosts(task_id)}
    for ip in discovered:
        hosts.setdefault(ip, [])

    result = []
    for ip in sorted(hosts, key=_ip_sort_key):
        best = {}
        for f in hosts[ip]:
            key = (f["port"], f["proto"])
            prior = best.get(key)
            # nmap rows carry the service label, so let them win over masscan.
            if prior is None or (f["source"] == "nmap" and prior["source"] != "nmap"):
                best[key] = f
        entry = {"ip": ip,
                 "ports": sorted(best.values(), key=lambda f: (f["proto"], f["port"]))}
        found = discovered.get(ip)
        if found:
            entry["hostname"] = found.get("hostname")
            entry["discovered_by"] = found.get("method")
            entry["reason"] = found.get("reason")
        result.append(entry)
    return result


def project_hosts(project_id):
    """Every host in the project, with each port listed once.

    Overlapping tasks (or a masscan sweep followed by an nmap rescan) can report
    the same port more than once; those are merged, keeping the nmap row for its
    service detail and noting every task that saw it.
    """
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT f.*, t.name AS task_name, t.id AS tid FROM findings f"
            " JOIN tasks t ON t.id = f.task_id WHERE t.project_id = ?"
            " ORDER BY f.ip, f.proto, f.port", (project_id,)).fetchall()
    finally:
        conn.close()

    hosts = {}
    for r in rows:
        by_port = hosts.setdefault(r["ip"], {})
        key = (r["port"], r["proto"])
        prior = by_port.get(key)
        if prior is None:
            entry = dict(r)
            entry["tasks"] = [r["task_name"]]
            by_port[key] = entry
            continue
        if r["task_name"] not in prior["tasks"]:
            prior["tasks"].append(r["task_name"])
        # An nmap row carries the service label, so let it win.
        if r["source"] == "nmap" and prior["source"] != "nmap":
            tasks = prior["tasks"]
            entry = dict(r)
            entry["tasks"] = tasks
            by_port[key] = entry

    return [{"ip": ip,
             "ports": sorted(hosts[ip].values(), key=lambda f: (f["proto"], f["port"]))}
            for ip in sorted(hosts, key=_ip_sort_key)]


def _ip_sort_key(ip):
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (99, ip)


# --- nmap scans ----------------------------------------------------------

def save_nmap_scan(scan_id, ip, tool, command, raw_output, ports, shots,
                   task_id=None, project_id=None):
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO nmap_scans (id, ip, tool, created_at, command, raw_output,"
            " ports_json, screenshots_json, task_id, project_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (scan_id, ip, tool, now(), command, raw_output,
             json.dumps(ports), json.dumps(shots), task_id, project_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_nmap_scan(scan_id):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM nmap_scans WHERE id = ?", (scan_id,)).fetchone()
    finally:
        conn.close()


def list_nmap_scans(task_id=None, project_id=None, ip=None):
    sql = ("SELECT n.id, n.ip, n.tool, n.created_at, n.task_id, n.project_id,"
           " n.screenshots_json, t.name AS task_name, p.name AS project_name"
           " FROM nmap_scans n"
           " LEFT JOIN tasks t ON t.id = n.task_id"
           " LEFT JOIN projects p ON p.id = n.project_id")
    where, params = [], []
    if task_id:
        where.append("n.task_id = ?"); params.append(task_id)
    if project_id:
        where.append("n.project_id = ?"); params.append(project_id)
    if ip:
        where.append("n.ip = ?"); params.append(ip)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY n.created_at DESC"
    conn = connect()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()
