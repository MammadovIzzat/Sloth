"""SQLite connection handling, schema and migrations.

The database predates the project system, so init_db() is written to upgrade an
existing scans.db in place: it adds the new tables, backfills the new columns on
nmap_scans, and files any pre-existing scans under a "Legacy scans" project so
nothing is orphaned.
"""
import os
import sqlite3
import threading
import uuid
from datetime import datetime

from .config import DB_PATH

_init_lock = threading.Lock()
_initialised = False


class DatabaseUnavailable(RuntimeError):
    """Raised at startup when scans.db cannot be opened for writing."""


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def new_id():
    return uuid.uuid4().hex[:12]


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    client      TEXT,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT,
    target      TEXT NOT NULL,
    tcp_ports   TEXT,
    udp_ports   TEXT,
    rate        INTEGER,
    status      TEXT NOT NULL DEFAULT 'pending',
    progress    REAL NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    error       TEXT,
    notes       TEXT,
    resumable   INTEGER NOT NULL DEFAULT 0
);

-- Hosts proven alive by a discovery probe. Separate from findings because a
-- host can be up with no open ports, and a discovery-only task has nothing else
-- to record.
CREATE TABLE IF NOT EXISTS hosts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id  TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    ip       TEXT NOT NULL,
    state    TEXT NOT NULL DEFAULT 'up',
    method   TEXT,
    reason   TEXT,
    hostname TEXT,
    latency  TEXT,
    found_at TEXT NOT NULL,
    UNIQUE (task_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_hosts_task ON hosts(task_id);

CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id  TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    ip       TEXT NOT NULL,
    port     INTEGER NOT NULL,
    proto    TEXT NOT NULL,
    state    TEXT,
    service  TEXT,
    source   TEXT NOT NULL DEFAULT 'masscan',
    found_at TEXT NOT NULL,
    UNIQUE (task_id, ip, port, proto, source)
);

CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_findings_ip   ON findings(task_id, ip);
CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id);

CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    api_token_hash TEXT,
    created_at     TEXT NOT NULL,
    last_login     TEXT,
    is_active      INTEGER NOT NULL DEFAULT 1
);

-- Scan activity worth telling someone about. In the database rather than in
-- memory so closing a toast does not lose it and a restart does not either:
-- coming back to read what a long sweep did overnight is the point.
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    level      TEXT NOT NULL DEFAULT 'info',   -- info | good | warn | bad
    title      TEXT NOT NULL,
    message    TEXT,
    task_id    TEXT,
    project_id TEXT,
    seen       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_notifications_time ON notifications(created_at DESC);

CREATE TABLE IF NOT EXISTS nmap_scans (
    id               TEXT PRIMARY KEY,
    ip               TEXT NOT NULL,
    tool             TEXT,
    created_at       TEXT NOT NULL,
    command          TEXT,
    raw_output       TEXT,
    ports_json       TEXT,
    screenshots_json TEXT
);
"""

# Columns added after the original release, per table.
ADDED_COLUMNS = {
    "nmap_scans": {
        "screenshots_json": "TEXT",
        "task_id": "TEXT",
        "project_id": "TEXT",
    },
    "tasks": {
        # 'full' (masscan sweep), 'discovery' (find live hosts only) or
        # 'quick' (nmap top-ports, no masscan).
        "scan_type": "TEXT NOT NULL DEFAULT 'full'",
        "discovery": "TEXT",          # discovery profile key, NULL = skip
        "top_ports": "INTEGER",       # how many top ports a quick scan covers
        "retries": "INTEGER",         # masscan --retries; 0 loses ports to packet loss
        "wait": "INTEGER",            # masscan --wait, seconds to listen after sending
        # Which port scanner runs a 'full' scan: masscan, nmap or rustscan.
        # masscan cannot traverse IPsec/VPN tunnels, so the choice matters.
        "engine": "TEXT NOT NULL DEFAULT 'masscan'",
        # Which protocols a 'quick' nmap scan covers: tcp, udp or both. UDP
        # needs root, which this build has anyway.
        "quick_proto": "TEXT NOT NULL DEFAULT 'tcp'",
    },
}


def _columns(conn, table):
    return [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]


def _migrate(conn):
    for table, columns in ADDED_COLUMNS.items():
        existing = _columns(conn, table)
        for col, coltype in columns.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")

    # File any pre-project scans under a Legacy project so every scan is reachable
    # from the project UI. Only runs when such rows actually exist.
    orphans = conn.execute(
        "SELECT COUNT(*) AS n FROM nmap_scans WHERE project_id IS NULL"
    ).fetchone()["n"]
    if not orphans:
        return

    row = conn.execute(
        "SELECT id FROM projects WHERE name = 'Legacy scans'"
    ).fetchone()
    if row:
        project_id = row["id"]
    else:
        project_id = new_id()
        conn.execute(
            "INSERT INTO projects (id, name, client, description, status, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (project_id, "Legacy scans", None,
             "Nmap scans saved before projects existed. Imported automatically.",
             "active", now(), now()),
        )

    task_row = conn.execute(
        "SELECT id FROM tasks WHERE project_id = ? AND name = 'Imported scans'",
        (project_id,),
    ).fetchone()
    if task_row:
        task_id = task_row["id"]
    else:
        task_id = new_id()
        conn.execute(
            "INSERT INTO tasks (id, project_id, name, target, tcp_ports, udp_ports, rate,"
            " status, created_at, finished_at, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (task_id, project_id, "Imported scans", "(imported)", None, None, None,
             "completed", now(), now(),
             "Placeholder task holding nmap scans that predate the project system."),
        )

    conn.execute(
        "UPDATE nmap_scans SET project_id = ?, task_id = ? WHERE project_id IS NULL",
        (project_id, task_id),
    )

    # Rebuild findings for the imported scans so they show up in the project views.
    import json
    rows = conn.execute(
        "SELECT id, ip, ports_json FROM nmap_scans WHERE task_id = ?", (task_id,)
    ).fetchall()
    for r in rows:
        try:
            ports = json.loads(r["ports_json"] or "[]")
        except (ValueError, TypeError):
            continue
        for p in ports:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO findings"
                    " (task_id, ip, port, proto, state, service, source, found_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (task_id, r["ip"], int(p["port"]), p.get("proto") or "tcp",
                     p.get("state"), p.get("service"), "nmap", now()),
                )
            except (KeyError, TypeError, ValueError):
                continue


def init_db():
    global _initialised
    with _init_lock:
        if _initialised:
            return
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        try:
            conn = connect()
        except sqlite3.OperationalError as exc:
            raise DatabaseUnavailable(_perm_hint(exc)) from exc
        try:
            # WAL lets the UI read findings while a scan is still writing them.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            _migrate(conn)
            conn.commit()
        except sqlite3.OperationalError as exc:
            raise DatabaseUnavailable(_perm_hint(exc)) from exc
        finally:
            conn.close()
        _initialised = True


def _perm_hint(exc):
    msg = str(exc)
    if "readonly" in msg or "unable to open" in msg or "permission" in msg.lower():
        return (f"Cannot write {DB_PATH} ({msg}). The database is usually owned by "
                f"root because this tool runs under sudo — start it the same way "
                f"('sudo python scanner.py'), or point SLOTH_DB at a writable file.")
    return f"Database error on {DB_PATH}: {msg}"
