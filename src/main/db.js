'use strict'
/** SQLite connection handling, schema and migrations.
 *
 * Ported from db.py, and deliberately schema-compatible with it: an existing
 * scans.db written by the Python build must open here with every project, task
 * and finding intact. The migration below still upgrades a database that
 * predates the project system, for the same reason.
 *
 * One connection, not one per call. The Python opened a connection in every
 * function because scan workers ran on their own threads; here everything
 * shares the main process's single thread, so a shared handle is both correct
 * and considerably faster.
 */
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

const Database = require('better-sqlite3')

const { DB_PATH } = require('./config')

class DatabaseUnavailable extends Error {}

let handle = null

/** 'YYYY-MM-DD HH:MM:SS' in local time, matching the Python's strftime. */
function now () {
  const d = new Date()
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

const newId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 12)

const SCHEMA = `
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

-- Scan activity worth telling someone about. Kept in the database rather than
-- in memory so closing a toast does not lose it and a restart does not either:
-- coming back the next morning to read what a long sweep did overnight is the
-- point of the feature.
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
`

// Columns added after the original release, per table.
const ADDED_COLUMNS = {
  nmap_scans: {
    screenshots_json: 'TEXT',
    task_id: 'TEXT',
    project_id: 'TEXT',
  },
  tasks: {
    // 'full' (masscan sweep), 'discovery' (find live hosts only) or
    // 'quick' (nmap top-ports, no masscan).
    scan_type: "TEXT NOT NULL DEFAULT 'full'",
    discovery: 'TEXT',            // discovery profile key, NULL = skip
    top_ports: 'INTEGER',         // how many top ports a quick scan covers
    retries: 'INTEGER',           // masscan --retries; 0 loses ports to packet loss
    wait: 'INTEGER',              // masscan --wait, seconds to listen after sending
    // Which port scanner runs a 'full' scan: masscan, nmap or rustscan.
    // masscan cannot traverse IPsec/VPN tunnels, so the choice matters.
    engine: "TEXT NOT NULL DEFAULT 'masscan'",
  },
}

const columnsOf = (conn, table) =>
  conn.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name)

function migrate (conn) {
  for (const [table, columns] of Object.entries(ADDED_COLUMNS)) {
    const existing = new Set(columnsOf(conn, table))
    for (const [column, type] of Object.entries(columns)) {
      if (!existing.has(column)) {
        conn.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`).run()
      }
    }
  }

  // File any pre-project scans under a Legacy project so every scan is
  // reachable from the project UI. Only runs when such rows actually exist.
  const orphans = conn.prepare(
    'SELECT COUNT(*) AS n FROM nmap_scans WHERE project_id IS NULL').get().n
  if (!orphans) return

  let projectId
  const existingProject = conn.prepare(
    "SELECT id FROM projects WHERE name = 'Legacy scans'").get()
  if (existingProject) {
    projectId = existingProject.id
  } else {
    projectId = newId()
    conn.prepare(
      'INSERT INTO projects (id, name, client, description, status, created_at, updated_at)' +
      ' VALUES (?,?,?,?,?,?,?)').run(
      projectId, 'Legacy scans', null,
      'Nmap scans saved before projects existed. Imported automatically.',
      'active', now(), now())
  }

  let taskId
  const existingTask = conn.prepare(
    "SELECT id FROM tasks WHERE project_id = ? AND name = 'Imported scans'").get(projectId)
  if (existingTask) {
    taskId = existingTask.id
  } else {
    taskId = newId()
    conn.prepare(
      'INSERT INTO tasks (id, project_id, name, target, tcp_ports, udp_ports, rate,' +
      ' status, created_at, finished_at, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(
      taskId, projectId, 'Imported scans', '(imported)', null, null, null,
      'completed', now(), now(),
      'Placeholder task holding nmap scans that predate the project system.')
  }

  conn.prepare('UPDATE nmap_scans SET project_id = ?, task_id = ? WHERE project_id IS NULL')
    .run(projectId, taskId)

  // Rebuild findings for the imported scans so they show up in the project views.
  const insertFinding = conn.prepare(
    'INSERT OR IGNORE INTO findings (task_id, ip, port, proto, state, service, source, found_at)' +
    ' VALUES (?,?,?,?,?,?,?,?)')
  for (const row of conn.prepare(
    'SELECT id, ip, ports_json FROM nmap_scans WHERE task_id = ?').all(taskId)) {
    let ports
    try {
      ports = JSON.parse(row.ports_json || '[]')
    } catch {
      continue
    }
    if (!Array.isArray(ports)) continue
    for (const port of ports) {
      const number = Number.parseInt(port && port.port, 10)
      if (!Number.isFinite(number)) continue
      insertFinding.run(taskId, row.ip, number, port.proto || 'tcp',
        port.state ?? null, port.service ?? null, 'nmap', now())
    }
  }
}

function permissionHint (err) {
  const message = String(err && err.message)
  if (/readonly|unable to open|permission/i.test(message)) {
    return `Cannot write ${DB_PATH} (${message}). The database may be owned by ` +
           'another user — a scans.db left behind by the Python build usually ' +
           'belongs to root. Fix its ownership, or point SLOTH_DB at a writable file.'
  }
  return `Database error on ${DB_PATH}: ${message}`
}

/** Opens the database, creating and migrating it as needed. Idempotent. */
function initDb () {
  if (handle) return handle
  try {
    fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true })
    const conn = new Database(DB_PATH)
    // WAL lets the interface read findings while a scan is still writing them.
    conn.pragma('journal_mode = WAL')
    conn.pragma('foreign_keys = ON')
    conn.exec(SCHEMA)
    conn.transaction(() => migrate(conn))()
    handle = conn
    return handle
  } catch (err) {
    throw new DatabaseUnavailable(permissionHint(err))
  }
}

/** The open connection. initDb() must have run first. */
function connect () {
  if (!handle) return initDb()
  return handle
}

function close () {
  if (handle) {
    handle.close()
    handle = null
  }
}

module.exports = { DatabaseUnavailable, initDb, connect, close, now, newId, SCHEMA }
