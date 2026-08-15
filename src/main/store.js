'use strict'
/** Query layer for projects, tasks and findings.
 *
 * Ported from store.py. Every SQL statement is unchanged from the Python — the
 * rollup subqueries in particular, where the DISTINCT on ip/proto/port is what
 * keeps a port found by both masscan and nmap from being counted twice.
 */
const fs = require('node:fs')
const path = require('node:path')

const { RUNS_DIR, SHOTS_DIR } = require('./config')
const { connect, newId, now } = require('./db')
const ip = require('./ipaddr')

/** Deletes the on-disk artefacts of tasks whose rows are going away.
 *
 * Row deletion cascades, but the run directories and captured screenshots used
 * to be left behind forever, so a busy install slowly filled up with orphans.
 */
function purgeFiles (taskIds) {
  const db = connect()
  for (const taskId of taskIds) {
    const rows = db.prepare('SELECT screenshots_json FROM nmap_scans WHERE task_id = ?')
      .all(taskId)
    for (const row of rows) {
      let shots
      try {
        shots = JSON.parse(row.screenshots_json || '[]')
      } catch {
        continue
      }
      if (!Array.isArray(shots)) continue
      for (const shot of shots) {
        const name = path.basename(String((shot && shot.file) || ''))
        if (name) {
          try { fs.unlinkSync(path.join(SHOTS_DIR, name)) } catch { /* already gone */ }
        }
      }
    }
    const runDir = path.join(RUNS_DIR, taskId)
    try { fs.rmSync(runDir, { recursive: true, force: true }) } catch { /* already gone */ }
  }
}

// --- projects ------------------------------------------------------------

function createProject (name, client = null, description = null) {
  const id = newId()
  const ts = now()
  connect().prepare(
    'INSERT INTO projects (id, name, client, description, status, created_at, updated_at)' +
    ' VALUES (?,?,?,?,?,?,?)').run(
    id, String(name).trim(),
    String(client || '').trim() || null,
    String(description || '').trim() || null,
    'active', ts, ts)
  return id
}

const PROJECT_FIELDS = new Set(['name', 'client', 'description', 'status'])

function updateProject (projectId, fields) {
  const sets = Object.entries(fields).filter(([key]) => PROJECT_FIELDS.has(key))
  if (!sets.length) return
  sets.push(['updated_at', now()])
  const clause = sets.map(([key]) => `${key} = ?`).join(', ')
  connect().prepare(`UPDATE projects SET ${clause} WHERE id = ?`)
    .run(...sets.map(([, value]) => value), projectId)
}

function deleteProject (projectId) {
  const db = connect()
  const taskIds = db.prepare('SELECT id FROM tasks WHERE project_id = ?')
    .all(projectId).map((row) => row.id)
  purgeFiles(taskIds)
  db.prepare('DELETE FROM nmap_scans WHERE project_id = ?').run(projectId)
  db.prepare('DELETE FROM projects WHERE id = ?').run(projectId)
}

const getProject = (projectId) =>
  connect().prepare('SELECT * FROM projects WHERE id = ?').get(projectId) ?? null

/** Projects with rolled-up task/host/port counts for the dashboard. */
function listProjects (status = null) {
  let sql = `
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
    `
  const params = []
  if (status) {
    sql += ' WHERE p.status = ?'
    params.push(status)
  }
  sql += ' ORDER BY p.updated_at DESC'
  return connect().prepare(sql).all(...params)
}

function getOrCreateProject (name, description = null) {
  const row = connect().prepare('SELECT id FROM projects WHERE name = ?').get(name)
  if (row) return row.id
  return createProject(name, null, description)
}

// --- tasks ---------------------------------------------------------------

function createTask (projectId, target, options = {}) {
  const {
    name = null, tcp_ports = null, udp_ports = null, rate = null, notes = null,
    scan_type = 'full', discovery = null, top_ports = null, retries = null,
    wait = null, engine = 'masscan',
  } = options

  const id = newId()
  const db = connect()
  db.prepare(
    'INSERT INTO tasks (id, project_id, name, target, tcp_ports, udp_ports, rate,' +
    ' status, created_at, notes, scan_type, discovery, top_ports, retries, wait,' +
    ' engine) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
    id, projectId, String(name || '').trim() || target, target,
    tcp_ports, udp_ports, rate, 'pending', now(), notes,
    scan_type, discovery, top_ports, retries, wait, engine)
  db.prepare('UPDATE projects SET updated_at = ? WHERE id = ?').run(now(), projectId)
  return id
}

const TASK_FIELDS = new Set(['name', 'status', 'progress', 'started_at', 'finished_at',
  'error', 'notes', 'resumable', 'tcp_ports', 'udp_ports', 'rate',
  'scan_type', 'discovery', 'top_ports', 'retries', 'wait', 'engine'])

function updateTask (taskId, fields) {
  const sets = Object.entries(fields).filter(([key]) => TASK_FIELDS.has(key))
  if (!sets.length) return
  const db = connect()
  const clause = sets.map(([key]) => `${key} = ?`).join(', ')
  db.prepare(`UPDATE tasks SET ${clause} WHERE id = ?`)
    .run(...sets.map(([, value]) => normalise(value)), taskId)
  db.prepare('UPDATE projects SET updated_at = ?' +
    ' WHERE id = (SELECT project_id FROM tasks WHERE id = ?)').run(now(), taskId)
}

/** better-sqlite3 refuses booleans and undefined; SQLite has neither. */
function normalise (value) {
  if (typeof value === 'boolean') return value ? 1 : 0
  return value === undefined ? null : value
}

function deleteTask (taskId) {
  purgeFiles([taskId])
  const db = connect()
  db.prepare('DELETE FROM nmap_scans WHERE task_id = ?').run(taskId)
  db.prepare('DELETE FROM tasks WHERE id = ?').run(taskId)
}

const getTask = (taskId) => connect().prepare(
  'SELECT t.*, p.name AS project_name FROM tasks t' +
  ' JOIN projects p ON p.id = t.project_id WHERE t.id = ?').get(taskId) ?? null

const listTasks = (projectId) => connect().prepare(`
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
        `).all(projectId)

const runningTasks = () => connect().prepare(
  "SELECT * FROM tasks WHERE status IN ('running','paused')").all()

/** Called at startup: a task marked running can't have survived a restart. */
function resetStaleTasks () {
  connect().prepare(
    "UPDATE tasks SET status = 'interrupted', error = ?" +
    " WHERE status IN ('running','paused')")
    .run('Server restarted while this task was running.')
}

// --- discovered hosts ----------------------------------------------------

/** Records hosts a discovery probe found alive. Returns the new ones. */
function addHosts (taskId, hosts, method = null) {
  if (!hosts || !hosts.length) return []
  const ts = now()
  const db = connect()
  const insert = db.prepare(
    'INSERT OR IGNORE INTO hosts (task_id, ip, state, method, reason, hostname, latency, found_at)' +
    ' VALUES (?,?,?,?,?,?,?,?)')
  const fresh = []
  db.transaction(() => {
    for (const host of hosts) {
      const address = host && host.ip
      if (!address) continue
      const result = insert.run(taskId, address, host.state || 'up', method,
        host.reason ?? null, host.hostname ?? null, host.latency ?? null, ts)
      if (result.changes) fresh.push(host)
    }
  })()
  return fresh
}

const liveHosts = (taskId) => connect()
  .prepare("SELECT * FROM hosts WHERE task_id = ? AND state = 'up'").all(taskId)
  .sort((a, b) => compareIps(a.ip, b.ip))

const clearHosts = (taskId) =>
  connect().prepare('DELETE FROM hosts WHERE task_id = ?').run(taskId)

const hostCount = (taskId) => connect()
  .prepare('SELECT COUNT(*) AS n FROM hosts WHERE task_id = ?').get(taskId).n

// --- findings ------------------------------------------------------------

/** Insert ports for a host. Returns the rows that were actually new. */
function addFindings (taskId, address, ports, source = 'masscan') {
  if (!ports || !ports.length) return []
  const ts = now()
  const db = connect()
  const insert = db.prepare(
    'INSERT OR IGNORE INTO findings (task_id, ip, port, proto, state, service, source, found_at)' +
    ' VALUES (?,?,?,?,?,?,?,?)')
  const enrich = db.prepare(
    'UPDATE findings SET service = ?, state = ? WHERE task_id = ?' +
    ' AND ip = ? AND port = ? AND proto = ? AND source = ?')

  const fresh = []
  db.transaction(() => {
    for (const entry of ports) {
      const port = Number.parseInt(entry && entry.port, 10)
      if (!Number.isFinite(port)) continue
      const proto = entry.proto || 'tcp'
      const state = entry.state || 'open'
      const result = insert.run(taskId, address, port, proto, state,
        entry.service ?? null, source, ts)
      if (result.changes) {
        fresh.push(entry)
      } else if (entry.service) {
        // Same port seen again but now with service detail — keep the richer row.
        enrich.run(entry.service, state, taskId, address, port, proto, source)
      }
    }
  })()
  return fresh
}

/** Swap out one source's findings for a host (used by rescans). */
function replaceFindings (taskId, address, ports, source) {
  connect().prepare('DELETE FROM findings WHERE task_id = ? AND ip = ? AND source = ?')
    .run(taskId, address, source)
  return addFindings(taskId, address, ports, source)
}

const taskFindings = (taskId) => connect().prepare(
  'SELECT * FROM findings WHERE task_id = ? ORDER BY ip, proto, port').all(taskId)

/** Hosts for a task, with their ports.
 *
 * Includes addresses that discovery proved alive but which have no open ports,
 * so a discovery-only run still has something to show.
 */
function taskHosts (taskId) {
  const byIp = new Map()
  for (const row of taskFindings(taskId)) {
    if (!byIp.has(row.ip)) byIp.set(row.ip, [])
    byIp.get(row.ip).push(row)
  }

  const discovered = new Map(liveHosts(taskId).map((host) => [host.ip, host]))
  for (const address of discovered.keys()) {
    if (!byIp.has(address)) byIp.set(address, [])
  }

  const result = []
  for (const address of [...byIp.keys()].sort(compareIps)) {
    const best = new Map()
    for (const finding of byIp.get(address)) {
      const key = `${finding.port}/${finding.proto}`
      const prior = best.get(key)
      // nmap rows carry the service label, so let them win over masscan.
      if (!prior || (finding.source === 'nmap' && prior.source !== 'nmap')) {
        best.set(key, finding)
      }
    }
    const entry = {
      ip: address,
      ports: [...best.values()].sort(comparePorts),
    }
    const found = discovered.get(address)
    if (found) {
      entry.hostname = found.hostname ?? null
      entry.discovered_by = found.method ?? null
      entry.reason = found.reason ?? null
    }
    result.push(entry)
  }
  return result
}

/** Every host in the project, with each port listed once.
 *
 * Overlapping tasks (or a masscan sweep followed by an nmap rescan) can report
 * the same port more than once; those are merged, keeping the nmap row for its
 * service detail and noting every task that saw it.
 */
function projectHosts (projectId) {
  const rows = connect().prepare(
    'SELECT f.*, t.name AS task_name, t.id AS tid FROM findings f' +
    ' JOIN tasks t ON t.id = f.task_id WHERE t.project_id = ?' +
    ' ORDER BY f.ip, f.proto, f.port').all(projectId)

  const hosts = new Map()
  for (const row of rows) {
    if (!hosts.has(row.ip)) hosts.set(row.ip, new Map())
    const byPort = hosts.get(row.ip)
    const key = `${row.port}/${row.proto}`
    const prior = byPort.get(key)
    if (!prior) {
      byPort.set(key, { ...row, tasks: [row.task_name] })
      continue
    }
    if (!prior.tasks.includes(row.task_name)) prior.tasks.push(row.task_name)
    // An nmap row carries the service label, so let it win.
    if (row.source === 'nmap' && prior.source !== 'nmap') {
      byPort.set(key, { ...row, tasks: prior.tasks })
    }
  }

  return [...hosts.keys()].sort(compareIps).map((address) => ({
    ip: address,
    ports: [...hosts.get(address).values()].sort(comparePorts),
  }))
}

/** Sorts numerically by address, with unparseable values last — the same
 *  ordering Python's (version, int(addr)) key produced. */
function compareIps (a, b) {
  const left = sortKey(a)
  const right = sortKey(b)
  if (left[0] !== right[0]) return left[0] - right[0]
  if (left[1] === right[1]) return 0
  return left[1] < right[1] ? -1 : 1
}

function sortKey (address) {
  try {
    const parsed = ip.parseAddress(address)
    return [parsed.version, parsed.value]
  } catch {
    return [99, address]
  }
}

const comparePorts = (a, b) =>
  (a.proto < b.proto ? -1 : a.proto > b.proto ? 1 : a.port - b.port)

// --- nmap scans ----------------------------------------------------------

function saveNmapScan (scanId, address, tool, command, rawOutput, ports, shots,
  { taskId = null, projectId = null, createdAt = null } = {}) {
  // createdAt is passed only by the importer, which keeps the timestamp from
  // the install the scan actually ran on — the reports display it, and "today"
  // would be a lie about when the host was seen.
  connect().prepare(
    'INSERT INTO nmap_scans (id, ip, tool, created_at, command, raw_output,' +
    ' ports_json, screenshots_json, task_id, project_id) VALUES (?,?,?,?,?,?,?,?,?,?)').run(
    scanId, address, tool, createdAt || now(), command, rawOutput,
    JSON.stringify(ports ?? []), JSON.stringify(shots ?? []), taskId, projectId)
}

const getNmapScan = (scanId) =>
  connect().prepare('SELECT * FROM nmap_scans WHERE id = ?').get(scanId) ?? null

/** Escapes the LIKE wildcards so a search for "10.0.0.%" looks for that
 *  literal string rather than matching every address. */
function likeTerm (text) {
  return '%' + String(text).replace(/[\\%_]/g, (ch) => '\\' + ch) + '%'
}

function listNmapScans ({ taskId = null, projectId = null, address = null,
  search = null } = {}) {
  let sql = 'SELECT n.id, n.ip, n.tool, n.created_at, n.task_id, n.project_id,' +
            ' n.screenshots_json, t.name AS task_name, p.name AS project_name' +
            ' FROM nmap_scans n' +
            ' LEFT JOIN tasks t ON t.id = n.task_id' +
            ' LEFT JOIN projects p ON p.id = n.project_id'
  const where = []
  const params = []
  if (taskId) { where.push('n.task_id = ?'); params.push(taskId) }
  if (projectId) { where.push('n.project_id = ?'); params.push(projectId) }
  if (address) { where.push('n.ip = ?'); params.push(address) }

  // One box across the four things worth searching by. Done in SQL rather than
  // filtered in the interface, so it reaches every scan and not just the page
  // that happens to be loaded.
  const term = String(search || '').trim()
  if (term) {
    where.push("(n.ip LIKE ? ESCAPE '\\' OR n.tool LIKE ? ESCAPE '\\'" +
               " OR t.name LIKE ? ESCAPE '\\' OR p.name LIKE ? ESCAPE '\\')")
    params.push(likeTerm(term), likeTerm(term), likeTerm(term), likeTerm(term))
  }

  if (where.length) sql += ' WHERE ' + where.join(' AND ')
  sql += ' ORDER BY n.created_at DESC'
  return connect().prepare(sql).all(...params)
}

module.exports = {
  createProject, updateProject, deleteProject, getProject, listProjects,
  getOrCreateProject,
  createTask, updateTask, deleteTask, getTask, listTasks, runningTasks,
  resetStaleTasks,
  addHosts, liveHosts, clearHosts, hostCount,
  addFindings, replaceFindings, taskFindings, taskHosts, projectHosts,
  saveNmapScan, getNmapScan, listNmapScans,
}
