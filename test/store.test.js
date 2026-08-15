'use strict'
/** Differential test: src/main/{db,store}.js against sloth/{db,store}.py.
 *
 * Two things have to hold. First, the two implementations must agree on every
 * query — the rollup counts especially, where a DISTINCT keeps a port found by
 * both masscan and nmap from being counted twice. Second, and more important,
 * a database the Python build wrote has to open here unchanged: this is
 * someone's engagement data, and a migration that silently drops a column
 * would be unrecoverable.
 *
 * Both sides are pointed at the *same* fixture file in turn, so this compares
 * behaviour rather than two separately-seeded databases.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

const REPO = path.resolve(__dirname, '..')

/** Runs a Python snippet against a given database, returning parsed JSON. */
function python (script, dbPath, dataDir, stdin = '') {
  return JSON.parse(execFileSync('python3', ['-c', script], {
    encoding: 'utf8',
    cwd: REPO,
    input: stdin,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      SLOTH_DATA: dataDir,
      SLOTH_DB: dbPath,
      SLOTH_RUNS: path.join(dataDir, 'runs'),
      SLOTH_SHOTS: path.join(dataDir, 'shots'),
      PYTHONPATH: REPO,
    },
  }))
}

/** Loads the JS modules fresh against a given database. */
function loadJs (dbPath, dataDir) {
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(path.join(REPO, 'src'))) delete require.cache[key]
  }
  process.env.SLOTH_DATA = dataDir
  process.env.SLOTH_DB = dbPath
  process.env.SLOTH_RUNS = path.join(dataDir, 'runs')
  process.env.SLOTH_SHOTS = path.join(dataDir, 'shots')
  const db = require('../src/main/db')
  db.close()
  db.initDb()
  return { db, store: require('../src/main/store') }
}

const SEED = `
import json, os, sys
from sloth import store
from sloth.db import init_db
init_db()

pid = store.create_project("Acme Corp", client="Acme", description="Scope agreed.")
empty = store.create_project("Empty", description=None)
store.update_project(empty, status="archived")

t1 = store.create_task(pid, "10.0.0.0/24", name="sweep", scan_type="full",
                       engine="rustscan", tcp_ports="1-65535", rate=1000,
                       retries=3, discovery="fping_sweep", notes="VLAN")
store.update_task(t1, status="completed", progress=100.0,
                  started_at="2026-03-04 09:12:00", finished_at="2026-03-04 09:19:41")
t2 = store.create_task(pid, "10.0.1.0/24", name="running", engine="masscan")
store.update_task(t2, status="running", progress=64.2, resumable=1)
t3 = store.create_task(pid, "10.0.2.0/24", name="discovery only", scan_type="discovery")

store.add_hosts(t1, [
    {"ip": "10.0.0.9",  "state": "up", "reason": "echo-reply", "hostname": "web01", "latency": "1200"},
    {"ip": "10.0.0.5",  "state": "up", "reason": "echo-reply"},
    {"ip": "10.0.0.90", "state": "up", "reason": "arp-response"},
    {"ip": "2001:db8::1", "state": "up", "reason": "echo-reply"},
    {"ip": "not-an-ip", "state": "up"},
], method="fping_sweep")
store.add_hosts(t3, [{"ip": "10.0.2.7", "state": "up"}], method="nmap_default")

# The same port from two sources, which the rollups must count once.
store.add_findings(t1, "10.0.0.9", [{"port": 80, "proto": "tcp", "state": "open"}], source="masscan")
store.add_findings(t1, "10.0.0.9", [{"port": 80, "proto": "tcp", "state": "open", "service": "http (nginx)"}], source="nmap")
store.add_findings(t1, "10.0.0.9", [{"port": 443, "proto": "tcp", "state": "open"}], source="masscan")
store.add_findings(t1, "10.0.0.5", [{"port": 22, "proto": "tcp", "state": "open", "service": "ssh"},
                                    {"port": 445, "proto": "tcp", "state": "open"}], source="nmap")
store.add_findings(t1, "10.0.0.9", [{"port": 161, "proto": "udp", "state": "open|filtered", "service": "snmp"}], source="nmap")
store.add_findings(t2, "10.0.0.9", [{"port": 80, "proto": "tcp", "state": "open"}], source="masscan")
# Re-adding with richer detail must enrich, not duplicate.
store.add_findings(t1, "10.0.0.5", [{"port": 445, "proto": "tcp", "state": "open", "service": "microsoft-ds"}], source="nmap")

store.save_nmap_scan("scan0001", "10.0.0.9", "nmap_deep", "nmap -sV 10.0.0.9",
                     "PORT STATE\\n80/tcp open", [{"port": 80, "proto": "tcp", "state": "open"}],
                     [{"url": "http://10.0.0.9:80", "file": "a.png"}], task_id=t1, project_id=pid)
store.save_nmap_scan("scan0002", "10.0.0.5", "nmap_quick", "nmap 10.0.0.5", "out", [], [],
                     task_id=t1, project_id=pid)

print(json.dumps({"pid": pid, "empty": empty, "t1": t1, "t2": t2, "t3": t3}))
`

const READ = `
import json, sys
from sloth import store
ids = json.loads(sys.stdin.readline())

def rows(seq):
    return [dict(r) for r in seq]

print(json.dumps({
    "projects":       rows(store.list_projects()),
    "projects_active": rows(store.list_projects(status="active")),
    "project":        dict(store.get_project(ids["pid"])),
    "tasks":          rows(store.list_tasks(ids["pid"])),
    "task":           dict(store.get_task(ids["t1"])),
    "task_hosts_1":   store.task_hosts(ids["t1"]),
    "task_hosts_3":   store.task_hosts(ids["t3"]),
    "project_hosts":  store.project_hosts(ids["pid"]),
    "findings":       rows(store.task_findings(ids["t1"])),
    "live_hosts":     store.live_hosts(ids["t1"]),
    "host_count":     store.host_count(ids["t1"]),
    "running":        rows(store.running_tasks()),
    "scans":          rows(store.list_nmap_scans()),
    "scans_task":     rows(store.list_nmap_scans(task_id=ids["t1"])),
    "scan":           dict(store.get_nmap_scan("scan0001")),
}, default=str))
`

function jsRead (store, ids) {
  const plain = (value) => JSON.parse(JSON.stringify(value))
  return plain({
    projects: store.listProjects(),
    projects_active: store.listProjects('active'),
    project: store.getProject(ids.pid),
    tasks: store.listTasks(ids.pid),
    task: store.getTask(ids.t1),
    task_hosts_1: store.taskHosts(ids.t1),
    task_hosts_3: store.taskHosts(ids.t3),
    project_hosts: store.projectHosts(ids.pid),
    findings: store.taskFindings(ids.t1),
    live_hosts: store.liveHosts(ids.t1),
    host_count: store.hostCount(ids.t1),
    running: store.runningTasks(),
    scans: store.listNmapScans(),
    scans_task: store.listNmapScans({ taskId: ids.t1 }),
    scan: store.getNmapScan('scan0001'),
  })
}

function haveDependencies () {
  try {
    execFileSync('python3', ['-c', 'import sloth'], {
      cwd: REPO,
      stdio: 'ignore',
      env: { ...process.env, PYTHONPATH: REPO, SLOTH_DATA: os.tmpdir() },
    })
    return true
  } catch {
    return false
  }
}

test('a database written by Python reads identically here', (t) => {
  if (!haveDependencies()) return t.skip('python3 or the sloth package unavailable')

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-store-'))
  const dbPath = path.join(dir, 'scans.db')
  try {
    // Python writes the whole fixture, then reads it back.
    const ids = python(SEED, dbPath, dir)
    const pyOut = python(READ, dbPath, dir, JSON.stringify(ids) + '\n')

    // Then the JS opens that same file and must see the same thing.
    const { store } = loadJs(dbPath, dir)
    const jsOut = jsRead(store, ids)

    for (const key of Object.keys(pyOut)) {
      assert.deepStrictEqual(jsOut[key], pyOut[key], `store.${key} differs`)
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('opening a Python database adds no columns and loses no rows', (t) => {
  if (!haveDependencies()) return t.skip('python3 or the sloth package unavailable')

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-schema-'))
  const dbPath = path.join(dir, 'scans.db')
  try {
    python(SEED, dbPath, dir)

    const before = python(`
import json, sqlite3, os
c = sqlite3.connect(os.environ["SLOTH_DB"])
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
print(json.dumps({
  "tables": tables,
  "columns": {t: [r[1] for r in c.execute(f"PRAGMA table_info({t})")] for t in tables},
  "counts":  {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables},
}))
`, dbPath, dir)

    loadJs(dbPath, dir)                       // opening runs the JS migration

    const after = python(`
import json, sqlite3, os
c = sqlite3.connect(os.environ["SLOTH_DB"])
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
print(json.dumps({
  "tables": tables,
  "columns": {t: [r[1] for r in c.execute(f"PRAGMA table_info({t})")] for t in tables},
  "counts":  {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables},
}))
`, dbPath, dir)

    // Additive is fine — the notifications table is new here and the Python
    // build simply ignores it. What must never happen is a table, a column or
    // a row disappearing: that would be someone's engagement data.
    for (const table of before.tables) {
      assert.ok(after.tables.includes(table), `table ${table} disappeared`)
      assert.deepStrictEqual(after.columns[table], before.columns[table],
        `columns of ${table} changed`)
      assert.strictEqual(after.counts[table], before.counts[table],
        `row count of ${table} changed`)
    }
    const added = after.tables.filter((t) => !before.tables.includes(t))
    assert.deepStrictEqual(added, ['notifications'],
      `unexpected new tables: ${added.join(', ')}`)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('writes made here are readable by the Python build', (t) => {
  if (!haveDependencies()) return t.skip('python3 or the sloth package unavailable')

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-rw-'))
  const dbPath = path.join(dir, 'scans.db')
  try {
    const { store, db } = loadJs(dbPath, dir)
    const pid = store.createProject('Written by JS', 'Client', 'desc')
    const tid = store.createTask(pid, '10.0.0.0/24', {
      name: 'js task', scan_type: 'full', engine: 'nmap', tcp_ports: '1-1000',
      rate: 900, retries: 2, discovery: 'nmap_default',
    })
    store.updateTask(tid, { status: 'completed', progress: 100, resumable: false })
    store.addHosts(tid, [{ ip: '10.0.0.7', state: 'up', reason: 'echo-reply' }], 'nmap_default')
    store.addFindings(tid, '10.0.0.7', [{ port: 8080, proto: 'tcp', state: 'open', service: 'http' }], 'nmap')
    store.saveNmapScan('jsscan01', '10.0.0.7', 'nmap_deep', 'nmap -sV', 'raw',
      [{ port: 8080, proto: 'tcp' }], [], { taskId: tid, projectId: pid })
    db.close()

    const seen = JSON.parse(execFileSync('python3', ['-c', `
import json, sys
from sloth import store
pid = sys.stdin.readline().strip()
p = dict(store.list_projects()[0])
t = dict(store.list_tasks(pid)[0])
print(json.dumps({
  "project": {k: p[k] for k in ("name","client","description","task_count","host_count","finding_count")},
  "task": {k: t[k] for k in ("name","status","engine","tcp_ports","rate","retries","discovery","resumable","host_count","finding_count")},
  "hosts": store.task_hosts(t["id"]),
  "scans": [dict(r)["id"] for r in store.list_nmap_scans()],
}, default=str))
`], {
      encoding: 'utf8',
      cwd: REPO,
      input: pid + '\n',
      env: {
        ...process.env,
        SLOTH_DATA: dir,
        SLOTH_DB: dbPath,
        SLOTH_RUNS: path.join(dir, 'runs'),
        SLOTH_SHOTS: path.join(dir, 'shots'),
        PYTHONPATH: REPO,
      },
    }))

    assert.deepStrictEqual(seen.project, {
      name: 'Written by JS', client: 'Client', description: 'desc',
      task_count: 1, host_count: 1, finding_count: 1,
    })
    assert.deepStrictEqual(seen.task, {
      name: 'js task', status: 'completed', engine: 'nmap', tcp_ports: '1-1000',
      rate: 900, retries: 2, discovery: 'nmap_default', resumable: 0,
      host_count: 1, finding_count: 1,
    })
    assert.strictEqual(seen.hosts.length, 1)
    assert.strictEqual(seen.hosts[0].ip, '10.0.0.7')
    assert.deepStrictEqual(seen.scans, ['jsscan01'])
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})
