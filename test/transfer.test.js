'use strict'
/** Exports and imports, tested for wire compatibility and for hostile input.
 *
 * Two things matter here. A bundle written by the Python build has to import
 * into this one and vice versa — otherwise the two halves of a team cannot
 * share results during the migration. And an imported bundle came off another
 * machine, so the hardening has to survive the port: the same attacks the
 * Python version was hardened against are replayed against this one.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

const REPO = path.resolve(__dirname, '..')

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-transfer-'))
process.env.SLOTH_DATA = dataDir
process.env.SLOTH_DB = path.join(dataDir, 'scans.db')
process.env.SLOTH_RUNS = path.join(dataDir, 'runs')
process.env.SLOTH_SHOTS = path.join(dataDir, 'shots')

const db = require('../src/main/db')
const store = require('../src/main/store')
const transfer = require('../src/main/transfer')
const reports = require('../src/main/reports')
db.initDb()
fs.mkdirSync(process.env.SLOTH_SHOTS, { recursive: true })

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64')

const havePython = (() => {
  try {
    execFileSync('python3', ['-c', 'import sloth'],
      { cwd: REPO, stdio: 'ignore', env: { ...process.env, PYTHONPATH: REPO } })
    return true
  } catch { return false }
})()

/** Builds a project with hosts, ports, an nmap scan and a screenshot. */
let seedCounter = 0
function seed (name) {
  // A fresh scan id per call: seeding twice in one run must not collide.
  const scanId = `scan${String(++seedCounter).padStart(8, '0')}`
  const pid = store.createProject(name, 'Acme Corp', 'Scope agreed.')
  const tid = store.createTask(pid, '10.0.0.0/24', {
    name: 'sweep', scan_type: 'full', engine: 'rustscan', tcp_ports: '1-65535',
    rate: 1000, retries: 3, discovery: 'fping_sweep', notes: 'Servers VLAN',
  })
  store.updateTask(tid, {
    status: 'completed', progress: 100,
    started_at: '2026-03-04 09:12:00', finished_at: '2026-03-04 09:19:41',
  })
  store.addHosts(tid, [
    { ip: '10.0.0.9', state: 'up', reason: 'echo-reply', hostname: 'web01' },
    { ip: '10.0.0.90', state: 'up', reason: 'echo-reply' },
  ], 'fping_sweep')
  store.addFindings(tid, '10.0.0.9', [
    { port: 80, proto: 'tcp', state: 'open', service: 'http (nginx 1.24.0)' },
    { port: 443, proto: 'tcp', state: 'open', service: 'https' },
  ], 'nmap')
  store.addFindings(tid, '10.0.0.9',
    [{ port: 161, proto: 'udp', state: 'open|filtered', service: 'snmp' }], 'nmap')

  fs.writeFileSync(path.join(process.env.SLOTH_SHOTS, 'shot.png'), PNG)
  store.saveNmapScan(scanId, '10.0.0.9', 'nmap_deep', 'nmap -sV 10.0.0.9',
    'PORT STATE\n80/tcp open http', [{ port: 80, proto: 'tcp', state: 'open' }],
    [{ url: 'http://10.0.0.9:80', file: 'shot.png' }], { taskId: tid, projectId: pid })

  // A task that was still running when exported.
  const running = store.createTask(pid, '10.0.1.0/24', { name: 'mid-flight' })
  store.updateTask(running, { status: 'running', progress: 64.2, resumable: 1 })
  return pid
}

test('a project survives an export/import round trip', () => {
  const pid = seed('Round trip')
  const bundle = reports.exportProject(pid, 'json', '3.0.0')
  assert.match(bundle.filename, /^project-.*\.json$/)

  const data = transfer.readBundle(Buffer.from(bundle.body))
  assert.strictEqual(data.sloth.format, transfer.FORMAT)
  // The screenshot must travel inside the file, not as a filename.
  const embedded = data.tasks[0].scans['10.0.0.9'][0].screenshots[0]
  assert.ok(embedded.data, 'the screenshot was not embedded')
  assert.strictEqual(Buffer.from(embedded.data, 'base64').equals(PNG), true)

  const tally = transfer.importBundle(data)
  assert.strictEqual(tally.created, true)
  assert.strictEqual(tally.tasks, 2)
  assert.strictEqual(tally.hosts, 2)
  assert.strictEqual(tally.ports, 3)
  assert.strictEqual(tally.scans, 1)
  assert.strictEqual(tally.shots, 1)

  const tasks = store.listTasks(tally.project)
  const sweep = tasks.find((t) => t.name === 'sweep')
  assert.strictEqual(sweep.status, 'completed')
  assert.strictEqual(sweep.engine, 'rustscan')
  assert.strictEqual(sweep.finished_at, '2026-03-04 09:19:41')

  // A task caught mid-run is imported honestly, not as completed.
  const midflight = tasks.find((t) => t.name === 'mid-flight')
  assert.strictEqual(midflight.status, 'interrupted')
  assert.match(midflight.error, /still running when it was exported/)
  assert.strictEqual(midflight.resumable, 0)

  // The screenshot landed on disk under a name chosen here.
  const scan = store.listNmapScans({ projectId: tally.project })[0]
  const shots = JSON.parse(store.getNmapScan(scan.id).screenshots_json)
  assert.strictEqual(shots.length, 1)
  assert.notStrictEqual(shots[0].file, 'shot.png', 'the incoming filename was reused')
  assert.ok(fs.existsSync(path.join(process.env.SLOTH_SHOTS, shots[0].file)))
})

test('importing twice makes two copies rather than overwriting', () => {
  const pid = seed('Twice')
  const body = reports.exportProject(pid, 'json', '3.0.0').body
  const before = store.listProjects().length
  transfer.importBundle(transfer.readBundle(Buffer.from(body)))
  transfer.importBundle(transfer.readBundle(Buffer.from(body)))
  const names = store.listProjects().map((p) => p.name)
  assert.strictEqual(store.listProjects().length, before + 2)
  assert.ok(names.includes('Twice (imported)'), `no disambiguated name in ${names}`)
})

test('a bundle written by the Python build imports here', (t) => {
  if (!havePython) return t.skip('python3 or the sloth package unavailable')

  const pyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-pyexp-'))
  try {
    const body = execFileSync('python3', ['-c', `
import base64, json, os, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth import store, transfer
from sloth.db import init_db
from sloth.config import SHOTS_DIR
init_db()
pid = store.create_project("From Python", client="Acme", description="d")
tid = store.create_task(pid, "10.0.5.0/24", name="py sweep", scan_type="full",
                        engine="masscan", tcp_ports="1-1000", rate=1500, retries=2)
store.update_task(tid, status="completed", finished_at="2026-05-01 10:00:00")
store.add_hosts(tid, [{"ip": "10.0.5.3", "state": "up", "reason": "echo-reply"}],
                method="nmap_default")
store.add_findings(tid, "10.0.5.3", [{"port": 22, "proto": "tcp", "state": "open",
                                      "service": "ssh"}], source="nmap")
os.makedirs(SHOTS_DIR, exist_ok=True)
open(os.path.join(SHOTS_DIR, "p.png"), "wb").write(base64.b64decode("${PNG.toString('base64')}"))
store.save_nmap_scan("pyscan000001", "10.0.5.3", "nmap_deep", "nmap -sV", "raw output",
                     [{"port": 22, "proto": "tcp", "state": "open"}],
                     [{"url": "http://10.0.5.3:80", "file": "p.png"}],
                     task_id=tid, project_id=pid)
sections = [transfer_section for transfer_section in []]
from sloth.views.reports import _task_bundle
sections = [_task_bundle(t) for t in store.list_tasks(pid)]
env = transfer.envelope(store.get_project(pid)["name"], sections,
                        store.get_project(pid), version="2.1.0")
print(json.dumps(env, default=str))
`], {
      encoding: 'utf8',
      cwd: REPO,
      maxBuffer: 64 * 1024 * 1024,
      env: {
        ...process.env,
        PYTHONPATH: REPO,
        SLOTH_DATA: pyDir,
        SLOTH_DB: path.join(pyDir, 'scans.db'),
        SLOTH_RUNS: path.join(pyDir, 'runs'),
        SLOTH_SHOTS: path.join(pyDir, 'shots'),
      },
    })

    const data = transfer.readBundle(Buffer.from(body))
    const tally = transfer.importBundle(data)
    assert.strictEqual(tally.tasks, 1)
    assert.strictEqual(tally.hosts, 1)
    assert.strictEqual(tally.ports, 1)
    assert.strictEqual(tally.scans, 1)
    assert.strictEqual(tally.shots, 1, 'the screenshot from the Python bundle was lost')

    const task = store.listTasks(tally.project)[0]
    assert.strictEqual(task.name, 'py sweep')
    assert.strictEqual(task.engine, 'masscan')
    assert.strictEqual(task.tcp_ports, '1-1000')
    assert.strictEqual(task.rate, 1500)
  } finally {
    fs.rmSync(pyDir, { recursive: true, force: true })
  }
})

test('a bundle written here imports into the Python build', (t) => {
  if (!havePython) return t.skip('python3 or the sloth package unavailable')

  const pid = seed('For Python')
  const body = reports.exportProject(pid, 'json', '3.0.0').body
  const pyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-pyimp-'))
  try {
    const result = JSON.parse(execFileSync('python3', ['-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth import store, transfer
from sloth.db import init_db
init_db()
data = transfer.read_bundle(sys.stdin.buffer.read())
tally = transfer.import_bundle(data)
tasks = [dict(t) for t in store.list_tasks(tally["project"])]
print(json.dumps({"tally": tally, "tasks": sorted(t["name"] for t in tasks),
                  "statuses": sorted(t["status"] for t in tasks)}, default=str))
`], {
      encoding: 'utf8',
      cwd: REPO,
      input: body,
      maxBuffer: 64 * 1024 * 1024,
      env: {
        ...process.env,
        PYTHONPATH: REPO,
        SLOTH_DATA: pyDir,
        SLOTH_DB: path.join(pyDir, 'scans.db'),
        SLOTH_RUNS: path.join(pyDir, 'runs'),
        SLOTH_SHOTS: path.join(pyDir, 'shots'),
      },
    }))

    assert.strictEqual(result.tally.tasks, 2)
    assert.strictEqual(result.tally.shots, 1,
      'the Python build could not read the screenshot this one embedded')
    assert.deepStrictEqual(result.tasks, ['mid-flight', 'sweep'])
    assert.deepStrictEqual(result.statuses, ['completed', 'interrupted'])
  } finally {
    fs.rmSync(pyDir, { recursive: true, force: true })
  }
})

// --- hostile input --------------------------------------------------------

test('malformed bundles are refused with a sentence', () => {
  const cases = [
    [Buffer.alloc(0), /empty/i],
    [Buffer.from('<!DOCTYPE html><h1>report</h1>'), /not valid JSON/i],
    [PNG, /not a text file|not valid JSON/i],
    [Buffer.from(JSON.stringify({ hello: 'world' })), /does not look like a Sloth export/i],
    [Buffer.from(JSON.stringify({ tasks: 'nope' })), /does not look like a Sloth export/i],
    [Buffer.from(JSON.stringify([1, 2, 3])), /does not look like a Sloth export/i],
    [Buffer.from(JSON.stringify({ sloth: { format: 99 }, tasks: [] })), /newer Sloth/i],
  ]
  for (const [raw, pattern] of cases) {
    assert.throws(() => transfer.readBundle(raw), pattern,
      `unexpected handling of ${raw.slice(0, 24).toString('utf8')}`)
  }
})

test('hostile content is neutralised rather than trusted', () => {
  const before = fs.readdirSync(process.env.SLOTH_SHOTS).length
  const evil = {
    sloth: { format: 1 },
    project: { name: '../../etc/passwd', client: 'x'.repeat(9000), description: null },
    tasks: [
      {
        task: {
          name: 'A'.repeat(5000), target: '10.0.0.1',
          status: "'; DROP TABLE tasks;--",
          engine: "__import__('os').system('id')", scan_type: '../../x',
          rate: -99999999, top_ports: 999999, retries: 'NaN', progress: 1e9,
          resumable: 1,
        },
        hosts: [
          {
            ip: '10.0.0.1',
            discovered_by: 'm',
            ports: [
              { port: 99999, proto: 'tcp' },                 // out of range
              { port: '22', proto: '../../etc', service: null }, // coercible, bad proto
              { port: null },
              'not even a dict',
            ],
          },
          'also not a dict',
        ],
        scans: {
          '10.0.0.1': [{
            tool: 'nmap',
            created_at: 'x',
            screenshots: [
              { url: 'http://a', file: '../../../../tmp/pwned.png', data: Buffer.from('not a png').toString('base64') },
              { url: 'http://b', file: '../../../../tmp/pwned2.png', data: Buffer.concat([PNG]).toString('base64') },
              { url: 'http://c', data: '!!!not base64!!!' },
              'junk',
            ],
          }],
        },
      },
      'task entry is a string',
      { 'no task key': 1 },
    ],
  }

  const tally = transfer.importBundle(transfer.readBundle(Buffer.from(JSON.stringify(evil))))
  assert.strictEqual(tally.tasks, 1)
  assert.strictEqual(tally.skipped, 2, 'malformed task entries were not counted')

  const project = store.getProject(tally.project)
  // The name is stored as a literal string and never used as a path.
  assert.strictEqual(project.name, '../../etc/passwd')
  assert.strictEqual(project.client.length, 300, 'an oversized field was not truncated')

  const task = store.listTasks(tally.project)[0]
  assert.strictEqual(task.status, 'interrupted', 'an SQL-looking status was stored verbatim')
  assert.strictEqual(task.engine, 'masscan', 'an unknown engine was accepted')
  assert.strictEqual(task.scan_type, 'full', 'an unknown scan type was accepted')
  assert.strictEqual(task.rate, null, 'a negative rate was accepted')
  assert.strictEqual(task.top_ports, null, 'an out-of-range top_ports was accepted')
  assert.strictEqual(task.retries, null, "'NaN' was accepted as a retry count")
  assert.strictEqual(task.progress, 100, 'progress was not clamped')
  assert.strictEqual(task.resumable, 0, 'resumable was carried over from the file')
  assert.strictEqual(task.name.length, 300)

  const hosts = store.taskHosts(task.id)
  assert.deepStrictEqual(hosts.map((h) => h.ip), ['10.0.0.1'])
  assert.deepStrictEqual(hosts[0].ports.map((p) => [p.port, p.proto]), [[22, 'tcp']],
    'an out-of-range or malformed port survived')

  // Exactly one screenshot — the valid PNG — and nothing escaped the directory.
  assert.strictEqual(tally.shots, 1)
  assert.strictEqual(fs.readdirSync(process.env.SLOTH_SHOTS).length, before + 1)
  for (const stray of ['/tmp/pwned.png', '/tmp/pwned2.png']) {
    assert.strictEqual(fs.existsSync(stray), false, `a file escaped to ${stray}`)
  }

  // The database is still intact after the DROP TABLE attempt.
  assert.ok(store.listProjects().length > 0)
})

test('the tables still exist after everything above', () => {
  assert.ok(store.listProjects().length > 0)
  assert.doesNotThrow(() => store.listNmapScans())
})

test.after(() => {
  db.close()
  fs.rmSync(dataDir, { recursive: true, force: true })
})
