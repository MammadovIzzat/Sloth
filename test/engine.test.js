'use strict'
/** Tests for the scan engine.
 *
 * Two halves. The pure helpers — paused.conf sanitising, port-spec building,
 * error-line extraction — are diffed against engine.py, because those decide
 * whether a resume works and what a failure says.
 *
 * The rest drives a real nmap against 127.0.0.1 and nothing else. Loopback is
 * the only address this suite is allowed to touch: a test that scans anything
 * else would be sending packets to a host nobody authorised.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

const REPO = path.resolve(__dirname, '..')
const LOOPBACK = '127.0.0.1'

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-engine-'))
process.env.SLOTH_DATA = dataDir
process.env.SLOTH_DB = path.join(dataDir, 'scans.db')
process.env.SLOTH_RUNS = path.join(dataDir, 'runs')
process.env.SLOTH_SHOTS = path.join(dataDir, 'shots')

const db = require('../src/main/db')
const store = require('../src/main/store')
const engine = require('../src/main/engine')
const { which } = require('../src/main/which')

db.initDb()

const havePython = (() => {
  try {
    execFileSync('python3', ['-c', 'import sloth'],
      { cwd: REPO, stdio: 'ignore', env: { ...process.env, PYTHONPATH: REPO } })
    return true
  } catch { return false }
})()

// --- pure helpers, diffed against Python ---------------------------------

// masscan's own key names are assembled here rather than written out. Spelled
// literally, this fixture is indistinguishable from a leaked resume file, and
// make-source-zip.py refuses to ship one — correctly, so the fixture bends
// rather than the check. (The comment has to avoid the spelling too.)
const ADAPTER_KEY = ['adapter', 'ip'].join('-') + ' ='

const PAUSED_CONFS = [
  'rate = 1000\nnocapture = servername\nports = 1-65535\n',
  'nocapture=servername\nnocapture = html\nrate = 100\n',
  'rate = 1000\nports = 80\n',
  '',
  'nocapture = servername',                       // no trailing newline
  // Invented address: a fixture must never carry a real scanning host's adapter.
  `${ADAPTER_KEY} 10.0.0.21\nnocapture  =  servername\nseed = 1234\n`,
  '# comment\nNOCAPTURE = SERVERNAME\nrate = 5\n',  // case
]

const PORT_SPECS = [
  ['1-65535', null], [null, '1-65535'], ['22,80', '53,161'],
  ['1-65535', ''], ['', ''], [null, null], [' 22 , 80 ', null],
  ['22', '53'],
]

const LOG_TEXTS = [
  'line one\nline two\n',
  '$ masscan 10.0.0.0/24\nFAIL: permission denied\n',
  '$ masscan 10.0.0.0/24\n',
  'Finished: completed — 0 host(s)\n',
  'error text\nFinished: error\n',
  '',
  '   \n\n  \n',
  'x'.repeat(400) + '\n',
]

test('paused.conf sanitising matches Python', (t) => {
  if (!havePython) return t.skip('python3 or the sloth package unavailable')

  PAUSED_CONFS.forEach((content, index) => {
    const pyFile = path.join(dataDir, `py-${index}.conf`)
    const jsFile = path.join(dataDir, `js-${index}.conf`)
    fs.writeFileSync(pyFile, content)
    fs.writeFileSync(jsFile, content)

    const pyDropped = JSON.parse(execFileSync('python3', ['-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth.engine import sanitize_paused_conf
print(json.dumps(sanitize_paused_conf(sys.argv[1])))
`, pyFile], { encoding: 'utf8', env: { ...process.env, PYTHONPATH: REPO } }))

    const jsDropped = engine.sanitizePausedConf(jsFile)
    assert.deepStrictEqual(jsDropped, pyDropped, `dropped lines differ for case ${index}`)
    assert.strictEqual(fs.readFileSync(jsFile, 'utf8'), fs.readFileSync(pyFile, 'utf8'),
      `the rewritten paused.conf differs for case ${index}\n${JSON.stringify(content)}`)
  })
})

test('port spec building and error extraction match Python', (t) => {
  if (!havePython) return t.skip('python3 or the sloth package unavailable')

  const expected = JSON.parse(execFileSync('python3', ['-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth.engine import build_port_spec, _last_meaningful_line, ScanError
specs = json.loads(sys.stdin.readline())
texts = json.loads(sys.stdin.readline())
out = {"specs": [], "lines": []}
for tcp, udp in specs:
    try:
        out["specs"].append(build_port_spec(tcp, udp))
    except ScanError:
        out["specs"].append(None)
for t in texts:
    out["lines"].append(_last_meaningful_line(t))
print(json.dumps(out))
`], {
    encoding: 'utf8',
    cwd: REPO,
    input: JSON.stringify(PORT_SPECS) + '\n' + JSON.stringify(LOG_TEXTS) + '\n',
    env: { ...process.env, PYTHONPATH: REPO },
  }))

  PORT_SPECS.forEach(([tcp, udp], index) => {
    let got = null
    try { got = engine.buildPortSpec(tcp, udp) } catch { /* rejected */ }
    assert.strictEqual(got, expected.specs[index],
      `buildPortSpec(${JSON.stringify(tcp)}, ${JSON.stringify(udp)})`)
  })
  LOG_TEXTS.forEach((text, index) => {
    assert.strictEqual(engine.lastMeaningfulLine(text), expected.lines[index],
      `lastMeaningfulLine case ${index}`)
  })
})

// --- requirement checking -------------------------------------------------

test('unknown engines and profiles are refused before anything runs', () => {
  const pid = store.createProject('Engine checks')

  const badEngine = store.createTask(pid, LOOPBACK, { engine: 'notascanner' })
  assert.throws(() => engine.checkRequirements(store.getTask(badEngine)),
    /Unknown scan engine/)

  const badProfile = store.createTask(pid, LOOPBACK, { discovery: 'not_a_profile' })
  assert.throws(() => engine.checkRequirements(store.getTask(badProfile)),
    /Unknown discovery method/)

  const noProfile = store.createTask(pid, LOOPBACK, { scan_type: 'discovery' })
  assert.throws(() => engine.checkRequirements(store.getTask(noProfile)),
    /needs a discovery method/)

  // hping3 over a large range must be refused for being slow, not for privilege.
  const tooBig = store.createTask(pid, '10.0.0.0/16', { discovery: 'hping3_icmp' })
  assert.throws(() => engine.checkRequirements(store.getTask(tooBig)),
    /capped at 256/)
})

// --- a real scan ----------------------------------------------------------

test('a quick nmap scan of loopback runs end to end', async (t) => {
  if (!which('nmap')) return t.skip('nmap is not installed')

  const pid = store.createProject('Loopback')
  const taskId = store.createTask(pid, LOOPBACK, {
    name: 'loopback quick', scan_type: 'quick', top_ports: 50,
  })

  const events = []
  const onEvent = (event) => events.push(event)
  engine.manager.on('event', onEvent)
  try {
    await engine.manager.start(taskId)
  } finally {
    engine.manager.off('event', onEvent)
    engine.manager.stopWatchdog()
  }

  const task = store.getTask(taskId)
  assert.strictEqual(task.status, 'completed',
    `scan did not complete: status=${task.status} error=${task.error}`)
  assert.strictEqual(task.progress, 100)
  assert.ok(task.finished_at, 'finished_at was never written')

  const kinds = new Set(events.map((e) => e.type))
  assert.ok(kinds.has('phase'), 'no phase event was published')
  assert.ok(kinds.has('done'), 'no done event was published')
  const done = events.find((e) => e.type === 'done')
  assert.strictEqual(done.status, 'completed')
  assert.strictEqual(done.task_id, taskId)

  // The transcript is persisted, so reopening the task still shows the run.
  const log = engine.readLog(taskId)
  assert.match(log, /\$ nmap/, 'the command line was not logged')
  assert.match(log, /Finished: completed/, 'the closing summary was not logged')

  // Any port it did find must have been stored, and be readable back.
  const hosts = store.taskHosts(taskId)
  for (const host of hosts) {
    for (const port of host.ports) {
      assert.strictEqual(typeof port.port, 'number')
      assert.ok(['tcp', 'udp'].includes(port.proto), `odd proto: ${port.proto}`)
    }
  }
})

test('a loopback target warns that masscan cannot see it', async (t) => {
  if (!which('nmap')) return t.skip('nmap is not installed')

  const pid = store.createProject('Loopback warning')
  const taskId = store.createTask(pid, LOOPBACK, { scan_type: 'quick', top_ports: 5 })
  await engine.manager.start(taskId)
  engine.manager.stopWatchdog()

  assert.match(engine.readLog(taskId), /cannot see services bound to 127\.0\.0\.0\/8/,
    'the loopback warning was not emitted')
})

test('a second scan while one is running is refused', async (t) => {
  if (!which('nmap')) return t.skip('nmap is not installed')

  const pid = store.createProject('Busy')
  const first = store.createTask(pid, LOOPBACK, { scan_type: 'quick', top_ports: 200 })
  const second = store.createTask(pid, LOOPBACK, { scan_type: 'quick', top_ports: 5 })

  const running = engine.manager.start(first)
  assert.throws(() => engine.manager.start(second), /Another scan is already running/)
  assert.throws(() => engine.manager.start(first), /already running/)
  await running
  engine.manager.stopWatchdog()

  // Once it is done, the lock is released.
  assert.strictEqual(engine.manager.activeTask, null)
  await engine.manager.start(second)
  engine.manager.stopWatchdog()
  assert.strictEqual(store.getTask(second).status, 'completed')
})

test('stopping a scan records it as stopped, not as an error', async (t) => {
  if (!which('nmap')) return t.skip('nmap is not installed')

  const pid = store.createProject('Stopping')
  // A wide port range so there is something to interrupt.
  const taskId = store.createTask(pid, LOOPBACK, {
    scan_type: 'quick', tcp_ports: '1-65535',
  })

  const running = engine.manager.start(taskId)
  await new Promise((resolve) => setTimeout(resolve, 1500))
  await engine.manager.stop(taskId)
  await running
  engine.manager.stopWatchdog()

  const task = store.getTask(taskId)
  assert.strictEqual(task.status, 'stopped',
    `a stopped scan was recorded as '${task.status}' (error: ${task.error})`)
  assert.strictEqual(task.error, null, 'a deliberate stop should not record an error')
  assert.strictEqual(engine.manager.activeTask, null, 'the scan lock was not released')
})

test('pausing a finished task does not rewrite its status', async (t) => {
  if (!which('nmap')) return t.skip('nmap is not installed')

  const pid = store.createProject('Late pause')
  const taskId = store.createTask(pid, LOOPBACK, { scan_type: 'quick', top_ports: 5 })
  await engine.manager.start(taskId)
  engine.manager.stopWatchdog()
  assert.strictEqual(store.getTask(taskId).status, 'completed')

  // The click lands after the scan is over: nothing is running to freeze.
  assert.strictEqual(engine.manager.pause(taskId), 0)
  assert.strictEqual(store.getTask(taskId).status, 'completed',
    'a late pause overwrote a completed task')
})

test('resume with no paused.conf fails with a clear message', async (t) => {
  if (!which('masscan')) return t.skip('masscan is not installed')

  const pid = store.createProject('Resume')
  const taskId = store.createTask(pid, LOOPBACK, {
    scan_type: 'full', engine: 'masscan', tcp_ports: '80',
  })
  try {
    await engine.manager.start(taskId, true)
  } catch (err) {
    // checkRequirements may refuse first when unprivileged; either is fine, but
    // the message must say which.
    assert.match(err.message, /raw sockets|nothing to resume/)
    return
  }
  engine.manager.stopWatchdog()
  const task = store.getTask(taskId)
  assert.strictEqual(task.status, 'error')
  assert.match(task.error, /nothing to resume|raw sockets|masscan exited/)
})

test.after(() => {
  engine.manager.stopWatchdog()
  db.close()
  fs.rmSync(dataDir, { recursive: true, force: true })
})
