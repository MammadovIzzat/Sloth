'use strict'
/** Scan orchestration: masscan sweeps and nmap follow-up scans.
 *
 * masscan is built to take a whole range in one process, so that is what
 * happens here: a single sweep whose stdout is streamed line by line, giving
 * live per-host results without a process launch per address. Results go to
 * SQLite as they arrive, so closing the window loses nothing.
 *
 * Ported from engine.py. Two structural differences, both consequences of Node
 * having one thread instead of many:
 *
 *   - The scan runs as a promise chain driven by stream events rather than a
 *     worker thread. Nothing blocks, so the RLock and the per-subscriber
 *     queues are gone; there is no concurrent access left to guard.
 *   - Subscribers are EventEmitter listeners. The Python queued events per
 *     browser tab because an HTTP stream could stall; an IPC send cannot, so a
 *     slow reader can no longer stall the scan and needs no bounded queue.
 */
const EventEmitter = require('node:events')
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')

const discovery = require('./discovery')
const store = require('./store')
const screenshots = require('./screenshots')
const {
  DEFAULT_ENGINE, DEFAULT_RATE, DEFAULT_RETRIES, DEFAULT_TCP_PORTS,
  DEFAULT_TOP_PORTS, MASSCAN_WAIT, NMAP_TIMEOUT, RUNS_DIR, RUSTSCAN_BATCH,
  RUSTSCAN_TIMEOUT_MS, RUSTSCAN_TRIES, RUSTSCAN_ULIMIT, STOP_GRACE_SECONDS,
} = require('./config')
const { now } = require('./db')
const {
  checkInternet, countTargets, ipsecOutNetworks, isLoopbackTarget,
  masscanReachability,
} = require('./netutil')
const {
  parseDiscoveryLine, parseMasscanListFile, parseMasscanStdout,
  parseNmapProgress, parseNmapXml, parseProgressLine, parseRustscanLine,
} = require('./parsers')
const privilege = require('./privilege')
const { registry, run: runOnce } = require('./procs')
const { describe } = require('./scanconfig')
const { which } = require('./which')

class ScanBusy extends Error {}
class ScanError extends Error {}
class ScanCancelled extends Error {}

function runDir (taskId) {
  const dir = path.join(RUNS_DIR, taskId)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

const pausedConfPath = (taskId) => path.join(runDir(taskId), 'paused.conf')
const logPath = (taskId) => path.join(runDir(taskId), 'scan.log')

// masscan writes these keys into paused.conf but its own config parser rejects
// them on the way back in, so `--resume` dies instantly with
// "CONF: unknown config option: nocapture=servername" having scanned nothing.
// Strip them before resuming. Dropping nocapture only affects banner capture,
// which this tool never enables.
const UNREADABLE_RESUME_KEYS = ['nocapture']

/** Removes keys masscan cannot read back. Returns the list of dropped lines. */
function sanitizePausedConf (file) {
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch {
    return []
  }
  // Keep the trailing newline structure intact: masscan's parser is fussy.
  const lines = text.split(/(?<=\n)/)
  const dropped = []
  const kept = []
  for (const line of lines) {
    const flat = line.trim().toLowerCase().replace(/ /g, '')
    if (UNREADABLE_RESUME_KEYS.some((key) => flat.startsWith(key + '='))) {
      dropped.push(line.trim())
    } else {
      kept.push(line)
    }
  }
  if (dropped.length) {
    try {
      fs.writeFileSync(file, kept.join(''))
    } catch {
      return []
    }
  }
  return dropped
}

/** Tail of a task's scanner output, for rendering the page after a reload. */
function readLog (taskId, maxLines = 400) {
  let text
  try {
    text = fs.readFileSync(logPath(taskId), 'utf8')
  } catch {
    return ''
  }
  const lines = text.split(/(?<=\n)/)
  return lines.slice(-maxLines).join('')
}

function requireTool (name) {
  const found = which(name)
  if (!found) {
    throw new ScanError(
      `${name} not found on PATH. Install it (e.g. 'sudo pacman -S ${name}' or ` +
      `'sudo apt install ${name}').`)
  }
  return found
}

/** One combined -p spec so TCP and UDP go out in a single sweep. */
function buildPortSpec (tcpPorts, udpPorts) {
  const parts = []
  if (tcpPorts) {
    parts.push(tcpPorts.split(',').filter((c) => c.trim())
      .map((c) => `T:${c.trim()}`).join(','))
  }
  if (udpPorts) {
    parts.push(udpPorts.split(',').filter((c) => c.trim())
      .map((c) => `U:${c.trim()}`).join(','))
  }
  const spec = parts.filter(Boolean).join(',')
  if (!spec) {
    throw new ScanError('No ports selected — set a TCP range, a UDP range, or both.')
  }
  return spec
}

const geteuid = () => (typeof process.geteuid === 'function' ? process.geteuid() : -1)

// The capability probes live in privilege.js, which also owns granting them;
// two implementations of "can this binary open a raw socket" would eventually
// disagree, and the disagreement would look like a scanner that refuses to run.
const inheritsCapNetRaw = privilege.inheritsCapNetRaw
const hasRawCaps = (tool) => privilege.toolPrivilege(tool).privileged

/** Verifies the tools a task needs are installed, and that we can use them. */
function checkRequirements (task) {
  const scanType = task.scan_type || 'full'
  const needed = new Set()

  if (task.discovery) {
    const profile = discovery.getProfile(task.discovery)
    if (!profile) throw new ScanError(`Unknown discovery method: '${task.discovery}'`)
    // The reuse option runs nothing, so it needs nothing installed.
    if (profile.tool) needed.add(profile.tool)
    // Checked before the privilege check: "this range is too big for hping3"
    // is more useful than "hping3 needs root" when both are true.
    const tooBig = discovery.checkHostCap(profile, task.target, countTargets(task.target))
    if (tooBig) throw new ScanError(tooBig)
  }
  if (scanType === 'full') {
    const engine = task.engine || DEFAULT_ENGINE
    if (!['masscan', 'nmap', 'rustscan'].includes(engine)) {
      throw new ScanError(`Unknown scan engine: '${engine}'`)
    }
    needed.add(engine)
  } else if (scanType === 'quick') {
    needed.add('nmap')
  } else if (scanType === 'discovery' && !task.discovery) {
    throw new ScanError('A host-discovery task needs a discovery method selected.')
  }

  for (const tool of [...needed].sort()) requireTool(tool)

  // masscan and hping3 craft raw packets and need the privilege; nmap degrades
  // gracefully without it.
  const blocking = privilege.blockingMessage([...needed].sort())
  if (blocking) {
    throw new ScanError(blocking +
      '\n\nOr pick an nmap or rustscan engine, which work unprivileged.')
  }
}

/** Calls back with each complete line from a stream, and resolves at EOF. */
function eachLine (stream, onLine) {
  return new Promise((resolve) => {
    let buffer = ''
    stream.on('data', (chunk) => {
      buffer += chunk
      const parts = buffer.split('\n')
      buffer = parts.pop()
      for (const part of parts) onLine(part.replace(/\r$/, ''))
    })
    const done = () => {
      if (buffer) { onLine(buffer); buffer = '' }
      resolve()
    }
    stream.once('end', done)
    stream.once('close', done)
    stream.once('error', done)
  })
}

/** Resolves with the child's exit code once it has exited. */
const exitCode = (child) => new Promise((resolve) => {
  if (child.exitCode !== null) return resolve(child.exitCode)
  child.once('exit', (code) => resolve(code))
  child.once('error', () => resolve(null))
})

const mtime = (file) => {
  try { return fs.statSync(file).mtimeMs } catch { return null }
}

const unlink = (file) => {
  try { fs.rmSync(file, { force: true }) } catch { /* already gone */ }
}

/** Last line of scanner output worth quoting in an error message. */
function lastMeaningfulLine (text) {
  const lines = String(text || '').split('\n')
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim()
    if (line && !line.startsWith('$ ') && !line.startsWith('Finished:')) {
      return line.slice(0, 200)
    }
  }
  return ''
}

/** Registry key for one host's rescan.
 *
 * Deliberately separate from the task's own key: a rescan must be stoppable on
 * its own, and stopping the sweep must not take a running rescan down with it.
 */
const rescanKey = (taskId, address) => `rescan:${taskId || 'adhoc'}:${address}`

// Ports that a SIP/SCCP-inspecting middlebox (router ALG, VoIP firewall)
// commonly answers on behalf of a host that is not really listening.
const ALG_PORTS = new Set([2000, 5060, 5061])

/** Owns the running scan, its subscribers, and the connectivity watchdog. */
class ScanManager extends EventEmitter {
  constructor () {
    super()
    this.setMaxListeners(0)
    this._activeTask = null
    this._net = { error: false, disconnected_at: null, reconnected_at: null }
    this._autoPaused = false
    this._stopping = new Set()      // tasks the user stopped, so we don't call it an error
    this._running = new Map()       // taskId -> promise for its sweep
    this._rescans = new Map()       // taskId -> Map(ip -> tool)
    this._rescanCancels = new Set() // `${taskId} ${ip}` the user asked to stop
    this._progressWritten = new Map()
    this._watchdog = null
  }

  // --- pub/sub ---------------------------------------------------------

  publish (taskId, event) {
    this.emit('event', { task_id: taskId, ...event })
  }

  /** Publishes a scanner output line and appends it to the task's log file.
   *
   * Persisting matters: without it a reload leaves you with an empty output
   * panel and no way to see why a scan found nothing.
   */
  log (taskId, line) {
    this.publish(taskId, { type: 'log', line })
    try {
      fs.appendFileSync(logPath(taskId), line + '\n')
    } catch { /* the scan matters more than its transcript */ }
  }

  // --- state -----------------------------------------------------------

  get activeTask () { return this._activeTask }

  networkState () { return { ...this._net } }

  isPaused (taskId) { return registry.isPaused(taskId) }

  // --- lifecycle -------------------------------------------------------

  /** Launches the scan. Returns a promise for its completion. Throws ScanBusy. */
  start (taskId, resume = false) {
    const task = store.getTask(taskId)
    if (!task) throw new ScanError('Task not found.')
    checkRequirements(task)

    if (this._activeTask && this._activeTask !== taskId) {
      const other = store.getTask(this._activeTask)
      const label = other ? other.name : this._activeTask
      throw new ScanBusy(
        `Another scan is already running ('${label}'). masscan saturates the ` +
        'link, so only one sweep runs at a time — stop that one first.')
    }
    if (this._activeTask === taskId) throw new ScanBusy('This task is already running.')
    this._activeTask = taskId

    store.updateTask(taskId, {
      status: 'running', started_at: now(), finished_at: null, error: null, progress: 0,
    })
    // The row says running, so the page has to hear about it. Without this the
    // only signal a start produced was a 'phase' event, which the controls did
    // not act on — so Start stayed Start while the scan ran behind it.
    this.publish(taskId, { type: 'status', status: 'running', message: 'Scan started.' })
    const promise = this._runTask(taskId, resume)
    this._running.set(taskId, promise)
    this.ensureWatchdog()
    return promise
  }

  pause (taskId) {
    const count = registry.pause(taskId)
    if (!count) {
      // Nothing was actually running — the scan finished before the click
      // landed. Leave the recorded status alone rather than marking a
      // completed task as paused.
      registry.resume(taskId)
      return 0
    }
    store.updateTask(taskId, { status: 'paused' })
    this.publish(taskId, {
      type: 'status', status: 'paused', message: `Paused ${count} running process(es).`,
    })
    return count
  }

  resume (taskId) {
    this._autoPaused = false
    this._net.error = false
    const count = registry.resume(taskId)
    if (registry.isRunning(taskId)) {
      store.updateTask(taskId, { status: 'running' })
      this.publish(taskId, { type: 'status', status: 'running', message: 'Resumed.' })
    }
    return count
  }

  /** Interrupts this task only. masscan gets a chance to write paused.conf. */
  async stop (taskId) {
    this._stopping.add(taskId)
    const count = await registry.stop(taskId, STOP_GRACE_SECONDS)
    // Let the sweep finish draining output and write its final status, so the
    // caller reads a settled state rather than "running".
    const pending = this._running.get(taskId)
    if (pending) {
      await Promise.race([pending, new Promise((r) => setTimeout(r, 15000))])
    }
    if (count) {
      this.publish(taskId, { type: 'status', status: 'stopped', message: 'Scan stopped.' })
    }
    return count
  }

  // --- rescans ---------------------------------------------------------

  activeRescans (taskId) {
    return Object.fromEntries(this._rescans.get(taskId) || new Map())
  }

  /** Runs a per-host rescan in the background; the outcome arrives as an event. */
  startRescan (taskId, address, tool, projectId = null) {
    if (!this._rescans.has(taskId)) this._rescans.set(taskId, new Map())
    const running = this._rescans.get(taskId)
    if (running.has(address)) {
      throw new ScanBusy(`A ${running.get(address)} rescan of ${address} is already running.`)
    }
    running.set(address, tool)
    const cancelKey = `${taskId} ${address}`
    this._rescanCancels.delete(cancelKey)
    const cancelled = () => this._rescanCancels.has(cancelKey)

    // What this host already had, so "new port" can mean it rather than being
    // a guess at how many the rescan happened to report.
    const before = new Set()
    for (const host of store.taskHosts(taskId)) {
      if (host.ip === address) {
        for (const port of host.ports) before.add(`${port.port}/${port.proto}`)
      }
    }

    const worker = async () => {
      this.publish(taskId, { type: 'rescan', state: 'running', ip: address, tool })
      let result
      try {
        const entry = rescanTool(tool)
        if (!entry) throw new ScanError(`Unknown tool: ${tool}`)
        result = await entry.run(address, { taskId, projectId, cancelled })
      } catch (err) {
        const state = err instanceof ScanCancelled ? 'cancelled' : 'error'
        const message = err instanceof ScanCancelled
          ? err.message
          : `${err.constructor.name}: ${err.message}`
        this.log(taskId, state === 'cancelled'
          ? `[i] ${message}`
          : `[!] Rescan of ${address} failed: ${message}`)
        this.publish(taskId, {
          type: 'rescan', state, ip: address, tool,
          ...(state === 'cancelled' ? { message } : { error: message }),
        })
        return
      } finally {
        const map = this._rescans.get(taskId)
        if (map) map.delete(address)
        this._rescanCancels.delete(cancelKey)
      }

      // Hand back the merged view so the card shows nmap services layered
      // over the ports masscan found.
      const host = store.taskHosts(taskId).find((h) => h.ip === address)
      const merged = host ? host.ports : (result.ports || [])
      const fresh = merged.filter((port) => !before.has(`${port.port}/${port.proto}`))
      const note = result.note
      const verb = result.stopped ? 'stopped' : 'finished'
      this.log(taskId,
        `Rescan of ${address} (${tool}) ${verb}: ${merged.length} port(s)` +
        (fresh.length ? `, ${fresh.length} new` : '') +
        (result.screenshots ? `, ${result.screenshots} screenshot(s)` : '') +
        (note ? ` — ${note}` : ''))
      this.publish(taskId, {
        type: 'rescan', state: 'done', ip: address, tool, ports: merged,
        new_ports: fresh.length,
        new_port_list: fresh.map((port) => `${port.port}/${port.proto}`).slice(0, 12),
        scan_id: result.scan_id, screenshots: result.screenshots || 0,
        note, stopped: Boolean(result.stopped),
      })
    }

    worker()
    return true
  }

  /** Stops one host's rescan, leaving the sweep and other hosts alone. */
  async stopRescan (taskId, address, settleMs = 5000) {
    const running = this._rescans.get(taskId)
    if (!running || !running.has(address)) return false
    this._rescanCancels.add(`${taskId} ${address}`)
    await registry.stop(rescanKey(taskId, address), 3)

    // Wait for the worker to unwind before reporting back. Otherwise the host
    // still counts as "being rescanned" for a moment, and an immediate second
    // click would be turned away as already running.
    const deadline = Date.now() + settleMs
    while (Date.now() < deadline) {
      const map = this._rescans.get(taskId)
      if (!map || !map.has(address)) break
      await new Promise((r) => setTimeout(r, 50))
    }
    return true
  }

  // --- the sweep -------------------------------------------------------

  /** Orchestrates a task: optional discovery, then the chosen port scan. */
  async _runTask (taskId, resume) {
    const task = store.getTask(taskId)
    const dir = runDir(taskId)
    const scanType = task.scan_type || 'full'
    let outcome = 'completed'
    let error = null

    try {
      // The log accumulates across runs, separated by a header: one task can
      // hold an nmap top-ports pass and a later full masscan sweep, and you
      // want to see both.
      this.log(taskId, '')
      this.log(taskId, `══ ${now()} · ${describe(task)} ══`)
      if (isLoopbackTarget(task.target)) {
        this.log(taskId,
          '[!] Warning: this target is loopback. masscan uses its own TCP/IP ' +
          'stack and transmits via a network adapter, so it cannot see services ' +
          'bound to 127.0.0.0/8 — this scan will report nothing no matter what ' +
          'is listening. Use nmap for localhost, or point this at a routable address.')
      }

      let targets = task.target

      // --- phase 1: host discovery ---------------------------------
      if (task.discovery && !resume) {
        const live = await this._phaseDiscovery(taskId, task, dir)
        if (live === null) { outcome = 'stopped'; return }
        if (!live.length) {
          this.log(taskId, 'Discovery found no live hosts — skipping the port ' +
            'scan. Try a different probe type if you expected hosts here.')
          store.updateTask(taskId, { progress: 100 })
          return
        }
        targets = live.map((h) => h.ip).join(',')
      }

      // --- phase 2: port scan --------------------------------------
      if (scanType === 'discovery') {
        store.updateTask(taskId, { progress: 100 })
        return
      }
      let result
      if (scanType === 'quick') {
        result = await this._phaseQuick(taskId, task, dir, targets)
      } else {
        const engine = task.engine || DEFAULT_ENGINE
        if (engine === 'nmap') {
          result = await this._phaseQuick(taskId, task, dir, targets)
        } else if (engine === 'rustscan') {
          result = await this._phaseRustscan(taskId, task, dir, targets)
        } else {
          this._warnMasscanUnreachable(taskId, targets)
          result = await this._phaseMasscan(taskId, task, dir, targets, resume)
        }
      }
      outcome = result.outcome
      error = result.error
    } catch (err) {
      outcome = 'error'
      error = err instanceof ScanError ? err.message : `${err.constructor.name}: ${err.message}`
    } finally {
      this._finishTask(taskId, outcome, error)
    }
  }

  /** Finds which addresses are alive. Returns the live hosts, or null if stopped. */
  async _phaseDiscovery (taskId, task, dir) {
    const profile = discovery.getProfile(task.discovery)
    if (!profile) throw new ScanError(`Unknown discovery method: '${task.discovery}'`)

    // Reuse: no probe, no clearing. Everything this task has ever seen alive —
    // discovery hits and hosts that turned up ports — becomes the target list.
    if (task.discovery === discovery.PREVIOUS) return this._reusePreviousHosts(taskId, task)

    requireTool(profile.tool)
    store.clearHosts(taskId)     // a re-run re-discovers from scratch
    this.publish(taskId, {
      type: 'phase', phase: 'discovery', tool: profile.tool, label: profile.label,
    })
    this.log(taskId, `[discovery] ${profile.label} over ${task.target}`)

    const found = profile.perHost
      ? await this._discoverPerHost(taskId, task, profile)
      : await this._discoverRange(taskId, task, dir, profile)
    if (found === null) return null

    store.addHosts(taskId, found, profile.key)
    const live = store.liveHosts(taskId)
    this.log(taskId, `[discovery] ${live.length} host(s) up out of ` +
      `${countTargets(task.target) ?? '?'} address(es).`)
    this.publish(taskId, { type: 'discovery_done', count: live.length })
    return live
  }

  /** Uses the hosts this task already knows instead of probing again. */
  _reusePreviousHosts (taskId, task) {
    this.publish(taskId, {
      type: 'phase', phase: 'discovery', tool: 'none',
      label: 'Reusing hosts found earlier',
    })

    // taskHosts is the union of discovery hits and anything with a finding, so
    // a task that only ever ran a port sweep still has a usable list.
    const known = store.taskHosts(taskId).map((host) => host.ip)
    if (!known.length) {
      throw new ScanError(
        'No hosts from an earlier run of this task, so there is nothing to ' +
        'reuse. Run a discovery sweep once — fping or nmap — and later runs ' +
        'can reuse what it finds.')
    }

    // Put them back in the hosts table so the rest of the run, and the host
    // list on the page, work exactly as they would after a real sweep.
    store.addHosts(taskId, known.map((ip) => ({
      ip, state: 'up', reason: 'found by an earlier run',
    })), discovery.PREVIOUS)

    const live = store.liveHosts(taskId)
    this.log(taskId, `[discovery] reusing ${live.length} host(s) found earlier — ` +
      'no probe sent.')
    this.publish(taskId, { type: 'discovery_done', count: live.length })
    return live
  }

  async _discoverRange (taskId, task, dir, profile) {
    const { argv, kind } = discovery.buildCommand(profile, task.target, dir, task.rate)
    this.log(taskId, '$ ' + argv.join(' '))
    const child = registry.spawn(taskId, argv, { cwd: dir })
    const streamed = []
    try {
      const stderrDone = this._pumpStderr(taskId, child)
      await eachLine(child.stdout, (raw) => {
        const line = raw.replace(/\s+$/, '')
        if (!line) return
        if (kind === 'stdout_ips') {
          // fping prints live addresses as it gets replies.
          for (const host of discovery.parseIpLines(line)) {
            streamed.push(host)
            this._publishHost(taskId, host, profile.key)
          }
          return
        }
        if (kind === 'masscan_list') {
          const hit = parseDiscoveryLine(line)
          if (hit) {
            const host = { ip: hit.ip, state: 'up', reason: 'icmp-reply' }
            streamed.push(host)
            this._publishHost(taskId, host, profile.key)
            return
          }
        }
        this.log(taskId, line)
      })
      await exitCode(child)
      await stderrDone
    } finally {
      registry.release(taskId, child)
    }

    if (this._stopping.has(taskId)) return null

    if (kind === 'nmap_xml') {
      let hosts = []
      try {
        hosts = discovery.parseNmapHosts(
          fs.readFileSync(path.join(dir, 'discovery.xml'), 'utf8'))
      } catch { hosts = [] }
      for (const host of hosts) this._publishHost(taskId, host, profile.key)
      return hosts
    }

    if (kind === 'masscan_list') {
      const hosts = new Map(streamed.map((h) => [h.ip, h]))
      for (const host of discovery.parseMasscanPings(path.join(dir, 'discovery.list'))) {
        if (!hosts.has(host.ip)) hosts.set(host.ip, host)
      }
      return [...hosts.values()]
    }

    // fping exits non-zero whenever anything was unreachable, which is the
    // normal outcome of a sweep, so its return code says nothing useful.
    return [...new Map(streamed.map((h) => [h.ip, h])).values()]
  }

  async _discoverPerHost (taskId, task, profile) {
    const addresses = discovery.expandTargets(task.target)
    const tooBig = discovery.checkHostCap(profile, task.target, addresses.length)
    if (tooBig) throw new ScanError(tooBig)

    const dir = runDir(taskId)
    const found = await discovery.runPerHost(
      profile, addresses,
      (argv, options) => runOnce(argv, { ...options, cwd: dir, taskId }),
      (message) => this.log(taskId, `[discovery] ${message}`),
      () => this._stopping.has(taskId))

    if (this._stopping.has(taskId)) return null
    for (const host of found) this._publishHost(taskId, host, profile.key)
    return found
  }

  _publishHost (taskId, host, method) {
    this.publish(taskId, {
      type: 'discovered', ip: host.ip,
      hostname: host.hostname ?? null, reason: host.reason ?? null, method,
    })
  }

  /** nmap-only port scan: top-N by default, or an explicit range. */
  async _phaseQuick (taskId, task, dir, targets) {
    requireTool('nmap')
    // Long host lists go to a file; discovery owns that rule so nmap and the
    // quick scan cannot disagree about when the command line is too long.
    const targetArgs = discovery.targetArgs(targets, dir, 'quick')
    // An explicit range wins over top-ports: that is how you ask for the
    // accurate full sweep (1-65535) when masscan's results look doubtful.
    const portArgs = task.tcp_ports
      ? ['-p', task.tcp_ports]
      : ['--top-ports', String(Number.parseInt(task.top_ports || DEFAULT_TOP_PORTS, 10))]

    const argv = ['nmap', '-sT', '-sV', '-T4', '-Pn', '-n', ...portArgs,
      '--stats-every', '5s', '-oX', 'quick.xml', ...targetArgs]

    this.log(taskId, '$ ' + argv.join(' '))
    this.publish(taskId, { type: 'phase', phase: 'portscan', tool: 'nmap' })

    const child = registry.spawn(taskId, argv, { cwd: dir })
    let code = null
    try {
      const stderrDone = this._pumpStderr(taskId, child)
      await eachLine(child.stdout, (raw) => {
        const line = raw.replace(/\s+$/, '')
        if (!line) return
        const percent = parseNmapProgress(line)
        if (percent !== null) {
          this._maybePersistProgress(taskId, percent)
          this.publish(taskId, {
            type: 'progress', percent, rateKpps: 0, remaining: null, found: null,
          })
        } else {
          this.log(taskId, line)
        }
      })
      code = await exitCode(child)
      await stderrDone
    } finally {
      registry.release(taskId, child)
    }

    let byHost = {}
    try {
      byHost = parseNmapXml(fs.readFileSync(path.join(dir, 'quick.xml'), 'utf8'))
    } catch { byHost = {} }

    const seen = new Set(store.taskHosts(taskId).map((h) => h.ip))
    for (const [address, ports] of Object.entries(byHost)) {
      if (!ports.length) continue
      store.addFindings(taskId, address, ports, 'nmap')
      for (const port of ports) {
        this.publish(taskId, {
          type: 'host', ip: address, new_host: !seen.has(address), port,
        })
        seen.add(address)
      }
    }

    if (this._stopping.has(taskId)) return { outcome: 'stopped', error: null }
    if (code !== 0 && code !== null) {
      const detail = lastMeaningfulLine(readLog(taskId))
      return {
        outcome: 'error',
        error: `nmap exited with code ${code}.` + (detail ? ` Last output: ${detail}` : ''),
      }
    }
    store.updateTask(taskId, { progress: 100 })
    return { outcome: 'completed', error: null }
  }

  /** Says up front when masscan physically cannot reach the target.
   *
   * Otherwise the run looks successful and simply reports nothing, which is the
   * single most misleading result this tool can produce.
   */
  _warnMasscanUnreachable (taskId, targets) {
    const networks = ipsecOutNetworks()
    const first = discovery.expandTargets(targets, 1)[0]
    if (!first) return
    const { ok, reason } = masscanReachability(first, networks)
    if (!ok) this.log(taskId, `[!] masscan is very unlikely to work here: ${reason}`)
  }

  /** rustscan: fast full-range TCP connect scan, works over tunnels. */
  async _phaseRustscan (taskId, task, dir, targets) {
    requireTool('rustscan')
    const ports = task.tcp_ports || DEFAULT_TCP_PORTS
    const addresses = discovery.expandTargets(targets, 4096)
    if (!addresses.length) {
      throw new ScanError(`Could not expand '${targets}' into addresses for rustscan.`)
    }

    const argv = ['rustscan', '-a', addresses.join(','), '--no-banner', '-n',
      '-g', '--scripts', 'none',
      '-b', String(RUSTSCAN_BATCH), '-u', String(RUSTSCAN_ULIMIT),
      '-t', String(RUSTSCAN_TIMEOUT_MS), '--tries', String(RUSTSCAN_TRIES)]
    // rustscan takes either a range or an explicit list, never both.
    if (ports.includes(',') || !ports.includes('-')) argv.push('-p', ports)
    else argv.push('-r', ports)
    if (task.udp_ports) {
      this.log(taskId, '[i] rustscan is TCP-only — the UDP range is ignored. ' +
        'Use masscan or nmap for UDP.')
    }

    this.log(taskId, '$ ' + argv.slice(0, 8).join(' ') + ' ...')
    this.publish(taskId, { type: 'phase', phase: 'portscan', tool: 'rustscan' })

    const seen = new Set(store.taskHosts(taskId).map((h) => h.ip))
    const child = registry.spawn(taskId, argv, { cwd: dir })
    let code = null
    try {
      const stderrDone = this._pumpStderr(taskId, child)
      await eachLine(child.stdout, (raw) => {
        const line = raw.replace(/\s+$/, '')
        if (!line) return
        const hit = parseRustscanLine(line)
        if (!hit) { this.log(taskId, line); return }
        store.addFindings(taskId, hit.ip,
          hit.ports.map((p) => ({ port: p, proto: 'tcp', state: 'open' })), 'rustscan')
        for (const port of hit.ports) {
          this.publish(taskId, {
            type: 'host', ip: hit.ip, new_host: !seen.has(hit.ip),
            port: { port, proto: 'tcp', state: 'open' },
          })
          seen.add(hit.ip)
        }
      })
      code = await exitCode(child)
      await stderrDone
    } finally {
      registry.release(taskId, child)
    }

    if (this._stopping.has(taskId)) return { outcome: 'stopped', error: null }
    if (code !== 0 && code !== null) {
      const detail = lastMeaningfulLine(readLog(taskId))
      return {
        outcome: 'error',
        error: `rustscan exited with code ${code}.` + (detail ? ` Last output: ${detail}` : ''),
      }
    }
    store.updateTask(taskId, { progress: 100 })
    return { outcome: 'completed', error: null }
  }

  async _phaseMasscan (taskId, task, dir, targets, resume) {
    const listPath = path.join(dir, 'findings.list')
    const pausedConf = pausedConfPath(taskId)
    const seenHosts = new Set(store.taskHosts(taskId).map((h) => h.ip))
    // Remembering the mtime lets us tell a paused.conf this run just wrote
    // (a real stop) from one left over from a previous run (a failed resume).
    const pausedBefore = mtime(pausedConf)

    let argv
    let dropped = []
    if (resume) {
      if (!fs.existsSync(pausedConf)) {
        throw new ScanError('No paused.conf saved for this task — nothing to resume.')
      }
      dropped = sanitizePausedConf(pausedConf)
      argv = ['masscan', '--resume', path.basename(pausedConf)]
    } else {
      const spec = buildPortSpec(task.tcp_ports, task.udp_ports)
      const rate = String(task.rate || DEFAULT_RATE)
      const retries = task.retries === null || task.retries === undefined
        ? DEFAULT_RETRIES
        : Number.parseInt(task.retries, 10)
      const wait = task.wait || MASSCAN_WAIT
      argv = ['masscan', ...String(targets).split(','), '-p', spec,
        '--rate', rate, '--wait', String(wait), '--retries', String(retries),
        '-oL', path.basename(listPath)]
      if (retries === 0) {
        this.log(taskId,
          '[!] retries is 0 — masscan will send a single SYN per port and never ' +
          'retransmit. Any dropped probe silently loses that port. Raise retries ' +
          'if results look thin.')
      }
      // A stale paused.conf from a previous run would be misleading.
      unlink(pausedConf)
      unlink(listPath)
    }

    if (dropped.length) {
      this.log(taskId, '[i] Removed config keys masscan cannot read back from ' +
        'its own paused.conf: ' + dropped.join('; '))
    }
    this.log(taskId, '$ ' + argv.join(' '))
    this.publish(taskId, { type: 'phase', phase: 'portscan', tool: 'masscan' })

    const child = registry.spawn(taskId, argv, { cwd: dir })
    let code = null
    try {
      const stderrDone = this._pumpStderr(taskId, child)
      await eachLine(child.stdout, (line) => {
        const hit = parseDiscoveryLine(line)
        if (hit) this._recordHit(taskId, hit, seenHosts)
        else if (line.trim()) this.log(taskId, line.replace(/\s+$/, ''))
      })
      code = await exitCode(child)
      await stderrDone
    } finally {
      registry.release(taskId, child)
    }

    // Backfill from -oL in case stdout was block-buffered or lines were
    // dropped; the file is masscan's own authoritative record.
    for (const hit of parseMasscanListFile(listPath)) {
      this._recordHit(taskId, hit, seenHosts, true)
    }

    const wasStopped = this._stopping.has(taskId)

    // Only a paused.conf written *by this run* means "resumable". An untouched
    // one is a leftover, and treating it as a stop is how a failed resume used
    // to disguise itself as a successful one.
    const pausedWrittenNow = fs.existsSync(pausedConf) && mtime(pausedConf) !== pausedBefore

    if (pausedWrittenNow) {
      store.updateTask(taskId, { resumable: 1 })
      return { outcome: 'stopped', error: null }
    }
    if (wasStopped) return { outcome: 'stopped', error: null }
    if (code !== 0 && code !== null) {
      // Not a stop, and masscan saved no new position: it genuinely failed —
      // bad permissions, bad interface, unreadable resume file.
      const detail = lastMeaningfulLine(readLog(taskId))
      let error = `masscan exited with code ${code}.`
      if (detail) error += ` Last output: ${detail}`
      if (resume) {
        error += ' The resume file may be unusable — start the scan from the beginning instead.'
      }
      return { outcome: 'error', error }
    }

    // A clean full sweep supersedes any older resume point.
    unlink(pausedConf)
    store.updateTask(taskId, { resumable: 0, progress: 100 })
    this._warnIfThin(taskId, task, targets)
    return { outcome: 'completed', error: null }
  }

  /** Flags results that look like packet loss rather than a quiet host. */
  _warnIfThin (taskId, task, targets) {
    const hostCount = countTargets(targets) || 1
    const found = store.taskHosts(taskId).flatMap((h) => h.ports)
    if (!found.length) return

    const retries = task.retries === null || task.retries === undefined
      ? DEFAULT_RETRIES
      : Number.parseInt(task.retries, 10)

    // Only two ports across a whole sweep, and both of them the classic ALG
    // pair, is the signature of a middlebox answering rather than the host.
    const ports = new Set(found.map((p) => p.port))
    if (ports.size && [...ports].every((p) => ALG_PORTS.has(p))) {
      this.log(taskId,
        `[!] Every port found (${[...ports].sort((a, b) => a - b).join(', ')}) is one ` +
        'a SIP/SCCP application-layer gateway commonly answers for. These are ' +
        'frequently NOT open on the host itself — a router or VoIP firewall in the ' +
        "path replies instead. Confirm with 'nmap -sV -Pn' before trusting them.")
    }

    if (retries === 0 && found.length <= 3 * hostCount) {
      this.log(taskId,
        '[!] Few ports found and retries is 0. masscan does not retransmit, so ' +
        'dropped probes look identical to closed ports. Re-run with retries 2-3 ' +
        'before concluding the host is quiet.')
    }
  }

  _finishTask (taskId, outcome, error) {
    if (this._activeTask === taskId) this._activeTask = null
    this._stopping.delete(taskId)
    this._running.delete(taskId)
    this._progressWritten.delete(taskId)

    store.updateTask(taskId, { status: outcome, finished_at: now(), error })
    const hosts = store.taskHosts(taskId)
    const ports = hosts.reduce((total, h) => total + h.ports.length, 0)
    this.log(taskId, `Finished: ${outcome} — ${hosts.length} host(s), ${ports} port(s).` +
      (error ? ` Error: ${error}` : ''))
    this.publish(taskId, {
      type: 'done', status: outcome, error,
      hosts: hosts.length, ports,
      resumable: fs.existsSync(pausedConfPath(taskId)),
    })
  }

  _recordHit (taskId, hit, seenHosts, quietIfKnown = false) {
    const fresh = store.addFindings(taskId, hit.ip, [hit], 'masscan')
    if (!fresh.length && quietIfKnown) return
    const isNewHost = !seenHosts.has(hit.ip)
    seenHosts.add(hit.ip)
    this.publish(taskId, {
      type: 'host', ip: hit.ip, new_host: isNewHost,
      port: { port: hit.port, proto: hit.proto, state: hit.state },
    })
  }

  _maybePersistProgress (taskId, percent, minIntervalMs = 3000) {
    const stamp = Date.now()
    const last = this._progressWritten.get(taskId) || 0
    if (stamp - last < minIntervalMs) return
    this._progressWritten.set(taskId, stamp)
    store.updateTask(taskId, { progress: percent })
  }

  /** masscan repaints its status line with \r, so split on both terminators. */
  _pumpStderr (taskId, child) {
    return new Promise((resolve) => {
      let buffer = ''
      child.stderr.on('data', (chunk) => {
        buffer += chunk
        const parts = buffer.split(/[\r\n]/)
        buffer = parts.pop()
        for (const raw of parts) {
          const part = raw.trim()
          if (!part) continue
          const progress = parseProgressLine(part)
          if (progress) {
            // Stream every repaint to the interface, but only persist every few
            // seconds — masscan repaints several times a second and a write per
            // repaint is pure churn.
            this._maybePersistProgress(taskId, progress.percent)
            this.publish(taskId, { type: 'progress', ...progress })
          } else {
            this.log(taskId, part)
          }
        }
      })
      const done = () => resolve()
      child.stderr.once('end', done)
      child.stderr.once('close', done)
      child.stderr.once('error', done)
    })
  }

  // --- connectivity watchdog ------------------------------------------

  ensureWatchdog () {
    if (this._watchdog) return
    this._watchdog = setInterval(() => { this._watchNetwork() }, 5000)
    // Must not keep the process alive on its own.
    if (this._watchdog.unref) this._watchdog.unref()
  }

  stopWatchdog () {
    if (this._watchdog) { clearInterval(this._watchdog); this._watchdog = null }
  }

  /** Freezes the sweep when connectivity drops, and says so once each way. */
  async _watchNetwork () {
    const taskId = this._activeTask
    if (!taskId) return
    const connected = await checkInternet()

    const wasError = this._net.error
    let announce = null
    if (!connected && !wasError) {
      this._net = { error: true, disconnected_at: now(), reconnected_at: null }
      if (!registry.isPaused(taskId)) {
        this._autoPaused = true
        announce = 'lost'
      }
    } else if (connected && wasError) {
      this._net = { ...this._net, error: false, reconnected_at: now() }
      // Only invite a resume if the drop is what paused it.
      announce = this._autoPaused ? 'restored' : null
      this._autoPaused = false
    }
    const snapshot = { ...this._net }

    if (announce === 'lost') {
      registry.pause(taskId)
      store.updateTask(taskId, { status: 'paused' })
      this.publish(taskId, {
        type: 'network', connected: false,
        disconnected_at: snapshot.disconnected_at,
        message: 'Network lost — scan paused automatically.',
      })
    } else if (announce === 'restored') {
      this.publish(taskId, {
        type: 'network', connected: true,
        reconnected_at: snapshot.reconnected_at,
        message: 'Network restored — press resume to continue.',
      })
    }
  }
}

const manager = new ScanManager()

// --- nmap ----------------------------------------------------------------

/** Runs nmap against exactly the ports masscan already found on this host. */
async function runNmap (taskId, address, ports, udp = false, extra = null) {
  // `ports` is normally the list already found. A full-port rescan passes a
  // spec string instead ('-' for every port), and a UDP sweep passes null and
  // supplies --top-ports through `extra`.
  const selector = extra || ['-p', Array.isArray(ports) ? ports.join(',') : String(ports)]
  const base = udp
    ? ['nmap', '-sU', '-sV', '-Pn', '-T4', ...selector, address]
    : ['nmap', '-sC', '-sV', '-Pn', '-T4', ...selector, address]

  const dir = runDir(taskId || 'adhoc')
  const xmlName = `nmap-${crypto.randomUUID().replace(/-/g, '').slice(0, 8)}.xml`
  const xmlPath = path.join(dir, xmlName)
  const argv = [...base, '-oX', xmlName, '-oN', '-']

  const key = rescanKey(taskId, address)
  const result = await runOnce(argv, { cwd: dir, timeout: NMAP_TIMEOUT * 1000, taskId: key })

  let normalOut = result.stdout || ''
  if (result.timedOut) {
    normalOut += `\nnmap timed out after ${NMAP_TIMEOUT}s and was terminated.`
  } else if (result.stderr) {
    normalOut += '\n' + result.stderr
  }

  let parsed = []
  try {
    const byHost = parseNmapXml(fs.readFileSync(xmlPath, 'utf8'))
    parsed = byHost[address] || Object.values(byHost)[0] || []
  } catch { /* nmap wrote nothing usable */ } finally {
    unlink(xmlPath)
  }

  return { output: normalOut, ports: parsed, command: argv.join(' ') }
}

/** Deep-scans one host over its known-open ports and stores the full report.
 *
 * `cancelled` is checked between phases. Stopping during nmap discards the run
 * — its output was cut off mid-scan and is not worth keeping. Stopping during
 * the screenshot pass keeps the nmap results, since those are already complete
 * and only the browser work was abandoned.
 */
async function nmapRescan (address, tool, { taskId = null, projectId = null, cancelled } = {}) {
  requireTool('nmap')
  const isCancelled = cancelled || (() => false)

  let known = []
  if (taskId) {
    const host = store.taskHosts(taskId).find((h) => h.ip === address)
    if (host) known = host.ports
  }
  if (!known.length) {
    throw new ScanError(
      'No discovered ports for this host yet. Run a masscan sweep first so nmap ' +
      'knows which ports to inspect.')
  }

  const tcpPorts = [...new Set(known.filter((p) => p.proto === 'tcp').map((p) => p.port))]
    .sort((a, b) => a - b)
  let udpPorts = [...new Set(known.filter((p) => p.proto === 'udp').map((p) => p.port))]
    .sort((a, b) => a - b)
  if (udpPorts.length && geteuid() !== 0) {
    udpPorts = []   // -sU needs root; skip rather than fail the whole rescan
  }

  const discovered = []
  const sections = []
  const commands = []
  if (tcpPorts.length) {
    const result = await runNmap(taskId, address, tcpPorts, false)
    discovered.push(...result.ports)
    sections.push(`# TCP service/script scan on ports: ${tcpPorts.join(',')}\n${result.output}`)
    commands.push(result.command)
  }
  if (isCancelled()) throw new ScanCancelled(`Rescan of ${address} stopped during the nmap scan.`)
  if (udpPorts.length) {
    const result = await runNmap(taskId, address, udpPorts, true)
    discovered.push(...result.ports)
    sections.push(`# UDP scan on ports: ${udpPorts.join(',')}\n${result.output}`)
    commands.push(result.command)
  }
  if (isCancelled()) throw new ScanCancelled(`Rescan of ${address} stopped during the nmap scan.`)

  const scanId = crypto.randomUUID().replace(/-/g, '').slice(0, 12)
  const { shots, note } = await screenshots.capture(address, discovered, scanId,
    { cancelled: isCancelled })
  if (note) sections.push(`# Web screenshots: ${note}`)

  store.saveNmapScan(scanId, address, tool, commands.join('\n'), sections.join('\n\n'),
    discovered, shots, { taskId, projectId })
  if (taskId && discovered.length) {
    store.replaceFindings(taskId, address, discovered, 'nmap')
  }

  return {
    ip: address, ports: discovered, scan_id: scanId,
    screenshots: shots.length, note, stopped: isCancelled(),
  }
}

/** One-shot full-port masscan against a single host. */
async function masscanRescan (address, proto, { taskId = null, rate = 5000, cancelled } = {}) {
  requireTool('masscan')
  const isCancelled = cancelled || (() => false)
  if (geteuid() !== 0 && !inheritsCapNetRaw() && !hasRawCaps('masscan')) {
    throw new ScanError(
      "masscan needs raw sockets. Grant them once with 'sudo setcap " +
      "cap_net_raw+ep $(which masscan)'.")
  }

  const spec = proto === 'tcp' ? 'T:1-65535' : 'U:1-65535'
  const dir = runDir(taskId || 'adhoc')
  const key = rescanKey(taskId, address)
  const argv = ['masscan', address, '-p', spec, '--rate', String(rate),
    '--wait', String(MASSCAN_WAIT)]
  const result = await runOnce(argv, { cwd: dir, timeout: NMAP_TIMEOUT * 1000, taskId: key })

  if (isCancelled()) throw new ScanCancelled(`Rescan of ${address} stopped.`)

  const ports = parseMasscanStdout(result.stdout)
  if (taskId) store.addFindings(taskId, address, ports, 'masscan')
  return { ip: address, ports }
}

/** A whole-host nmap rescan, rather than only the ports already known.
 *
 * The known-ports scan (nmapRescan) can only confirm what a sweep already
 * found; this is what you reach for when you suspect the sweep under-reported.
 */
async function nmapFullRescan (address, tool, { taskId = null, projectId = null,
  cancelled } = {}) {
  requireTool('nmap')
  const isCancelled = cancelled || (() => false)

  const selector = ['-p', '-']
  const { output, ports, command } = await runNmap(taskId, address, null, false, selector)
  if (isCancelled()) {
    throw new ScanCancelled(`Rescan of ${address} stopped during the nmap scan.`)
  }

  const heading = '# TCP service/script scan over every port (-p-)'

  const scanId = crypto.randomUUID().replace(/-/g, '').slice(0, 12)
  // Same capture path as the known-ports rescan: browsers go through the
  // registry, so a per-host stop reaches them too.
  const { shots, note } = await screenshots.capture(address, ports, scanId,
    { cancelled: isCancelled })
  const sections = [`${heading}\n${output}`]
  if (note) sections.push(`# Web screenshots: ${note}`)

  store.saveNmapScan(scanId, address, tool, command, sections.join('\n\n'),
    ports, shots, { taskId, projectId })
  if (taskId && ports.length) store.replaceFindings(taskId, address, ports, 'nmap')

  return { ip: address, ports, scan_id: scanId, screenshots: shots.length,
    note, stopped: isCancelled() }
}

/** Full-port TCP rescan of one host with rustscan.
 *
 * The reason to pick this over masscan: rustscan uses ordinary kernel sockets,
 * so it reaches hosts behind an IPsec or VPN tunnel that masscan cannot, and it
 * needs no privilege at all.
 */
async function rustscanRescan (address, { taskId = null, cancelled } = {}) {
  requireTool('rustscan')
  const isCancelled = cancelled || (() => false)

  const dir = runDir(taskId || 'adhoc')
  const key = rescanKey(taskId, address)
  const argv = ['rustscan', '-a', address, '--no-banner', '-n', '-g',
    '--scripts', 'none', '-r', '1-65535',
    '-b', String(RUSTSCAN_BATCH), '-u', String(RUSTSCAN_ULIMIT),
    '-t', String(RUSTSCAN_TIMEOUT_MS), '--tries', String(RUSTSCAN_TRIES)]
  const result = await runOnce(argv, { cwd: dir, timeout: NMAP_TIMEOUT * 1000, taskId: key })

  if (isCancelled()) throw new ScanCancelled(`Rescan of ${address} stopped.`)

  const ports = []
  for (const line of String(result.stdout || '').split('\n')) {
    const hit = parseRustscanLine(line)
    if (hit) for (const port of hit.ports) ports.push({ port, proto: 'tcp', state: 'open' })
  }
  if (taskId) store.addFindings(taskId, address, ports, 'rustscan')
  return { ip: address, ports }
}

/** Every per-host rescan the interface can offer.
 *
 * Defined here rather than in the renderer so the list and the code that runs
 * it cannot drift apart, and so a tool that is not installed can be marked
 * unavailable rather than failing only once someone picks it.
 */
const RESCAN_TOOLS = [
  { key: 'nmap_deep', label: 'nmap -sC -sV (known ports)', tool: 'nmap',
    note: 'Service and script scan over the ports already found, plus web screenshots. The usual follow-up.',
    run: (ip, o) => nmapRescan(ip, 'nmap_deep', o) },
  { key: 'nmap_tcp', label: 'nmap all TCP (-p-)', tool: 'nmap',
    note: 'Every TCP port with service detection. Slow, but the most trustworthy answer when a sweep looks thin.',
    run: (ip, o) => nmapFullRescan(ip, 'nmap_tcp', o) },
  { key: 'rustscan_tcp', label: 'rustscan all TCP', tool: 'rustscan',
    note: 'Every TCP port over kernel sockets: fast, needs no privilege, and works through IPsec and VPN tunnels.',
    run: (ip, o) => rustscanRescan(ip, o) },
  { key: 'masscan_tcp', label: 'masscan all TCP', tool: 'masscan',
    note: 'Fastest full TCP sweep. Needs CAP_NET_RAW and cannot cross a tunnel.',
    run: (ip, o) => masscanRescan(ip, 'tcp', o) },
  { key: 'masscan_udp', label: 'masscan all UDP', tool: 'masscan',
    note: 'Every UDP port at masscan speed. Needs CAP_NET_RAW and cannot cross a tunnel.',
    run: (ip, o) => masscanRescan(ip, 'udp', o) },
]

const rescanTool = (key) => RESCAN_TOOLS.find((entry) => entry.key === key) || null

module.exports = {
  ScanBusy, ScanError, ScanCancelled,
  RESCAN_TOOLS, rescanTool, nmapFullRescan, rustscanRescan,
  manager, ScanManager,
  runDir, pausedConfPath, logPath, readLog,
  sanitizePausedConf, requireTool, buildPortSpec, checkRequirements,
  inheritsCapNetRaw, hasRawCaps,
  rescanKey, nmapRescan, masscanRescan,
  lastMeaningfulLine,
}
