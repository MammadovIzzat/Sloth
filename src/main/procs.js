'use strict'
/** Child-process registry with real pause/resume/stop.
 *
 * Every child is spawned into its own process group (detached: true) and
 * tracked against the task that owns it, so signals go to exactly that group
 * and nothing else on the machine:
 *
 *     pause  -> SIGSTOP   (freezes immediately, mid-sweep)
 *     resume -> SIGCONT
 *     stop   -> SIGCONT (in case it was paused), then SIGINT so masscan gets the
 *               chance to write paused.conf for --resume, then SIGKILL on timeout.
 *
 * Ported from procs.py. Node signals a group the same way POSIX does — a
 * negative pid — but process.kill() throws instead of returning a status, and
 * a detached child's pid *is* its process group id, so getpgid has no
 * equivalent and is not needed.
 */
const { spawn } = require('node:child_process')

const { STOP_GRACE_SECONDS } = require('./config')

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

class ProcessRegistry {
  constructor () {
    this._procs = new Map()      // taskId -> Set<ChildProcess>
    this._paused = new Set()
  }

  /** Starts a child in its own process group and registers it under taskId. */
  spawn (taskId, argv, { cwd = null, env = null } = {}) {
    const [file, ...args] = argv
    const child = spawn(file, args, {
      cwd: cwd || undefined,
      env: env || process.env,
      detached: true,            // its own process group, so signals stay contained
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')

    // Track exit ourselves: child.killed only reflects whether we signalled it.
    child.__exited = false
    child.once('exit', () => { child.__exited = true })
    // Without a listener, a spawn failure (ENOENT) is an unhandled error event
    // that would take the whole main process down.
    child.once('error', () => { child.__exited = true })

    if (!this._procs.has(taskId)) this._procs.set(taskId, new Set())
    this._procs.get(taskId).add(child)

    // A child started while the task is paused should start paused too.
    if (this._paused.has(taskId)) signalGroup(child, 'SIGSTOP')
    return child
  }

  release (taskId, child) {
    const procs = this._procs.get(taskId)
    if (!procs) return
    procs.delete(child)
    if (!procs.size) this._procs.delete(taskId)
  }

  _live (taskId) {
    const procs = this._procs.get(taskId)
    if (!procs) return []
    return [...procs].filter((child) => !child.__exited && child.exitCode === null)
  }

  isRunning (taskId) {
    return this._live(taskId).length > 0
  }

  isPaused (taskId) {
    return this._paused.has(taskId)
  }

  pause (taskId) {
    this._paused.add(taskId)
    let count = 0
    for (const child of this._live(taskId)) {
      if (signalGroup(child, 'SIGSTOP')) count++
    }
    return count
  }

  resume (taskId) {
    this._paused.delete(taskId)
    let count = 0
    for (const child of this._live(taskId)) {
      if (signalGroup(child, 'SIGCONT')) count++
    }
    return count
  }

  /** Interrupts this task's children only. Returns how many were signalled. */
  async stop (taskId, grace = STOP_GRACE_SECONDS) {
    this._paused.delete(taskId)
    const procs = this._live(taskId)
    for (const child of procs) {
      // A SIGSTOPped process cannot act on SIGINT until it is resumed.
      signalGroup(child, 'SIGCONT')
      signalGroup(child, 'SIGINT')
    }

    const deadline = Date.now() + grace * 1000
    for (const child of procs) {
      const remaining = deadline - Date.now()
      const exited = remaining > 0 && await waitFor(child, remaining)
      if (!exited) {
        signalGroup(child, 'SIGKILL')
        await waitFor(child, 5000)
      }
      // Sweep the group even when the leader went quietly. A shell that
      // backgrounds a job sets that child to ignore SIGINT, so it can outlive
      // the leader; it then holds the inherited stdout pipe open forever and
      // the scan never looks finished. Harmless when the group is already
      // empty — the kill simply fails.
      killGroup(child.pid, 'SIGKILL')
      // Drop our end of the pipes: a survivor we could not reach must not keep
      // a handle alive on this side either.
      for (const stream of [child.stdout, child.stderr]) {
        if (stream && !stream.destroyed) stream.destroy()
      }
    }
    return procs.length
  }

  async stopAll () {
    for (const taskId of [...this._procs.keys()]) {
      await this.stop(taskId, 2)
    }
  }
}

/** Resolves true if the child exited within the timeout, false otherwise. */
function waitFor (child, timeoutMs) {
  if (child.__exited || child.exitCode !== null) return Promise.resolve(true)
  return new Promise((resolve) => {
    let timer = null
    const done = (value) => {
      if (timer) clearTimeout(timer)
      child.removeListener('exit', onExit)
      resolve(value)
    }
    const onExit = () => done(true)
    child.once('exit', onExit)
    timer = setTimeout(() => done(false), timeoutMs)
  })
}

/** Signals the child's whole process group; false if it is already gone.
 *
 * A detached child leads its own group, so -pid addresses the group. If that
 * fails — the group is gone, or the child was never detached — fall back to the
 * single pid rather than leaving it running.
 */
function signalGroup (child, sig) {
  if (child.__exited || child.exitCode !== null || !child.pid) return false
  if (killGroup(child.pid, sig)) return true
  try {
    process.kill(child.pid, sig)
    return true
  } catch {
    return false
  }
}

/** Signals a process group by leader pid, whatever state the leader is in.
 *
 * Separate from signalGroup because that one short-circuits once the leader has
 * exited, which is precisely when a surviving group member needs reaching.
 */
function killGroup (pid, sig) {
  if (!pid) return false
  try {
    process.kill(-pid, sig)
    return true
  } catch {
    return false
  }
}

/** Runs a command to completion, collecting its output.
 *
 * Replaces Popen.communicate(timeout=...) for the one-shot probes. On timeout
 * the whole group is killed, not just the leader, so a tool that forked cannot
 * leave children behind.
 */
function run (argv, { cwd = null, env = null, timeout = 0, taskId = null,
  registry: reg = registry } = {}) {
  return new Promise((resolve) => {
    const child = reg.spawn(taskId ?? '__oneshot__', argv, { cwd, env })
    let stdout = ''
    let stderr = ''
    let timedOut = false

    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })

    const timer = timeout
      ? setTimeout(() => { timedOut = true; signalGroup(child, 'SIGKILL') }, timeout)
      : null

    const finish = (code) => {
      if (timer) clearTimeout(timer)
      reg.release(taskId ?? '__oneshot__', child)
      resolve({ code, stdout, stderr, timedOut })
    }
    child.once('exit', (code) => finish(code))
    child.once('error', (err) => {
      stderr += String(err && err.message)
      finish(null)
    })
  })
}

const registry = new ProcessRegistry()

module.exports = { ProcessRegistry, registry, run, signalGroup, killGroup, sleep }
