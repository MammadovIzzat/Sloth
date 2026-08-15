'use strict'
/** Scan notifications, and the log that outlives them.
 *
 * A sweep can run for an hour. Sitting on the task page watching it is not how
 * anyone actually works, so the interesting moments — it started, discovery
 * found this many hosts, it finished with this many ports, a rescan turned up
 * something new, the network dropped — are raised wherever you happen to be.
 *
 * Every one is written to the database first and shown second. Dismissing a
 * toast is meant to get it out of your way, not to destroy the record: the
 * whole point is being able to come back and read what happened overnight.
 *
 * Notifications are *derived* from the events the engine already publishes
 * rather than raised by hand at each call site. One translator means a new
 * event cannot quietly go unreported, and the engine keeps knowing nothing
 * about the interface.
 */
const { EventEmitter } = require('node:events')

const store = require('./store')
const { connect, now } = require('./db')

const LEVELS = new Set(['info', 'good', 'warn', 'bad'])

const emitter = new EventEmitter()

/** Writes one notification and announces it. Returns the stored row. */
function record (level, title, message = null, { taskId = null, projectId = null } = {}) {
  const safeLevel = LEVELS.has(level) ? level : 'info'
  const result = connect().prepare(
    'INSERT INTO notifications (created_at, level, title, message, task_id, project_id, seen)' +
    ' VALUES (?,?,?,?,?,?,0)').run(now(), safeLevel, String(title), message, taskId, projectId)
  const row = connect().prepare('SELECT * FROM notifications WHERE id = ?')
    .get(result.lastInsertRowid)
  emitter.emit('notification', row)
  return row
}

function list ({ limit = 200, unseenOnly = false } = {}) {
  const sql = 'SELECT * FROM notifications' + (unseenOnly ? ' WHERE seen = 0' : '') +
              ' ORDER BY id DESC LIMIT ?'
  return connect().prepare(sql).all(limit)
}

const unseenCount = () =>
  connect().prepare('SELECT COUNT(*) AS n FROM notifications WHERE seen = 0').get().n

/** Marking as seen only clears the badge — the entry stays in the log. */
function markSeen (id = null) {
  if (id === null) connect().prepare('UPDATE notifications SET seen = 1').run()
  else connect().prepare('UPDATE notifications SET seen = 1 WHERE id = ?').run(id)
  return unseenCount()
}

/** Deletes history. Separate from markSeen precisely because dismissing and
 *  deleting are different intentions. */
function clear () {
  connect().prepare('DELETE FROM notifications').run()
  return 0
}

// --- deriving notifications from scan events ------------------------------

/** Remembers the task name so a notification can say more than an id. */
const taskLabel = (taskId) => {
  if (!taskId) return null
  const task = store.getTask(taskId)
  return task ? { name: task.name, projectId: task.project_id } : null
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`

/** Translates one engine event into a notification, or nothing.
 *
 * Deliberately quiet: log lines, progress ticks and per-port discoveries are
 * far too frequent to raise. A notification that arrives hundreds of times an
 * hour trains you to ignore all of them, including the one that mattered.
 */
function fromScanEvent (event) {
  if (!event || typeof event !== 'object') return null
  const taskId = event.task_id || null
  const label = taskLabel(taskId)
  const where = { taskId, projectId: label ? label.projectId : null }
  const name = label ? label.name : 'a task'

  switch (event.type) {
    case 'phase':
      // Only the first phase of a run: "started" once, not once per stage.
      if (event.phase !== 'discovery' && event.phase !== 'portscan') return null
      if (event.phase === 'discovery') {
        return record('info', `Scan started — ${name}`,
          `Host discovery with ${event.label || event.tool}.`, where)
      }
      return record('info', `Port scan started — ${name}`,
        `Scanning with ${event.tool}.`, where)

    case 'discovery_done':
      return record(event.count ? 'good' : 'warn', `Discovery finished — ${name}`,
        event.count
          ? `${plural(event.count, 'host')} answered.`
          : 'No hosts answered. The port scan will cover the whole range.',
        where)

    case 'done': {
      const good = event.status === 'completed'
      return record(good ? 'good' : (event.status === 'error' ? 'bad' : 'warn'),
        `Scan ${event.status} — ${name}`,
        good
          ? `${plural(event.hosts || 0, 'host')}, ${plural(event.ports || 0, 'open port')}.`
          : (event.error || `Finished as ${event.status}.`),
        where)
    }

    case 'rescan': {
      if (event.state === 'done') {
        const fresh = event.new_ports || 0
        return record(fresh ? 'good' : 'info', `Rescan finished — ${event.ip}`,
          (fresh
            ? `${plural(fresh, 'new port')} found by ${event.tool}.`
            : `No new ports; ${event.tool} confirmed ${plural((event.ports || []).length, 'port')}.`) +
          (event.screenshots ? ` ${plural(event.screenshots, 'screenshot')}.` : ''),
          where)
      }
      if (event.state === 'error') {
        return record('bad', `Rescan failed — ${event.ip}`, event.error, where)
      }
      return null      // 'running' and 'cancelled' are visible on the page itself
    }

    case 'network':
      return record(event.connected ? 'good' : 'warn',
        event.connected ? 'Network restored' : 'Waiting — network lost',
        event.message, where)

    case 'status':
      // Pause and stop are things you just did; a notification would only tell
      // you what you already know. An interruption you did not cause is not.
      if (event.status === 'interrupted') {
        return record('warn', `Scan interrupted — ${name}`, event.message, where)
      }
      return null

    default:
      return null
  }
}

module.exports = {
  emitter, record, list, unseenCount, markSeen, clear, fromScanEvent,
}
