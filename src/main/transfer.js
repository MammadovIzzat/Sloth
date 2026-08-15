'use strict'
/** Moving whole projects between installs.
 *
 * The JSON export doubles as the interchange format: one analyst exports a
 * project, another imports it and gets the tasks, hosts, ports, nmap output and
 * screenshots in their own database.
 *
 * Everything arriving here was written by another machine, so none of it is
 * trusted. Identifiers are regenerated rather than reused, every field is
 * range-checked before it reaches SQL, and screenshots are verified to be PNGs
 * and written under names this side chose. A malformed or hostile file should
 * fail with a sentence, not a traceback or a stray write outside SHOTS_DIR.
 *
 * Ported from transfer.py, and wire-compatible with it: a bundle written by
 * the Python build imports here, and vice versa.
 */
const fs = require('node:fs')
const path = require('node:path')

const store = require('./store')
const { SHOTS_DIR } = require('./config')
const { newId, now } = require('./db')
const { ENGINES, SCAN_TYPES } = require('./scanconfig')

// Bumped when the shape changes in a way an older Sloth could not read.
const FORMAT = 1

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const MAX_SHOT_BYTES = 12 * 1024 * 1024

// Statuses a task can legitimately arrive in. Anything else was still moving
// when it was exported, and there is no process on this side behind it.
const TERMINAL = new Set(['completed', 'stopped', 'error', 'interrupted'])
const STILL_RUNNING = 'This task was still running when it was exported, so its ' +
                      'results may be incomplete.'

class BundleError extends Error {}

// --- writing -------------------------------------------------------------

/** The JSON export, with screenshots embedded so the file travels alone. */
function envelope (title, sections, project = null, version = '?') {
  const tasks = sections.map((section) => {
    const scans = {}
    for (const [address, list] of Object.entries(section.scans)) {
      scans[address] = list.map((scan) => ({
        ...scan,
        screenshots: (scan.screenshots || []).map(packShot),
      }))
    }
    return { task: { ...section.task }, hosts: section.hosts, scans }
  })

  return {
    sloth: { format: FORMAT, version, exported_at: now() },
    title,
    project: project ? { ...project } : null,
    tasks,
  }
}

/** Adds the PNG itself to a screenshot record, keeping its metadata. */
function packShot (shot) {
  const out = { ...shot }
  delete out.data_uri            // the HTML export's field, not ours
  const name = path.basename(String(out.file || ''))
  try {
    out.data = fs.readFileSync(path.join(SHOTS_DIR, name)).toString('base64')
  } catch {
    out.data = null              // capture failed, or the file is long gone
  }
  return out
}

// --- reading -------------------------------------------------------------

/** Parses and sanity-checks an uploaded export. Throws BundleError. */
function readBundle (raw) {
  if (!raw || !raw.length) throw new BundleError('The chosen file is empty.')

  let text
  try {
    text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw)
    // A binary file decodes to replacement characters rather than throwing.
    if (text.includes('�')) {
      throw new BundleError('That is not a text file. Import expects the JSON ' +
        'export, not the HTML report or a zip.')
    }
  } catch (err) {
    if (err instanceof BundleError) throw err
    throw new BundleError('That file could not be read as text.')
  }

  let data
  try {
    data = JSON.parse(text)
  } catch (err) {
    throw new BundleError(`The file is not valid JSON (${err.message}).`)
  }

  if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.tasks)) {
    throw new BundleError('This does not look like a Sloth export — no task list ' +
      'in it. Export with the JSON format, not HTML or text.')
  }

  const header = data.sloth || {}
  if (Number.isInteger(header.format) && header.format > FORMAT) {
    throw new BundleError(`The file was written by a newer Sloth (format ` +
      `${header.format}, this one reads ${FORMAT}). Upgrade before importing it.`)
  }
  return data
}

/** Writes a parsed bundle into the database. Returns a summary.
 *
 * Nothing from the file names a row: project, task and scan identifiers are
 * all minted here, so importing the same export twice makes two independent
 * copies rather than silently overwriting the first.
 */
function importBundle (data, projectId = null) {
  const target = projectId ? store.getProject(projectId) : null
  let created = false
  if (!target) {
    projectId = newProject(data)
    created = true
  }

  const tally = {
    project: projectId, created, tasks: 0, hosts: 0, ports: 0,
    scans: 0, shots: 0, skipped: 0,
  }

  for (const entry of data.tasks) {
    if (!entry || typeof entry !== 'object' || !entry.task ||
        typeof entry.task !== 'object' || Array.isArray(entry.task)) {
      tally.skipped++
      continue
    }
    importTask(entry, projectId, tally)
  }
  return tally
}

function newProject (data) {
  const project = (data.project && typeof data.project === 'object' && !Array.isArray(data.project))
    ? data.project
    : {}
  const name = text(project.name) || text(data.title) || 'Imported project'
  return store.createProject(uniqueName(name), text(project.client),
    text(project.description, 4000))
}

/** Keeps an import from being mistaken for the project it sits next to. */
function uniqueName (name) {
  const taken = new Set(store.listProjects().map((p) => p.name))
  if (!taken.has(name)) return name
  for (let n = 2; n < 100; n++) {
    const candidate = n > 2 ? `${name} (imported ${n})` : `${name} (imported)`
    if (!taken.has(candidate)) return candidate
  }
  return `${name} (${newId()})`
}

function importTask (entry, projectId, tally) {
  const src = entry.task
  const target = text(src.target, 500) || '(imported)'

  const taskId = store.createTask(projectId, target, {
    name: text(src.name, 300) || target,
    tcp_ports: text(src.tcp_ports, 200),
    udp_ports: text(src.udp_ports, 200),
    rate: integer(src.rate, 1, 10000000),
    notes: text(src.notes, 4000),
    scan_type: choice(src.scan_type, SCAN_TYPES, 'full'),
    discovery: text(src.discovery, 60),
    top_ports: integer(src.top_ports, 1, 65535),
    retries: integer(src.retries, 0, 100),
    wait: integer(src.wait, 0, 3600),
    engine: choice(src.engine, ENGINES, 'masscan'),
  })
  tally.tasks++

  let status = text(src.status, 40)
  let error = text(src.error, 2000)
  if (!TERMINAL.has(status)) {
    // Honest about what arrived: a half-finished run, not a completed one.
    status = 'interrupted'
    error = error || STILL_RUNNING
  }
  store.updateTask(taskId, {
    status,
    error,
    progress: real(src.progress, 0, 100) || 0,
    started_at: text(src.started_at, 40),
    finished_at: text(src.finished_at, 40),
    // There is no paused.conf on this side, so resume would only fail.
    resumable: 0,
  })

  importHosts(entry.hosts, taskId, tally)
  importScans(entry.scans, taskId, projectId, tally)
}

function importHosts (hosts, taskId, tally) {
  if (!Array.isArray(hosts)) return
  // Grouped by discovery method so this is a couple of statements rather than
  // one round trip per host.
  const byMethod = new Map()
  const findings = []

  for (const host of hosts) {
    if (!host || typeof host !== 'object') continue
    const address = text(host.ip, 60)
    if (!address) continue
    const method = text(host.discovered_by, 60)
    if (!byMethod.has(method)) byMethod.set(method, [])
    byMethod.get(method).push({
      ip: address,
      state: 'up',
      reason: text(host.reason, 200),
      hostname: text(host.hostname, 300),
    })
    tally.hosts++

    const bySource = new Map()
    for (const port of host.ports || []) {
      const clean = cleanPort(port)
      if (!clean) continue
      const source = text(port.source, 40) || 'masscan'
      if (!bySource.has(source)) bySource.set(source, [])
      bySource.get(source).push(clean)
    }
    for (const [source, ports] of bySource) findings.push([address, source, ports])
  }

  for (const [method, group] of byMethod) store.addHosts(taskId, group, method)
  for (const [address, source, ports] of findings) {
    tally.ports += store.addFindings(taskId, address, ports, source).length
  }
}

function cleanPort (port) {
  if (!port || typeof port !== 'object') return null
  const number = integer(port.port, 0, 65535)
  if (number === null) return null
  return {
    port: number,
    proto: choice(port.proto, ['tcp', 'udp', 'sctp'], 'tcp'),
    state: text(port.state, 40) || 'open',
    service: text(port.service, 500),
  }
}

function importScans (scans, taskId, projectId, tally) {
  if (!scans || typeof scans !== 'object' || Array.isArray(scans)) return
  for (const [rawAddress, list] of Object.entries(scans)) {
    const address = text(rawAddress, 60)
    if (!address || !Array.isArray(list)) continue
    for (const scan of list) {
      if (!scan || typeof scan !== 'object') continue
      const shots = (scan.screenshots || [])
        .map((shot) => unpackShot(shot, tally))
        .filter(Boolean)
      store.saveNmapScan(
        newId(), address,
        text(scan.tool, 60) || 'nmap',
        text(scan.command, 4000),
        text(scan.raw_output, 2000000),
        (scan.ports || []).map(cleanPort).filter(Boolean),
        shots,
        { taskId, projectId, createdAt: text(scan.created_at, 40) })
      tally.scans++
    }
  }
}

/** Writes an embedded screenshot out under a name chosen on this side.
 *
 * The filename in the bundle is never used — not even as a basename — so a
 * crafted export cannot land a file anywhere but SHOTS_DIR, nor overwrite a
 * screenshot already there.
 */
function unpackShot (shot, tally) {
  if (!shot || typeof shot !== 'object') return null
  const url = text(shot.url, 2000)
  const fallback = url ? { url, file: null } : null

  const blob = shot.data
  if (typeof blob !== 'string' || !blob) return fallback

  let raw
  try {
    raw = Buffer.from(blob, 'base64')
    // Buffer.from is lenient where Python's validate=True is not; re-encoding
    // and comparing is how you tell "decoded" from "silently discarded junk".
    if (raw.toString('base64').replace(/=+$/, '') !== blob.replace(/[\s=]+$/g, '')) {
      return fallback
    }
  } catch {
    return fallback
  }
  if (!raw.subarray(0, 8).equals(PNG_MAGIC) || raw.length > MAX_SHOT_BYTES) return fallback

  const name = `${newId()}.png`
  try {
    fs.mkdirSync(SHOTS_DIR, { recursive: true })
    fs.writeFileSync(path.join(SHOTS_DIR, name), raw)
  } catch {
    return fallback
  }
  tally.shots++
  return { url, file: name }
}

// --- field cleaning ------------------------------------------------------

function text (value, limit = 300) {
  if (value === null || value === undefined || typeof value === 'boolean') return null
  if (typeof value !== 'string' && typeof value !== 'number') return null
  let out = String(value).trim()
  // Control characters would corrupt the text export and the log view.
  out = [...out].filter((ch) => ch >= ' ' || ch === '\t' || ch === '\n').join('')
  return out.slice(0, limit) || null
}

/** int(value) with Python's rules, not JavaScript's.
 *
 * Number() is far too forgiving here: Number(null), Number('') and Number([])
 * are all 0, so a bundle carrying {"port": null} would import as port 0 — a
 * value the Python build rejects outright. Floats truncate, as int() does.
 */
function integer (value, low, high) {
  let number
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return null
    number = Math.trunc(value)
  } else if (typeof value === 'boolean') {
    number = value ? 1 : 0
  } else if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!/^[-+]?\d+$/.test(trimmed)) return null    // int('3.7') raises in Python too
    number = Number.parseInt(trimmed, 10)
  } else {
    return null
  }
  return number >= low && number <= high ? number : null
}

/** float(value), likewise: null and '' are errors, not zero. */
function real (value, low, high) {
  let number
  if (typeof value === 'number') number = value
  else if (typeof value === 'boolean') number = value ? 1 : 0
  else if (typeof value === 'string' && value.trim() !== '') number = Number(value)
  else return null
  if (!Number.isFinite(number)) return null
  return Math.min(Math.max(number, low), high)
}

function choice (value, allowed, fallback) {
  if (typeof value !== 'string') return fallback
  const ok = Array.isArray(allowed) ? allowed.includes(value) : Object.hasOwn(allowed, value)
  return ok ? value : fallback
}

module.exports = { FORMAT, BundleError, envelope, readBundle, importBundle }
