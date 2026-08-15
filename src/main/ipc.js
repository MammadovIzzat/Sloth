'use strict'
/** IPC handlers — what the Flask blueprints used to be.
 *
 * Every handler is registered here so the channel list in preload.js has one
 * place to correspond to. A handler returns plain data; it never returns a
 * function, a stream or anything else that cannot cross the structured-clone
 * boundary.
 *
 * Authentication is enforced here rather than per-module, the way the Flask
 * build used a before_request hook: one list of public channels, and
 * everything else refuses until someone has signed in.
 */
const { app, dialog, ipcMain, shell } = require('electron')
const fs = require('node:fs')

const auth = require('./auth')
const config = require('./config')
const engine = require('./engine')
const notify = require('./notify')
const privilege = require('./privilege')
const reports = require('./reports')
const store = require('./store')
const transfer = require('./transfer')
const { ENGINES, SCAN_TYPES, ScanError, parseScanConfig } = require('./scanconfig')
const { profilesForUi } = require('./discovery')
const { TargetError, applyStartIp, countTargets, normalizeTarget } = require('./netutil')
const { which } = require('./which')

// Reachable before anyone has signed in. Everything else is refused.
const PUBLIC = new Set(['app:info', 'auth:status', 'auth:setup', 'auth:login', 'auth:logout'])

/** Wraps a handler so a thrown error reaches the renderer as a value.
 *
 * An unhandled rejection in ipcMain.handle reaches the renderer as an opaque
 * "Error invoking remote method", which tells the user nothing. Scan failures
 * are routine here — a missing masscan, a refused capability — and each needs
 * to arrive as a sentence the interface can display.
 */
function handle (channel, fn) {
  ipcMain.handle(channel, async (_event, payload) => {
    try {
      if (!PUBLIC.has(channel)) auth.requireSignedIn()
      return { ok: true, data: await fn(payload ?? {}) }
    } catch (err) {
      return { ok: false, error: err && err.message ? err.message : String(err) }
    }
  })
}

/** Sends scan events to every open window, and turns the interesting ones
 *  into notifications.
 *
 * Both happen here so a page that is not open still gets its activity
 * recorded: the notification is written whether or not anyone is looking.
 */
function wireScanEvents (windows) {
  const broadcast = (channel, payload) => {
    for (const win of windows()) {
      if (!win.isDestroyed()) win.webContents.send(channel, payload)
    }
  }

  engine.manager.on('event', (event) => {
    broadcast('scan:event', event)
    try {
      notify.fromScanEvent(event)
    } catch (err) {
      // A notification must never take a scan down with it.
      console.error('[notify]', err.message)
    }
  })

  notify.emitter.on('notification', (row) => {
    broadcast('notify:new', { notification: row, unseen: notify.unseenCount() })
  })
}

function register (windows) {
  wireScanEvents(windows)

  // --- app + auth -------------------------------------------------------

  handle('app:info', () => ({
    version: app.getVersion(),
    dataDir: config.DATA_DIR,
    dbPath: config.DB_PATH,
    platform: process.platform,
    electron: process.versions.electron,
    node: process.versions.node,
    uid: typeof process.getuid === 'function' ? process.getuid() : null,
  }))

  handle('auth:status', () => auth.status())
  handle('auth:setup', ({ username, password, confirm }) =>
    auth.setup(username, password, confirm))
  handle('auth:login', ({ username, password }) => auth.login(username, password))
  handle('auth:logout', () => auth.logout())
  handle('auth:changePassword', ({ current, next, confirm }) =>
    auth.changePassword(current, next, confirm))

  // --- projects ---------------------------------------------------------

  handle('projects:list', ({ status }) => ({
    projects: store.listProjects(status || null),
    archived: store.listProjects('archived').length,
    activeTask: engine.manager.activeTask,
  }))

  handle('projects:get', ({ projectId }) => {
    const project = store.getProject(projectId)
    if (!project) throw new Error('Project not found.')
    return {
      project,
      tasks: store.listTasks(projectId),
      hosts: store.projectHosts(projectId),
      scans: store.listNmapScans({ projectId }),
      activeTask: engine.manager.activeTask,
      scanTypes: SCAN_TYPES,
      engines: ENGINES,
      discoveryProfiles: profilesForUi(),
      defaults: {
        tcp: config.DEFAULT_TCP_PORTS,
        udp: config.DEFAULT_UDP_PORTS,
        rate: config.DEFAULT_RATE,
        top_ports: config.DEFAULT_TOP_PORTS,
        discovery: config.DEFAULT_DISCOVERY,
        retries: config.DEFAULT_RETRIES,
        engine: config.DEFAULT_ENGINE,
      },
    }
  })

  handle('projects:create', ({ name, client, description }) => {
    if (!String(name || '').trim()) throw new Error('A project needs a name.')
    return { projectId: store.createProject(name, client, description) }
  })

  handle('projects:update', ({ projectId, ...fields }) => {
    if (!store.getProject(projectId)) throw new Error('Project not found.')
    store.updateProject(projectId, fields)
    return true
  })

  handle('projects:delete', ({ projectId }) => {
    store.deleteProject(projectId)
    return true
  })

  handle('projects:hosts', ({ projectId }) => store.projectHosts(projectId))

  // --- tasks ------------------------------------------------------------

  handle('tasks:list', ({ projectId }) => store.listTasks(projectId))

  handle('tasks:get', ({ taskId }) => {
    const task = store.getTask(taskId)
    if (!task) throw new Error('Task not found.')
    return {
      task,
      hosts: store.taskHosts(taskId),
      scans: store.listNmapScans({ taskId }),
      log: engine.readLog(taskId),
      active: engine.manager.activeTask === taskId,
      paused: engine.manager.isPaused(taskId),
      rescans: engine.manager.activeRescans(taskId),
      network: engine.manager.networkState(),
      scanTypes: SCAN_TYPES,
      engines: ENGINES,
      discoveryProfiles: profilesForUi(),
      // Which per-host rescans this machine can actually run. Marking a tool
      // unavailable here beats letting someone pick it and meet the failure
      // only after the click.
      rescanTools: engine.RESCAN_TOOLS.map(({ key, label, tool, note }) => ({
        key, label, tool, note, available: Boolean(which(tool)),
      })),
    }
  })

  handle('tasks:create', ({ projectId, form }) => {
    if (!store.getProject(projectId)) throw new Error('Project not found.')
    return { taskId: createTaskFromForm(projectId, form || {}) }
  })

  handle('tasks:update', ({ taskId, ...fields }) => {
    if (!store.getTask(taskId)) throw new Error('Task not found.')
    store.updateTask(taskId, fields)
    return true
  })

  handle('tasks:delete', ({ taskId }) => {
    const task = store.getTask(taskId)
    if (!task) throw new Error('Task not found.')
    store.deleteTask(taskId)
    return { projectId: task.project_id }
  })

  handle('tasks:hosts', ({ taskId }) => store.taskHosts(taskId))
  handle('tasks:log', ({ taskId }) => engine.readLog(taskId))

  // --- running scans ----------------------------------------------------

  handle('scan:start', ({ taskId, form, resume }) => {
    if (form && Object.keys(form).length) {
      // Re-running with different settings: the task keeps its findings and
      // gains the new configuration, which is how "nmap first, masscan after"
      // stays one task.
      const task = store.getTask(taskId)
      if (!task) throw new Error('Task not found.')
      const config = parseScanConfig(form, task.target, task)
      store.updateTask(taskId, config)
    }
    // Deliberately not awaited: start() resolves when the scan finishes, and
    // the caller wants to know it began, not wait for it.
    engine.manager.start(taskId, Boolean(resume)).catch(() => {})
    return true
  })

  handle('scan:pause', ({ taskId }) => ({ paused: engine.manager.pause(taskId) }))
  handle('scan:resume', ({ taskId }) => ({ resumed: engine.manager.resume(taskId) }))
  handle('scan:stop', ({ taskId }) => engine.manager.stop(taskId).then((n) => ({ stopped: n })))
  handle('scan:resumeSaved', ({ taskId }) => {
    engine.manager.start(taskId, true).catch(() => {})
    return true
  })
  handle('scan:active', () => ({ taskId: engine.manager.activeTask }))

  handle('scan:rescanHost', ({ taskId, ip, tool, projectId }) => {
    engine.manager.startRescan(taskId, ip, tool, projectId || null)
    return true
  })
  handle('scan:stopHost', ({ taskId, ip }) =>
    engine.manager.stopRescan(taskId, ip).then((stopped) => ({ stopped })))

  // What the scanners can currently do, and how to fix it if the answer is
  // "not much". The renderer renders this; it never decides it.
  handle('scan:capabilities', () => privilege.report())

  handle('privilege:revoke', async ({ tool }) => {
    const result = await privilege.revoke(String(tool || ''))
    return { ...result, state: privilege.report() }
  })

  handle('privilege:grant', async ({ tool }) => {
    // grant() re-checks the name against its own allowlist; passing it straight
    // through is safe, and keeping the check in one place avoids the two
    // drifting apart.
    const result = await privilege.grant(String(tool || ''))
    return { ...result, state: privilege.report() }
  })

  // --- saved nmap scans -------------------------------------------------

  handle('scans:list', ({ limit, projectId, search }) => {
    const matched = store.listNmapScans({
      projectId: projectId || null,
      search: search || null,
    })
    const cap = Number.isFinite(limit) ? limit : 200
    return {
      scans: matched.slice(0, cap),
      total: matched.length,
      truncated: matched.length > cap,
      // The unfiltered count, so the page can say "3 of 22" rather than
      // leaving you wondering whether a filter is hiding something.
      grandTotal: store.listNmapScans().length,
      // Only projects that actually have a report; offering empty ones would
      // just be a list of dead ends.
      projects: store.listProjects()
        .filter((project) => store.listNmapScans({ projectId: project.id }).length)
        .map((project) => ({ id: project.id, name: project.name })),
    }
  })

  handle('scans:get', ({ scanId }) => {
    const row = store.getNmapScan(scanId)
    if (!row) throw new Error('Scan not found.')
    return {
      scan: row,
      ports: safeJson(row.ports_json),
      shots: safeJson(row.screenshots_json).map((shot) => ({
        ...shot,
        data_uri: inlineShot(shot.file),
      })),
    }
  })

  // --- export and import ------------------------------------------------

  handle('report:export', async ({ kind, id, format }) => {
    const rendered = kind === 'task'
      ? reports.exportTask(id, format, app.getVersion())
      : reports.exportProject(id, format, app.getVersion())

    const { canceled, filePath } = await dialog.showSaveDialog({
      title: 'Export',
      defaultPath: rendered.filename,
      filters: [{ name: format.toUpperCase(), extensions: [format] }],
    })
    if (canceled || !filePath) return { saved: false }
    fs.writeFileSync(filePath, rendered.body)
    return { saved: true, path: filePath }
  })

  handle('report:import', async ({ projectId }) => {
    const { canceled, filePaths } = await dialog.showOpenDialog({
      title: 'Import a Sloth export',
      properties: ['openFile'],
      filters: [{ name: 'Sloth export', extensions: ['json'] }],
    })
    if (canceled || !filePaths.length) return { imported: false }

    const raw = fs.readFileSync(filePaths[0])
    if (raw.length > config.MAX_UPLOAD_MB * 1024 * 1024) {
      throw new Error(`That file is larger than the ${config.MAX_UPLOAD_MB} MB limit.`)
    }
    const data = transfer.readBundle(raw)
    const tally = transfer.importBundle(data, projectId || null)
    return { imported: true, ...tally }
  })

  // --- notifications ------------------------------------------------------

  handle('notify:list', ({ limit }) => ({
    notifications: notify.list({ limit: Number.isFinite(limit) ? limit : 200 }),
    unseen: notify.unseenCount(),
  }))
  handle('notify:markSeen', ({ id }) => ({ unseen: notify.markSeen(id ?? null) }))
  handle('notify:clear', () => ({ unseen: notify.clear() }))

  // --- misc -------------------------------------------------------------

  handle('shell:openExternal', async ({ url }) => {
    // Only ever http(s): a report could otherwise carry a file:// or a
    // desktop-handler URL and get the OS to open something local.
    const protocol = (() => {
      try { return new URL(url).protocol } catch { return '' }
    })()
    if (protocol !== 'http:' && protocol !== 'https:') {
      throw new Error('Only http and https links can be opened.')
    }
    await shell.openExternal(url)
    return true
  })
}

/** Shared by the project page and the dashboard's quick-scan box. */
function createTaskFromForm (projectId, form) {
  let target
  try {
    target = normalizeTarget(form.target || '')
    target = applyStartIp(target, String(form.start_octet || '').trim())
  } catch (err) {
    if (err instanceof TargetError) throw new ScanError(err.message)
    throw err
  }
  const settings = parseScanConfig(form, target)

  const hosts = countTargets(target)
  // The name describes the target, not the first scan run against it — the
  // same task can later be re-run with a different engine or scan type.
  const defaultName = target + (hosts && hosts > 1 ? ` (${hosts} hosts)` : '')

  return store.createTask(projectId, target, {
    name: String(form.name || '').trim() || defaultName,
    notes: String(form.notes || '').trim() || null,
    ...settings,
  })
}

function safeJson (value) {
  try {
    const parsed = JSON.parse(value || '[]')
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

/** Screenshots are read here and handed over as data URIs: the renderer has no
 *  filesystem access, and giving it a path it could not open would be a lie. */
function inlineShot (name) {
  if (!name) return null
  const path = require('node:path')
  try {
    const raw = fs.readFileSync(path.join(config.SHOTS_DIR, path.basename(name)))
    return 'data:image/png;base64,' + raw.toString('base64')
  } catch {
    return null
  }
}

module.exports = { register, handle }
