'use strict'
/** Thin wrapper over the preload bridge.
 *
 * Every handler returns {ok, data} or {ok:false, error}. Unwrapping that in one
 * place means a view can `await api.projects.list()` and let a thrown error be
 * caught by the caller, instead of every call site remembering to check .ok.
 */
const call = async (channel, payload) => {
  const result = await window.sloth.call(channel, payload)
  if (!result || !result.ok) throw new Error((result && result.error) || 'Unknown error')
  return result.data
}

export const api = {
  info: () => call('app:info'),

  auth: {
    status: () => call('auth:status'),
    setup: (username, password, confirm) => call('auth:setup', { username, password, confirm }),
    login: (username, password) => call('auth:login', { username, password }),
    logout: () => call('auth:logout'),
    changePassword: (current, next, confirm) =>
      call('auth:changePassword', { current, next, confirm }),
  },

  projects: {
    list: (status) => call('projects:list', { status }),
    get: (projectId) => call('projects:get', { projectId }),
    create: (fields) => call('projects:create', fields),
    update: (projectId, fields) => call('projects:update', { projectId, ...fields }),
    remove: (projectId) => call('projects:delete', { projectId }),
  },

  tasks: {
    get: (taskId) => call('tasks:get', { taskId }),
    create: (projectId, form) => call('tasks:create', { projectId, form }),
    remove: (taskId) => call('tasks:delete', { taskId }),
    log: (taskId) => call('tasks:log', { taskId }),
  },

  scan: {
    start: (taskId, form, resume) => call('scan:start', { taskId, form, resume }),
    pause: (taskId) => call('scan:pause', { taskId }),
    resume: (taskId) => call('scan:resume', { taskId }),
    stop: (taskId) => call('scan:stop', { taskId }),
    resumeSaved: (taskId) => call('scan:resumeSaved', { taskId }),
    rescanHost: (taskId, ip, tool, projectId) =>
      call('scan:rescanHost', { taskId, ip, tool, projectId }),
    stopHost: (taskId, ip) => call('scan:stopHost', { taskId, ip }),
    capabilities: () => call('scan:capabilities'),
    grant: (tool) => call('privilege:grant', { tool }),
    revoke: (tool) => call('privilege:revoke', { tool }),
  },

  scans: {
    list: (options) => call('scans:list', options || {}),
    get: (scanId) => call('scans:get', { scanId }),
  },

  report: {
    exportOne: (kind, id, format) => call('report:export', { kind, id, format }),
    import: (projectId) => call('report:import', { projectId }),
  },

  notifications: {
    list: (limit) => call('notify:list', { limit }),
    markSeen: (id) => call('notify:markSeen', { id }),
    clear: () => call('notify:clear'),
  },

  openExternal: (url) => call('shell:openExternal', { url }),

  onScanEvent: (handler) => window.sloth.on('scan:event', handler),
  onNotification: (handler) => window.sloth.on('notify:new', handler),
}
