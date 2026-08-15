'use strict'
/** The only bridge between the sandboxed renderer and the privileged main
 *  process.
 *
 * Deliberately a fixed list of channels rather than a general "invoke anything"
 * function. A generic bridge would mean that anything which manages to run
 * script in the renderer — and this app renders page titles, service banners
 * and nmap output taken from hosts under someone else's control — could reach
 * every handler in the main process, including the ones that spawn scanners.
 */
const { contextBridge, ipcRenderer } = require('electron')

// Request/response channels. Each maps to one ipcMain.handle in the main process.
const CALLS = [
  'app:info',

  'auth:status', 'auth:setup', 'auth:login', 'auth:logout', 'auth:changePassword',

  'projects:list', 'projects:get', 'projects:create', 'projects:update',
  'projects:delete', 'projects:hosts',

  'tasks:list', 'tasks:get', 'tasks:create', 'tasks:update', 'tasks:delete',
  'tasks:hosts', 'tasks:log',

  'scan:start', 'scan:pause', 'scan:resume', 'scan:stop', 'scan:resumeSaved',
  'scan:active', 'scan:rescanHost', 'scan:stopHost', 'scan:capabilities',
  'privilege:grant', 'privilege:revoke',

  'scans:list', 'scans:get',

  'report:export', 'report:import',

  'notify:list', 'notify:markSeen', 'notify:clear',

  'shell:openExternal',
]

// One-way pushes from main to renderer: scan progress, findings, log lines.
const EVENTS = ['scan:event', 'auth:signedOut', 'notify:new']

const api = {
  call (channel, payload) {
    if (!CALLS.includes(channel)) {
      return Promise.reject(new Error(`Unknown channel: ${channel}`))
    }
    return ipcRenderer.invoke(channel, payload)
  },

  /** Subscribes to a push channel. Returns an unsubscribe function. */
  on (channel, handler) {
    if (!EVENTS.includes(channel)) {
      throw new Error(`Unknown event channel: ${channel}`)
    }
    // The listener is wrapped so the renderer never receives the IpcRendererEvent
    // itself, which carries a handle back into the main process.
    const wrapped = (_event, payload) => handler(payload)
    ipcRenderer.on(channel, wrapped)
    return () => ipcRenderer.removeListener(channel, wrapped)
  },
}

contextBridge.exposeInMainWorld('sloth', api)
