'use strict'
/** Screenshots of discovered web services, captured in-process.
 *
 * The Python build shelled out to headless Chromium or Firefox. Electron
 * already ships Chromium, so this loads each page into an offscreen
 * BrowserWindow instead. Three things get better:
 *
 *   - No external browser dependency, and no "install chromium" dead end.
 *   - The old command line carried --no-sandbox, and the whole tool ran as
 *     root; these windows keep the sandbox and run as the ordinary user.
 *   - A capture is cancelled by destroying the window, which is immediate.
 *     Killing a browser process left temp profiles behind and could take the
 *     full timeout to land.
 *
 * The pages being loaded are hostile by assumption — they are services on a
 * network under test. Each one gets a throwaway in-memory session with no node
 * integration, no preload, and no access to the app's own storage.
 */
const fs = require('node:fs')
const path = require('node:path')

const { SCREENSHOT_TIMEOUT, SHOTS_DIR, WEB_PORTS } = require('./config')
const { webUrlFor } = require('./netutil')

/** Screenshots every web port on a host. Returns {shots, note}. */
async function capture (address, ports, scanId, { cancelled } = {}) {
  const isCancelled = cancelled || (() => false)

  const targets = []
  for (const port of ports) {
    const url = webUrlFor(address, port, WEB_PORTS)
    if (url) targets.push({ port, url })
  }
  if (!targets.length) return { shots: [], note: 'No web services detected on this host.' }

  let BrowserWindow, session
  try {
    ({ BrowserWindow, session } = require('electron'))
  } catch { /* handled by the check below */ }
  // Outside Electron this require does not throw: the npm package resolves to
  // a string holding the path to the binary, so both names come back undefined
  // and the failure only surfaces later as "shoot is not a function". Check
  // what we actually got instead of trusting the catch.
  if (typeof BrowserWindow !== 'function' || !session) {
    return { shots: [], note: 'Screenshots need the Electron runtime — skipped.' }
  }

  // The directory can be missing on a fresh profile, or after someone clears
  // out old results. Without this the write throws and every capture is
  // reported as "could not be captured", which points at the target host
  // rather than at the real problem.
  try {
    fs.mkdirSync(SHOTS_DIR, { recursive: true })
  } catch (err) {
    return { shots: [], note: `Cannot write to ${SHOTS_DIR}: ${err.message}` }
  }

  const shots = []
  const failed = []
  let unwritable = null
  let stopped = false

  for (const { port, url } of targets) {
    if (isCancelled()) { stopped = true; break }
    const name = `${scanId}_${port.proto}_${port.port}.png`
    const file = path.join(SHOTS_DIR, name)
    const image = await shoot(BrowserWindow, session, url, isCancelled)
    if (!image || image.isEmpty()) { failed.push(url); continue }
    try {
      fs.writeFileSync(file, image.toPNG())
    } catch (err) {
      // A storage problem is not the target's fault; say so separately.
      unwritable = err.message
      continue
    }
    shots.push({ port: port.port, proto: port.proto, url, file: name })
  }

  let note = ''
  if (stopped) note = `stopped after ${shots.length} of ${targets.length} screenshot(s)`
  else if (failed.length) {
    note = `${failed.length} web service(s) could not be captured: ` +
           failed.slice(0, 5).join(', ')
  }
  if (unwritable) {
    note = (note ? note + '. ' : '') + `Could not save screenshots: ${unwritable}`
  }
  return { shots, note }
}

/** Loads one URL offscreen and returns a NativeImage, or null. */
function shoot (BrowserWindow, session, url, isCancelled) {
  return new Promise((resolve) => {
    // A fresh partition per capture: no cookies, no cache and no storage shared
    // with the app or between the hosts being scanned.
    const partition = `sloth-shot-${Date.now()}-${Math.floor(Math.random() * 1e9)}`
    const scanSession = session.fromPartition(partition, { cache: false })

    // Scan targets routinely use self-signed certificates; that is a finding to
    // record, not a reason to refuse the screenshot. Scoped to this throwaway
    // session, so it cannot loosen anything else.
    scanSession.setCertificateVerifyProc((_request, callback) => callback(0))

    const win = new BrowserWindow({
      show: false,
      width: 1280,
      height: 900,
      webPreferences: {
        session: scanSession,
        offscreen: true,
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true,
        javascript: true,
        images: true,
      },
    })

    let settled = false
    const finish = async (capturePage) => {
      if (settled) return
      settled = true
      clearInterval(poll)
      clearTimeout(timer)
      let image = null
      if (capturePage && !win.isDestroyed()) {
        try { image = await win.webContents.capturePage() } catch { image = null }
      }
      if (!win.isDestroyed()) win.destroy()
      // Drop the throwaway session's data rather than leaving it on disk.
      try { await scanSession.clearStorageData() } catch { /* nothing to clear */ }
      resolve(image)
    }

    // A page that never finishes loading — common on a scan target — still gets
    // captured at the deadline rather than being lost entirely.
    const timer = setTimeout(() => finish(true), SCREENSHOT_TIMEOUT * 1000)
    const poll = setInterval(() => { if (isCancelled()) finish(false) }, 250)

    win.webContents.once('did-finish-load', () => {
      // A beat for late paints: webfonts, and content the page draws itself.
      setTimeout(() => finish(true), 1200)
    })
    win.webContents.once('did-fail-load', (_event, code) => {
      // -3 is ERR_ABORTED, which a redirect raises; the load that follows is
      // the real one, so it is not a failure.
      if (code !== -3) finish(false)
    })
    win.webContents.on('render-process-gone', () => finish(false))

    win.loadURL(url).catch(() => finish(false))
  })
}

module.exports = { capture }
