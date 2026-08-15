'use strict'
/** Sloth — Electron entry point.
 *
 * The old build was a Flask server you reached through a browser. This one has
 * no listening socket of any kind: the window talks to this process over
 * Electron IPC, and nothing outside the machine — or elsewhere on it — can
 * reach the tool.
 *
 * The privileged work stays out here in the main process. The renderer runs
 * sandboxed with no node access, which matters more than usual for this tool:
 * it renders scan output, hostnames and page titles pulled off hostile hosts.
 */
const path = require('node:path')
const { app, BrowserWindow, dialog, shell } = require('electron')

const config = require('./config')
const ipc = require('./ipc')

const DEV = Boolean(process.env.SLOTH_DEV)

let mainWindow = null

const asRoot = () => Boolean(process.getuid && process.getuid() === 0)

// Running as root is allowed, but only when asked for explicitly — it is not
// something to arrive at by accident from a stray sudo.
const ROOT_ALLOWED = process.argv.includes('--allow-root') ||
                     process.env.SLOTH_ALLOW_ROOT === '1'

/** Chromium cannot enable its sandbox as root and will not start without
 *  --no-sandbox, so running this way means an unsandboxed browser engine.
 *
 * That is a real cost and worth naming, but it is the operator's call: root
 * makes every scanner work at once with no capabilities granted to any binary,
 * which is exactly the trade the previous build made.
 */
function checkRoot () {
  if (!asRoot()) return true
  if (!ROOT_ALLOWED) {
    dialog.showErrorBox(
      'Sloth was started as root',
      'Running as root works, but Chromium cannot sandbox itself as root, so ' +
      'the interface runs unsandboxed — and Sloth renders scan output, and ' +
      'optionally loads web pages, from the hosts you are testing.\n\n' +
      'If that is what you want, start it with --allow-root:\n\n' +
      '    sudo sloth --allow-root\n\n' +
      'Otherwise run it as your normal user; the scanners that need raw ' +
      'sockets are elevated on their own.')
    return false
  }
  // Chromium refuses to launch as root without this, and the switch has to be
  // set before the app is ready.
  app.commandLine.appendSwitch('no-sandbox')
  return true
}

function createWindow () {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 940,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#151b26',      // Nocturne's --color-bg, so there is no white flash
    autoHideMenuBar: true,
    show: false,
    // A packaged install takes its icon from the .desktop entry, but a run
    // straight from the checkout has nothing to go on without this.
    icon: path.join(__dirname, '..', '..', 'build', 'icons', '256x256.png'),
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // The renderer displays scan results; it has no business fetching
      // anything over the network on its own.
      webSecurity: true,
    },
  })

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
    if (process.env.SLOTH_SHOT) captureAndQuit(process.env.SLOTH_SHOT)
  })
  const page = path.join(__dirname, '..', 'renderer', 'index.html')
  // SLOTH_SHOT_ROUTE is part of the screenshot hook below: it opens straight
  // onto one view so each page can be photographed without clicking through.
  mainWindow.loadFile(page, process.env.SLOTH_SHOT && process.env.SLOTH_SHOT_ROUTE
    ? { hash: process.env.SLOTH_SHOT_ROUTE }
    : undefined)
  if (DEV) mainWindow.webContents.openDevTools({ mode: 'right' })

  // A scan report can carry a link to a discovered service. Those open in the
  // user's real browser — never inside the app window, which has the preload
  // bridge attached to it.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:$/.test(safeProtocol(url))) shell.openExternal(url)
    return { action: 'deny' }
  })
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault()
  })

  mainWindow.on('closed', () => { mainWindow = null })
}

/** QA hook: SLOTH_SHOT=<path> renders the window to a PNG and exits.
 *
 * The old build could be photographed by pointing a headless browser at a URL.
 * With no server there is no URL, so the app has to take its own picture — this
 * is how the interface gets checked. Off unless the variable is set.
 */
async function captureAndQuit (target) {
  // A beat for webfonts and the first paint; capturing sooner catches the
  // fallback font and reads as a layout bug that isn't there.
  await new Promise((resolve) => setTimeout(resolve, 1200))
  try {
    const image = await mainWindow.webContents.capturePage()
    require('node:fs').writeFileSync(target, image.toPNG())
    console.log(`[shot] ${target}`)
  } catch (err) {
    console.error(`[shot] failed: ${err.message}`)
  }
  app.quit()
}

function safeProtocol (url) {
  try {
    return new URL(url).protocol
  } catch {
    return ''
  }
}

// Chromium reads its sandbox switches during startup, well before whenReady,
// so this cannot wait for the check inside the ready handler.
if (asRoot() && ROOT_ALLOWED) app.commandLine.appendSwitch('no-sandbox')

// A second copy would fight the first over the database and the scan lock.
if (!app.requestSingleInstanceLock()) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.focus()
    }
  })

  app.whenReady().then(() => {
    if (!checkRoot()) return app.quit()

    const problems = config.ensureDirs()
    if (problems.length) {
      dialog.showErrorBox('Sloth cannot start', problems.join('\n\n'))
      return app.quit()
    }

    // Say so before opening an empty database, not after: an install that
    // silently starts blank next to a full scans.db looks like data loss.
    const legacy = require('./migrate').findLegacyDatabase()

    // Anything marked running in the database died with the previous process.
    try {
      require('./db').initDb()
      require('./store').resetStaleTasks()
    } catch (err) {
      dialog.showErrorBox('Sloth cannot open its database', err.message)
      return app.quit()
    }

    if (legacy && !process.env.SLOTH_SHOT) {
      dialog.showMessageBoxSync({
        type: 'info',
        title: 'Earlier scan data found',
        message: 'Sloth found results from the previous build',
        detail: require('./migrate').migrationAdvice(legacy),
        buttons: ['Continue'],
      })
    }

    ipc.register(() => BrowserWindow.getAllWindows())
    // Screenshot hook only: sign in before the window opens so the signed-in
    // views can be photographed. Ignored unless SLOTH_SHOT is set, so it is
    // not a way into a real install.
    if (process.env.SLOTH_SHOT && process.env.SLOTH_SHOT_USER) {
      require('./auth')
        .login(process.env.SLOTH_SHOT_USER, process.env.SLOTH_SHOT_PASS || '')
        .catch((err) => console.error('[shot] sign-in failed:', err.message))
        .finally(createWindow)
      return
    }
    createWindow()
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow()
    })
  })

  // Never leave a scanner running after the window goes away.
  app.on('before-quit', () => { require('./procs').registry.stopAll() })
  app.on('window-all-closed', () => app.quit())
}
