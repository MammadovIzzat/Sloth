'use strict'
/** Paths and tuning knobs. Everything here can be overridden by env vars.
 *
 * Ported from config.py. The defaults are deliberately unchanged: an install
 * that has been running the Python build must find its database where it left
 * it, so SLOTH_DATA still wins over Electron's own userData directory.
 */
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const BASE_DIR = path.resolve(__dirname, '..', '..')

/** Electron's per-user data directory, without requiring electron.
 *
 * The pure-logic modules are unit-tested with plain node, where requiring
 * electron throws. Falling back to the XDG location keeps those tests running
 * outside the app, and lands on the same path Electron would have chosen.
 */
function userDataDir () {
  try {
    return require('electron').app.getPath('userData')
  } catch {
    const base = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config')
    return path.join(base, 'sloth')
  }
}

const DATA_DIR = process.env.SLOTH_DATA || userDataDir()

const DB_PATH = process.env.SLOTH_DB || path.join(DATA_DIR, 'scans.db')
const SHOTS_DIR = process.env.SLOTH_SHOTS || path.join(DATA_DIR, 'screenshots')
// Each scan task gets a working directory here; masscan drops its paused.conf in
// it, which is what makes --resume possible without tasks stepping on each other.
const RUNS_DIR = process.env.SLOTH_RUNS || path.join(DATA_DIR, 'runs')

const DEFAULT_RATE = int(process.env.SLOTH_RATE, 1000)
const DEFAULT_TCP_PORTS = '1-65535'
const DEFAULT_UDP_PORTS = '1-65535'
const DEFAULT_TOP_PORTS = 1000   // what a "quick" nmap scan covers, matching nmap's default
const DEFAULT_DISCOVERY = 'nmap_default'
const DEFAULT_ENGINE = 'masscan'

// rustscan tuning: it opens a lot of sockets at once, so the ulimit matters.
const RUSTSCAN_BATCH = int(process.env.SLOTH_RUSTSCAN_BATCH, 4500)
const RUSTSCAN_ULIMIT = int(process.env.SLOTH_RUSTSCAN_ULIMIT, 5000)
const RUSTSCAN_TIMEOUT_MS = int(process.env.SLOTH_RUSTSCAN_TIMEOUT, 1500)
const RUSTSCAN_TRIES = int(process.env.SLOTH_RUSTSCAN_TRIES, 2)

// masscan defaults to zero retries: one SYN per port, no retransmission. Against
// any host that drops packets (a firewalled Windows box, a rate-limiting router)
// a single lost probe silently loses the port forever. Retrying is the single
// biggest accuracy win available, at a proportional cost in packets and time.
const DEFAULT_RETRIES = 3
// masscan's own default wait is 10s; the previous 5 risked discarding late
// SYN/ACKs from slow or filtered paths.
const MASSCAN_WAIT = int(process.env.SLOTH_WAIT, 10)
const STOP_GRACE_SECONDS = 12   // time masscan gets to write paused.conf after SIGINT
const NMAP_TIMEOUT = 3600       // hard ceiling on a single nmap invocation
const SCREENSHOT_TIMEOUT = 45

// TCP ports treated as web even when nmap can't name the service.
const WEB_PORTS = new Set([80, 81, 443, 591, 3000, 5000, 7001, 8000, 8008, 8080,
  8081, 8443, 8888, 9000, 9090, 9200, 10000])

function int (value, fallback) {
  const n = Number.parseInt(value, 10)
  return Number.isFinite(n) ? n : fallback
}

/** Creates a data directory, explaining clearly if it cannot.
 *
 * Returns an error string rather than throwing: the main process turns this
 * into a dialog, because an Electron app that dies before its window opens
 * shows the user nothing at all.
 */
function ensureDir (dir, label) {
  try {
    fs.mkdirSync(dir, { recursive: true })
    return null
  } catch (err) {
    return `Cannot create the ${label} directory ${dir}: ${err.message}\n` +
           'Fix its ownership, or point SLOTH_DATA somewhere writable.'
  }
}

/** Called once at startup, before anything touches the database. */
function ensureDirs () {
  return [ensureDir(SHOTS_DIR, 'screenshots'), ensureDir(RUNS_DIR, 'run')]
    .filter(Boolean)
}

module.exports = {
  BASE_DIR,
  DATA_DIR,
  DB_PATH,
  SHOTS_DIR,
  RUNS_DIR,
  DEFAULT_RATE,
  DEFAULT_TCP_PORTS,
  DEFAULT_UDP_PORTS,
  DEFAULT_TOP_PORTS,
  DEFAULT_DISCOVERY,
  DEFAULT_ENGINE,
  RUSTSCAN_BATCH,
  RUSTSCAN_ULIMIT,
  RUSTSCAN_TIMEOUT_MS,
  RUSTSCAN_TRIES,
  DEFAULT_RETRIES,
  MASSCAN_WAIT,
  STOP_GRACE_SECONDS,
  NMAP_TIMEOUT,
  SCREENSHOT_TIMEOUT,
  WEB_PORTS,
  ensureDirs,
}
