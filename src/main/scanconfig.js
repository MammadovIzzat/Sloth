'use strict'
/** Scan type/engine definitions and form parsing.
 *
 * Shared by task creation and by re-running an existing task with different
 * settings, so "nmap top ports now, full masscan sweep afterwards" is one task
 * accumulating results rather than two tasks with the findings split between
 * them.
 *
 * Ported from scanconfig.py. validate_port_spec lived in engine.py there; it
 * sits here instead, because this is the only module that validates input and
 * the engine has no other reason to own it.
 */
const {
  DEFAULT_DISCOVERY, DEFAULT_ENGINE, DEFAULT_RATE, DEFAULT_RETRIES,
  DEFAULT_TCP_PORTS, DEFAULT_TOP_PORTS,
} = require('./config')
const { checkHostCap, getProfile } = require('./discovery')
const { countTargets } = require('./netutil')

class ScanError extends Error {}

const SCAN_TYPES = {
  full: 'Full port scan',
  quick: 'Quick scan (nmap top ports)',
  discovery: 'Host discovery only',
}

// Engines for a full port scan. masscan is the fastest but runs its own TCP/IP
// stack, so it cannot cross an IPsec or VPN tunnel — the others use ordinary
// kernel sockets and can.
const ENGINES = {
  masscan: {
    label: 'masscan — fastest, huge ranges',
    note: 'Its own TCP/IP stack, so it is by far the fastest over large ' +
          'ranges. Cannot traverse IPsec/VPN tunnels, needs root, and ' +
          'under-reports when probes are dropped.',
  },
  rustscan: {
    label: 'rustscan — fast, works through tunnels',
    note: 'Kernel TCP connect scan: works over IPsec, WireGuard and any ' +
          'other tunnel, and needs no root. TCP only.',
  },
  nmap: {
    label: 'nmap — slowest, most accurate',
    note: 'Retransmits and fingerprints services, so results are the most ' +
          'trustworthy. Works through tunnels. Slow over large ranges.',
  },
}

const PORT_SPEC_RE = /^[0-9,\-]+$/

/** Ports arrive from a form field, so keep them to digits, commas and dashes. */
function validatePortSpec (value) {
  if (value === null || value === undefined) return null
  const text = String(value).trim()
  if (!text) return null
  if (!PORT_SPEC_RE.test(text)) {
    throw new ScanError(`Invalid port range: '${text}'. Use forms like 1-65535 or 22,80,443.`)
  }
  for (const raw of text.split(',')) {
    const chunk = raw.trim()
    if (!chunk) continue
    const bounds = chunk.split('-')
    if (bounds.length > 2 || !bounds.every((b) => /^\d+$/.test(b))) {
      throw new ScanError(`Invalid port range: '${chunk}'`)
    }
    const numbers = bounds.map((b) => Number.parseInt(b, 10))
    if (numbers.some((n) => n < 1 || n > 65535)) {
      throw new ScanError(`Ports must be between 1 and 65535: '${chunk}'`)
    }
    if (numbers.length === 2 && numbers[1] < numbers[0]) {
      throw new ScanError(`Port range runs backwards: '${chunk}'`)
    }
  }
  return text
}

function clampInt (value, fallback, low, high) {
  let number = Number.parseInt(value, 10)
  // Python's int() rejects "12abc" and floats-as-strings; Number.parseInt would
  // happily take the leading digits, so anything not wholly numeric falls back.
  if (!Number.isFinite(number) || !/^\s*[-+]?\d+\s*$/.test(String(value))) {
    number = fallback
  }
  return Math.max(low, Math.min(number, high))
}

/** Validates scan settings from a form into columns ready for the tasks table.
 *
 * `target` is needed to sanity-check the discovery method against the range
 * size. `defaults` supplies fallbacks when re-running an existing task, so a
 * field the user left alone keeps its previous value.
 */
function parseScanConfig (form, target, defaults = {}) {
  const get = (key) => (Object.hasOwn(form, key) ? form[key] : undefined)

  /** Absent means "unchanged"; present-but-empty means "none".
   *
   * The distinction matters: clearing the TCP field is how you ask for a
   * UDP-only scan, so an empty string must not be quietly refilled with the
   * default range.
   */
  const pick = (key, fallback) => {
    const value = get(key)
    return value === undefined || value === null ? fallback : value
  }

  /** For fields that must always hold something — selects and numbers. */
  const pickValue = (key, fallback) => {
    const value = get(key)
    if (value === undefined || value === null || String(value).trim() === '') return fallback
    return value
  }

  const scanType = String(pickValue('scan_type', defaults.scan_type || 'full')).trim()
  if (!Object.hasOwn(SCAN_TYPES, scanType)) {
    throw new ScanError(`Unknown scan type: '${scanType}'`)
  }

  let method = get('discovery')
  if (method === undefined || method === null) method = defaults.discovery
  method = String(method || '').trim() || null
  if (method && !getProfile(method)) {
    throw new ScanError(`Unknown discovery method: '${method}'`)
  }
  if (scanType === 'discovery' && !method) method = DEFAULT_DISCOVERY
  if (method) {
    // Catch "hping3 over a /16" here rather than after the user hits Run.
    const tooBig = checkHostCap(getProfile(method), target, countTargets(target))
    if (tooBig) throw new ScanError(tooBig)
  }

  const engine = String(pickValue('engine', defaults.engine || DEFAULT_ENGINE)).trim()
  let tcp = null, udp = null, top = null

  if (scanType === 'full') {
    if (!Object.hasOwn(ENGINES, engine)) {
      throw new ScanError(`Unknown scan engine: '${engine}'`)
    }
    tcp = validatePortSpec(String(pick('tcp_ports', DEFAULT_TCP_PORTS)))
    udp = validatePortSpec(String(pick('udp_ports', '') || ''))
    if (!tcp && !udp) throw new ScanError('Select a TCP range, a UDP range, or both.')
    if (engine === 'rustscan' && !tcp) {
      throw new ScanError('rustscan is TCP-only — give it a TCP range.')
    }
  } else if (scanType === 'quick') {
    // An explicit range beats top-ports — this is how you get an accurate
    // nmap -p- when a stateless sweep under-reports.
    tcp = validatePortSpec(String(get('nmap_ports') || '') || '')
    if (!tcp) top = clampInt(pickValue('top_ports', DEFAULT_TOP_PORTS), DEFAULT_TOP_PORTS, 1, 65535)
  }

  const retryDefault = defaults.retries === undefined || defaults.retries === null
    ? DEFAULT_RETRIES
    : defaults.retries

  return {
    scan_type: scanType,
    engine,
    discovery: method,
    tcp_ports: tcp,
    udp_ports: udp,
    top_ports: top,
    rate: clampInt(pickValue('rate', defaults.rate || DEFAULT_RATE), DEFAULT_RATE, 100, 10000000),
    retries: clampInt(pickValue('retries', retryDefault), DEFAULT_RETRIES, 0, 10),
  }
}

/** Short human label for a run, e.g. 'full port scan · rustscan · TCP 1-65535'. */
function describe (config) {
  const bits = [SCAN_TYPES[config.scan_type] || config.scan_type]
  if (config.scan_type === 'full') bits.push(config.engine)
  if (config.discovery) bits.push(`discovery: ${config.discovery}`)
  if (config.tcp_ports) bits.push(`TCP ${config.tcp_ports}`)
  if (config.udp_ports) bits.push(`UDP ${config.udp_ports}`)
  if (config.top_ports) bits.push(`top ${config.top_ports}`)
  return bits.join(' · ')
}

module.exports = {
  ScanError,
  SCAN_TYPES,
  ENGINES,
  validatePortSpec,
  parseScanConfig,
  describe,
}
