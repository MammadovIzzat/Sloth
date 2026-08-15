'use strict'
/** Target parsing/validation and the connectivity watchdog.
 *
 * Ported from netutil.py. The address arithmetic underneath comes from
 * ipaddr.js, which is checked against Python's ipaddress directly.
 */
const dns = require('node:dns')
const net = require('node:net')
const { execFileSync } = require('node:child_process')

const ip = require('./ipaddr')

// Anything we hand to masscan is validated against these forms first. We always
// invoke masscan with an argument list (never a shell), but a strict whitelist
// still keeps typos and pasted junk from turning into a surprising scan.
const MAX_TARGETS = 64

class TargetError extends Error {}

function isValidIp (value) {
  try {
    ip.parseAddress(value)
    return true
  } catch {
    return false
  }
}

/** Returns a canonical target string for a single IP / CIDR / a.b.c.d-e.f.g.h. */
function parseOne (part) {
  const text = part.trim()
  if (!text) throw new TargetError('empty target')

  if (text.includes('-')) {
    const cut = text.indexOf('-')
    const lo = text.slice(0, cut).trim()
    let hi = text.slice(cut + 1).trim()
    // masscan also accepts a short form like 10.0.0.1-50
    if (!hi.includes('.') && /^\d+$/.test(hi)) {
      const octets = lo.split('.')
      if (octets.length !== 4) throw new TargetError(`invalid range: ${text}`)
      hi = octets.slice(0, 3).concat(hi).join('.')
    }
    let first, last
    try {
      first = ip.parseAddress(lo)
      last = ip.parseAddress(hi)
    } catch (err) {
      throw new TargetError(err.message)
    }
    if (first.version !== last.version) {
      throw new TargetError(`mixed address families in range: ${text}`)
    }
    if (last.value < first.value) {
      throw new TargetError(`range end is before its start: ${text}`)
    }
    return `${ip.addressToString(first)}-${ip.addressToString(last)}`
  }

  try {
    if (text.includes('/')) return ip.formatNetwork(ip.parseNetwork(text))
    return ip.addressToString(ip.parseAddress(text))
  } catch (err) {
    throw new TargetError(err.message)
  }
}

/** Validates a comma-separated target spec and returns the cleaned string.
 *
 * Accepts single addresses, CIDRs and ranges, IPv4 or IPv6. Throws TargetError
 * with a message suitable for showing to the user.
 */
function normalizeTarget (raw) {
  if (!raw || !String(raw).trim()) throw new TargetError('No target given.')
  const parts = String(raw).replace(/ /g, ',').split(',').filter((p) => p.trim())
  if (parts.length > MAX_TARGETS) {
    throw new TargetError(`Too many targets (${parts.length}); ${MAX_TARGETS} is the limit.`)
  }
  return parts.map(parseOne).join(',')
}

/** Narrows a single IPv4 CIDR to start at the given last octet.
 *
 * Under the old per-host scanner this was a filter over the expanded host list.
 * Now that the whole range goes to masscan in one process, it becomes a range.
 * Anything it can't express (multiple targets, IPv6) is returned untouched.
 */
function applyStartIp (target, startOctet) {
  if (!startOctet && startOctet !== 0) return target
  const start = Number.parseInt(startOctet, 10)
  if (!Number.isFinite(start)) return target
  if (target.includes(',') || !target.includes('/')) return target

  let network
  try {
    network = ip.parseNetwork(target)
  } catch {
    return target
  }
  if (network.version !== 4 || network.prefixlen < 24) return target

  // prefixlen >= 24, so this is at most 256 addresses to walk.
  const { first, last } = ip.hostRange(network)
  const kept = []
  for (let value = first; value <= last; value++) {
    if (Number(value & 0xffn) >= start) kept.push(value)
  }
  if (!kept.length) {
    throw new TargetError(`Start IP .${start} excludes every host in ${target}.`)
  }
  return `${ip.formatAddress(4, kept[0])}-${ip.formatAddress(4, kept[kept.length - 1])}`
}

/** Rough host count for display. Returns null when it can't tell. */
function countTargets (target) {
  let total = 0n
  for (const part of String(target).split(',')) {
    try {
      if (part.includes('-')) {
        const cut = part.indexOf('-')
        const lo = ip.parseAddress(part.slice(0, cut))
        const hi = ip.parseAddress(part.slice(cut + 1))
        total += hi.value - lo.value + 1n
      } else if (part.includes('/')) {
        total += ip.numAddresses(ip.parseNetwork(part))
      } else {
        ip.parseAddress(part)
        total += 1n
      }
    } catch {
      return null
    }
  }
  // Number, not BigInt: this is only ever displayed or compared against a
  // discovery cap. Beyond 2^53 the precision is gone, but so is any reason to
  // care — nothing scans a /64.
  return Number(total)
}

/** True when every part of a target spec is loopback.
 *
 * masscan drives its own userland TCP/IP stack and transmits through a network
 * adapter, so packets to 127.0.0.0/8 never reach it — a loopback scan always
 * reports nothing, however many ports are actually listening. Worth saying out
 * loud rather than letting someone burn a full-port sweep on it.
 */
function isLoopbackTarget (target) {
  const parts = String(target || '').split(',').filter((p) => p.trim())
  if (!parts.length) return false
  for (const part of parts) {
    try {
      if (part.includes('-')) {
        const cut = part.indexOf('-')
        const lo = ip.parseAddress(part.slice(0, cut))
        const hi = ip.parseAddress(part.slice(cut + 1))
        if (!(ip.isLoopbackAddress(lo.version, lo.value) &&
              ip.isLoopbackAddress(hi.version, hi.value))) return false
      } else if (part.includes('/')) {
        if (!ip.isLoopbackNetwork(ip.parseNetwork(part))) return false
      } else {
        const addr = ip.parseAddress(part)
        if (!ip.isLoopbackAddress(addr.version, addr.value)) return false
      }
    } catch {
      return false
    }
  }
  return true
}

/** DNS round-trip against a well-known name, then a raw connect.
 *
 * Async here where the Python was blocking: this runs on the same thread that
 * services the interface, and a stalled DNS lookup used to be invisible.
 */
function checkInternet (timeoutMs = 2000) {
  return new Promise((resolve) => {
    let settled = false
    const done = (value) => { if (!settled) { settled = true; resolve(value) } }

    dns.lookup('google.com', (err) => {
      if (!err) return done(true)
      // DNS may be broken while routing is fine; fall back to a raw TCP connect.
      const socket = net.createConnection({ host: '1.1.1.1', port: 53 })
      socket.setTimeout(timeoutMs)
      socket.once('connect', () => { socket.destroy(); done(true) })
      socket.once('timeout', () => { socket.destroy(); done(false) })
      socket.once('error', () => { socket.destroy(); done(false) })
    })
    setTimeout(() => done(false), timeoutMs + 500).unref()
  })
}

/** Runs a short command, returning its stdout or '' — never throwing. */
function readCommand (file, args, timeout = 5000) {
  try {
    return execFileSync(file, args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] })
  } catch {
    return ''
  }
}

/** Asks the kernel how it would reach an address.
 *
 * Returns {dev, src, via, table} or null. Used to detect the case where masscan
 * simply cannot work, which is otherwise invisible: it looks like a quiet host
 * rather than a scanner that never delivered a packet.
 */
function routeFor (address) {
  const out = readCommand('ip', ['route', 'get', address])
  if (!out.trim()) return null
  const tokens = out.split(/\s+/)
  const info = { dev: null, src: null, via: null, table: null }
  for (const key of ['dev', 'src', 'via', 'table']) {
    const index = tokens.indexOf(key)
    if (index >= 0 && index + 1 < tokens.length) info[key] = tokens[index + 1]
  }
  return info
}

function addressesOn (dev) {
  const out = readCommand('ip', ['-o', 'addr', 'show', 'dev', dev])
  const found = new Set()
  for (const line of out.split('\n')) {
    const parts = line.split(/\s+/)
    parts.forEach((token, index) => {
      if ((token === 'inet' || token === 'inet6') && index + 1 < parts.length) {
        found.add(parts[index + 1].split('/')[0])
      }
    })
  }
  return found
}

// Interface name prefixes that carry traffic the kernel encapsulates.
const TUNNEL_DEVS = ['tun', 'tap', 'wg', 'ppp', 'ipsec', 'utun', 'gre', 'sit', 'vti']

/** Destination networks covered by an outbound IPsec policy.
 *
 * Reading these needs privilege. A policy routing table on its own is not
 * enough to conclude anything — a strongSwan install puts every route in table
 * 220 while only encrypting the protected subnets, so the xfrm policy is the
 * signal that actually distinguishes them.
 *
 * Returns null when it cannot tell, which callers must not read as "none".
 */
function ipsecOutNetworks () {
  let out
  try {
    out = execFileSync('ip', ['xfrm', 'policy'],
      { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })
  } catch {
    return null      // no permission, or no iproute2 — cannot tell
  }

  const networks = []
  let pending = null
  for (const line of out.split('\n')) {
    const stripped = line.trim()
    if (stripped.startsWith('src ') && stripped.includes(' dst ')) {
      const parts = stripped.split(/\s+/)
      pending = parts[parts.indexOf('dst') + 1]
    } else if (stripped.startsWith('dir out') && pending) {
      try {
        networks.push(ip.parseNetwork(pending))
      } catch { /* not a network we can read; skip it */ }
      pending = null
    }
  }
  return networks
}

/** Whether masscan can plausibly deliver packets to this address.
 *
 * masscan brings its own TCP/IP stack and writes raw frames straight to a
 * network adapter, so anything the *kernel* would do on the way out — IPsec
 * transforms, tunnel encapsulation, policy routing to a different source
 * address — simply does not happen. Packets leave in the clear, from the wrong
 * address, and never arrive. The scan then reports an empty host, which is
 * indistinguishable from a genuinely quiet one.
 *
 * Returns {ok, reason}.
 */
function masscanReachability (address, ipsecNetworks) {
  const route = routeFor(address)
  if (!route || !route.dev) return { ok: true, reason: null }
  const dev = route.dev

  if (TUNNEL_DEVS.some((prefix) => dev.startsWith(prefix))) {
    return {
      ok: false,
      reason: `the route to ${address} goes over ${dev}, a tunnel interface. ` +
              'masscan bypasses the kernel and cannot encapsulate traffic, so its ' +
              'packets will not traverse it. Use the nmap or rustscan engine instead.',
    }
  }

  const networks = ipsecNetworks === undefined ? ipsecOutNetworks() : ipsecNetworks
  if (networks && networks.length) {
    let addr = null
    try { addr = ip.parseAddress(address) } catch { /* leave null */ }
    if (addr) {
      for (const network of networks) {
        if (ip.networkContains(network, addr.version, addr.value)) {
          return {
            ok: false,
            reason: `${address} falls inside ${ip.formatNetwork(network)}, which the ` +
                    'kernel protects with an IPsec policy. masscan writes raw frames ' +
                    `straight to ${dev} and never applies that transform, so its packets ` +
                    'leave unencrypted and are dropped — the scan will look like a quiet ' +
                    'host. Use the nmap or rustscan engine.',
          }
        }
      }
    }
  }

  if (route.src && !addressesOn(dev).has(route.src)) {
    return {
      ok: false,
      reason: `the kernel would send from ${route.src}, which is not an address ` +
              `configured on ${dev}. masscan sources from the adapter's own address, ` +
              'so replies will not come back.',
    }
  }

  return { ok: true, reason: null }
}

/** Builds an http(s) URL if this port looks like a web app, else null. */
function webUrlFor (address, portRow, webPorts) {
  if (portRow.proto !== 'tcp') return null
  const name = String(portRow.service || '').toLowerCase()
  const port = Number.parseInt(portRow.port, 10)
  if (!Number.isFinite(port)) return null
  if (!name.includes('http') && !webPorts.has(port)) return null
  const https = name.includes('https') || name.includes('ssl') || port === 443 || port === 8443
  const host = address.includes(':') ? `[${address}]` : address
  return `${https ? 'https' : 'http'}://${host}:${port}`
}

module.exports = {
  TargetError,
  isValidIp,
  normalizeTarget,
  applyStartIp,
  countTargets,
  isLoopbackTarget,
  checkInternet,
  routeFor,
  ipsecOutNetworks,
  masscanReachability,
  webUrlFor,
}
