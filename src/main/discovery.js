'use strict'
/** Host discovery: find which addresses are alive before port-scanning them.
 *
 * Sweeping every port of a /24 means 254 full-port scans, most of them against
 * nothing. Discovering live hosts first cuts the port scan down to the addresses
 * that actually answer — far less traffic, far less noise, and much faster.
 *
 * Each method is a named profile so you can pick the probe that suits the
 * network: ICMP echo is the obvious one, but plenty of hosts drop it while
 * still answering a timestamp request, a TCP ACK to 443, or an ARP who-has on
 * the local segment.
 *
 * Ported from discovery.py.
 */
const fs = require('node:fs')
const path = require('node:path')
const { XMLParser } = require('fast-xml-parser')

const ip = require('./ipaddr')
const { DEFAULT_RATE } = require('./config')

// Ports worth knocking on for TCP/UDP ping probes: common enough to be open or
// at least to elicit a RST, which is all a discovery probe needs.
const SYN_PORTS = '21,22,23,25,53,80,110,143,443,445,993,995,3389,8080'
const ACK_PORTS = '80,443,3389'
const UDP_PORTS = '53,67,123,137,161'

/** A named probe method. Mirrors DiscoveryProfile in the Python build. */
function profile (key, label, tool, description, extra = {}) {
  return {
    key,
    label,
    tool,
    description,
    nmapArgs: extra.nmapArgs || [],
    fpingArgs: extra.fpingArgs || [],
    hpingArgs: extra.hpingArgs || [],
    localOnly: Boolean(extra.localOnly),   // ARP: same broadcast domain only
    perHost: Boolean(extra.perHost),       // tool probes one address at a time
    maxHosts: extra.maxHosts ?? null,
  }
}

/** The key of the reuse option. Not a probe: it sends nothing and simply takes
 *  the hosts this task already found, so re-running a task with different port
 *  settings does not repeat a sweep that already answered the question. */
const PREVIOUS = 'previous'

const PROFILES = [
  profile(PREVIOUS, 'Reuse hosts found earlier in this task', null,
    'Sends no packets at all. Takes the addresses this task already proved ' +
    'alive, so a re-run with different ports skips the sweep. Fails if the ' +
    'task has never found a host.'),
  profile('nmap_default', 'Nmap default probes (-sn)', 'nmap',
    'ICMP echo + timestamp, TCP SYN 443, TCP ACK 80, and ARP on the local ' +
    "segment. The balanced choice when you don't know the network.",
    { nmapArgs: ['-sn'] }),
  profile('nmap_icmp_echo', 'ICMP echo ping (-PE)', 'nmap',
    'Classic ping. Fast and quiet, but firewalls very commonly drop it.',
    { nmapArgs: ['-sn', '-PE'] }),
  profile('nmap_icmp_timestamp', 'ICMP timestamp ping (-PP)', 'nmap',
    'ICMP type 13. Often answered by hosts configured to ignore echo, so ' +
    'worth trying when -PE finds nothing.',
    { nmapArgs: ['-sn', '-PP'] }),
  profile('nmap_icmp_netmask', 'ICMP address-mask ping (-PM)', 'nmap',
    'ICMP type 17. Rarely answered by modern hosts, but free to try and ' +
    'occasionally finds old network gear.',
    { nmapArgs: ['-sn', '-PM'] }),
  profile('nmap_tcp_syn', 'TCP SYN ping (-PS)', 'nmap',
    `SYN to ${SYN_PORTS}. Gets through firewalls that drop ICMP; a RST ` +
    'counts as alive just as much as a SYN/ACK.',
    { nmapArgs: ['-sn', `-PS${SYN_PORTS}`] }),
  profile('nmap_tcp_ack', 'TCP ACK ping (-PA)', 'nmap',
    `ACK to ${ACK_PORTS}. Slips past stateless filters that only block ` +
    'inbound SYN.',
    { nmapArgs: ['-sn', `-PA${ACK_PORTS}`] }),
  profile('nmap_udp', 'UDP ping (-PU)', 'nmap',
    `UDP to ${UDP_PORTS}. A closed port replies with ICMP unreachable, ` +
    'which proves the host is there.',
    { nmapArgs: ['-sn', `-PU${UDP_PORTS}`] }),
  profile('nmap_sctp', 'SCTP INIT ping (-PY)', 'nmap',
    'SCTP INIT chunks. Niche, but telecom and some Linux hosts answer.',
    { nmapArgs: ['-sn', '-PY'] }),
  profile('nmap_arp', 'ARP ping (-PR) — local segment only', 'nmap',
    'ARP who-has. Cannot be firewalled and is extremely fast and reliable, ' +
    'but only works on your own broadcast domain.',
    { nmapArgs: ['-sn', '-PR'], localOnly: true }),
  profile('nmap_thorough', 'Nmap thorough (every probe type)', 'nmap',
    'ICMP echo/timestamp/mask plus TCP SYN, TCP ACK and UDP probes. The ' +
    'most likely to find hosts, and the loudest.',
    { nmapArgs: ['-sn', '-PE', '-PP', '-PM', `-PS${SYN_PORTS}`,
      `-PA${ACK_PORTS}`, `-PU${UDP_PORTS}`] }),
  profile('fping_sweep', 'fping ICMP sweep (-a -g)', 'fping',
    'Fast parallel ICMP echo sweep. Excellent for large ranges when you ' +
    'only care about hosts that answer ping.',
    { fpingArgs: ['-r', '1', '-t', '300'] }),
  profile('fping_thorough', 'fping patient sweep (retries)', 'fping',
    'Same sweep with 3 retries and a longer timeout — for lossy links or ' +
    'slow WAN targets where a single probe drops.',
    { fpingArgs: ['-r', '3', '-t', '1000'] }),
  profile('masscan_ping', 'masscan ICMP sweep (--ping)', 'masscan',
    "ICMP echo using masscan's own stack. Built for enormous ranges — a " +
    '/8 is realistic. Cannot see loopback.'),
  profile('hping3_icmp', 'hping3 ICMP probe (per host)', 'hping3',
    'One crafted ICMP echo per address. Slow — probes sequentially — so ' +
    'keep it to small ranges. Useful when you need control over the packet.',
    { hpingArgs: ['-1'], perHost: true, maxHosts: 256 }),
  profile('hping3_syn', 'hping3 TCP SYN probe (per host)', 'hping3',
    'One crafted SYN to port 443 per address. Sequential and slow, but ' +
    'gets through ICMP-blocking filters.',
    { hpingArgs: ['-S', '-p', '443'], perHost: true, maxHosts: 256 }),
]

const PROFILES_BY_KEY = new Map(PROFILES.map((p) => [p.key, p]))

const getProfile = (key) => PROFILES_BY_KEY.get(key) || null

/** The shape the interface needs — no argv, which it has no business seeing. */
const profilesForUi = () => PROFILES.map((p) => ({
  key: p.key,
  label: p.label,
  tool: p.tool,
  description: p.description,
  local_only: p.localOnly,
  per_host: p.perHost,
  max_hosts: p.maxHosts,
}))

// --- target helpers ------------------------------------------------------

/** Per-host tools are far too slow for a big range — say so up front.
 *
 * Returns an explanatory message, or null when the target is within reach.
 */
function checkHostCap (prof, target, count) {
  if (!prof || !prof.maxHosts || !count) return null
  if (count <= prof.maxHosts) return null
  return `${prof.label} probes one address at a time and is capped at ` +
         `${prof.maxHosts}; this target has ${count}. Pick an fping or ` +
         'nmap sweep for a range this size.'
}

/** Expands a target spec into individual addresses.
 *
 * Used by the per-host tools (hping3) and to decide whether a host list needs
 * to go into a file rather than onto the command line.
 */
function expandTargets (target, limit = 65536) {
  const out = []
  for (const raw of String(target).split(',')) {
    const part = raw.trim()
    if (!part) continue
    try {
      if (part.includes('-')) {
        const cut = part.indexOf('-')
        const lo = ip.parseAddress(part.slice(0, cut))
        const hi = ip.parseAddress(part.slice(cut + 1))
        for (let value = lo.value; value <= hi.value; value++) {
          out.push(ip.formatAddress(lo.version, value))
          if (out.length > limit) return out.slice(0, limit)
        }
      } else if (part.includes('/')) {
        const net = ip.parseNetwork(part)
        const { first, last } = ip.hostRange(net)
        for (let value = first; value <= last; value++) {
          out.push(ip.formatAddress(net.version, value))
          if (out.length > limit) return out.slice(0, limit)
        }
      } else {
        out.push(ip.addressToString(ip.parseAddress(part)))
      }
    } catch {
      continue
    }
  }
  return out
}

function writeTargetFile (file, targets) {
  fs.writeFileSync(file, targets.join('\n') + '\n')
  return file
}

// --- command building ----------------------------------------------------

/** Returns {argv, kind} for a whole-range probe.
 *
 * `kind` tells the caller how to read the results: 'nmap_xml', 'stdout_ips'
 * or 'masscan_list'.
 */
function buildCommand (prof, target, runDir, rate) {
  if (prof.tool === 'nmap') {
    const argv = ['nmap', ...prof.nmapArgs, '-n', '-oX', 'discovery.xml',
      ...targetArgs(target, runDir, 'nmap')]
    return { argv, kind: 'nmap_xml' }
  }

  if (prof.tool === 'fping') {
    // -a prints only the addresses that answered; -q suppresses per-probe
    // noise. fping exits non-zero when anything is unreachable, which for a
    // sweep is the normal case, so the caller must not treat that as failure.
    const argv = ['fping', '-a', '-q', ...prof.fpingArgs]
    if (isSimpleRange(target)) {
      argv.push('-g', ...fpingRange(target))
    } else {
      const file = path.join(runDir, 'discovery-targets.txt')
      writeTargetFile(file, expandTargets(target))
      argv.push('-f', path.basename(file))
    }
    return { argv, kind: 'stdout_ips' }
  }

  if (prof.tool === 'masscan') {
    return {
      argv: ['masscan', ...String(target).split(','), '--ping',
        '--rate', String(rate || DEFAULT_RATE), '-oL', 'discovery.list'],
      kind: 'masscan_list',
    }
  }

  throw new Error(`${prof.tool} has no whole-range command form`)
}

/** Per-host probe for tools that only take one address at a time. */
function buildHostCommand (prof, address) {
  if (prof.tool === 'hping3') {
    return ['hping3', ...prof.hpingArgs, '-c', '1', '--fast', address]
  }
  throw new Error(`${prof.tool} is not a per-host tool`)
}

/** Rewrites one target into a form nmap actually accepts.
 *
 * nmap does not understand a full dotted range like 10.0.0.1-10.0.0.9 — it
 * tries to resolve it as a hostname and scans nothing. It wants octet-range
 * notation (10.0.0.1-9), so convert when the range sits inside one /24 and
 * fall back to expanding the addresses when it doesn't.
 */
function nmapTarget (raw) {
  const part = raw.trim()
  if (!part.includes('-') || part.includes('/')) return [part]
  const cut = part.indexOf('-')
  const lo = part.slice(0, cut).trim()
  const hi = part.slice(cut + 1).trim()
  if (!hi.includes('.') && !hi.includes(':')) return [part]   // already 10.0.0.1-9 form

  let first, last
  try {
    first = ip.parseAddress(lo)
    last = ip.parseAddress(hi)
  } catch {
    return [part]
  }
  if (first.version === 4) {
    const firstText = ip.formatAddress(4, first.value)
    const lastText = ip.formatAddress(4, last.value)
    const firstPrefix = firstText.slice(0, firstText.lastIndexOf('.'))
    const lastCut = lastText.lastIndexOf('.')
    if (firstPrefix === lastText.slice(0, lastCut)) {
      return [`${firstText}-${lastText.slice(lastCut + 1)}`]
    }
  }
  return expandTargets(part)
}

/** Long host lists go in a file — a command line has a length limit. */
function targetArgs (target, runDir, tool) {
  const parts = []
  for (const part of String(target).split(',')) {
    if (part.trim()) parts.push(...nmapTarget(part))
  }
  if (parts.length <= 64) return parts
  const file = path.join(runDir, `${tool}-targets.txt`)
  writeTargetFile(file, parts)
  return ['-iL', path.basename(file)]
}

const isSimpleRange = (target) =>
  !target.includes(',') && (target.includes('/') || target.includes('-'))

function fpingRange (target) {
  if (target.includes('/')) return [target]
  const cut = target.indexOf('-')
  return [target.slice(0, cut).trim(), target.slice(cut + 1).trim()]
}

// --- result parsing ------------------------------------------------------

const xml = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  processEntities: true,
  htmlEntities: false,
  parseAttributeValue: false,
  trimValues: true,
})

const many = (node) => (node === undefined || node === null
  ? []
  : (Array.isArray(node) ? node : [node]))

function collectHosts (node, out) {
  if (!node || typeof node !== 'object') return out
  for (const [key, value] of Object.entries(node)) {
    if (key === 'host') out.push(...many(value))
    else if (typeof value === 'object') for (const child of many(value)) collectHosts(child, out)
  }
  return out
}

/** Extracts live hosts from `nmap -sn` XML output. */
function parseNmapHosts (xmlText) {
  const hosts = []
  if (!xmlText || !String(xmlText).trim()) return hosts

  let root
  try {
    root = xml.parse(String(xmlText).trim())
  } catch {
    return hosts
  }

  for (const host of collectHosts(root, [])) {
    const status = host.status ? many(host.status)[0] : null
    if (!status || status['@state'] !== 'up') continue

    let address = null
    for (const entry of many(host.address)) {
      const type = entry['@addrtype']
      if (type === 'ipv4' || type === 'ipv6') { address = entry['@addr']; break }
    }
    if (!address) continue

    const hostnames = host.hostnames ? many(host.hostnames)[0] : null
    const nameNode = hostnames && hostnames.hostname ? many(hostnames.hostname)[0] : null
    const times = host.times ? many(host.times)[0] : null

    hosts.push({
      ip: address,
      state: 'up',
      reason: status['@reason'] ?? null,
      hostname: nameNode ? (nameNode['@name'] ?? null) : null,
      latency: times ? (times['@srtt'] ?? null) : null,
    })
  }
  return hosts
}

const IP_LINE = /^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)\s*$/

/** fping -a prints one live address per line. */
function parseIpLines (text) {
  const hosts = []
  for (const line of String(text || '').split('\n')) {
    const match = IP_LINE.exec(line)
    if (!match) continue
    try {
      ip.parseAddress(match[1])
    } catch {
      continue
    }
    hosts.push({ ip: match[1], state: 'up', reason: 'echo-reply' })
  }
  return hosts
}

const HPING_ALIVE = /(\d+) packets received/

/** hping3 reports its summary on stderr; one reply means the host answered. */
function hpingIsAlive (stdout, stderr) {
  const blob = `${stdout || ''}\n${stderr || ''}`
  const match = HPING_ALIVE.exec(blob)
  if (match) return Number.parseInt(match[1], 10) > 0
  return blob.includes('bytes from') || blob.includes('flags=')
}

/** masscan --ping writes ICMP replies into its -oL list as proto 'icmp'. */
function parseMasscanPings (file) {
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch {
    return []
  }
  const hosts = []
  for (const line of text.split('\n')) {
    const parts = line.split(/\s+/).filter(Boolean)
    if (parts.length >= 4 && parts[0] === 'open') {
      hosts.push({ ip: parts[3], state: 'up', reason: 'icmp-reply' })
    }
  }
  return hosts
}

/** Sequentially probes each address with a per-host tool such as hping3.
 *
 * `run` is injected rather than imported so the engine owns process handling
 * (and its stop signalling) in one place, exactly as the Python took a `spawn`.
 */
async function runPerHost (prof, addresses, run, log, shouldStop) {
  const alive = []
  for (let index = 0; index < addresses.length; index++) {
    if (shouldStop && shouldStop()) break
    const address = addresses[index]
    let result
    try {
      result = await run(buildHostCommand(prof, address), { timeout: 10000 })
    } catch {
      continue           // timed out or failed to launch; treat as no answer
    }
    if (hpingIsAlive(result.stdout, result.stderr)) {
      alive.push({ ip: address, state: 'up', reason: prof.tool })
      if (log) log(`${address} is up`)
    }
    if (log && index && index % 25 === 0) {
      log(`probed ${index}/${addresses.length} addresses, ${alive.length} up so far`)
    }
  }
  return alive
}

module.exports = {
  PROFILES,
  PREVIOUS,
  getProfile,
  targetArgs,
  profilesForUi,
  checkHostCap,
  expandTargets,
  buildCommand,
  buildHostCommand,
  nmapTarget,
  parseNmapHosts,
  parseIpLines,
  hpingIsAlive,
  parseMasscanPings,
  runPerHost,
}
