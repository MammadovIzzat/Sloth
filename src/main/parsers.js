'use strict'
/** Parsers for masscan, rustscan and nmap output.
 *
 * Ported from parsers.py. Everything reaching these functions came off the
 * wire from a host under someone else's control, by way of a scanner, so they
 * only ever extract — nothing here evaluates, and every number is bounded by
 * the pattern that matched it.
 */
const fs = require('node:fs')
const { XMLParser } = require('fast-xml-parser')

// masscan prints these to stdout as it finds them, which is what makes live
// streaming possible: "Discovered open port 80/tcp on 192.168.1.10"
const DISCOVERY_RE = /Discovered open port (\d+)\/(tcp|udp) on ([0-9a-fA-F:.]+)/

// The status line masscan repaints on stderr:
// "rate: 0.98-kpps, 12.34% done,   0:01:23 remaining, found=7"
const PROGRESS_RE =
  /rate:\s*([\d.]+)-kpps,\s*([\d.]+)%\s*done(?:,\s*([\d:]+)\s*remaining)?(?:,\s*found=(\d+))?/

/** Returns {ip, port, proto, state} for a masscan discovery line, else null. */
function parseDiscoveryLine (line) {
  const match = DISCOVERY_RE.exec(line || '')
  if (!match) return null
  return { ip: match[3], port: Number.parseInt(match[1], 10), proto: match[2], state: 'open' }
}

/** Returns {rateKpps, percent, remaining, found} or null. */
function parseProgressLine (line) {
  const match = PROGRESS_RE.exec(line || '')
  if (!match) return null
  return {
    rateKpps: Number.parseFloat(match[1]),
    percent: Number.parseFloat(match[2]),
    remaining: match[3] === undefined ? null : match[3],
    found: match[4] === undefined ? null : Number.parseInt(match[4], 10),
  }
}

// nmap --stats-every prints: "SYN Stealth Scan Timing: About 45.30% done; ..."
const NMAP_PROGRESS_RE = /About\s+([\d.]+)%\s+done/

/** Percentage from an nmap timing line, or null. */
function parseNmapProgress (line) {
  const match = NMAP_PROGRESS_RE.exec(line || '')
  return match ? Number.parseFloat(match[1]) : null
}

/** Batch version of parseDiscoveryLine, kept for one-shot rescans. */
function parseMasscanStdout (text) {
  const ports = []
  for (const line of String(text || '').split('\n')) {
    const hit = parseDiscoveryLine(line)
    if (hit) ports.push(hit)
  }
  return ports
}

// rustscan --greppable prints one line per host: "192.168.1.5 -> [22,80,443]"
const RUSTSCAN_RE = /^\s*([0-9a-fA-F:.]+)\s*->\s*\[([0-9,\s]*)\]/

/** Returns {ip, ports} from a rustscan greppable line, or null. */
function parseRustscanLine (line) {
  const match = RUSTSCAN_RE.exec(line || '')
  if (!match) return null
  const ports = match[2].replace(/ /g, '').split(',')
    .filter((part) => part.trim() && /^\d+$/.test(part.trim()))
    .map((part) => Number.parseInt(part, 10))
  return { ip: match[1], ports }
}

/** Reads masscan's -oL output: 'open tcp 80 192.168.1.1 1730000000'.
 *
 * Written alongside the live stdout stream as the authoritative record, so a
 * scan is never lost to stdout buffering.
 */
function parseMasscanListFile (path) {
  let text
  try {
    text = fs.readFileSync(path, 'utf8')
  } catch {
    return []
  }
  const results = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const parts = line.split(/\s+/)
    if (parts.length < 4 || parts[0] !== 'open') continue
    const [, proto, port, ip] = parts
    if (!/^\d+$/.test(port)) continue
    results.push({ ip, port: Number.parseInt(port, 10), proto, state: 'open' })
  }
  return results
}

// Attribute values are the only thing read out of nmap's XML, and they are
// wanted verbatim — a service banner containing "&amp;" should come back as
// "&". Entity expansion beyond the predefined five stays off, so a crafted
// DOCTYPE cannot make the parser read files or expand exponentially.
const xml = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  processEntities: true,
  htmlEntities: false,
  parseAttributeValue: false,     // portid stays a string; we parse it ourselves
  trimValues: true,
})

/** Always returns an array for a node that may be absent, single or repeated. */
function many (node) {
  if (node === undefined || node === null) return []
  return Array.isArray(node) ? node : [node]
}

/** Depth-first walk collecting every <port> under a host, wherever nmap put it. */
function collectPorts (node, out) {
  if (!node || typeof node !== 'object') return out
  for (const [key, value] of Object.entries(node)) {
    if (key === 'port') {
      out.push(...many(value))
    } else if (typeof value === 'object') {
      for (const child of many(value)) collectPorts(child, out)
    }
  }
  return out
}

/** Extracts per-host ports and service labels from nmap's XML output. */
function parseNmapXml (xmlText) {
  const hosts = {}
  if (!xmlText || !String(xmlText).trim()) return hosts

  let root
  try {
    root = xml.parse(String(xmlText).trim())
  } catch {
    return hosts       // truncated output from a killed scan; not an error here
  }

  const hostNodes = []
  collectHosts(root, hostNodes)

  for (const host of hostNodes) {
    let address = null
    for (const entry of many(host.address)) {
      const type = entry['@addrtype']
      if (type === 'ipv4' || type === 'ipv6') { address = entry['@addr']; break }
    }
    if (!address) continue

    const ports = []
    for (const portNode of collectPorts(host, [])) {
      const state = portNode.state ? (many(portNode.state)[0]['@state'] || '') : ''
      const portId = portNode['@portid']
      if (!portNode.state || portId === undefined) continue
      // UDP is often "open|filtered"; keep those plus plain "filtered".
      if (!(state.startsWith('open') || state === 'filtered')) continue
      ports.push({
        port: Number.parseInt(portId, 10),
        proto: portNode['@protocol'] ?? null,
        state,
        service: serviceLabel(portNode.service ? many(portNode.service)[0] : null),
      })
    }
    hosts[address] = ports
  }
  return hosts
}

function collectHosts (node, out) {
  if (!node || typeof node !== 'object') return out
  for (const [key, value] of Object.entries(node)) {
    if (key === 'host') {
      out.push(...many(value))
    } else if (typeof value === 'object') {
      for (const child of many(value)) collectHosts(child, out)
    }
  }
  return out
}

/** Builds "http" or "http (Apache httpd 2.4.58)" from an nmap <service> node. */
function serviceLabel (node) {
  if (!node) return null
  const name = node['@name']
  if (!name) return null
  const detail = [node['@product'], node['@version']].filter(Boolean).join(' ')
  return detail ? `${name} (${detail})` : String(name)
}

module.exports = {
  parseDiscoveryLine,
  parseProgressLine,
  parseNmapProgress,
  parseMasscanStdout,
  parseRustscanLine,
  parseMasscanListFile,
  parseNmapXml,
}
