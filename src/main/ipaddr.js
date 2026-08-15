'use strict'
/** IPv4/IPv6 address and network arithmetic.
 *
 * Python's `ipaddress` is in its standard library; Node has nothing equivalent,
 * so this is the one part of the port that had to be built rather than
 * translated. It deliberately mirrors `ipaddress` semantics — including the
 * strict ones, like rejecting leading zeros in an octet, where 010.0.0.1 is a
 * typo and not an octal address.
 *
 * Getting this wrong means scanning a different network than the one that was
 * authorised, so it is checked against Python's implementation directly:
 * test/ipaddr.test.js fuzzes both and compares, rather than asserting against
 * values written out by hand here.
 */

const V4_MAX = (1n << 32n) - 1n
const V6_MAX = (1n << 128n) - 1n

class AddressError extends Error {}

function fail (message) {
  throw new AddressError(message)
}

// --- addresses -----------------------------------------------------------

/** Parses an IPv4 or IPv6 literal into {version, value}.
 *
 * Surrounding whitespace is *not* stripped, because ipaddress does not strip it
 * either: " 10.0.0.1" is rejected. Callers that want to be forgiving trim
 * first — normalizeTarget does. Silently accepting it here would make this
 * module disagree with the Python build on which targets are valid.
 */
function parseAddress (text) {
  if (typeof text !== 'string') fail(`invalid address: ${text}`)
  if (!text) fail('invalid address: empty')
  return text.includes(':') ? parseV6(text) : parseV4(text)
}

function parseV4 (raw) {
  const parts = raw.split('.')
  if (parts.length !== 4) fail(`invalid IPv4 address: ${raw}`)
  let value = 0n
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) fail(`invalid IPv4 address: ${raw}`)
    // Python rejects these outright rather than reading them as octal.
    if (part.length > 1 && part[0] === '0') fail(`leading zeros are not permitted: ${raw}`)
    const octet = Number(part)
    if (octet > 255) fail(`octet out of range: ${raw}`)
    value = (value << 8n) | BigInt(octet)
  }
  return { version: 4, value }
}

function parseV6 (raw) {
  // A scope ("fe80::1%eth0") is kept verbatim and plays no part in the value,
  // matching ipaddress: two addresses differing only by zone compare equal.
  let zone
  let body = raw
  const percent = raw.indexOf('%')
  if (percent >= 0) {
    zone = raw.slice(percent + 1)
    body = raw.slice(0, percent)
    if (!zone) fail(`empty scope id: ${raw}`)
  }

  // A trailing IPv4 literal ("::ffff:192.0.2.1") stands for the last two groups.
  let text = body
  const lastColon = text.lastIndexOf(':')
  const tail = text.slice(lastColon + 1)
  if (tail.includes('.')) {
    const { value } = parseV4(tail)
    const high = (value >> 16n).toString(16)
    const low = (value & 0xffffn).toString(16)
    text = `${text.slice(0, lastColon + 1)}${high}:${low}`
  }

  const halves = text.split('::')
  if (halves.length > 2) fail(`'::' may appear only once: ${raw}`)

  const groups = (chunk) => (chunk === '' ? [] : chunk.split(':'))
  let head, tailGroups
  if (halves.length === 2) {
    head = groups(halves[0])
    tailGroups = groups(halves[1])
    if (head.length + tailGroups.length > 7) fail(`too many groups: ${raw}`)
  } else {
    head = groups(halves[0])
    tailGroups = []
    if (head.length !== 8) fail(`invalid IPv6 address: ${raw}`)
  }

  const fill = 8 - head.length - tailGroups.length
  const all = [...head, ...Array(fill).fill('0'), ...tailGroups]

  let value = 0n
  for (const group of all) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) fail(`invalid IPv6 address: ${raw}`)
    value = (value << 16n) | BigInt(parseInt(group, 16))
  }
  return zone === undefined ? { version: 6, value } : { version: 6, value, zone }
}

/** Canonical text form, matching what Python's str() produces. */
function formatAddress (version, value, zone) {
  if (version === 4) {
    return [24n, 16n, 8n, 0n].map((shift) => (value >> shift) & 0xffn).join('.')
  }
  const suffix = zone === undefined ? '' : `%${zone}`

  // The IPv4-mapped block ::ffff:0:0/96 prints as a dotted quad. Note this
  // covers only that block — the deprecated IPv4-compatible form ::1.2.3.4
  // prints as ::102:304, exactly as ipaddress does.
  if ((value >> 32n) === 0xffffn) {
    return `::ffff:${formatAddress(4, value & 0xffffffffn)}${suffix}`
  }
  const groups = []
  for (let i = 7n; i >= 0n; i--) groups.push(Number((value >> (i * 16n)) & 0xffffn))

  // RFC 5952: compress the longest run of zero groups, leftmost on a tie, and
  // only when it covers more than one group.
  let bestStart = -1, bestLen = 0, start = -1, len = 0
  groups.forEach((group, index) => {
    if (group === 0) {
      if (start < 0) start = index
      len++
      if (len > bestLen) { bestLen = len; bestStart = start }
    } else {
      start = -1; len = 0
    }
  })

  const hex = groups.map((group) => group.toString(16))
  if (bestLen < 2) return hex.join(':') + suffix
  const head = hex.slice(0, bestStart).join(':')
  const tail = hex.slice(bestStart + bestLen).join(':')
  return `${head}::${tail}${suffix}`
}

/** formatAddress for a parsed address, carrying its scope through. */
const addressToString = (addr) => formatAddress(addr.version, addr.value, addr.zone)

const maxFor = (version) => (version === 4 ? V4_MAX : V6_MAX)
const bitsFor = (version) => (version === 4 ? 32 : 128)

function isLoopbackAddress (version, value) {
  if (version === 4) return (value >> 24n) === 127n     // 127.0.0.0/8
  // An IPv4-mapped address answers by its IPv4 half, so ::ffff:127.0.0.1 is
  // loopback. ipaddress does the same, and masscan cannot reach either form.
  if ((value >> 32n) === 0xffffn) return isLoopbackAddress(4, value & 0xffffffffn)
  return value === 1n                                    // ::1
}

// --- networks ------------------------------------------------------------

/** Parses "10.0.0.0/24". Host bits are masked off, as ipaddress does with
 *  strict=False; a bare address is treated as a single-address network. */
function parseNetwork (text) {
  if (typeof text !== 'string') fail(`invalid network: ${text}`)
  const raw = text                    // see parseAddress: no implicit trimming
  const slash = raw.indexOf('/')
  if (slash < 0) {
    const { version, value } = parseAddress(raw)
    return { version, network: value, prefixlen: bitsFor(version) }
  }

  const { version, value } = parseAddress(raw.slice(0, slash))
  const suffix = raw.slice(slash + 1)
  if (!/^\d{1,3}$/.test(suffix)) fail(`invalid prefix length: ${raw}`)
  const prefixlen = Number(suffix)
  if (prefixlen > bitsFor(version)) fail(`prefix length out of range: ${raw}`)

  const hostBits = BigInt(bitsFor(version) - prefixlen)
  const mask = hostBits === 0n ? maxFor(version) : maxFor(version) ^ ((1n << hostBits) - 1n)
  return { version, network: value & mask, prefixlen }
}

const numAddresses = (net) => 1n << BigInt(bitsFor(net.version) - net.prefixlen)
const broadcastAddress = (net) => net.network + numAddresses(net) - 1n
const formatNetwork = (net) => `${formatAddress(net.version, net.network)}/${net.prefixlen}`

function networkContains (net, version, value) {
  if (net.version !== version) return false
  return value >= net.network && value <= broadcastAddress(net)
}

function isLoopbackNetwork (net) {
  return isLoopbackAddress(net.version, net.network) &&
         isLoopbackAddress(net.version, broadcastAddress(net))
}

/** Usable hosts, following ipaddress.hosts().
 *
 * The two families differ, and not symmetrically:
 *   IPv4  drops the network *and* the broadcast address
 *   IPv6  drops only the network address (the subnet-router anycast); there is
 *         no broadcast address to reserve
 * Both make an exception when the block holds two addresses or fewer — a /31
 * point-to-point link and a /32 host route yield everything they contain.
 *
 * Returns {first, last} rather than a list: the callers only need the ends, and
 * a /8 would be sixteen million BigInts.
 */
function hostRange (net) {
  const total = numAddresses(net)
  if (total <= 2n) return { first: net.network, last: broadcastAddress(net) }
  return {
    first: net.network + 1n,
    last: net.version === 4 ? broadcastAddress(net) - 1n : broadcastAddress(net),
  }
}

module.exports = {
  AddressError,
  parseAddress,
  formatAddress,
  addressToString,
  parseNetwork,
  formatNetwork,
  numAddresses,
  broadcastAddress,
  networkContains,
  isLoopbackAddress,
  isLoopbackNetwork,
  hostRange,
  bitsFor,
}
