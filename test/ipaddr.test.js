'use strict'
/** Differential test: src/main/ipaddr.js against Python's ipaddress.
 *
 * Address maths decides which network gets scanned, so this does not assert
 * against values typed out by hand — those would only prove the port agrees
 * with whatever I believed while writing it. Instead it generates cases, asks
 * Python for the answers, and requires the two to agree exactly.
 *
 * Python is a test-time dependency only; the application no longer needs it.
 * The test skips itself when python3 is absent rather than failing.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const { test } = require('node:test')

const ip = require('../src/main/ipaddr')

const GENERATOR = `
import ipaddress, json, random
random.seed(11)
addrs, nets = [], []

def add(v):
    try:
        a = ipaddress.ip_address(v)
        addrs.append([v, str(a), a.is_loopback])
    except ValueError:
        addrs.append([v, None, None])

for v in ["10.0.0.1","0.0.0.0","255.255.255.255","127.0.0.1","127.255.255.254","127.0.0.0",
          "010.0.0.1","1.2.3","1.2.3.4.5","256.0.0.1","-1.0.0.0","","  ","1.2.3.-4",
          "::1","::","::1%lo","2001:db8::1","2001:0db8:0000:0000:0000:0000:0000:0001",
          "fe80::1%eth0","fe80::1%25","fe80::1%","::ffff:192.168.0.1","::ffff:c0a8:1",
          "::ffff:0.0.0.0","::ffff:255.255.255.255","::ffff:127.0.0.1","::ffff:0:192.168.0.1",
          "::1.2.3.4","::102:304","2002:c000:204::","1:2:3:4:5:6:7:8","1::2::3","g::1",
          "1:2:3:4:5:6:7","1:2:3:4:5:6:7:8:9","2001:db8:0:0:1:0:0:1","abcd::12:0:0:34",
          "1:0:0:2:0:0:0:3","0:0:0:0:0:0:0:1","::0.0.0.0","1:2:3:4:5:6:1.2.3.4"]:
    add(v)
for _ in range(500):
    add(".".join(str(random.randint(0,255)) for _ in range(4)))
for _ in range(500):
    g = [f"{random.randint(0,0xffff):x}" if random.random() > 0.45 else "0" for _ in range(8)]
    v = ":".join(g)
    add(v)
    if random.random() > 0.7: add(v + "%eth0")
for _ in range(150):
    add("::ffff:" + ".".join(str(random.randint(0,255)) for _ in range(4)))

def addnet(v):
    try:
        n = ipaddress.ip_network(v, strict=False)
        # hosts() differs by family and by block size, so both are exercised.
        h = list(n.hosts()) if n.num_addresses <= 65536 else None
        nets.append([v, str(n), int(n.num_addresses), n.is_loopback,
                     [str(h[0]), str(h[-1])] if h else None])
    except ValueError:
        nets.append([v, None, None, None, None])

for v in ["10.0.0.0/24","10.0.0.5/24","10.0.0.0/8","0.0.0.0/0","10.0.0.1/32","10.0.0.0/31",
          "10.0.0.0/30","127.0.0.0/8","127.0.0.1/32","192.168.1.0/25","2001:db8::/32",
          "::1/128","::/0","10.0.0.0/33","10.0.0.0/-1","10.0.0.0/x","1.2.3.4","2001:db8::1",
          "172.16.0.0/22","10.0.1.128/25","fe80::1%eth0/64","::ffff:1.2.3.0/120",
          "2001:db8::/126","2001:db8::/127","2001:db8::1/128","::/128","2001:db8::/112",
          "2001:db8::/120","10.0.0.0/29","10.0.0.0/16"]:
    addnet(v)
for _ in range(400):
    addnet(".".join(str(random.randint(0,255)) for _ in range(4)) + "/" + str(random.randint(0,32)))
for _ in range(200):
    addnet(":".join(f"{random.randint(0,0xffff):x}" for _ in range(8)) + "/" + str(random.randint(0,128)))

print(json.dumps({"addrs": addrs, "nets": nets}))
`

function pythonCases () {
  try {
    return JSON.parse(execFileSync('python3', ['-c', GENERATOR],
      { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }))
  } catch {
    return null
  }
}

test('addresses and networks match Python ipaddress', (t) => {
  const cases = pythonCases()
  if (!cases) return t.skip('python3 unavailable — nothing to compare against')

  const mismatches = []

  for (const [input, expected, loopback] of cases.addrs) {
    let text = null, isLoopback = null
    try {
      const addr = ip.parseAddress(input)
      text = ip.addressToString(addr)
      isLoopback = ip.isLoopbackAddress(addr.version, addr.value)
    } catch { /* both sides record a rejection as null */ }
    if (text !== expected || (expected !== null && isLoopback !== loopback)) {
      mismatches.push(`address ${JSON.stringify(input)}: ` +
        `python=${expected}/${loopback} node=${text}/${isLoopback}`)
    }
  }

  for (const [input, expected, count, loopback, hosts] of cases.nets) {
    let text = null, total = null, isLoopback = null, ends = null
    try {
      const net = ip.parseNetwork(input)
      text = ip.formatNetwork(net)
      total = Number(ip.numAddresses(net))
      isLoopback = ip.isLoopbackNetwork(net)
      if (hosts) {
        const range = ip.hostRange(net)
        ends = [ip.formatAddress(net.version, range.first),
                ip.formatAddress(net.version, range.last)]
      }
    } catch { /* as above */ }
    const sameHosts = JSON.stringify(ends) === JSON.stringify(hosts)
    if (text !== expected ||
        (expected !== null && (total !== count || isLoopback !== loopback || !sameHosts))) {
      mismatches.push(`network ${JSON.stringify(input)}: ` +
        `python=${expected}/${count}/${loopback}/${JSON.stringify(hosts)} ` +
        `node=${text}/${total}/${isLoopback}/${JSON.stringify(ends)}`)
    }
  }

  assert.deepStrictEqual(mismatches, [],
    `${mismatches.length} of ${cases.addrs.length + cases.nets.length} cases differ:\n` +
    mismatches.slice(0, 20).join('\n'))
})
