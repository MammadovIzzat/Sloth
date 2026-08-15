'use strict'
/** Differential test: src/main/parsers.js against sloth/parsers.py.
 *
 * These read output produced by hosts under someone else's control, so the
 * cases include malformed and hostile shapes as well as real ones: a service
 * banner carrying XML entities, a truncated document from a killed scan, a
 * DOCTYPE that would expand exponentially in a parser that allowed it.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const path = require('node:path')
const { test } = require('node:test')

const parsers = require('../src/main/parsers')

const REPO = path.resolve(__dirname, '..')

const LINES = [
  'Discovered open port 80/tcp on 192.168.1.10',
  'Discovered open port 65535/udp on 10.0.0.1',
  'Discovered open port 22/tcp on 2001:db8::1',
  'Discovered open port 0/tcp on 10.0.0.1',
  'Discovered open port 80/sctp on 10.0.0.1',
  'Discovered open port abc/tcp on 10.0.0.1',
  'noise before Discovered open port 443/tcp on 10.0.0.9 and after',
  '',
  'rate:  0.98-kpps, 12.34% done,   0:01:23 remaining, found=7',
  'rate: 1000.00-kpps, 100.00% done',
  'rate: 0.00-kpps, 0.00% done, 0:00:00 remaining',
  'rate: 12-kpps, 5% done, found=0',
  'SYN Stealth Scan Timing: About 45.30% done; ETC: 09:12 (0:00:412 remaining)',
  'About 100% done',
  'About done',
  '192.168.1.5 -> [22,80,443]',
  '  10.0.0.1 -> [1, 2 , 3]',
  '2001:db8::1 -> []',
  '10.0.0.1 -> [22,notaport,443]',
  '10.0.0.1 -> 22,80',
  'garbage',
]

const XML_CASES = [
  // A normal scan.
  `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.9" addrtype="ipv4"/>
   <ports><port protocol="tcp" portid="80"><state state="open"/>
   <service name="http" product="nginx" version="1.24.0"/></port>
   <port protocol="tcp" portid="443"><state state="open"/>
   <service name="https"/></port></ports></host></nmaprun>`,
  // Closed and filtered states: only open* and filtered survive.
  `<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>
   <port protocol="tcp" portid="1"><state state="closed"/></port>
   <port protocol="udp" portid="161"><state state="open|filtered"/>
   <service name="snmp"/></port>
   <port protocol="tcp" portid="8080"><state state="filtered"/></port>
   </ports></host></nmaprun>`,
  // Several hosts, plus one with no usable address.
  `<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/></host>
   <host><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>
   <host><address addr="2001:db8::5" addrtype="ipv6"/><ports>
   <port protocol="tcp" portid="22"><state state="open"/>
   <service name="ssh" product="OpenSSH" version="9.8p1"/></port></ports></host></nmaprun>`,
  // Entities and quotes inside a service banner.
  `<nmaprun><host><address addr="10.0.0.2" addrtype="ipv4"/><ports>
   <port protocol="tcp" portid="80"><state state="open"/>
   <service name="http" product="A &amp; B &lt;server&gt;" version="1.0 &quot;beta&quot;"/>
   </port></ports></host></nmaprun>`,
  // Truncated: a scan that was killed mid-write.
  '<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.3" addrtype="ipv4"/><por',
  // Empty and junk.
  '', '   ', 'not xml at all', '<nmaprun></nmaprun>',
  // A port with no state element, and one with no portid.
  `<nmaprun><host><address addr="10.0.0.4" addrtype="ipv4"/><ports>
   <port protocol="tcp" portid="80"/>
   <port protocol="tcp"><state state="open"/></port>
   <port protocol="tcp" portid="99"><state state="open"/></port>
   </ports></host></nmaprun>`,
]

// A billion-laughs style document. Python's ElementTree refuses entity
// expansion; this asserts the JS parser does not blow up either.
const XML_BOMB = `<?xml version="1.0"?><!DOCTYPE lolz [
 <!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="&lol4;"/></port></ports></host></nmaprun>`

function pythonResults (lines, xmlCases) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth.parsers import (parse_discovery_line, parse_progress_line,
                           parse_nmap_progress, parse_rustscan_line, parse_nmap_xml)
lines = json.loads(sys.stdin.readline())
xmls  = json.loads(sys.stdin.readline())
out = {"disc": [], "prog": [], "nprog": [], "rust": [], "xml": []}
for line in lines:
    out["disc"].append(parse_discovery_line(line))
    out["prog"].append(parse_progress_line(line))
    out["nprog"].append(parse_nmap_progress(line))
    r = parse_rustscan_line(line)
    out["rust"].append(None if r is None else [r[0], r[1]])
for doc in xmls:
    try:
        out["xml"].append(parse_nmap_xml(doc))
    except Exception as exc:
        out["xml"].append({"__error__": type(exc).__name__})
print(json.dumps(out))
`
  try {
    return JSON.parse(execFileSync('python3', ['-c', script], {
      encoding: 'utf8',
      cwd: REPO,
      input: JSON.stringify(lines) + '\n' + JSON.stringify(xmlCases) + '\n',
      maxBuffer: 32 * 1024 * 1024,
    }))
  } catch {
    return null
  }
}

test('line parsers match the Python implementation', (t) => {
  const expected = pythonResults(LINES, [])
  if (!expected) return t.skip('python3 or the sloth package unavailable')

  LINES.forEach((line, index) => {
    const disc = parsers.parseDiscoveryLine(line)
    assert.deepStrictEqual(disc, expected.disc[index], `discovery: ${JSON.stringify(line)}`)

    const progress = parsers.parseProgressLine(line)
    const pyProgress = expected.prog[index] && {
      rateKpps: expected.prog[index].rate_kpps,
      percent: expected.prog[index].percent,
      remaining: expected.prog[index].remaining,
      found: expected.prog[index].found,
    }
    assert.deepStrictEqual(progress, pyProgress ?? null, `progress: ${JSON.stringify(line)}`)

    assert.deepStrictEqual(parsers.parseNmapProgress(line), expected.nprog[index] ?? null,
      `nmap progress: ${JSON.stringify(line)}`)

    const rust = parsers.parseRustscanLine(line)
    const pyRust = expected.rust[index] && { ip: expected.rust[index][0], ports: expected.rust[index][1] }
    assert.deepStrictEqual(rust, pyRust ?? null, `rustscan: ${JSON.stringify(line)}`)
  })
})

test('nmap XML parsing matches the Python implementation', (t) => {
  const expected = pythonResults([], XML_CASES)
  if (!expected) return t.skip('python3 or the sloth package unavailable')

  XML_CASES.forEach((doc, index) => {
    const got = parsers.parseNmapXml(doc)
    assert.deepStrictEqual(got, expected.xml[index],
      `XML case ${index}:\n${doc.slice(0, 160)}`)
  })
})

test('a nested-entity document neither expands nor hangs', () => {
  const started = Date.now()
  const hosts = parsers.parseNmapXml(XML_BOMB)
  assert.ok(Date.now() - started < 5000, 'parsing took too long — entities may be expanding')
  // Whatever it returns, it must not contain a megabyte of "lol".
  const text = JSON.stringify(hosts)
  assert.ok(text.length < 10000, `output ballooned to ${text.length} bytes`)
})
