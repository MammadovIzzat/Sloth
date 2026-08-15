'use strict'
/** Differential test: src/main/netutil.js against sloth/netutil.py.
 *
 * Same reasoning as ipaddr.test.js — a target spec that parses differently
 * from the Python build means scanning something the operator did not ask for,
 * so the two implementations are compared directly rather than against
 * hand-written expectations.
 *
 * Only the pure functions are compared. routeFor/ipsecOutNetworks/checkInternet
 * shell out to the host's networking and would make the result depend on
 * whatever machine the suite runs on.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const path = require('node:path')
const { test } = require('node:test')

const netutil = require('../src/main/netutil')

const REPO = path.resolve(__dirname, '..')

const GENERATOR = `
import json, random, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth.netutil import (normalize_target, apply_start_ip, count_targets,
                           is_loopback_target, web_url_for)
from sloth.config import WEB_PORTS
random.seed(23)

targets = [
    "10.0.0.1", "10.0.0.0/24", "10.0.0.1-50", "10.0.0.1-10.0.0.50",
    "10.0.0.1, 10.0.0.2", "10.0.0.1 10.0.0.2", "10.0.0.0/24,192.168.1.0/24",
    "  10.0.0.1  ", "10.0.0.5/24", "0.0.0.0/0", "127.0.0.1", "127.0.0.0/8",
    "127.0.0.1-127.0.0.5", "127.0.0.1,10.0.0.1", "::1", "2001:db8::/64",
    "2001:db8::1-2001:db8::ff", "10.0.0.50-10.0.0.1", "10.0.0.1-2001:db8::1",
    "10.0.0.1-", "-10.0.0.1", "10.0.0.256", "010.0.0.1", "", "   ", ",",
    "not an ip", "10.0.0.0/33", "1.2.3", "10.0.0.1/32", "10.0.0.0/31",
    "172.16.0.0/22", "10.0.1.128/25", "::ffff:127.0.0.1", "10.0.0.1-300",
]
targets += [",".join(f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
                     for _ in range(random.randint(1, 5))) for _ in range(60)]
targets += [f"10.{random.randint(0,255)}.{random.randint(0,255)}.0/{random.randint(8,32)}"
            for _ in range(60)]
targets.append(",".join(f"10.0.0.{i}" for i in range(1, 70)))     # over the limit

norm = []
for t in targets:
    try:
        norm.append([t, normalize_target(t), None])
    except ValueError as exc:
        norm.append([t, None, str(exc)])

starts = []
for t in ["10.0.0.0/24", "10.0.0.0/25", "192.168.1.0/24", "10.0.0.0/23",
          "10.0.0.0/8", "10.0.0.1", "10.0.0.0/24,10.0.1.0/24", "2001:db8::/120",
          "10.0.0.0/31", "10.0.0.0/32"]:
    for s in ["", "1", "50", "128", "254", "255", "300", "0", "abc"]:
        try:
            starts.append([t, s, apply_start_ip(t, s), None])
        except ValueError as exc:
            starts.append([t, s, None, str(exc)])

counts = [[t, count_targets(t)] for t in targets if t.strip()]
loops = [[t, is_loopback_target(t)] for t in targets]

urls = []
for ip_ in ["10.0.0.1", "2001:db8::1"]:
    for port in [22, 80, 443, 8080, 8443, 3000, 9999, 161]:
        for proto in ["tcp", "udp"]:
            for svc in [None, "http", "https", "ssl/http", "ssh", "HTTP-proxy"]:
                pd = {"port": port, "proto": proto, "service": svc}
                urls.append([ip_, port, proto, svc, web_url_for(ip_, pd, WEB_PORTS)])

print(json.dumps({"norm": norm, "starts": starts, "counts": counts,
                  "loops": loops, "urls": urls}))
`

function pythonCases () {
  try {
    return JSON.parse(execFileSync('python3', ['-c', GENERATOR],
      { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, cwd: REPO }))
  } catch {
    return null
  }
}

const WEB_PORTS = require('../src/main/config').WEB_PORTS

test('target handling matches the Python implementation', (t) => {
  const cases = pythonCases()
  if (!cases) return t.skip('python3 or the sloth package unavailable')

  const bad = []

  for (const [input, expected] of cases.norm) {
    let got = null
    try { got = netutil.normalizeTarget(input) } catch { /* rejection */ }
    // The exact wording of an error is allowed to differ; whether it rejects
    // at all is not.
    if (got !== expected) bad.push(`normalizeTarget(${JSON.stringify(input)}): python=${expected} node=${got}`)
  }

  for (const [target, start, expected] of cases.starts) {
    let got = null
    try { got = netutil.applyStartIp(target, start) } catch { /* rejection */ }
    if (got !== expected) {
      bad.push(`applyStartIp(${JSON.stringify(target)}, ${JSON.stringify(start)}): ` +
               `python=${expected} node=${got}`)
    }
  }

  for (const [target, expected] of cases.counts) {
    const got = netutil.countTargets(target)
    if (got !== expected) bad.push(`countTargets(${JSON.stringify(target)}): python=${expected} node=${got}`)
  }

  for (const [target, expected] of cases.loops) {
    const got = netutil.isLoopbackTarget(target)
    if (got !== expected) bad.push(`isLoopbackTarget(${JSON.stringify(target)}): python=${expected} node=${got}`)
  }

  for (const [address, port, proto, service, expected] of cases.urls) {
    const got = netutil.webUrlFor(address, { port, proto, service }, WEB_PORTS)
    if (got !== expected) {
      bad.push(`webUrlFor(${address}, ${port}/${proto}, ${service}): python=${expected} node=${got}`)
    }
  }

  const total = cases.norm.length + cases.starts.length + cases.counts.length +
                cases.loops.length + cases.urls.length
  assert.deepStrictEqual(bad, [],
    `${bad.length} of ${total} cases differ:\n` + bad.slice(0, 25).join('\n'))
})
