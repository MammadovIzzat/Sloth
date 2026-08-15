'use strict'
/** Differential test: src/main/scanconfig.js against sloth/scanconfig.py.
 *
 * This module decides the columns a scan runs with, so a divergence means a
 * task quietly scanning different ports than the same form produced before.
 * Rejections are compared too — whether a bad spec is refused matters as much
 * as what an accepted one becomes.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const path = require('node:path')
const { test } = require('node:test')

const scanconfig = require('../src/main/scanconfig')

const REPO = path.resolve(__dirname, '..')

const PORT_SPECS = [
  '1-65535', '22,80,443', '1', '65535', ' 22 , 80 ', '', '   ', null,
  '0', '65536', '80-22', '1-2-3', 'abc', '22;80', '-', ',', '22,',
  '1-', '-80', '22,,80', '99999999999', '1-65536', '0-100',
]

// Field sets a form can realistically produce, including the empty-string
// cases that mean "none" rather than "unchanged".
const FORMS = [
  {},
  { scan_type: 'full' },
  { scan_type: 'full', engine: 'masscan', tcp_ports: '1-65535' },
  { scan_type: 'full', engine: 'rustscan', tcp_ports: '', udp_ports: '53' },
  { scan_type: 'full', engine: 'rustscan', tcp_ports: '1-1000' },
  { scan_type: 'full', engine: 'nmap', tcp_ports: '', udp_ports: '' },
  { scan_type: 'full', engine: 'nope' },
  { scan_type: 'quick' },
  { scan_type: 'quick', top_ports: '100' },
  { scan_type: 'quick', top_ports: '0' },
  { scan_type: 'quick', top_ports: '999999' },
  { scan_type: 'quick', top_ports: 'abc' },
  { scan_type: 'quick', nmap_ports: '80,443' },
  { scan_type: 'quick', nmap_ports: '80,443', top_ports: '500' },
  { scan_type: 'discovery' },
  { scan_type: 'discovery', discovery: 'fping_sweep' },
  { scan_type: 'discovery', discovery: 'not_a_profile' },
  { scan_type: 'nonsense' },
  { scan_type: 'full', rate: '5' },
  { scan_type: 'full', rate: '99999999' },
  { scan_type: 'full', rate: '' },
  { scan_type: 'full', rate: 'abc' },
  { scan_type: 'full', retries: '0' },
  { scan_type: 'full', retries: '99' },
  { scan_type: 'full', retries: '' },
  { scan_type: 'full', discovery: 'hping3_icmp' },
  { scan_type: 'full', discovery: '' },
  { scan_type: 'full', tcp_ports: '80-22' },
]

const DEFAULTS = [
  {},
  { scan_type: 'quick', engine: 'rustscan', rate: 4000, retries: 0, discovery: 'nmap_arp' },
  { retries: 7 },
  { rate: 250 },
]

// Small ranges and one large enough to trip the per-host cap.
const TARGETS = ['10.0.0.0/24', '10.0.0.1', '10.0.0.0/16']

function pythonResults () {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth.scanconfig import parse_scan_config, describe, SCAN_TYPES, ENGINES
from sloth.engine import ScanError, validate_port_spec

specs    = json.loads(sys.stdin.readline())
forms    = json.loads(sys.stdin.readline())
defaults = json.loads(sys.stdin.readline())
targets  = json.loads(sys.stdin.readline())

out = {"specs": [], "configs": [], "types": SCAN_TYPES,
       "engines": {k: v for k, v in ENGINES.items()}}
for s in specs:
    try:
        out["specs"].append([s, validate_port_spec(s), None])
    except ScanError as exc:
        out["specs"].append([s, None, str(exc)])

for fi, form in enumerate(forms):
    for di, d in enumerate(defaults):
        for t in targets:
            try:
                cfg = parse_scan_config(form, t, d)
                out["configs"].append([fi, di, t, cfg, describe(cfg), None])
            except ScanError as exc:
                out["configs"].append([fi, di, t, None, None, str(exc)])
print(json.dumps(out))
`
  const input = [PORT_SPECS, FORMS, DEFAULTS, TARGETS]
    .map((v) => JSON.stringify(v)).join('\n') + '\n'
  try {
    return JSON.parse(execFileSync('python3', ['-c', script],
      { encoding: 'utf8', cwd: REPO, input, maxBuffer: 64 * 1024 * 1024 }))
  } catch {
    return null
  }
}

test('scan configuration matches the Python implementation', (t) => {
  const expected = pythonResults()
  if (!expected) return t.skip('python3 or the sloth package unavailable')

  assert.deepStrictEqual(scanconfig.SCAN_TYPES, expected.types, 'scan type list differs')
  assert.deepStrictEqual(scanconfig.ENGINES, expected.engines, 'engine list differs')

  for (const [spec, accepted, rejection] of expected.specs) {
    let got = null, threw = null
    try { got = scanconfig.validatePortSpec(spec) } catch (err) { threw = err.message }
    assert.strictEqual(got, accepted, `validatePortSpec(${JSON.stringify(spec)})`)
    // The wording may differ; whether it rejects at all may not.
    assert.strictEqual(Boolean(threw), Boolean(rejection),
      `validatePortSpec(${JSON.stringify(spec)}) rejection: python=${rejection} node=${threw}`)
  }

  for (const [formIndex, defaultIndex, target, config, label, rejection] of expected.configs) {
    const where = `form#${formIndex} defaults#${defaultIndex} target=${target}: ` +
                  JSON.stringify(FORMS[formIndex])
    let got = null, threw = null
    try {
      got = scanconfig.parseScanConfig(FORMS[formIndex], target, DEFAULTS[defaultIndex])
    } catch (err) {
      threw = err.message
    }
    assert.strictEqual(Boolean(threw), Boolean(rejection),
      `${where}\n  python ${rejection ? 'rejected' : 'accepted'}, node ${threw ? 'rejected' : 'accepted'}` +
      `\n  python: ${rejection}\n  node:   ${threw}`)
    if (!rejection) {
      assert.deepStrictEqual(got, config, where)
      assert.strictEqual(scanconfig.describe(got), label, `describe() for ${where}`)
    }
  }
})
