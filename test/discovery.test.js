'use strict'
/** Differential test: src/main/discovery.js against sloth/discovery.py.
 *
 * The argv these build is what actually gets executed against a client's
 * network, so the comparison covers the exact argument vectors, not just the
 * parsed results.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

const discovery = require('../src/main/discovery')

const REPO = path.resolve(__dirname, '..')

const TARGETS = [
  '10.0.0.0/24', '10.0.0.1', '10.0.0.1-10.0.0.9', '10.0.0.1-9',
  '10.0.0.1,10.0.0.2', '10.0.0.0/30', '10.0.0.0/31', '10.0.0.1/32',
  '192.168.1.0/24,10.0.0.0/29', '2001:db8::/126', '2001:db8::1',
  '2001:db8::1-2001:db8::5', '10.0.0.1-10.0.1.9', '10.0.0.0/23',
]

const PROFILE_KEYS = ['nmap_default', 'nmap_thorough', 'nmap_arp', 'fping_sweep',
  'fping_thorough', 'masscan_ping', 'hping3_icmp', 'hping3_syn']

const NMAP_SN_XML = [
  `<?xml version="1.0"?><nmaprun><host><status state="up" reason="echo-reply"/>
   <address addr="10.0.0.5" addrtype="ipv4"/>
   <hostnames><hostname name="dc01.internal" type="PTR"/></hostnames>
   <times srtt="1234"/></host>
   <host><status state="down" reason="no-response"/>
   <address addr="10.0.0.6" addrtype="ipv4"/></host></nmaprun>`,
  `<nmaprun><host><status state="up" reason="arp-response"/>
   <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>
   <host><status state="up" reason="syn-ack"/>
   <address addr="2001:db8::9" addrtype="ipv6"/></host></nmaprun>`,
  '<nmaprun></nmaprun>', '', 'not xml',
  '<?xml version="1.0"?><nmaprun><host><status state="up"',
]

const IP_TEXT = [
  '10.0.0.1\n10.0.0.2\n10.0.0.3\n',
  '  10.0.0.1  \n\n2001:db8::1\n',
  '10.0.0.1 is alive\n10.0.0.999\nnonsense\n::1\n',
  '',
]

const HPING = [
  ['', '1 packets transmitted, 1 packets received, 0% packet loss'],
  ['', '1 packets transmitted, 0 packets received, 100% packet loss'],
  ['len=46 ip=10.0.0.1 flags=RA seq=0', ''],
  ['64 bytes from 10.0.0.1: icmp_seq=0', ''],
  ['', ''],
]

function pythonResults (runDir) {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REPO)})
from sloth import discovery as d

targets = json.loads(sys.stdin.readline())
keys    = json.loads(sys.stdin.readline())
xmls    = json.loads(sys.stdin.readline())
texts   = json.loads(sys.stdin.readline())
hpings  = json.loads(sys.stdin.readline())
run_dir = json.loads(sys.stdin.readline())

out = {"cmds": [], "hostcmds": [], "expand": [], "nmaptarget": [],
       "caps": [], "hosts": [], "iplines": [], "hping": [],
       "profiles": d.profiles_for_ui()}

for key in keys:
    p = d.get_profile(key)
    for t in targets:
        try:
            cmd, kind = d.build_command(p, t, run_dir, 1000)
            out["cmds"].append([key, t, cmd, kind])
        except ValueError as exc:
            out["cmds"].append([key, t, None, str(exc)])
        out["caps"].append([key, t, d.check_host_cap(p, t, 300)])
    try:
        out["hostcmds"].append([key, d.build_host_command(p, "10.0.0.1")])
    except ValueError as exc:
        out["hostcmds"].append([key, None])

for t in targets:
    out["expand"].append([t, d.expand_targets(t, 4096)])
    out["nmaptarget"].append([t, d.nmap_target(t)])
for x in xmls:
    out["hosts"].append(d.parse_nmap_hosts(x))
for t in texts:
    out["iplines"].append(d.parse_ip_lines(t))
for so, se in hpings:
    out["hping"].append(d.hping_is_alive(so, se))
print(json.dumps(out))
`
  const input = [TARGETS, PROFILE_KEYS, NMAP_SN_XML, IP_TEXT, HPING, runDir]
    .map((value) => JSON.stringify(value)).join('\n') + '\n'
  try {
    return JSON.parse(execFileSync('python3', ['-c', script],
      { encoding: 'utf8', cwd: REPO, input, maxBuffer: 64 * 1024 * 1024 }))
  } catch {
    return null
  }
}

test('discovery matches the Python implementation', (t) => {
  // Both sides write target files into the run directory; give each its own so
  // one cannot read the other's leftovers.
  const pyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-py-'))
  const jsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-js-'))

  const expected = pythonResults(pyDir)
  if (!expected) {
    fs.rmSync(pyDir, { recursive: true, force: true })
    fs.rmSync(jsDir, { recursive: true, force: true })
    return t.skip('python3 or the sloth package unavailable')
  }

  try {
    // The Electron build adds a reuse option that sends no packets and has no
    // Python counterpart. Everything both builds have must still match exactly.
    const ours = discovery.profilesForUi()
    const extra = ours.filter((p) => !expected.profiles.some((q) => q.key === p.key))
    assert.deepStrictEqual(extra.map((p) => p.key), ['previous'],
      `unexpected profiles only in the Electron build: ${extra.map((p) => p.key)}`)
    assert.deepStrictEqual(ours.filter((p) => p.key !== 'previous'), expected.profiles,
      'a profile shared with the Python build differs')

    for (const [key, target, cmd, kind] of expected.cmds) {
      const prof = discovery.getProfile(key)
      let got = null, gotKind = null
      try {
        const built = discovery.buildCommand(prof, target, jsDir, 1000)
        got = built.argv; gotKind = built.kind
      } catch (err) { gotKind = err.message }
      assert.deepStrictEqual(got, cmd, `argv for ${key} on ${target}`)
      assert.strictEqual(gotKind, kind, `kind for ${key} on ${target}`)
    }

    for (const [key, cmd] of expected.hostcmds) {
      const prof = discovery.getProfile(key)
      let got = null
      try { got = discovery.buildHostCommand(prof, '10.0.0.1') } catch { /* not per-host */ }
      assert.deepStrictEqual(got, cmd, `host argv for ${key}`)
    }

    for (const [key, target, message] of expected.caps) {
      assert.strictEqual(discovery.checkHostCap(discovery.getProfile(key), target, 300),
        message, `host cap for ${key} on ${target}`)
    }

    for (const [target, addresses] of expected.expand) {
      assert.deepStrictEqual(discovery.expandTargets(target, 4096), addresses,
        `expandTargets(${target})`)
    }
    for (const [target, parts] of expected.nmaptarget) {
      assert.deepStrictEqual(discovery.nmapTarget(target), parts, `nmapTarget(${target})`)
    }

    NMAP_SN_XML.forEach((doc, index) => {
      assert.deepStrictEqual(discovery.parseNmapHosts(doc), expected.hosts[index],
        `parseNmapHosts case ${index}`)
    })
    IP_TEXT.forEach((text, index) => {
      assert.deepStrictEqual(discovery.parseIpLines(text), expected.iplines[index],
        `parseIpLines case ${index}`)
    })
    HPING.forEach(([stdout, stderr], index) => {
      assert.strictEqual(discovery.hpingIsAlive(stdout, stderr), expected.hping[index],
        `hpingIsAlive case ${index}`)
    })

    // The target files written along the way must match too — an -iL pointing
    // at different contents is the same bug as a different argv.
    for (const name of fs.readdirSync(pyDir)) {
      assert.strictEqual(fs.readFileSync(path.join(jsDir, name), 'utf8'),
        fs.readFileSync(path.join(pyDir, name), 'utf8'),
        `contents of ${name} differ`)
    }
  } finally {
    fs.rmSync(pyDir, { recursive: true, force: true })
    fs.rmSync(jsDir, { recursive: true, force: true })
  }
})
