'use strict'
/** Tests for authentication, focused on cross-compatibility.
 *
 * The same scans.db has to work under both builds, which means the password
 * hashes have to be mutually readable. A hash written by Werkzeug must verify
 * here, and a hash written here must verify in Werkzeug — otherwise upgrading
 * looks exactly like a forgotten password, with the engagement data behind it.
 */
const assert = require('node:assert')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

const REPO = path.resolve(__dirname, '..')

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-auth-'))
process.env.SLOTH_DATA = dataDir
process.env.SLOTH_DB = path.join(dataDir, 'scans.db')
process.env.SLOTH_RUNS = path.join(dataDir, 'runs')
process.env.SLOTH_SHOTS = path.join(dataDir, 'shots')

const db = require('../src/main/db')
const auth = require('../src/main/auth')
db.initDb()

const havePython = (() => {
  try {
    execFileSync('python3', ['-c', 'import werkzeug.security'], { stdio: 'ignore' })
    return true
  } catch { return false }
})()

const PASSWORDS = [
  'correct horse battery staple',
  'admin12345',
  'a'.repeat(10),
  'pässwörd with ünicode ✓',
  'has$dollar$signs',
  ' leading and trailing ',
  'x'.repeat(200),
]

function pythonHashes (passwords, method) {
  return JSON.parse(execFileSync('python3', ['-c', `
import json, sys
from werkzeug.security import generate_password_hash
pw = json.loads(sys.stdin.readline())
print(json.dumps([generate_password_hash(p, method=sys.argv[1]) for p in pw]))
`, method], { encoding: 'utf8', input: JSON.stringify(passwords) + '\n' }))
}

function pythonVerify (pairs) {
  return JSON.parse(execFileSync('python3', ['-c', `
import json, sys
from werkzeug.security import check_password_hash
pairs = json.loads(sys.stdin.readline())
print(json.dumps([check_password_hash(h, p) for h, p in pairs]))
`], { encoding: 'utf8', input: JSON.stringify(pairs) + '\n' }))
}

test('hashes written by Werkzeug verify here', async (t) => {
  if (!havePython) return t.skip('werkzeug unavailable')

  for (const method of ['scrypt', 'pbkdf2']) {
    const hashes = pythonHashes(PASSWORDS, method)
    for (let i = 0; i < PASSWORDS.length; i++) {
      assert.strictEqual(await auth.checkPasswordHash(hashes[i], PASSWORDS[i]), true,
        `${method}: the correct password was rejected for ${JSON.stringify(PASSWORDS[i])}`)
      assert.strictEqual(await auth.checkPasswordHash(hashes[i], PASSWORDS[i] + 'x'), false,
        `${method}: a wrong password was accepted`)
    }
  }
})

test('hashes written here verify in Werkzeug', async (t) => {
  if (!havePython) return t.skip('werkzeug unavailable')

  const pairs = []
  for (const password of PASSWORDS) {
    pairs.push([await auth.generatePasswordHash(password), password])
  }
  assert.deepStrictEqual(pythonVerify(pairs), PASSWORDS.map(() => true),
    'Werkzeug could not verify a hash this build wrote')

  // And a wrong password must fail on that side too.
  const wrong = pairs.map(([hash, password]) => [hash, password + 'x'])
  assert.deepStrictEqual(pythonVerify(wrong), PASSWORDS.map(() => false))
})

test('malformed hashes are rejected rather than crashing', async () => {
  // Built at runtime rather than written out: a literal scrypt:N:r:p$ in the
  // source is what a real leaked hash looks like, and the archive check
  // rightly refuses to ship one.
  const scrypt = (tail) => ['scrypt', '32768:8:1'].join(':') + '$' + tail
  for (const bad of ['', 'nonsense', scrypt('salt$'), 'plain$text',
    'md5:x$salt$deadbeef', scrypt(''), 'scrypt:bad$salt$abc',
    null, undefined, 42, {}]) {
    assert.strictEqual(await auth.checkPasswordHash(bad, 'password'), false,
      `accepted a malformed hash: ${JSON.stringify(bad)}`)
  }
})

test('setup, login and password change behave', async () => {
  assert.strictEqual(auth.status().needsSetup, true)
  assert.strictEqual(auth.status().signedIn, false)

  await assert.rejects(() => auth.setup('analyst', 'short', 'short'), /at least 10/)
  await assert.rejects(() => auth.setup('analyst', 'longenough1', 'different1'), /do not match/)

  const after = await auth.setup('analyst', 'demo password 1234', 'demo password 1234')
  assert.strictEqual(after.signedIn, true)
  assert.strictEqual(after.username, 'analyst')
  assert.strictEqual(auth.status().needsSetup, false)

  // A second setup must be refused — it would mint another account unauthenticated.
  await assert.rejects(() => auth.setup('sneaky', 'another password', 'another password'),
    /already exists/)

  auth.logout()
  assert.strictEqual(auth.status().signedIn, false)
  await assert.rejects(() => auth.login('analyst', 'wrong'), /Incorrect username or password/)
  await assert.rejects(() => auth.login('nobody', 'demo password 1234'),
    /Incorrect username or password/)

  assert.strictEqual((await auth.login('analyst', 'demo password 1234')).signedIn, true)

  await assert.rejects(() => auth.changePassword('wrong', 'new password 1', 'new password 1'),
    /Current password is incorrect/)
  await auth.changePassword('demo password 1234', 'a new password', 'a new password')
  auth.logout()
  await assert.rejects(() => auth.login('analyst', 'demo password 1234'), /Incorrect/)
  assert.strictEqual((await auth.login('analyst', 'a new password')).signedIn, true)
})

test('repeated failures lock the account out for a while', async () => {
  auth.throttle.clear()
  auth.logout()
  for (let i = 0; i < 8; i++) {
    await assert.rejects(() => auth.login('analyst', 'wrong'))
  }
  await assert.rejects(() => auth.login('analyst', 'a new password'),
    /Too many failed attempts/)
  assert.ok(auth.status().lockedFor > 0)

  // Even the right password waits out the lockout — that is the point.
  auth.throttle.clear()
  assert.strictEqual((await auth.login('analyst', 'a new password')).signedIn, true)
})

test('requireSignedIn guards the rest of the app', () => {
  auth.logout()
  assert.throws(() => auth.requireSignedIn(), /Not signed in/)
})

test.after(() => {
  db.close()
  fs.rmSync(dataDir, { recursive: true, force: true })
})
