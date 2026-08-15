'use strict'
/** Authentication.
 *
 * The Python build guarded an HTTP port that ran as root. There is no port
 * here, so the threat this defends against is narrower and more concrete:
 * someone else at the keyboard, or with the laptop. The engagement database
 * holds client hosts, open ports and screenshots of their internal systems,
 * and that is worth a password.
 *
 * Ported from auth.py, with two deliberate changes:
 *
 *   - API tokens are gone. They existed so curl and scripts could reach the
 *     HTTP API; with no socket there is nothing for a token to authenticate
 *     to. Offering one would mint a credential that cannot be used. The
 *     api_token_hash column stays so the schema still matches the Python
 *     build, and an existing token is left untouched rather than deleted.
 *   - The session lives in this process, not in a signed cookie. Closing the
 *     app signs you out; there is no cookie to steal and nothing on disk.
 *
 * Password hashes stay in Werkzeug's format, so an account created by the
 * Python build logs in here and vice versa. That compatibility is the point:
 * the same scans.db has to work under both.
 */
const crypto = require('node:crypto')

const { connect, newId, now } = require('./db')

const MIN_PASSWORD_LENGTH = 10

// Werkzeug's default. Kept identical so a hash written here is readable by the
// Python build — 128 * N * r bytes of memory, which is 32 MB at these settings.
const SCRYPT = { n: 32768, r: 8, p: 1, keylen: 64 }
const SCRYPT_MAXMEM = 128 * SCRYPT.n * SCRYPT.r * 2

class AuthError extends Error {}

// --- password hashing ----------------------------------------------------

function scryptHash (password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT.keylen,
      { N: SCRYPT.n, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT_MAXMEM },
      (err, key) => (err ? reject(err) : resolve(key)))
  })
}

/** Werkzeug-format hash: "scrypt:N:r:p$salt$hex". */
async function generatePasswordHash (password) {
  const salt = crypto.randomBytes(12).toString('base64').replace(/[+/=]/g, '').slice(0, 16)
  const key = await scryptHash(password, salt)
  return `scrypt:${SCRYPT.n}:${SCRYPT.r}:${SCRYPT.p}$${salt}$${key.toString('hex')}`
}

/** Verifies against Werkzeug's scrypt or pbkdf2 formats.
 *
 * Both are supported for reading because a database old enough to predate the
 * scrypt default still has pbkdf2 rows in it, and refusing to log those in
 * would look exactly like a lost password.
 */
async function checkPasswordHash (stored, password) {
  if (typeof stored !== 'string' || !stored.includes('$')) return false
  const [method, salt, expected] = splitHash(stored)
  if (!method || salt === undefined || !expected) return false

  let derived
  try {
    if (method.startsWith('scrypt:')) {
      const [, n, r, p] = method.split(':')
      derived = await new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, expected.length / 2, {
          N: Number(n), r: Number(r), p: Number(p),
          maxmem: 128 * Number(n) * Number(r) * 2,
        }, (err, key) => (err ? reject(err) : resolve(key)))
      })
    } else if (method.startsWith('pbkdf2:')) {
      const [, digest, iterations] = method.split(':')
      derived = crypto.pbkdf2Sync(password, salt, Number(iterations || 260000),
        expected.length / 2, digest || 'sha256')
    } else {
      return false
    }
  } catch {
    return false
  }

  const expectedBuf = Buffer.from(expected, 'hex')
  if (expectedBuf.length !== derived.length) return false
  return crypto.timingSafeEqual(expectedBuf, derived)
}

/** Splits on the first two '$' only — a salt could contain one. */
function splitHash (stored) {
  const first = stored.indexOf('$')
  const second = stored.indexOf('$', first + 1)
  if (first < 0 || second < 0) return []
  return [stored.slice(0, first), stored.slice(first + 1, second), stored.slice(second + 1)]
}

// A real hash to compare against for unknown usernames, so a failed lookup
// costs the same time as a wrong password.
let dummyHash = null
async function dummy () {
  if (!dummyHash) dummyHash = await generatePasswordHash('unused-placeholder-value')
  return dummyHash
}

// --- storage -------------------------------------------------------------

const userCount = () =>
  connect().prepare('SELECT COUNT(*) AS n FROM users').get().n

const getUser = (userId) => connect()
  .prepare('SELECT * FROM users WHERE id = ? AND is_active = 1').get(userId) ?? null

const getUserByName = (username) => connect()
  .prepare('SELECT * FROM users WHERE username = ? AND is_active = 1').get(username) ?? null

async function createUser (username, password) {
  if (String(password).length < MIN_PASSWORD_LENGTH) {
    throw new AuthError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
  }
  const name = String(username || '').trim()
  if (!name) throw new AuthError('Username is required.')
  if (getUserByName(name)) throw new AuthError('That username is already taken.')

  const id = newId()
  connect().prepare(
    'INSERT INTO users (id, username, password_hash, created_at, is_active)' +
    ' VALUES (?,?,?,?,1)').run(id, name, await generatePasswordHash(password), now())
  return id
}

async function setPassword (userId, password) {
  if (String(password).length < MIN_PASSWORD_LENGTH) {
    throw new AuthError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
  }
  connect().prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .run(await generatePasswordHash(password), userId)
}

const touchLogin = (userId) =>
  connect().prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now(), userId)

// --- brute-force throttling ---------------------------------------------

/** Slows down password guessing.
 *
 * Less critical than it was — an attacker at the keyboard could read the
 * database file directly — but it still blunts someone tapping at a screen
 * they walked past, and costs nothing.
 */
class Throttle {
  constructor () {
    this.LIMIT = 8
    this.WINDOW = 300000     // failures older than this stop counting
    this.LOCKOUT = 300000    // how long a tripped client waits
    this._failures = []
    this._until = 0
  }

  lockedFor () {
    const remaining = this._until - Date.now()
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0
  }

  recordFailure () {
    const cutoff = Date.now() - this.WINDOW
    this._failures = this._failures.filter((stamp) => stamp > cutoff)
    this._failures.push(Date.now())
    if (this._failures.length >= this.LIMIT) {
      this._until = Date.now() + this.LOCKOUT
      this._failures = []
    }
  }

  clear () {
    this._failures = []
    this._until = 0
  }
}

const throttle = new Throttle()

// --- session -------------------------------------------------------------

let signedInUserId = null

const currentUser = () => (signedInUserId ? getUser(signedInUserId) : null)

/** What the interface needs to decide which screen to show. */
function status () {
  const user = currentUser()
  return {
    needsSetup: userCount() === 0,
    signedIn: user !== null,
    username: user ? user.username : null,
    minLength: MIN_PASSWORD_LENGTH,
    lockedFor: throttle.lockedFor(),
  }
}

/** Creates the first account. Only possible while none exists. */
async function setup (username, password, confirm) {
  if (userCount() > 0) throw new AuthError('An account already exists — sign in instead.')
  if (password !== confirm) throw new AuthError('Those passwords do not match.')
  const id = await createUser(username, password)
  signedInUserId = id
  touchLogin(id)
  return status()
}

async function login (username, password) {
  const wait = throttle.lockedFor()
  if (wait) throw new AuthError(`Too many failed attempts. Try again in ${wait} seconds.`)

  const user = getUserByName(String(username || '').trim())
  // Hash even when the user does not exist, so the response time does not
  // reveal which usernames are real.
  const stored = user ? user.password_hash : await dummy()
  const ok = await checkPasswordHash(stored, String(password || ''))

  if (!ok || !user) {
    throttle.recordFailure()
    throw new AuthError('Incorrect username or password.')
  }
  throttle.clear()
  signedInUserId = user.id
  touchLogin(user.id)
  return status()
}

function logout () {
  signedInUserId = null
  return status()
}

async function changePassword (current, next, confirm) {
  const user = currentUser()
  if (!user) throw new AuthError('Not signed in.')
  if (!await checkPasswordHash(user.password_hash, String(current || ''))) {
    throw new AuthError('Current password is incorrect.')
  }
  if (next !== confirm) throw new AuthError('Those passwords do not match.')
  await setPassword(user.id, next)
  return true
}

/** Throws unless someone is signed in. Guards every other IPC handler. */
function requireSignedIn () {
  if (!currentUser()) throw new AuthError('Not signed in.')
}

module.exports = {
  AuthError, MIN_PASSWORD_LENGTH,
  generatePasswordHash, checkPasswordHash,
  userCount, getUser, getUserByName, createUser, setPassword,
  currentUser, status, setup, login, logout, changePassword, requireSignedIn,
  throttle,
}
