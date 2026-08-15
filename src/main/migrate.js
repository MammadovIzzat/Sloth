'use strict'
/** Finding a database left behind by the Python build.
 *
 * That build ran under sudo, so its scans.db is usually owned by root and
 * sits either next to the source or in /var/lib/sloth. This one runs as you
 * and keeps its data under the user profile, so a fresh start would silently
 * show an empty tool while the real engagement data sat untouched on disk —
 * the worst possible outcome, because it looks like data loss.
 *
 * The app does not copy it automatically. It cannot: reading a root-owned
 * file needs a privilege this process deliberately does not have, and quietly
 * duplicating someone's client data is not a decision to make on their behalf.
 * Instead it says exactly what it found and prints the two commands.
 */
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { DB_PATH } = require('./config')

/** Places the Python build could have left a database. */
function candidates () {
  const home = os.homedir()
  return [
    '/var/lib/sloth/scans.db',
    path.join(home, 'Documents', 'tools', 'Sloth', 'scans.db'),
    path.join(home, 'Documents', 'tools', 'SubnetScanner', 'scans.db'),
    path.join(process.cwd(), 'scans.db'),
  ]
}

/** Reports a usable database elsewhere on disk, or null.
 *
 * Only ever returns something when this install has no database of its own —
 * once you are up and running, an old file is not interesting.
 */
function findLegacyDatabase () {
  try {
    if (fs.statSync(DB_PATH).size > 0) return null    // already have our own
  } catch { /* no database yet, which is the case we care about */ }

  for (const candidate of candidates()) {
    if (path.resolve(candidate) === path.resolve(DB_PATH)) continue
    let stat
    try {
      stat = fs.statSync(candidate)
    } catch {
      continue
    }
    if (!stat.isFile() || stat.size === 0) continue

    let readable = true
    try {
      fs.accessSync(candidate, fs.constants.R_OK)
    } catch {
      readable = false
    }
    return {
      path: candidate,
      size: stat.size,
      owner: stat.uid,
      readable,
      ownedByRoot: stat.uid === 0,
    }
  }
  return null
}

/** The message shown once, at first start, when an old database is found. */
function migrationAdvice (found) {
  const target = DB_PATH
  const lines = [
    `Sloth found a database from the previous build at:\n  ${found.path}`,
    `It holds ${(found.size / 1024).toFixed(0)} KB of scan results, and this ` +
    'install is starting empty.',
    '',
    'Nothing has been copied — that is your call, and the file is ' +
    (found.ownedByRoot ? 'owned by root, so it needs a password. ' : '') +
    'To bring it across, run:',
    '',
    `  mkdir -p ${path.dirname(target)}`,
    found.ownedByRoot
      ? `  sudo cp ${found.path} ${target} && sudo chown $USER ${target}`
      : `  cp ${found.path} ${target}`,
    '',
    'Then restart Sloth. The schema is unchanged, so every project, task and ' +
    'finding comes across as it is.',
  ]
  return lines.join('\n')
}

module.exports = { findLegacyDatabase, migrationAdvice }
