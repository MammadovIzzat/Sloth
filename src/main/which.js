'use strict'
/** shutil.which for Node.
 *
 * Node has no equivalent, and shelling out to which(1) would be one process
 * launch per lookup on a path this code checks often. The rules match Python's:
 * an absolute or relative path is tested directly, otherwise each PATH entry is
 * tried in order, and the result must be a file the current user can execute.
 */
const fs = require('node:fs')
const path = require('node:path')

function isExecutableFile (candidate) {
  try {
    if (!fs.statSync(candidate).isFile()) return false
    fs.accessSync(candidate, fs.constants.X_OK)
    return true
  } catch {
    return false
  }
}

/** Absolute path to `name`, or null if it is not on PATH. */
function which (name, searchPath = process.env.PATH) {
  if (!name) return null

  // A name with a separator is a path, not something to look up.
  if (name.includes(path.sep)) {
    return isExecutableFile(name) ? path.resolve(name) : null
  }

  for (const dir of String(searchPath || '').split(path.delimiter)) {
    if (!dir) continue
    const candidate = path.join(dir, name)
    if (isExecutableFile(candidate)) return candidate
  }
  return null
}

module.exports = { which }
