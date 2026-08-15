'use strict'
/** Raw-socket privilege for the scanners.
 *
 * masscan, fping and hping3 build their own packets and need CAP_NET_RAW. The
 * Python build got this by running the whole tool under sudo. That is not an
 * option here, and not only because Chromium refuses to sandbox itself as root:
 *
 *   An unprivileged process cannot signal a root-owned one. If the app ran as
 *   you and elevated masscan with pkexec, every kill() would return EPERM —
 *   Pause, Resume and Stop would all silently do nothing, and Stop is what
 *   gives masscan the chance to write paused.conf for a later --resume.
 *
 * So the scanner has to run as the same user as the app, holding just the one
 * capability. `setcap cap_net_raw+ep` does exactly that, and is how fping
 * already ships on most distributions. Granting it needs root once; pkexec
 * asks for the password through the desktop's own dialog, and this process
 * never sees it.
 */
const { spawn } = require('node:child_process')
const fs = require('node:fs')

const { which } = require('./which')

const CAP_NET_RAW = 13

// What each tool needs to build raw packets. Detection only — see GRANTABLE
// below for what this is willing to hand out.
//
const REQUIRED_CAPS = {
  masscan: ['cap_net_raw'],
  fping: ['cap_net_raw'],
  hping3: ['cap_net_raw'],
}

// Every scanner here can be granted its capabilities from the interface.
//
// Worth knowing for anyone maintaining this: a file capability belongs to the
// binary, and these live world-executable in /usr/bin, so every local account
// gets it. For nmap and hping3 that also means arbitrary code — nmap --script
// runs Lua holding the capability. On a single-operator machine that is a
// non-issue, which is the case this tool is built for; on a shared box, see
// restrictCommand() below.
const GRANTABLE = new Set(Object.keys(REQUIRED_CAPS))

// All of them need it to do anything at all.
const RAW_ONLY = new Set(Object.keys(REQUIRED_CAPS))

/** Anyone on the machine can run it, so anyone gets its capability. */
function worldExecutable (file) {
  if (!file) return false
  try {
    return Boolean(fs.statSync(file).mode & 0o001)
  } catch {
    return false
  }
}

const geteuid = () => (typeof process.geteuid === 'function' ? process.geteuid() : -1)

/** True when children inherit CAP_NET_RAW from this process. */
function inheritsCapNetRaw () {
  try {
    for (const line of fs.readFileSync('/proc/self/status', 'utf8').split('\n')) {
      if (line.startsWith('CapAmb:')) {
        return Boolean((BigInt('0x' + line.split(/\s+/)[1]) >> BigInt(CAP_NET_RAW)) & 1n)
      }
    }
  } catch { /* not Linux */ }
  return false
}

/** How a binary currently gets its raw-socket privilege, if at all. */
function toolPrivilege (tool) {
  const file = which(tool)
  if (!file) return { tool, path: null, installed: false, privileged: false, via: null }

  let setuid = false
  try {
    setuid = Boolean(fs.statSync(file).mode & 0o4000)
  } catch { /* unreadable; treat as unprivileged */ }
  if (setuid) return { tool, path: file, installed: true, privileged: true, via: 'setuid' }

  const needed = REQUIRED_CAPS[tool] || ['cap_net_raw']
  const getcap = which('getcap')
  if (getcap) {
    const result = require('node:child_process').spawnSync(getcap, [file],
      { encoding: 'utf8', timeout: 5000 })
    const granted = String(result.stdout || '').toLowerCase()
    // Every capability the tool needs, not merely one of them.
    const missing = needed.filter((cap) => !granted.includes(cap))
    if (!missing.length) {
      return { tool, path: file, installed: true, privileged: true, via: 'capability' }
    }
    if (granted.includes('cap_net_')) {
      // Partly granted is its own state: the usual cause is following advice
      // written for masscan and applying it to nmap.
      return { tool, path: file, installed: true, privileged: false,
        via: null, partial: needed.filter((cap) => granted.includes(cap)), missing }
    }
  }
  return { tool, path: file, installed: true, privileged: false, via: null }
}

/** Everything the interface needs to explain the current state. */
function report () {
  const uid = geteuid()
  const asRoot = uid === 0
  const ambient = inheritsCapNetRaw()
  const tools = {}
  for (const tool of Object.keys(REQUIRED_CAPS)) {
    const info = toolPrivilege(tool)
    // Running as root, or with an ambient capability, covers every tool at once.
    info.usable = info.installed && (asRoot || ambient || info.privileged)
    info.grantable = GRANTABLE.has(tool)
    info.grantCommand = grantCommand(tool)
    info.revokeCommand = revokeCommand(tool)
    info.restrictCommand = restrictCommand(tool)
    // World-executable plus a capability is the thing that makes this a
    // local-user concern rather than a per-user one.
    info.worldExecutable = worldExecutable(info.path)
    tools[tool] = info
  }
  return {
    uid,
    root: asRoot,
    ambient,
    canGrant: Boolean(which('pkexec') && which('setcap')),
    tools,
  }
}

/** The command a user would run themselves, for display and for copying.
 *
 * +ep, not +eip: the inheritable bit lets the capability follow an exec into
 * another binary that also carries it, which nothing here needs and which only
 * widens the blast radius.
 */
function grantCommand (tool) {
  const file = which(tool)
  const caps = (REQUIRED_CAPS[tool] || ['cap_net_raw']).join(',')
  return `sudo setcap ${caps}+ep ${file || tool}`
}

/** Taking it back. Offered next to every grant, because the easiest privilege
 *  to reason about is one you can remove as readily as you added it. */
function revokeCommand (tool) {
  const file = which(tool)
  return `sudo setcap -r ${file || tool}`
}

/** Restricting the capability to one group, so it stops being world-usable.
 *
 * Not run automatically: it changes ownership of a packaged system binary, a
 * package upgrade will undo it, and on a shared machine the group has to be one
 * that actually exists. Worth showing, worth deciding yourself.
 */
function restrictCommand (tool, group = 'wheel') {
  const file = which(tool) || tool
  return `sudo chgrp ${group} ${file} && sudo chmod 750 ${file}`
}

/** Grants CAP_NET_RAW to one scanner, asking for a password via pkexec.
 *
 * Resolves {ok, message}. Never throws: a refused password is an ordinary
 * outcome, not an error worth a stack trace.
 */
function grant (tool) {
  return new Promise((resolve) => {
    if (!GRANTABLE.has(tool)) {
      return resolve({ ok: false, message: `${tool} is not a scanner this can grant.` })
    }
    const file = which(tool)
    if (!file) return resolve({ ok: false, message: `${tool} is not installed.` })

    const pkexec = which('pkexec')
    const setcap = which('setcap')
    if (!pkexec || !setcap) {
      return resolve({
        ok: false,
        message: 'pkexec and setcap are needed to do this from here. Run this ' +
                 `in a terminal instead:\n  ${grantCommand(tool)}`,
      })
    }

    // An argument vector, never a shell string: `file` comes from PATH lookup
    // of an allowlisted name, but there is no reason to involve a shell at all.
    const caps = (REQUIRED_CAPS[tool] || ['cap_net_raw']).join(',') + '+ep'
    const child = spawn(pkexec, [setcap, caps, file],
      { stdio: ['ignore', 'pipe', 'pipe'] })
    let stderr = ''
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.once('error', (err) => resolve({ ok: false, message: err.message }))
    child.once('exit', (code) => {
      if (code === 0) {
        const after = toolPrivilege(tool)
        return resolve(after.privileged
          ? { ok: true, message: `${tool} can now open raw sockets without root.` }
          : { ok: false, message: `setcap reported success but ${tool} still has no capability.` })
      }
      // 126 is pkexec's "not authorised", 127 "dismissed or failed to run".
      const message = code === 126 || code === 127
        ? 'Cancelled — no password given, or the request was refused.'
        : `setcap failed (exit ${code}). ${stderr.trim()}`.trim()
      resolve({ ok: false, message })
    })
  })
}

/** Explains what is missing and what to do, or null when nothing is. */
function blockingMessage (tools) {
  const state = report()
  if (state.root || state.ambient) return null
  const blocked = [...tools].filter((t) => RAW_ONLY.has(t) && !state.tools[t]?.privileged)
  if (!blocked.length) return null
  return `${blocked.join(', ')} ${blocked.length === 1 ? 'needs' : 'need'} raw ` +
         'sockets. Grant the capability once — Sloth can do it for you, or run:\n  ' +
         blocked.map(grantCommand).join('\n  ')
}

/** Removes a tool's file capabilities. Always allowed: this only ever reduces
 *  privilege, so it needs none of the caution that granting does. */
function revoke (tool) {
  return new Promise((resolve) => {
    const file = which(tool)
    if (!file) return resolve({ ok: false, message: `${tool} is not installed.` })
    const pkexec = which('pkexec')
    const setcap = which('setcap')
    if (!pkexec || !setcap) {
      return resolve({ ok: false, message: `Run this in a terminal:\n  ${revokeCommand(tool)}` })
    }
    const child = spawn(pkexec, [setcap, '-r', file], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stderr = ''
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.once('error', (err) => resolve({ ok: false, message: err.message }))
    child.once('exit', (code) => resolve(code === 0
      ? { ok: true, message: `${tool} no longer holds any capability.` }
      : { ok: false, message: `Could not revoke (exit ${code}). ${stderr.trim()}`.trim() }))
  })
}

module.exports = {
  GRANTABLE, RAW_ONLY, REQUIRED_CAPS,
  report, grant, revoke, grantCommand, revokeCommand, restrictCommand,
  blockingMessage, inheritsCapNetRaw, toolPrivilege,
}
