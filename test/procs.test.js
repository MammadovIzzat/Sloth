'use strict'
/** Behavioural tests for the process registry.
 *
 * Unlike the other ported modules there is nothing to diff against Python
 * here — the whole point of this code is which signal reaches which process, so
 * it is tested by starting real children and observing what happens to them.
 *
 * The properties that matter, and that the old pkill-based implementation got
 * wrong: a pause genuinely freezes the process rather than being noticed later,
 * a stop reaches grandchildren, and neither touches another task's processes.
 */
const assert = require('node:assert')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

const { ProcessRegistry, run, sleep } = require('../src/main/procs')

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sloth-procs-'))

/** A child that appends a line every 50ms, so its progress is observable. */
function ticker (name) {
  const script = path.join(dir, `${name}.sh`)
  const out = path.join(dir, `${name}.out`)
  fs.writeFileSync(script, `#!/bin/sh\nwhile true; do echo tick >> ${out}; sleep 0.05; done\n`)
  fs.chmodSync(script, 0o755)
  return { argv: [script], out }
}

const lines = (file) => {
  try { return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length } catch { return 0 }
}

const alive = (pid) => {
  try { process.kill(pid, 0); return true } catch { return false }
}

test('pause freezes the child, resume lets it continue', async () => {
  const registry = new ProcessRegistry()
  const { argv, out } = ticker('pause')
  registry.spawn('task-a', argv)
  await sleep(250)

  assert.ok(lines(out) > 0, 'child never started producing output')
  assert.strictEqual(registry.pause('task-a'), 1)
  assert.ok(registry.isPaused('task-a'))

  const frozenAt = lines(out)
  await sleep(300)
  assert.strictEqual(lines(out), frozenAt,
    'output kept advancing while paused — SIGSTOP did not land')

  assert.strictEqual(registry.resume('task-a'), 1)
  await sleep(250)
  assert.ok(lines(out) > frozenAt, 'output did not resume after SIGCONT')

  await registry.stop('task-a', 1)
})

test('stop reaches the whole process group, not just the leader', async () => {
  const registry = new ProcessRegistry()
  const parent = path.join(dir, 'parent.sh')
  const child = path.join(dir, 'grandchild.sh')
  const pidFile = path.join(dir, 'grandchild.pid')
  fs.writeFileSync(child, `#!/bin/sh\necho $$ > ${pidFile}\nwhile true; do sleep 0.05; done\n`)
  fs.writeFileSync(parent, `#!/bin/sh\n${child} &\nwhile true; do sleep 0.05; done\n`)
  fs.chmodSync(child, 0o755)
  fs.chmodSync(parent, 0o755)

  registry.spawn('task-b', [parent])
  await sleep(400)
  const grandchild = Number.parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10)
  assert.ok(alive(grandchild), 'grandchild never started')

  await registry.stop('task-b', 2)
  await sleep(200)
  assert.ok(!alive(grandchild),
    'the grandchild survived the stop — the signal did not reach the process group')
})

test('a child that ignores SIGINT is escalated to SIGKILL', async () => {
  const registry = new ProcessRegistry()
  const stubborn = path.join(dir, 'stubborn.sh')
  fs.writeFileSync(stubborn,
    '#!/bin/sh\ntrap "" INT TERM\nwhile true; do sleep 0.05; done\n')
  fs.chmodSync(stubborn, 0o755)

  const proc = registry.spawn('task-c', [stubborn])
  await sleep(300)
  assert.ok(alive(proc.pid))

  const started = Date.now()
  await registry.stop('task-c', 1)          // one second of grace, then SIGKILL
  const elapsed = Date.now() - started

  await sleep(150)
  assert.ok(!alive(proc.pid), 'the process ignored SIGINT and was never killed')
  assert.ok(elapsed >= 900, `gave up after ${elapsed}ms — did not wait out the grace period`)
  assert.ok(elapsed < 6000, `took ${elapsed}ms — escalation was too slow`)
})

test('a stop touches only the task it names', async () => {
  const registry = new ProcessRegistry()
  const a = ticker('isolated-a')
  const b = ticker('isolated-b')
  const procA = registry.spawn('task-d', a.argv)
  const procB = registry.spawn('task-e', b.argv)
  await sleep(250)

  await registry.stop('task-d', 1)
  await sleep(150)

  assert.ok(!alive(procA.pid), "the named task's process survived")
  assert.ok(alive(procB.pid), "another task's process was killed by an unrelated stop")
  assert.ok(registry.isRunning('task-e'))
  assert.ok(!registry.isRunning('task-d'))

  await registry.stop('task-e', 1)
})

test('a child spawned while paused starts paused', async () => {
  const registry = new ProcessRegistry()
  const { argv, out } = ticker('late')
  registry.pause('task-f')                   // pause before anything is running
  registry.spawn('task-f', argv)
  await sleep(300)

  assert.strictEqual(lines(out), 0,
    'a child started during a pause ran anyway')

  registry.resume('task-f')
  await sleep(250)
  assert.ok(lines(out) > 0, 'the child never ran after the pause was lifted')

  await registry.stop('task-f', 1)
})

test('run() collects output and reports a clean exit', async () => {
  const result = await run(['/bin/sh', '-c', 'echo out; echo err >&2; exit 3'])
  assert.strictEqual(result.stdout.trim(), 'out')
  assert.strictEqual(result.stderr.trim(), 'err')
  assert.strictEqual(result.code, 3)
  assert.strictEqual(result.timedOut, false)
})

test('run() kills the group on timeout instead of hanging', async () => {
  const started = Date.now()
  const result = await run(['/bin/sh', '-c', 'sleep 30'], { timeout: 400 })
  const elapsed = Date.now() - started
  assert.ok(result.timedOut, 'the timeout was not reported')
  assert.ok(elapsed < 5000, `run() waited ${elapsed}ms for a 400ms timeout`)
})

test('a missing binary is reported, not thrown', async () => {
  const result = await run(['/nonexistent/definitely-not-a-scanner'])
  assert.strictEqual(result.code, null)
  assert.match(result.stderr, /ENOENT|not found|no such file/i)
})

test.after(() => fs.rmSync(dir, { recursive: true, force: true }))
