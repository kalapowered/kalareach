#!/usr/bin/env node
// Builds both bundles and drives them with Playwright. The bundles are built first so the tests
// run against real output rather than a development server: the harness bundle, which substitutes
// a scripted host, and the bundle the desktop window loads, which one test opens to prove the
// shipped entry mounts. The harness goes to its own directory, so the entry with the fake host in
// it can never end up where the desktop shell looks. Each build states which one it is rather than
// inheriting the answer, because a run started from a shell that already set the flag would
// otherwise build the harness twice and leave yesterday's bundle where the shell reads.
//
// This run serves both bundles itself, each from a server of its own that is given a free port by
// the system, asks for another when one is taken before it binds it, and says which it serves on.
// No port is looked for by this script and released before a server is started, and a second run on
// the same machine is never the server this one tests. Each server ends with this run, however it
// ends.
import { spawn, spawnSync } from 'node:child_process'
import { clearTimeout, setTimeout } from 'node:timers'
import { URL, fileURLToPath } from 'node:url'

import { SERVING_LINE } from './preview-serve.mjs'
import { toolPath } from './tools.mjs'

const run = (tool, args, env = {}) => {
  const result = spawnSync(process.execPath, [toolPath(tool), ...args], {
    stdio: 'inherit',
    env: { ...process.env, ...env }
  })
  if (result.error) {
    console.error(result.error.message)
    process.exit(1)
  }
  if (result.status !== 0) process.exit(result.status ?? 1)
}

/**
 * How long a server is given to say its port before it is called not started. A server says it as
 * soon as it listens, and one that cannot ends with its reason, so this only bounds a server that
 * does neither, which a machine with every core busy does not make.
 */
const START_WITHIN_MS = 120_000

/** The servers started, which end with this run. */
const servers = []

/** What has become of each server that ended, from the moment it was started. */
const gone = []

/** The tests' process once it runs, which a server that ends or a signal to this script ends. */
let tests = null
const running = (child) => child !== null && child.exitCode === null && child.signalCode === null

/** Starts the server in `script` on a port the system chooses and says which port that was. */
const serve = (script) =>
  new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [fileURLToPath(new URL(script, import.meta.url)), '0', String(process.pid)],
      { stdio: ['ignore', 'pipe', 'inherit'] }
    )
    servers.push(child)
    const gaveUp = setTimeout(
      () => reject(new Error(`${script} did not say its port within ${START_WITHIN_MS / 1000} s`)),
      START_WITHIN_MS
    )
    let said = ''
    child.stdout.on('data', (chunk) => {
      said += chunk
      const serving = SERVING_LINE.exec(said)
      if (serving) {
        clearTimeout(gaveUp)
        resolve(serving[1])
      }
    })
    // Watched from the moment it starts, to its end: one that ends after it said its port while the
    // other is still starting is told of once both are, and one that ends while the tests run ends
    // them, which would otherwise fail one by one on a connection nothing answers.
    child.once('exit', (code) => {
      clearTimeout(gaveUp)
      gone.push(`${script} ended with ${code ?? 'a signal'}`)
      reject(new Error(`${script} ended with ${code ?? 'a signal'} before it served`))
      if (running(tests)) {
        console.error(`a bundle's server ended with ${code ?? 'a signal'} while the tests ran`)
        process.exitCode = 1
        tests.kill('SIGTERM')
      }
    })
  })

run('vite', ['build'], { KR_COMPANION_HARNESS: '1' })
run('vite', ['build'], { KR_COMPANION_HARNESS: '0' })
process.on('exit', () => {
  for (const child of servers) child.kill('SIGTERM')
})
// A signal to this script ends the tests too, and the run waits for them to shut down: the tests
// would otherwise go on through the suite with their servers gone.
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    process.exitCode = 1
    if (running(tests)) tests.kill('SIGTERM')
    else process.exit(1)
  })
}
let harness
let desktop
try {
  ;[harness, desktop] = await Promise.all([serve('preview-harness.mjs'), serve('preview-desktop.mjs')])
} catch (error) {
  console.error(error instanceof Error ? error.message : error)
  process.exit(1)
}
if (gone.length > 0) {
  console.error(`a bundle's server ended while the other started: ${gone.join(', ')}`)
  process.exit(1)
}
tests = spawn(process.execPath, [toolPath('@playwright/test'), 'test', ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: { ...process.env, KR_E2E_HARNESS_PORT: harness, KR_E2E_DESKTOP_PORT: desktop }
})
const ended = await new Promise((resolve) => tests.once('exit', (code, signal) => resolve({ code, signal })))
process.exit(process.exitCode || ended.code || (ended.signal ? 1 : 0))
