#!/usr/bin/env node
// Holds the preview servers to ending with the run that started them.
//
// The end-to-end run starts two of them and tells each which process the run is. A run that
// finishes ends them, and so does a run that is killed: it runs no cleanup of its own, so the
// servers have to notice it has gone. Each case starts the harness server as the run does, in a
// process group of its own, from a directory holding a bundle of one page, and asks whether the
// server is gone once its run is.
//
//   node scripts/preview-selftest.mjs
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { get } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { clearTimeout, setTimeout } from 'node:timers'
import { URL, fileURLToPath } from 'node:url'

import { EPHEMERAL_STARTS, SERVING_LINE, startPreview } from './preview-serve.mjs'

const entry = fileURLToPath(new URL('./preview-harness.mjs', import.meta.url))

/** How long a server is given to start before the case is called failed. */
const START_WITHIN_MS = 60_000

/** How long a server is given to end once its run has, which is a few looks at the run. */
const END_WITHIN_MS = 15_000

/** How many looks at its run a server is given before the control case expects it still there. */
const CONTROL_MS = 2_500

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Whether the page the bundle holds is served on `port` now. */
const answers = (port) =>
  new Promise((resolve) => {
    const request = get({ host: 'localhost', port, path: '/', timeout: 1_000 }, (response) => {
      response.resume()
      resolve(response.statusCode === 200)
    })
    request.once('timeout', () => {
      request.destroy()
      resolve(false)
    })
    request.once('error', () => resolve(false))
  })

/** Waits until `condition` holds, and says whether it did within `within` milliseconds. */
const until = async (condition, within) => {
  const started = Date.now()
  while (!(await condition())) {
    if (Date.now() - started > within) return false
    await sleep(50)
  }
  return true
}

const directory = mkdtempSync(join(tmpdir(), 'kr-preview-'))
mkdirSync(join(directory, 'dist-harness'))
writeFileSync(join(directory, 'dist-harness', 'index.html'), '<!doctype html><title>bundle</title>')

/** Everything a case started, ended whatever became of the case. */
const started = []
const endAll = () => {
  for (const child of started) {
    // A child this process has collected has no identifier of its own any more, and what is left
    // of its group is not signalled by an identifier nothing holds.
    if (child.exitCode !== null || child.signalCode !== null) continue
    for (const target of [-child.pid, child.pid]) {
      try {
        process.kill(target, 'SIGKILL')
      } catch {
        // Already gone.
      }
    }
  }
  rmSync(directory, { recursive: true, force: true })
}
process.on('exit', endAll)

/**
 * A stand-in for the run: it does nothing until it is ended, and it ends by itself when this
 * process has gone, so a self-test that is killed leaves neither it nor a server that watches it.
 */
const STAND_IN = `
  const parent = ${process.pid}
  setInterval(() => {
    try { process.kill(parent, 0) } catch { process.exit(0) }
  }, 500)
`
const run = () => {
  const child = spawn(process.execPath, ['-e', STAND_IN], { stdio: 'ignore' })
  started.push(child)
  return child
}

/** The server, started as the end-to-end run starts it, for `owner`, on the port it chose. */
const server = async (owner) => {
  const child = spawn(process.execPath, [entry, '0', String(owner.pid)], {
    cwd: directory,
    detached: true,
    stdio: ['ignore', 'pipe', 'ignore']
  })
  const ended = new Promise((resolve) => child.once('exit', resolve))
  started.push(child)
  const port = await new Promise((resolve, reject) => {
    const gaveUp = setTimeout(() => reject(new Error('the server did not say its port')), START_WITHIN_MS)
    let said = ''
    child.stdout.on('data', (chunk) => {
      said += chunk
      const serving = SERVING_LINE.exec(said)
      if (serving) {
        clearTimeout(gaveUp)
        resolve(Number(serving[1]))
      }
    })
    child.once('exit', () => {
      clearTimeout(gaveUp)
      reject(new Error('the server ended before it served'))
    })
  })
  if (!(await until(() => answers(port), START_WITHIN_MS))) throw new Error('the server did not start serving')
  return { child, port, ended }
}

/** Says whether the server is gone: its process has ended and its port answers no more. */
const gone = async ({ child, port }) => {
  const ended = await until(
    async () => child.exitCode !== null || child.signalCode !== null,
    END_WITHIN_MS
  )
  return ended && (await until(async () => !(await answers(port)), END_WITHIN_MS))
}

const failures = []
const check = async (name, body) => {
  try {
    await body()
    console.log(`ok   ${name}`)
  } catch (error) {
    failures.push(name)
    console.log(`FAIL ${name}: ${error instanceof Error ? error.message : error}`)
  }
}

await check('a server ends when its run is killed', async () => {
  const owner = run()
  const serving = await server(owner)
  owner.kill('SIGKILL')
  if (!(await gone(serving))) throw new Error('the server outlived the run that was killed')
})

await check('a server ends when it is told to stop', async () => {
  const owner = run()
  const serving = await server(owner)
  serving.child.kill('SIGTERM')
  if (!(await gone(serving))) throw new Error('the server went on serving after it was told to stop')
  owner.kill('SIGKILL')
})

await check('a server keeps serving while its run is there', async () => {
  const owner = run()
  const serving = await server(owner)
  await sleep(CONTROL_MS)
  if (serving.child.exitCode !== null || serving.child.signalCode !== null) {
    throw new Error('the server ended with its run there')
  }
  if (!(await until(() => answers(serving.port), START_WITHIN_MS))) {
    throw new Error('the server stopped serving with its run there')
  }
  owner.kill('SIGKILL')
  if (!(await gone(serving))) throw new Error('the server outlived its run')
})

/** A stand-in for Vite's `preview` that fails as it is told to, and says how often it was asked. */
const standIn = (failures) => {
  const asked = { count: 0 }
  const start = async () => {
    asked.count += 1
    if (asked.count <= failures.length) throw failures[asked.count - 1]
    return { started: asked.count }
  }
  return { asked, start }
}
const taken = (port) => new Error(`Port ${port} is already in use`)

await check('a server asked for port 0 asks again when the port it was given is taken', async () => {
  const { asked, start } = standIn([taken(50001), taken(50002), taken(50003)])
  const server = await startPreview({ outDir: 'dist', port: '0', start })
  if (asked.count !== 4 || server.started !== 4) throw new Error(`it was started ${asked.count} times`)
})

await check('a server asked for port 0 stops asking when the bound is spent', async () => {
  const { asked, start } = standIn(Array.from({ length: 100 }, () => taken(50001)))
  const failed = await startPreview({ outDir: 'dist', port: '0', start }).then(() => false, () => true)
  if (!failed) throw new Error('a start that never worked was reported as started')
  if (asked.count !== EPHEMERAL_STARTS) throw new Error(`it was started ${asked.count} times`)
})

await check('a start that fails for another reason, or on a named port, is not asked again', async () => {
  for (const [port, failure] of [
    ['0', new Error('listen EACCES: permission denied')],
    ['4188', taken(4188)]
  ]) {
    const { asked, start } = standIn([failure, failure])
    const failed = await startPreview({ outDir: 'dist', port, start }).then(() => false, () => true)
    if (!failed || asked.count !== 1) throw new Error(`port ${port} was started ${asked.count} times`)
  }
})

process.exit(failures.length === 0 ? 0 : 1)
