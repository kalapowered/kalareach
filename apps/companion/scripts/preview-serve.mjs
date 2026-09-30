// Serves one built bundle with Vite's preview server for a test run, and ends with that run.
//
// The server runs inside this process, so there is one process to end and nothing it started can
// outlive it. It ends in three ways: when it is told to stop, when it fails, and when the run that
// started it has gone. The last is the one a killed run needs. A run that is killed runs no
// cleanup, and Playwright's own end-of-run cleanup is part of it, so a server that only waited to
// be told to stop would go on serving for as long as the machine stayed up. `owner` is the
// process identifier of that run; the server looks for it twice a second and ends once it is gone.
// That is a look at an identifier and not at one process: if the system gives the identifier to
// another process, the server goes on until that process ends too. Nothing is ever signalled
// through it.
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { clearInterval, setInterval, setTimeout } from 'node:timers'

import { preview } from 'vite'

/** How often the run that owns the server is looked for. */
const OWNER_LOOK_MS = 500

/** How long closing the server may take before the process ends anyway. */
const CLOSE_WITHIN_MS = 2_000

/** Whether a process with this identifier is still running. */
const running = (pid) => {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    // A process this one may not signal is still there.
    return error.code === 'EPERM'
  }
}

/**
 * Serves `outDir` on `port` until told to stop, until the process `owner` ends, or until the
 * server fails. The port is taken as given: a port already in use ends the process with a failure
 * rather than serving on another one.
 */
export async function servePreview({ outDir, port, owner }) {
  // The bundle has to be there: Vite's own check for it belongs to its command line and not to the
  // function this calls, and a server with no bundle would answer every request with a 404.
  if (!existsSync(resolve(outDir))) {
    console.error(`the directory ${outDir} does not exist. Did you build the bundle?`)
    process.exit(1)
  }
  // The run is named before the server starts: one that has gone already leaves nothing to serve.
  let pid
  if (owner !== undefined) {
    pid = Number(owner)
    if (!Number.isInteger(pid) || pid <= 0) {
      console.error(`the run to serve for is named by a process identifier, not ${owner}`)
      process.exit(1)
    }
    if (!running(pid)) process.exit(0)
  }
  let server
  try {
    server = await preview({
      build: { outDir },
      preview: { port: Number(port), strictPort: true }
    })
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  }
  server.printUrls()

  let stopping = false
  const stop = async (code) => {
    if (stopping) return
    stopping = true
    const closed = server.close().catch(() => {})
    await Promise.race([closed, new Promise((resolve) => setTimeout(resolve, CLOSE_WITHIN_MS))])
    process.exit(code)
  }
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    process.on(signal, () => void stop(0))
  }
  if (pid !== undefined) {
    const watching = setInterval(() => {
      if (!running(pid)) {
        clearInterval(watching)
        void stop(0)
      }
    }, OWNER_LOOK_MS)
  }
}
