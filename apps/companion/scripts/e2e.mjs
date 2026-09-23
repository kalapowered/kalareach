#!/usr/bin/env node
// Builds both bundles and drives them with Playwright. The bundles are built first so the tests
// run against real output rather than a development server: the harness bundle, which substitutes
// a scripted host, and the bundle the desktop window loads, which one test opens to prove the
// shipped entry mounts. The harness goes to its own directory, so the entry with the fake host in
// it can never end up where the desktop shell looks. Each build states which one it is rather than
// inheriting the answer, because a run started from a shell that already set the flag would
// otherwise build the harness twice and leave yesterday's bundle where the shell reads.
//
// The tests serve both bundles themselves, on two ports the system reports nothing is listening
// on, so a second run on the same machine is never the server this one tests.
import { spawnSync } from 'node:child_process'
import { connect, createServer } from 'node:net'

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

// A port the system hands out for a new listener.
const unusedPort = () =>
  new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })

// Whether anything accepts a connection on `port` of the loopback address `host`. A connection
// that neither opens nor fails in time counts as something there.
const answers = (port, host) =>
  new Promise((resolve) => {
    const socket = connect({ port, host })
    socket.setTimeout(2_000, () => {
      socket.destroy()
      resolve(true)
    })
    socket.once('connect', () => {
      socket.destroy()
      resolve(true)
    })
    socket.once('error', () => resolve(false))
  })

// Ports nothing answers on over either loopback address. The system's own answer is not enough:
// on macOS a port another program listens on at one loopback address can still be handed out.
const freePorts = async (count) => {
  const ports = []
  for (let attempt = 0; ports.length < count && attempt < 50; attempt += 1) {
    const port = await unusedPort()
    if (ports.includes(port)) continue
    if ((await answers(port, '127.0.0.1')) || (await answers(port, '::1'))) continue
    ports.push(port)
  }
  if (ports.length < count) throw new Error(`found ${ports.length} of ${count} free ports`)
  return ports.map(String)
}

run('vite', ['build'], { KR_COMPANION_HARNESS: '1' })
run('vite', ['build'], { KR_COMPANION_HARNESS: '0' })
const [harness, desktop] = await freePorts(2)
run('@playwright/test', ['test', ...process.argv.slice(2)], {
  KR_E2E_HARNESS_PORT: harness,
  KR_E2E_DESKTOP_PORT: desktop
})
