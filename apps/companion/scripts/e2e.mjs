#!/usr/bin/env node
// Builds both bundles and drives them with Playwright. The bundles are built first so the tests
// run against real output rather than a development server: the harness bundle, which substitutes
// a scripted host, and the bundle the desktop window loads, which one test opens to prove the
// shipped entry mounts. The harness goes to its own directory, so the entry with the fake host in
// it can never end up where the desktop shell looks. Each build states which one it is rather than
// inheriting the answer, because a run started from a shell that already set the flag would
// otherwise build the harness twice and leave yesterday's bundle where the shell reads.
import { spawnSync } from 'node:child_process'

import { toolPath } from './tools.mjs'

const run = (tool, args, harness = null) => {
  const result = spawnSync(process.execPath, [toolPath(tool), ...args], {
    stdio: 'inherit',
    env: harness === null ? process.env : { ...process.env, KR_COMPANION_HARNESS: harness }
  })
  if (result.error) {
    console.error(result.error.message)
    process.exit(1)
  }
  if (result.status !== 0) process.exit(result.status ?? 1)
}

run('vite', ['build'], '1')
run('vite', ['build'], '0')
run('@playwright/test', ['test', ...process.argv.slice(2)])
