#!/usr/bin/env node
// Builds both bundles and drives them with Playwright. The bundles are built first so the tests
// run against real output rather than a development server: the harness bundle, which substitutes
// a scripted host, and the bundle the desktop window loads, which one test opens to prove the
// shipped entry mounts. The harness is built into its own directory, so a test run and a release
// build never overwrite each other.
import { spawnSync } from 'node:child_process'

import { toolPath } from './tools.mjs'

const run = (tool, args, extraEnv = {}) => {
  const result = spawnSync(process.execPath, [toolPath(tool), ...args], {
    stdio: 'inherit',
    env: { ...process.env, ...extraEnv }
  })
  if (result.error) {
    console.error(result.error.message)
    process.exit(1)
  }
  if (result.status !== 0) process.exit(result.status ?? 1)
}

run('vite', ['build'], { KR_COMPANION_HARNESS: '1' })
run('vite', ['build'])
run('@playwright/test', ['test', ...process.argv.slice(2)])
