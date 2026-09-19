#!/usr/bin/env node
// Builds the harness bundle and drives it with Playwright. The bundle is built first so the tests
// run against the same output the desktop shell loads rather than against a development server,
// and it is built into its own directory so a test run never replaces the production bundle.
import { spawnSync } from 'node:child_process'

import { toolPath } from './tools.mjs'

const run = (tool, args) => {
  const result = spawnSync(process.execPath, [toolPath(tool), ...args], {
    stdio: 'inherit',
    env: { ...process.env, KR_COMPANION_HARNESS: '1' }
  })
  if (result.error) {
    console.error(result.error.message)
    process.exit(1)
  }
  if (result.status !== 0) process.exit(result.status ?? 1)
}

run('vite', ['build'])
run('@playwright/test', ['test', ...process.argv.slice(2)])
