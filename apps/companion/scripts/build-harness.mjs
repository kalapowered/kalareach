#!/usr/bin/env node
// Builds the test harness into its own directory, so a test run never replaces the bundle a
// desktop build carries. The environment is set here because a script line that sets one is a
// Unix shell's syntax and this has to run on Windows too.
import { spawnSync } from 'node:child_process'

import { toolPath } from './tools.mjs'

const result = spawnSync(process.execPath, [toolPath('vite'), 'build'], {
  stdio: 'inherit',
  env: { ...process.env, KR_COMPANION_HARNESS: '1' }
})
if (result.error) {
  console.error(result.error.message)
  process.exit(1)
}
process.exit(result.status ?? 0)
