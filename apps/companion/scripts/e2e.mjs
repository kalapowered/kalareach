#!/usr/bin/env node
// Builds the harness bundle and drives it with Playwright. The bundle is built first so the tests
// run against the same output the desktop shell loads rather than against a development server,
// and it is built into its own directory so a test run never replaces the production bundle.
//
// The environment is set here rather than in the script line, because a script line that sets one
// is a Unix shell's syntax and this has to run on Windows too.
import { spawnSync } from 'node:child_process'

const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm'

const run = (args) => {
  const result = spawnSync(pnpm, args, {
    stdio: 'inherit',
    env: { ...process.env, KR_COMPANION_HARNESS: '1' }
  })
  if (result.status !== 0) process.exit(result.status ?? 1)
}

run(['exec', 'vite', 'build'])
run(['exec', 'playwright', 'test', ...process.argv.slice(2)])
