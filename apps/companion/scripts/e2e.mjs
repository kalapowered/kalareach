#!/usr/bin/env node
// Builds the harness bundle and drives it with Playwright. The bundle is built first so the tests
// run against the same output the desktop shell loads rather than a development server.
import { spawnSync } from 'node:child_process'

const run = (command, args) => {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    env: { ...process.env, KR_COMPANION_HARNESS: '1' }
  })
  if (result.status !== 0) process.exit(result.status ?? 1)
}

run('pnpm', ['run', 'build:harness'])
run('pnpm', ['exec', 'playwright', 'test', ...process.argv.slice(2)])
