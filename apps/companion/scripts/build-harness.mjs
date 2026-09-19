#!/usr/bin/env node
// Builds the test harness into its own directory. The environment is set here because a script
// line that sets one is a Unix shell's syntax.
import { spawnSync } from 'node:child_process'

const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm'
const result = spawnSync(pnpm, ['exec', 'vite', 'build'], {
  stdio: 'inherit',
  env: { ...process.env, KR_COMPANION_HARNESS: '1' }
})
process.exit(result.status ?? 1)
