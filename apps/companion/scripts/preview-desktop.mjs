#!/usr/bin/env node
// Serves the bundle the desktop window loads, so a test can open the same files the shell embeds.
import { spawnSync } from 'node:child_process'

import { toolPath } from './tools.mjs'

const result = spawnSync(
  process.execPath,
  [toolPath('vite'), 'preview', '--outDir', 'dist', '--port', '4189', '--strictPort'],
  { stdio: 'inherit' }
)
if (result.error) {
  console.error(result.error.message)
  process.exit(1)
}
process.exit(result.status ?? 0)
