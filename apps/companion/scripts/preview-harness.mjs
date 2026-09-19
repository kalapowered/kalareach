#!/usr/bin/env node
// Serves the harness bundle for the end-to-end run, on every platform.
import { spawnSync } from 'node:child_process'

import { toolPath } from './tools.mjs'

const result = spawnSync(
  process.execPath,
  [toolPath('vite'), 'preview', '--outDir', 'dist-harness', '--port', '4188', '--strictPort'],
  { stdio: 'inherit' }
)
if (result.error) {
  console.error(result.error.message)
  process.exit(1)
}
process.exit(result.status ?? 0)
