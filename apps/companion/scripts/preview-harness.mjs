#!/usr/bin/env node
// Serves the harness bundle for the end-to-end run, on every platform, on the port named by the
// first argument or on 4188.
import { spawnSync } from 'node:child_process'

import { toolPath } from './tools.mjs'

const port = process.argv[2] ?? '4188'
const result = spawnSync(
  process.execPath,
  [toolPath('vite'), 'preview', '--outDir', 'dist-harness', '--port', port, '--strictPort'],
  { stdio: 'inherit' }
)
if (result.error) {
  console.error(result.error.message)
  process.exit(1)
}
process.exit(result.status ?? 0)
