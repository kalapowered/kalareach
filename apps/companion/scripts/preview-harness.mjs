#!/usr/bin/env node
// Serves the harness bundle for the end-to-end run, on every platform, on the port named by the
// first argument or on 4188, for as long as the process named by the second argument, the run,
// exists.
import { servePreview } from './preview-serve.mjs'

await servePreview({
  outDir: 'dist-harness',
  port: process.argv[2] ?? '4188',
  owner: process.argv[3]
})
