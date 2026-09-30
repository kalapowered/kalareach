#!/usr/bin/env node
// Serves the bundle the desktop window loads, so a test can open the same files the shell embeds,
// on the port named by the first argument or on 4189, for as long as the process named by the
// second argument, the run, exists.
import { servePreview } from './preview-serve.mjs'

await servePreview({
  outDir: 'dist',
  port: process.argv[2] ?? '4189',
  owner: process.argv[3]
})
