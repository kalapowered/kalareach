#!/usr/bin/env node
// Runs the command line tool's iOS commands (`pnpm ios build ...`) in a temporary directory of
// their own.
//
// The command line tool starts a small server for the build's options, and the script phase of the
// Xcode build (`tauri ios xcode-script`) reads the options back from it. It finds the server through
// a file in the temporary directory, named for the application's identifier, which every build of
// this application on one machine shares: the last build to start owns it, and a step of an earlier
// build then reads the later build's options. Xcode gives its script phase the temporary directory
// it was started with, so a build started in a directory of its own has a file of its own (see
// `private-temp.mjs`).
//
// The directory is removed when this command ends, whether the build succeeded or not. A signal
// that ends the command first leaves it for the system's own cleanup of the temporary directory.
import { spawnSync } from 'node:child_process'

import { privateTemporary } from './private-temp.mjs'
import { toolPath } from './tools.mjs'

const temporary = privateTemporary()
process.on('exit', temporary.remove)

const result = spawnSync(process.execPath, [toolPath('@tauri-apps/cli'), 'ios', ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: temporary.env
})
if (result.error) {
  console.error(result.error.message)
  process.exit(1)
}
process.exit(result.status ?? 1)
