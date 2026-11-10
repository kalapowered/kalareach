#!/usr/bin/env node
// Runs the command line tool's iOS build (`pnpm ios build ...`) in a temporary directory of its own.
//
// The command line tool starts a small server for the build's options, and the script phase of the
// Xcode build (`tauri ios xcode-script`) reads the options back from it. It finds the server through
// a file in the temporary directory, named for the application's identifier, which every build of
// this application on one machine shares: the last build to start owns it, and a step of an earlier
// build then reads the later build's options. Xcode gives its script phase the temporary directory
// it was started with, so a build started in a directory of its own has a file of its own (see
// `private-temp.mjs`).
//
// Only the build is run. A command that hands the work to Xcode.app (`dev`, `open`, `--open`) starts
// it through the system, with the person's own temporary directory, and the directory made here
// would hold a file that Xcode never reads.
//
// The directory is removed when this command ends, whether the build succeeded or not. A signal
// that ends the command first leaves it for the system's own cleanup of the temporary directory.
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

import { privateTemporary } from './private-temp.mjs'
import { toolPath } from './tools.mjs'

/** What is wrong with the arguments this was given, or null when it can run them. */
export function refusal(argv) {
  const [command, ...options] = argv
  if (command !== 'build' || options.some((option) => option === '--open' || /^-[a-z]*o[a-z]*$/.test(option))) {
    return (
      `pnpm ios runs \`tauri ios build\` and nothing that opens Xcode (it was given \`${argv.join(' ')}\`): ` +
      'Xcode.app starts with its own temporary directory, and not with the one made for this build.'
    )
  }
  return null
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const argv = process.argv.slice(2)
  const problem = refusal(argv)
  if (problem !== null) {
    console.error(problem)
    process.exit(2)
  }
  const temporary = privateTemporary()
  process.on('exit', temporary.remove)
  const result = spawnSync(process.execPath, [toolPath('@tauri-apps/cli'), 'ios', ...argv], {
    stdio: 'inherit',
    env: temporary.env
  })
  if (result.error) {
    console.error(result.error.message)
    process.exit(1)
  }
  process.exit(result.status ?? 1)
}
