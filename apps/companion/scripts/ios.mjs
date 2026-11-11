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
// Only the build is run, and `--open` is refused: it hands the work to Xcode.app, which the system
// starts with the person's own temporary directory, so the directory made here would hold a file
// that Xcode never reads.
//
// The directory is removed when this command ends, whether the build succeeded or not. A signal
// that ends the command first leaves it for the system's own cleanup of the temporary directory.
import { spawnSync } from 'node:child_process'
import { startedAs } from './entry-point.mjs'

import { privateTemporary } from './private-temp.mjs'
import { toolPath } from './tools.mjs'

/**
 * Whether an option asks the build to open Xcode. The long option may be written as any prefix of
 * itself, as far as the command line tool allows (`--o` for the only option that starts so). A short
 * option is one of a bundle (`-do`), which the tool reads from left to right: `o` opens, and the
 * first `t`, `f` or `c` takes the rest of the bundle as its value (`-fopus` is a feature, `-otx86`
 * is `-o -t x86`).
 */
function opens(option) {
  if (option.length >= 3 && '--open'.startsWith(option)) return true
  return /^-[^-tfc]*o/.test(option)
}

/** What is wrong with the arguments this was given, or null when it can run them. */
export function refusal(argv) {
  const [command, ...rest] = argv
  if (command !== 'build') {
    return `pnpm ios runs \`tauri ios build\` and nothing else (it was given \`${argv.join(' ')}\`).`
  }
  // What follows a bare `--` is passed on to the build's runner, and is none of this command's.
  const options = rest.includes('--') ? rest.slice(0, rest.indexOf('--')) : rest
  if (options.some(opens)) {
    return (
      `pnpm ios does not run a build that opens Xcode (it was given \`${argv.join(' ')}\`): ` +
      'Xcode.app starts with its own temporary directory, and not with the one made for this build.'
    )
  }
  return null
}

// Run only as the command: the entry point is compared by its real path, which is the one Node
// gives the module, so that a start through a symbolic link still runs.
if (startedAs(import.meta.url)) {
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
