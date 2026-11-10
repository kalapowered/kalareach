// A temporary directory of one run's own, for a build that must not share one with another.
//
// The command line tool that builds a mobile application starts a small server for the build's
// options, and the Gradle and Xcode steps it runs read the options back from it. It tells them where
// the server is through a file in the temporary directory, named for the application's identifier
// (`<temporary directory>/to.kala.reach-server-addr`). Every build of this application on one
// machine therefore shares that file, and the last build to start owns it: a step of an earlier build
// then reads the later build's options and environment, builds into the later build's target
// directory with the later build's profile, and fails when the later build ends. Two builds at once
// cross like that on a machine with several people's work on it.
//
// A build given a temporary directory of its own, which its steps inherit, has a file of its own.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * Makes a temporary directory for one run and answers it, the environment that points a child
 * process at it (`TMPDIR` for Unix, `TEMP` and `TMP` for Windows), and the function that removes it.
 */
export function privateTemporary(env = process.env) {
  const directory = mkdtempSync(join(tmpdir(), 'kr-mobile-build-'))
  return {
    directory,
    env: { ...env, TMPDIR: directory, TEMP: directory, TMP: directory },
    // A directory that cannot be removed is left for the system's cleanup, and does not change how
    // the build ended.
    remove: () => {
      try {
        rmSync(directory, { recursive: true, force: true })
      } catch {
        // Nothing to do: the directory holds what the build's tools cached, and its options file.
      }
    }
  }
}
