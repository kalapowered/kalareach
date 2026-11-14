/**
 * Where the browser tests keep what they produce, and the one reader of `KR_TEST_ARTIFACTS_DIR`
 * for TypeScript.
 *
 * Section 27 puts every test artefact in one platform-resolved directory, set under a temporary
 * folder for the build, and the landing workflow uploads that directory as the run's evidence. A
 * screenshot written anywhere else is lost with the runner, so every screenshot in these tests
 * takes its path from here. A value outside this platform's temporary roots is refused where it is
 * used, so a build that gives the variable a wrong value fails at the first screenshot whatever
 * way the value took.
 *
 * The temporary roots are `/tmp` (Unix), the folder `os.tmpdir()` names and the folder
 * `RUNNER_TEMP` names, where each is an absolute path to a directory. A root is resolved through
 * its links as the platform resolves it (`/tmp` is `/private/tmp` on macOS), and so is the part of
 * the value that exists, so a link inside a root that leads out of it is refused and a root that
 * is itself behind a link is honoured. A value is compared with a root by path components, never
 * by text: `/tmpfoo` is not inside `/tmp`. A relative value, an empty value and a value with a
 * `..` in it are refused, and so is a root itself.
 *
 * Where the variable is not set, the first read makes a directory of its own under the temporary
 * folder, says where it is and sets the variable to it, so the workers the run starts read the
 * same directory.
 *
 * Declared against `node:process` for the same reason `served.ts` is: the browser tests are
 * type-checked with the interface's own settings, which carry no Node types.
 */

import { existsSync, mkdtempSync, realpathSync } from 'node:fs'
import { platform, tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, sep } from 'node:path'
import { env } from 'node:process'

/** The variable that names where a run keeps its evidence. */
const VARIABLE = 'KR_TEST_ARTIFACTS_DIR'

const windows = platform() === 'win32'

/**
 * Whether `path` names one place whatever the current drive and directory are: `/…` off Windows;
 * on Windows `C:\…`, a UNC path (`\\server\share\…`) or an extended-length path (`\\?\C:\…`). A path
 * that depends on the current drive (`\folder`) or on a drive's current directory (`C:folder`) is
 * rooted or has a drive, but is not fully qualified, and Node's `isAbsolute` accepts the first.
 */
export function fullyQualified(path: string, onWindows: boolean = windows): boolean {
  return onWindows ? /^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/])/.test(path) : path.startsWith('/')
}

/** `path` with every link in it resolved: the part that exists by the system, the rest as written. */
function resolveThrough(path: string): string {
  let probe = path
  const rest: string[] = []
  while (!existsSync(probe)) {
    const parent = dirname(probe)
    if (parent === probe) break
    rest.unshift(basename(probe))
    probe = parent
  }
  return join(realpathSync.native(probe), ...rest)
}

/**
 * Each of `named` that is a fully qualified path (by the rules of `onWindows`) to a folder that
 * exists, resolved through its links, as a root. A filesystem root is not one.
 */
export function temporaryRoots(named: readonly string[], onWindows: boolean = windows): string[] {
  const found: string[] = []
  for (const candidate of named) {
    if (candidate === '' || !fullyQualified(candidate, onWindows) || !existsSync(candidate)) continue
    const real = realpathSync.native(candidate)
    // A temporary folder that is a filesystem root (`/`, `C:\`) would admit every path on its disk.
    if (dirname(real) === real) continue
    if (!found.includes(real)) found.push(real)
  }
  return found
}

/** This platform's temporary roots: its temporary folder, `/tmp` off Windows, and the runner's. */
function roots(): string[] {
  return temporaryRoots([tmpdir(), ...(windows ? [] : ['/tmp']), env['RUNNER_TEMP'] ?? ''])
}

function refused(value: string, why: string): Error {
  return new Error(
    `the evidence directory '${value}' (${VARIABLE}) is refused: ${why}. It has to be an absolute ` +
      `path inside one of this platform's temporary roots (${roots().join(', ')}). Set it to a ` +
      'folder under one of them, or leave it unset and the run makes a directory of its own.'
  )
}

/** Whether `real` is a folder inside `root`, by path components. */
function inside(real: string, root: string): boolean {
  const from = windows ? root.toLowerCase() : root
  const to = windows ? real.toLowerCase() : real
  const path = relative(from, to)
  return path !== '' && path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path)
}

/**
 * The real path of `value`, which has to be inside one of this platform's temporary roots.
 *
 * @throws When the value is empty, relative, steps up with `..` or is not inside a root.
 */
export function confine(value: string): string {
  if (value === '') throw refused(value, 'it is empty')
  if (!fullyQualified(value)) throw refused(value, 'it is not an absolute path')
  if (value.split(/[\\/]/).includes('..')) {
    throw refused(value, 'it steps up a directory with `..`')
  }
  const real = resolveThrough(value)
  if (!roots().some((root) => inside(real, root))) {
    throw refused(value, 'it is not inside a temporary root')
  }
  return real
}

/** The directory this run keeps its artefacts in. */
export function artefactsDirectory(): string {
  const named = env[VARIABLE]
  if (named !== undefined) return confine(named)
  const own = confine(mkdtempSync(join(tmpdir(), 'kr-test-artifacts-')))
  // The variable now names it, for this process's later reads and for the workers it starts.
  env[VARIABLE] = own
  console.error(`${VARIABLE} is not set: this run keeps its evidence in ${own}`)
  return own
}

/** The path of the screenshot called `name`, without its extension. */
export function screenshotPath(name: string): string {
  return `${artefactsDirectory()}/companion-screenshots/${name}.png`
}
