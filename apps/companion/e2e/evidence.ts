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
 * On Windows a value, and each temporary variable, is read as Windows writes a full path:
 * `C:\folder` or `C:/folder`, `\\server\share\folder` or `//server/share/folder`, either of those
 * behind `\\?\` with backslashes only. Any other spelling is refused, in words that say which are
 * taken: a device path, a server with no share, three separators at the start, a path that depends
 * on the current drive and one that depends on a drive's current directory.
 *
 * Where the variable is not set, the first read makes a directory of its own under the temporary
 * folder, says where it is and sets the variable to it, so the workers the run starts read the
 * same directory.
 *
 * The reader guards a test run against a mistake: for any value of the evidence variable, and any
 * temporary variable as a platform, a runner, one of our scripts or a developer's shell sets it,
 * with folders and links as tools make them, it returns a folder inside the roots or refuses, and
 * it refuses nothing that the run set right. It is no boundary against a process of the same
 * account, which can write wherever the run can and can change a link or a folder while the reader
 * reads. On Windows the comparison ignores letter case, so a folder made case-sensitive, and a
 * letter that the disk and the reader do not fold alike, are not told apart.
 *
 * On Windows `os.tmpdir()` takes the temporary folder from `TEMP` first and then `TMP`, and the
 * shell reader takes it from `TEMP`; the Rust reader and the PowerShell reader take `TMP` first.
 * Where `TMP` and `TEMP` differ, only a value under the runner's folder satisfies all four readers.
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

/** The spellings of an absolute path that this reader takes on Windows, for the words of a refusal. */
const TAKES =
  'on Windows this reader takes C:\\folder or C:/folder, \\\\server\\share\\folder or ' +
  '//server/share/folder, and either behind \\\\?\\, as \\\\?\\C:\\folder or ' +
  '\\\\?\\UNC\\server\\share\\folder'

/** How a path is written: whether this reader takes the spelling. */
export type Spelling = 'taken' | 'not-absolute' | 'kind'

/**
 * How `path` is written. Off Windows a path is taken when it begins with `/`. On Windows it is
 * `taken` when it is a drive with a root (`C:\x`, `C:/x`) or a share with a server and a name
 * (`\\server\share\x`, `//server/share/x`), with either separator or both, or either one behind
 * `\\?\` with backslashes only (Windows reads a slash behind `\\?\` as a letter of a name);
 * `not-absolute` when it is relative, `\folder` (the current drive's root) or `C:folder` (a drive's
 * current directory), which Node's `isAbsolute` accepts the first of; and `kind` for any other
 * spelling: a device path (`\\.\`, or `\\?\` with anything but a drive or a share behind it), a
 * server with no share, three separators at the start.
 */
export function spellingOf(path: string, onWindows: boolean = windows): Spelling {
  if (!onWindows) return path.startsWith('/') ? 'taken' : 'not-absolute'
  let rest = path
  if (path.startsWith('\\\\?\\')) {
    const behind = path.slice(4)
    if (behind.includes('/')) return 'kind'
    if (/^unc\\./i.test(behind)) rest = `\\\\${behind.slice(4)}`
    else if (/^[A-Za-z]:\\/.test(behind)) rest = behind
    else return 'kind'
  }
  if (/^[\\/]{2}[.?](?:[\\/]|$)/.test(rest) || /^[\\/]{3}/.test(rest)) return 'kind'
  if (/^[\\/]{2}/.test(rest)) return /^[\\/]{2}[^\\/]+[\\/][^\\/]+/.test(rest) ? 'taken' : 'kind'
  return /^[A-Za-z]:[\\/]/.test(rest) ? 'taken' : 'not-absolute'
}

/** Whether `path` names one place whatever the current drive and directory are. */
export function fullyQualified(path: string, onWindows: boolean = windows): boolean {
  return spellingOf(path, onWindows) === 'taken'
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

/** The roots as the refusal's words list them: never an empty list. */
export function listed(found: readonly string[]): string {
  return found.length === 0
    ? 'none: no folder that a temporary variable names exists'
    : found.join(', ')
}

function refused(value: string, why: string): Error {
  return new Error(
    `the evidence directory '${value}' (${VARIABLE}) is refused: ${why}. It has to be an absolute ` +
      `path inside one of this platform's temporary roots (${listed(roots())}). Set it to a ` +
      'folder under one of them, or leave it unset and the run makes a directory of its own.'
  )
}

/**
 * Why the run's own directory cannot be made under `temporary`: nothing was set, so the words name
 * the temporary folder and do not tell the caller to leave the variable unset.
 */
function refusedOwn(temporary: string, why: string): Error {
  return new Error(
    `no directory of this run's own can be made for its evidence: the temporary folder ` +
      `'${temporary}' is refused: ${why}. It has to be an absolute path to a folder inside one of ` +
      `this platform's temporary roots (${listed(roots())}). Point TMPDIR (on Windows, TEMP) ` +
      `at such a folder, or set ${VARIABLE} to a folder under one of the roots.`
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
  return confineOr(value, (why) => refused(value, why))
}

/** As `confine`, with `refuse` making the error for the reason a value is refused. */
function confineOr(value: string, refuse: (why: string) => Error): string {
  if (value === '') throw refuse('it is empty')
  const spelling = spellingOf(value)
  if (spelling === 'not-absolute') {
    throw refuse(`it is not an absolute path${windows ? ` (${TAKES})` : ''}`)
  }
  if (spelling === 'kind') {
    throw refuse(`it is a Windows path of a kind this reader does not take (${TAKES})`)
  }
  if (value.split(/[\\/]/).includes('..')) {
    throw refuse('it steps up a directory with `..`')
  }
  const real = resolveThrough(value)
  if (!roots().some((root) => inside(real, root))) {
    throw refuse('it is not inside a temporary root')
  }
  return real
}

/**
 * A directory of this run's own under `temporary`, which has to be inside a root. The folder is
 * checked before the directory is made in it, so that a temporary folder that is no root is left
 * as it was.
 */
export function ownDirectory(temporary: string): string {
  const prefix = 'kr-test-artifacts-'
  const refuse = (why: string): Error => refusedOwn(temporary, why)
  confineOr(join(temporary, `${prefix}XXXXXX`), refuse)
  return confineOr(mkdtempSync(join(temporary, prefix)), refuse)
}

/** The directory this run keeps its artefacts in. */
export function artefactsDirectory(): string {
  const named = env[VARIABLE]
  if (named !== undefined) return confine(named)
  const own = ownDirectory(tmpdir())
  // The variable now names it, for this process's later reads and for the workers it starts.
  env[VARIABLE] = own
  console.error(`${VARIABLE} is not set: this run keeps its evidence in ${own}`)
  return own
}

/** The path of the screenshot called `name`, without its extension. */
export function screenshotPath(name: string): string {
  return `${artefactsDirectory()}/companion-screenshots/${name}.png`
}
