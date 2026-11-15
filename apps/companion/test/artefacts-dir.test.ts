// KR-REQ-27.03: the reader of `KR_TEST_ARTIFACTS_DIR` for TypeScript refuses a value outside this
// platform's temporary roots where the value is used. Each case sets the variable in the
// environment the way a build does and reads the directory through the reader's own entry point.

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync
} from 'node:fs'
import { platform, tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { chdir, cwd } from 'node:process'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  artefactsDirectory,
  fullyQualified,
  listed,
  spellingOf,
  temporaryRoots
} from '../e2e/evidence'

const VARIABLE = 'KR_TEST_ARTIFACTS_DIR'

const windows = platform() === 'win32'
const elsewhere = windows ? 'C:\\Windows\\kr-evidence' : '/etc/kr-evidence'
const made: string[] = []

/** The words of every reader's refusal of a backslash off Windows. */
const BACKSLASH = "a backslash is not taken in the folder's path on this platform"

function folder(parent: string): string {
  const path = mkdtempSync(join(parent, 'artefacts-reader-'))
  made.push(path)
  return path
}

function read(value: string): string {
  vi.stubEnv(VARIABLE, value)
  return artefactsDirectory()
}

afterEach(() => {
  vi.unstubAllEnvs()
  for (const path of made.splice(0)) rmSync(path, { recursive: true, force: true })
})

describe('the evidence directory reader', () => {
  it('refuses a value outside the temporary roots in words that name the variable and the roots', () => {
    expect(() => read(elsewhere)).toThrow(/KR_TEST_ARTIFACTS_DIR.*temporary roots/s)
    expect(existsSync(elsewhere)).toBe(false)
  })

  it('accepts a value inside a root, resolved, whether or not it exists yet', () => {
    const parent = folder(tmpdir())
    expect(read(join(parent, 'evidence', 'screenshots'))).toBe(
      join(realpathSync.native(parent), 'evidence', 'screenshots')
    )
    expect(existsSync(join(parent, 'evidence'))).toBe(false)
  })

  it('makes a directory of its own that exists where the variable is not set', () => {
    vi.stubEnv(VARIABLE, undefined)
    const own = artefactsDirectory()
    made.push(own)
    expect(existsSync(own)).toBe(true)
    // The variable names it now, so a worker the run starts reads the same directory.
    expect(artefactsDirectory()).toBe(own)
  })

  it.each([
    // `/tmp` is a root off Windows, whatever the temporary folder is, so a folder beside the
    // temporary folder can lie inside it.
    [
      'a name that only begins like a root',
      windows ? `${realpathSync.native(tmpdir())}foo\\evidence` : '/tmpfoo/evidence',
      'not inside a temporary root'
    ],
    ['a relative value', 'evidence', 'not an absolute path'],
    ['a relative value with a dot', './evidence', 'not an absolute path'],
    ['an empty value', '', 'it is empty'],
    // Written out, because `join` would remove the step up before the reader saw it.
    ['a step up that ends inside a root', `${tmpdir()}/evidence/../evidence`, 'steps up a directory'],
    ['the root itself', windows ? realpathSync.native(tmpdir()) : '/tmp', 'not inside a temporary root']
  ])('refuses %s', (_name, value, why) => {
    expect(() => read(value)).toThrow(/KR_TEST_ARTIFACTS_DIR.*temporary roots/s)
    expect(() => read(value)).toThrow(why)
  })

  it('takes a relative runner folder for no root, though it exists under the working directory', () => {
    vi.stubEnv('RUNNER_TEMP', 'src')
    expect(() => read(join(cwd(), 'src', 'evidence'))).toThrow('not inside a temporary root')
  })

  it('refuses a relative value that names a folder under the working directory', () => {
    const parent = folder(tmpdir())
    mkdirSync(join(parent, 'sub'), { recursive: true })
    const before = cwd()
    chdir(parent)
    try {
      expect(() => read('sub')).toThrow('not an absolute path')
    } finally {
      chdir(before)
    }
  })

  it.skipIf(windows)('refuses a link inside a root that leads out of it', () => {
    const parent = folder(tmpdir())
    symlinkSync('/etc', join(parent, 'escape'))
    expect(() => read(join(parent, 'escape', 'kr-evidence'))).toThrow(/temporary roots/)
    expect(existsSync('/etc/kr-evidence')).toBe(false)
  })

  it.skipIf(windows)('refuses a value that holds a backslash, before any other read of it', () => {
    const parent = folder(tmpdir())
    const root = realpathSync.native(parent)
    symlinkSync('/etc', join(root, 'out'))
    for (const value of [
      `${root}/a\\..\\..\\kr-letters`,
      `${root}\\a\\..\\..\\kr-letters`,
      `${root}/out\\kr-evidence`,
      `${root}/a\\b`,
      '\\private\\tmp\\kr-evidence'
    ]) {
      expect(() => read(value)).toThrow(BACKSLASH)
      expect(() => read(value)).toThrow(/temporary roots/)
    }
    expect(existsSync('/etc/kr-evidence')).toBe(false)
  })

  it.skipIf(windows)('passes over a temporary variable that holds a backslash as a root', () => {
    // The folder sits outside every platform root, so a root that is passed over admits nothing.
    const parent = folder(cwd())
    const root = realpathSync.native(parent)
    const lettered = join(root, 'a\\b')
    mkdirSync(lettered, { recursive: true })
    mkdirSync(join(root, 'a', 'b'), { recursive: true })
    symlinkSync(lettered, join(root, 'link'))
    vi.stubEnv('TMPDIR', lettered)
    expect(() => read(join(root, 'a', 'b', 'evidence'))).toThrow('not inside a temporary root')
    expect(() => read(join(root, 'link', 'evidence'))).toThrow('not inside a temporary root')
    // The run's own directory is made under the next root.
    vi.stubEnv(VARIABLE, undefined)
    const own = artefactsDirectory()
    made.push(own)
    expect(dirname(own)).toBe(realpathSync.native('/tmp'))
  })

  it.skipIf(windows)('honours a root behind a link and refuses its neighbours', () => {
    // The folder sits outside every platform root, so only the runner's root can admit it.
    const parent = folder(cwd())
    mkdirSync(join(parent, 'target'), { recursive: true })
    mkdirSync(join(parent, 'neighbour'), { recursive: true })
    symlinkSync(join(parent, 'target'), join(parent, 'link'))
    vi.stubEnv('RUNNER_TEMP', join(parent, 'link'))
    const expected = join(realpathSync.native(join(parent, 'target')), 'evidence')
    expect(read(join(parent, 'link', 'evidence'))).toBe(expected)
    expect(read(join(parent, 'target', 'evidence'))).toBe(expected)
    expect(() => read(join(parent, 'neighbour', 'evidence'))).toThrow(/temporary roots/)
  })

  it.skipIf(windows)('takes /tmp for a root where the temporary folder names another', () => {
    vi.stubEnv('TMPDIR', folder(cwd()))
    expect(read('/tmp/kr-evidence-reader-case/evidence')).toBe(
      join(realpathSync.native('/tmp'), 'kr-evidence-reader-case', 'evidence')
    )
  })

  it('makes nothing in a temporary folder that is no root, and names the folder in its refusal', () => {
    // A relative name is no root, though the folder exists under the working directory. The case
    // reads through the entry point, as a test does.
    const parent = folder(cwd())
    const name = relative(cwd(), parent)
    for (const variable of ['TMPDIR', 'TEMP', 'TMP']) vi.stubEnv(variable, name)
    vi.stubEnv(VARIABLE, undefined)
    let words = ''
    try {
      artefactsDirectory()
    } catch (error) {
      words = String(error)
    }
    expect(words).toContain('temporary roots')
    expect(words).toContain(name)
    expect(words).toContain('not an absolute path')
    expect(words).not.toContain('leave it unset')
    expect(readdirSync(parent)).toEqual([])
  })

  it('takes a temporary folder that is a filesystem root for no root', () => {
    const top = windows ? 'C:\\' : '/'
    for (const name of ['TMPDIR', 'TEMP', 'TMP', 'RUNNER_TEMP']) vi.stubEnv(name, top)
    expect(() => read(elsewhere)).toThrow(/temporary roots/)
  })

  it.skipIf(!windows)('takes a runner folder that depends on the current drive for no root', () => {
    vi.stubEnv('RUNNER_TEMP', '\\Windows')
    expect(() => read(elsewhere)).toThrow(/temporary roots/)
  })

  it('takes a path for a root only when it is fully qualified by the platform rules', () => {
    // The temporary folder is an absolute path here and not on the other platform: the same folder
    // is a root by one platform's rules and none by the other's.
    const real = realpathSync.native(tmpdir())
    expect(temporaryRoots([tmpdir()], windows)).toEqual([real])
    expect(temporaryRoots([tmpdir()], !windows)).toEqual([])
  })

  it.each([
    ['/x', false, true],
    ['x', false, false],
    ['', false, false],
    ['C:\\x', true, true],
    ['C:/x', true, true],
    ['\\\\server\\share\\x', true, true],
    ['\\\\?\\C:\\x', true, true],
    ['//?/C:/x', true, false],
    ['\\x', true, false],
    ['/x', true, false],
    ['C:x', true, false],
    ['x\\y', true, false]
  ])('says of %s on Windows=%s that it is fully qualified: %s', (path, onWindows, expected) => {
    expect(fullyQualified(path, onWindows)).toBe(expected)
  })

  // The table of spellings, the same in every reader: what each one is, whatever platform this runs on.
  it.each([
    ['C:\\Users\\x\\Temp\\evidence', 'taken'],
    ['c:/Users/x/Temp/evidence', 'taken'],
    ['C:\\Users/x\\Temp/evidence', 'taken'],
    ['\\\\server\\share\\evidence', 'taken'],
    ['//server/share/evidence', 'taken'],
    ['\\\\server/share\\evidence', 'taken'],
    ['//server\\share/evidence', 'taken'],
    ['\\\\localhost\\C$\\Users\\x', 'taken'],
    ['\\\\?\\C:\\Users\\x\\Temp\\evidence', 'taken'],
    ['\\\\?\\c:\\Users\\x', 'taken'],
    ['\\\\?\\UNC\\server\\share\\evidence', 'taken'],
    ['\\\\?\\unc\\server\\share\\evidence', 'taken'],
    ['C:\\', 'taken'],
    ['\\\\?\\C:\\a/b', 'kind'],
    ['\\\\?\\UNC\\server\\share/b', 'kind'],
    ['\\\\?\\Volume{1234}\\x', 'kind'],
    ['\\\\?\\C:', 'kind'],
    ['\\\\?\\UNC\\server', 'kind'],
    ['\\\\?\\', 'kind'],
    ['\\\\.\\C:\\Users\\x', 'kind'],
    ['\\\\.\\pipe\\x', 'kind'],
    ['//?/C:/Users/x', 'kind'],
    ['//./C:/Users/x', 'kind'],
    ['\\\\.', 'kind'],
    ['\\\\server', 'kind'],
    ['//server', 'kind'],
    ['//server/', 'kind'],
    ['\\\\server\\', 'kind'],
    ['\\\\server\\\\share', 'kind'],
    ['///server/share/x', 'kind'],
    ['\\\\\\server\\share\\x', 'kind'],
    ['\\Windows\\Temp', 'not-absolute'],
    ['C:Windows', 'not-absolute'],
    ['C:', 'not-absolute'],
    ['relative\\x', 'not-absolute'],
    ['./x', 'not-absolute'],
    ['/tmp/a\\b\\c', 'not-absolute'],
    ['/c/Users/x/Temp', 'not-absolute'],
    ['/', 'not-absolute']
  ])('reads %s on Windows as %s', (path, expected) => {
    expect(spellingOf(path, true)).toBe(expected)
  })

  it('reads a backslash off Windows as a spelling that is not taken', () => {
    expect(spellingOf('/tmp/a\\..\\b', false)).toBe('backslash')
    expect(spellingOf('\\tmp\\x', false)).toBe('backslash')
    expect(spellingOf('relative/x', false)).toBe('not-absolute')
  })

  it('says that there are no roots where there are none, and shows no empty list', () => {
    expect(listed([])).toBe('none: no folder that a temporary variable names exists')
    expect(listed(['/a', '/b'])).toBe('/a, /b')
  })

  it.skipIf(!windows)('refuses the spellings it does not take, and names those it takes', () => {
    const root = folder(tmpdir())
    const text = realpathSync.native(root)
    const device = `\\\\.\\${text}\\evidence`
    expect(() => read(device)).toThrow(/a kind this reader does not take.*\/\/server\/share\/folder/s)
    expect(() => read('C:evidence')).toThrow(/not an absolute path \(on Windows this reader takes/)
    expect(() => read(`${text}\\a\\..\\..\\kr-evidence`)).toThrow(/steps up a directory/)
    expect(() => read(`${text}/a\\..\\kr-evidence`)).toThrow(/steps up a directory/)
  })

  it.skipIf(!windows)('reads every spelling that a platform gives as the same folder', () => {
    const root = folder(tmpdir())
    const text = realpathSync.native(root)
    const expected = join(text, 'evidence')
    for (const value of [
      `${text}\\evidence`,
      `${text.replaceAll('\\', '/')}/evidence`,
      `${text}/evidence`,
      `\\\\?\\${text}\\evidence`
    ]) {
      expect(read(value).toLowerCase()).toBe(expected.toLowerCase())
    }
  })
})
