// KR-REQ-27.03: the reader of `KR_TEST_ARTIFACTS_DIR` for TypeScript refuses a value outside this
// platform's temporary roots where the value is used. Each case sets the variable in the
// environment the way a build does and reads the directory through the reader's own entry point.

import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from 'node:fs'
import { platform, tmpdir } from 'node:os'
import { join } from 'node:path'
import { chdir, cwd } from 'node:process'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { VARIABLE, artefactsDirectory } from '../e2e/evidence'

const windows = platform() === 'win32'
const elsewhere = windows ? 'C:\\Windows\\kr-evidence' : '/etc/kr-evidence'
const made: string[] = []

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
    [
      'a name that only begins like a root',
      `${realpathSync.native(tmpdir())}foo${windows ? '\\' : '/'}evidence`,
      'not inside a temporary root'
    ],
    ['a relative value', 'evidence', 'not an absolute path'],
    ['a relative value with a dot', './evidence', 'not an absolute path'],
    ['an empty value', '', 'it is empty'],
    // Written out, because `join` would remove the step up before the reader saw it.
    ['a step up that ends inside a root', `${tmpdir()}/evidence/../evidence`, 'steps up a directory'],
    ['the root itself', realpathSync.native(tmpdir()), 'not inside a temporary root']
  ])('refuses %s', (_name, value, why) => {
    expect(() => read(value)).toThrow(/KR_TEST_ARTIFACTS_DIR.*temporary roots/s)
    expect(() => read(value)).toThrow(why)
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
})
