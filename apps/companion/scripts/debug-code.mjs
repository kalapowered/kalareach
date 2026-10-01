#!/usr/bin/env node
// Says whether a built application carries code that only a debug build may.
//
// Usage: node scripts/debug-code.mjs <KalaReach.app>
//
// Reads every executable in the bundle: the application's, its extension's, each framework's and a
// debug build's separate library. Exit 0 when none holds any of it, 1 when some does, and 2 when it
// could not be read. A debug build holds all of it by design, so this is run on a release.
import { Buffer } from 'node:buffer'
import { closeSync, openSync, readdirSync, readFileSync, readSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

/**
 * The names the debug-only code is made of, and what no release may link.
 *
 * A string literal of fifteen bytes or fewer can be compiled into instructions rather than kept as
 * bytes, so the probe's flags and keys may not show in a release that wrongly holds the probe. Its
 * type names are kept in the binary's metadata whatever the optimiser does with its strings, so they
 * are named too.
 */
export const DEBUG_CODE_NAMES = [
  // The probe's type name, which is also inside its launch flag, `-KRDeviceProbe`.
  'DeviceProbe',
  'KRColourMode',
  'kr_probe_nonce',
  'kr_probe_group',
  'kr_ext_',
  'kr.probe.',
  'probe-presented',
  'to.kala.reach.probe.shot',
  'ProbeSurface',
  'ExtensionProbe',
  'ProbeFixture',
  'NotificationRecorder',
  'KeychainSweepPlan',
  // Firebase's analytics library writes an installation of its own, whatever else is switched off.
  // These are names only that library holds: the core and messaging libraries, which are linked,
  // look up and refer to `FIRAnalytics` and its interop by name, so that name proves nothing.
  'APMAnalytics',
  'GoogleAppMeasurement'
]

/** The first four bytes of a Mach-O file, thin or universal, in either byte order. */
const MACH_O_MAGICS = [
  [0xfe, 0xed, 0xfa, 0xce],
  [0xfe, 0xed, 0xfa, 0xcf],
  [0xce, 0xfa, 0xed, 0xfe],
  [0xcf, 0xfa, 0xed, 0xfe],
  [0xca, 0xfe, 0xba, 0xbe],
  [0xbe, 0xba, 0xfe, 0xca]
]

function isMachO(path) {
  const head = Buffer.alloc(4)
  const file = openSync(path, 'r')
  try {
    if (readSync(file, head, 0, 4, 0) < 4) return false
  } finally {
    closeSync(file)
  }
  return MACH_O_MAGICS.some((magic) => magic.every((byte, at) => head[at] === byte))
}

/**
 * Every executable in a bundle: the application's, each extension's and each framework's, and the
 * separate library a debug build keeps its code in. A bundle's own executables are found by what
 * they are rather than by where they are or what they are called, so none is left out.
 */
function executables(root) {
  const found = []
  for (const entry of readdirSync(root)) {
    const path = join(root, entry)
    const kind = statSync(path)
    if (kind.isDirectory()) found.push(...executables(path))
    else if (kind.isFile() && isMachO(path)) found.push(path)
  }
  return found
}

/** The problems found in a built application: each is one executable holding one name. */
export function debugCodeIn(app) {
  const problems = []
  const found = executables(app).sort()
  if (found.length === 0) throw new Error('the bundle holds no executable')
  for (const path of found) {
    const bytes = readFileSync(path)
    for (const name of DEBUG_CODE_NAMES) {
      if (bytes.includes(Buffer.from(name))) problems.push(`${relative(app, path)} holds ${name}`)
    }
  }
  return problems
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const app = process.argv[2]
  if (!app) {
    console.error('usage: node scripts/debug-code.mjs <KalaReach.app>')
    process.exit(2)
  }
  let problems
  try {
    problems = debugCodeIn(app)
  } catch (error) {
    console.error(`could not read ${app}: ${error.message}`)
    process.exit(2)
  }
  for (const problem of problems) console.error(problem)
  if (problems.length > 0) process.exit(1)
  console.log('the application and its extension hold none of the debug-only code')
}
