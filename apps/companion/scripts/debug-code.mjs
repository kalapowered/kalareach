#!/usr/bin/env node
// Says whether a built application carries code that only a debug build may.
//
// Usage: node scripts/debug-code.mjs <KalaReach.app>
//
// Exit 0 when the application and its extension hold none of it, 1 when they hold some, and 2 when
// it could not be read. A debug build holds all of it by design, so this is run on a release.
import { Buffer } from 'node:buffer'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

/** The names the debug-only code is made of, and what no release may link. */
export const DEBUG_CODE_NAMES = [
  'KRDeviceProbe',
  'KRColourMode',
  'kr_probe_nonce',
  'kr_probe_group',
  'kr_ext_',
  'kr.probe.',
  'probe-keychain',
  'to.kala.reach.probe.shot',
  // Firebase's analytics library writes an installation of its own, whatever else is switched off.
  'FIRAnalytics'
]

/** The files of a bundle that are executables: the application's and each extension's. */
function executables(app) {
  const found = []
  const name = 'KalaReach'
  found.push(join(app, name))
  const plugins = join(app, 'PlugIns')
  let entries = []
  try {
    entries = readdirSync(plugins)
  } catch {
    // No extension is a bundle with fewer files to read.
  }
  for (const entry of entries) {
    if (!entry.endsWith('.appex')) continue
    const extension = join(plugins, entry)
    for (const file of readdirSync(extension)) {
      const path = join(extension, file)
      if (statSync(path).isFile() && !file.includes('.')) found.push(path)
    }
  }
  return found
}

/** The problems found in a built application: each is one executable holding one name. */
export function debugCodeIn(app) {
  const problems = []
  for (const path of executables(app)) {
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
