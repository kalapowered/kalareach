#!/usr/bin/env node
// Holds the check that a release build carries none of the code only a debug build has.
//
// A debug build can be started to run device checks, and its notification extension answers them.
// Neither belongs in a release: the first writes to and reads the keychain on request, and the
// second puts facts about the device into a notification. The check reads a built application and
// its extension for the names that code is made of. Compiling the release is not needed to test it:
// the bundle is built here, with executables that hold those names or do not.
import { Buffer } from 'node:buffer'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { debugCodeIn, DEBUG_CODE_NAMES } from './debug-code.mjs'

const work = mkdtempSync(join(tmpdir(), 'kr-debug-code-'))
let failures = 0

function held(what, expected, answer) {
  if (JSON.stringify(answer) === JSON.stringify(expected)) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${JSON.stringify(expected)}\n        answered: ${JSON.stringify(answer)}`)
}

/** An executable: a 64-bit Mach-O header, then the given bytes. */
function executable(content) {
  return Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.from(`\u0000${content}\u0000`)])
}

/**
 * An application bundle whose executables hold the given bytes: the application's, its extension's,
 * and any further file, named by its path inside the bundle (a debug build's separate library, a
 * framework, a resource that is not an executable).
 */
function bundle(name, { app = '', extension = '', extra = {} } = {}) {
  const root = join(work, `${name}.app`)
  mkdirSync(join(root, 'PlugIns', 'KalaReachNotificationService.appex'), { recursive: true })
  writeFileSync(join(root, 'KalaReach'), executable(app))
  writeFileSync(join(root, 'PlugIns', 'KalaReachNotificationService.appex', 'KalaReachNotificationService'), executable(extension))
  for (const [path, file] of Object.entries(extra)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), file)
  }
  return root
}

held('the names are the ones the debug code is made of', true, ['DeviceProbe', 'kr_probe_nonce', 'kr.probe.', 'kr_ext_', 'ExtensionProbe'].every((name) => DEBUG_CODE_NAMES.includes(name)))
held('a release with none of them is clean', [], debugCodeIn(bundle('clean', { app: 'KRNativeLaunch didFinishLaunching', extension: 'PreviewDecider' })))

for (const name of DEBUG_CODE_NAMES) {
  held(`the application holding ${name} is found`, [`KalaReach holds ${name}`], debugCodeIn(bundle(`app-${name}`, { app: `x${name}y` })))
  held(`the extension holding ${name} is found`, [`PlugIns/KalaReachNotificationService.appex/KalaReachNotificationService holds ${name}`], debugCodeIn(bundle(`ext-${name}`, { extension: `x${name}y` })))
}

held('a name in both is reported for both', 2, debugCodeIn(bundle('both', { app: 'KRDeviceProbe', extension: 'KRDeviceProbe' })).length)
held('a name split across two reads is still found', ['KalaReach holds DeviceProbe'], debugCodeIn(bundle('long', { app: `${'a'.repeat(3_000_000)}KRDeviceProbe${'b'.repeat(10)}` })))
held('an analytics library is found', ['KalaReach holds APMAnalytics'], debugCodeIn(bundle('analytics', { app: 'APMAnalytics' })))
held('the core library looking the analytics library up by name is not one', [], debugCodeIn(bundle('core', { app: 'FIRAnalytics FIRAnalyticsConfiguration FIRAnalyticsInterop FIRAnalyticsConfigurationSetEnabledNotification' })))
held(
  "a debug build's separate library is read, and named by its path",
  ['KalaReach.debug.dylib holds DeviceProbe'],
  debugCodeIn(bundle('dylib', { extra: { 'KalaReach.debug.dylib': executable('KRDeviceProbe') } }))
)
held(
  "a framework's executable is read",
  ['Frameworks/Other.framework/Other holds kr_ext_'],
  debugCodeIn(bundle('framework', { extra: { 'Frameworks/Other.framework/Other': executable('kr_ext_') } }))
)
held(
  'a universal binary is read',
  ['Frameworks/Fat holds ProbeSurface'],
  debugCodeIn(bundle('fat', { extra: { 'Frameworks/Fat': Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe]), Buffer.from('ProbeSurface')]) } }))
)
held(
  'a universal binary with 64-bit offsets is read, in either byte order',
  ['Frameworks/Fat64 holds ProbeSurface', 'Frameworks/Fat64Swapped holds ProbeSurface'],
  debugCodeIn(
    bundle('fat64', {
      extra: {
        'Frameworks/Fat64': Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbf]), Buffer.from('ProbeSurface')]),
        'Frameworks/Fat64Swapped': Buffer.concat([Buffer.from([0xbf, 0xba, 0xfe, 0xca]), Buffer.from('ProbeSurface')])
      }
    })
  )
)
held(
  'a file that is not an executable is not read',
  [],
  debugCodeIn(bundle('resource', { extra: { 'assets/page.js': Buffer.from('kr.probe. KRDeviceProbe') } }))
)
held(
  'a bundle with no executable cannot be read',
  'could not be read',
  (() => {
    mkdirSync(join(work, 'empty.app'))
    writeFileSync(join(work, 'empty.app', 'Info.plist'), 'a resource')
    try {
      debugCodeIn(join(work, 'empty.app'))
      return 'read'
    } catch {
      return 'could not be read'
    }
  })()
)

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`\n${failures} case${failures === 1 ? '' : 's'} failed`)
  process.exit(1)
}
console.log('\nevery case held')
