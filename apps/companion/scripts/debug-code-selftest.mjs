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
import { join } from 'node:path'

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

/** An application bundle whose two executables hold the given bytes. */
function bundle(name, { app = '', extension = '', plist } = {}) {
  const root = join(work, `${name}.app`)
  mkdirSync(join(root, 'PlugIns', 'KalaReachNotificationService.appex'), { recursive: true })
  writeFileSync(join(root, 'KalaReach'), Buffer.from(`\u0000MH-O${app}\u0000`))
  writeFileSync(join(root, 'PlugIns', 'KalaReachNotificationService.appex', 'KalaReachNotificationService'), Buffer.from(`\u0000MH-O${extension}\u0000`))
  if (plist !== undefined) writeFileSync(join(root, 'GoogleService-Info.plist'), plist)
  return root
}

held('the names are the ones the debug code is made of', true, ['KRDeviceProbe', 'kr_probe_nonce', 'kr.probe.', 'kr_ext_'].every((name) => DEBUG_CODE_NAMES.includes(name)))
held('a release with none of them is clean', [], debugCodeIn(bundle('clean', { app: 'KRNativeLaunch didFinishLaunching', extension: 'PreviewDecider' })))

for (const name of DEBUG_CODE_NAMES) {
  held(`the application holding ${name} is found`, [`KalaReach holds ${name}`], debugCodeIn(bundle(`app-${name}`, { app: `x${name}y` })))
  held(`the extension holding ${name} is found`, [`PlugIns/KalaReachNotificationService.appex/KalaReachNotificationService holds ${name}`], debugCodeIn(bundle(`ext-${name}`, { extension: `x${name}y` })))
}

held('a name in both is reported for both', 2, debugCodeIn(bundle('both', { app: 'KRDeviceProbe', extension: 'KRDeviceProbe' })).length)
held('a name split across two reads is still found', ['KalaReach holds KRDeviceProbe'], debugCodeIn(bundle('long', { app: `${'a'.repeat(3_000_000)}KRDeviceProbe${'b'.repeat(10)}` })))
held('an analytics library is found', ['KalaReach holds FIRAnalytics'], debugCodeIn(bundle('analytics', { app: 'FIRAnalytics' })))

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`\n${failures} case${failures === 1 ? '' : 's'} failed`)
  process.exit(1)
}
console.log('\nevery case held')
