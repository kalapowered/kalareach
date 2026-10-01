#!/usr/bin/env node
// Holds the packaged-class check to the answers it must give.
//
// The check reads a packaged Android application and says whether it carries the hand-written
// native classes. Three ways of getting that wrong would be silent: counting a dex the runtime
// never loads as application code, taking a class the code merely mentions for one the code
// defines, and losing the central directory to an archive comment that happens to contain the
// end-of-directory signature. A fourth would be reading the wrong build: checking the package a
// different variant left behind, or passing over one the build was asked for. None of them can be
// produced by building the application, so all of them are built here, in memory and in a
// throwaway outputs directory, and fed to the same reader and the same selection the build uses.
//
// The archives are the smallest ones that exercise the reader: a dex here carries its string,
// type and class tables and nothing else, which is what the reader looks at, and is not a dex any
// runtime would accept.
import { Buffer } from 'node:buffer'
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'

import { dex, zip } from './archive-fixtures.mjs'
import { definedStrings, missingFrom, packagesOf, requestFrom } from './android-classes.mjs'

const PRESENT = [
  'to.kala.reach.companion.push.KalaReachMessagingService',
  'to.kala.reach.companion.push.PreviewWorker'
]

/**
 * The same archive again, with a 22-byte comment shaped like a record that claims the real
 * central directory: `count` entries of it, and `over` bytes more than it holds.
 *
 * This is the comment that hides the rest of an archive. It sits 22 bytes past the real record,
 * so claiming the real directory's offset and 22 more bytes puts its own end exactly where a
 * reader would expect the directory to end, and every other field agrees as well.
 */
function forgedEnd(members, count, over) {
  const whole = zip(members)
  const real = whole.length - 22
  const comment = Buffer.alloc(22)
  comment.writeUInt32LE(0x06054b50, 0)
  comment.writeUInt16LE(count, 8)
  comment.writeUInt16LE(count, 10)
  comment.writeUInt32LE(whole.readUInt32LE(real + 12) + over, 12)
  comment.writeUInt32LE(whole.readUInt32LE(real + 16), 16)
  return zip(members, comment)
}

const work = mkdtempSync(join(tmpdir(), 'kr-android-classes-'))
let failures = 0

/** Says what the check answered, and whether that is what it had to answer. */
function held(what, expected, answer) {
  if (answer === expected) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${expected}\n        answered: ${answer}`)
}

/** Writes one archive and states what the check must answer about it. */
function expect(what, name, bytes, missing) {
  const path = join(work, name)
  writeFileSync(path, bytes)
  let answer
  try {
    answer = missingFrom(path).join(', ') || 'nothing'
  } catch (failure) {
    answer = `refused: ${failure.message}`
  }
  held(what, missing, answer)
}

const code = dex({ defined: PRESENT })
const filler = { name: 'AndroidManifest.xml', bytes: Buffer.from('not a manifest', 'utf8') }

expect(
  'an APK whose application dex carries both classes is whole',
  'whole.apk',
  zip([filler, { name: 'classes.dex', bytes: code }]),
  'nothing'
)
expect(
  'a class defined only in an asset dex does not count as application code',
  'asset-only.apk',
  zip([filler, { name: 'assets/classes.dex', bytes: code }]),
  'refused: the artefact carries no application dex file'
)
expect(
  'an AAB is read from its base module',
  'whole.aab',
  zip([filler, { name: 'base/dex/classes.dex', bytes: code }]),
  'nothing'
)
expect(
  'a class defined only in an optional feature does not count',
  'feature-only.aab',
  zip([filler, { name: 'voice/dex/classes.dex', bytes: code }]),
  'refused: the artefact carries no application dex file'
)
expect(
  'a class the dex only mentions is not a class the dex defines',
  'reference-only.apk',
  zip([
    filler,
    { name: 'classes.dex', bytes: dex({ defined: [PRESENT[0]], referenced: [PRESENT[1]] }) }
  ]),
  PRESENT[1]
)
expect(
  'an archive comment holding the end-of-directory signature is still read',
  'commented.apk',
  zip(
    [filler, { name: 'classes.dex', bytes: code }],
    Buffer.concat([Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(40)])
  ),
  'nothing'
)
expect(
  'a 22-byte comment shaped like an empty end-of-directory record is still read',
  'commented-22.apk',
  zip(
    [filler, { name: 'classes.dex', bytes: code }],
    Buffer.concat([Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(18)])
  ),
  'nothing'
)
expect(
  'a comment that claims the real directory and 22 bytes more is not the record',
  'forged-prefix.apk',
  forgedEnd([filler, { name: 'classes.dex', bytes: code }], 1, 22),
  'nothing'
)
expect(
  'a comment that claims more entries than the archive holds is not the record',
  'forged-count.apk',
  forgedEnd([filler, { name: 'classes.dex', bytes: code }], 3, 22),
  'nothing'
)
expect(
  'an application missing the worker is named, not passed',
  'partial.apk',
  zip([filler, { name: 'classes.dex', bytes: dex({ defined: [PRESENT[0]] }) }]),
  PRESENT[1]
)
expect(
  'a dex layout this does not read is refused rather than guessed at',
  'future.apk',
  zip([
    filler,
    {
      name: 'classes.dex',
      bytes: (() => {
        const other = Buffer.from(code)
        other.write('dex\n099\0', 0, 'latin1')
        return other
      })()
    }
  ]),
  'refused: dex version 099 is not read here'
)

// -- the strings a dex carries -------------------------------------------------------------------
// The identifier check reads every string, which is how it finds a name the code carries as a
// constant. It must see the constants, the descriptors of the classes and nothing in between.

const carried = definedStrings(dex({ defined: [PRESENT[0]], constants: ['to.kala.reach.push'] }))
held(
  'a constant the code carries is read from the string table',
  'true',
  String(carried.includes('to.kala.reach.push'))
)
held(
  'a class descriptor is read from the string table in its own form',
  'true',
  String(carried.includes('Lto/kala/reach/companion/push/KalaReachMessagingService;'))
)
held(
  'the string table is read whole, and nothing else is taken for part of it',
  JSON.stringify(
    [
      'Ljava/lang/Object;',
      'Lto/kala/reach/companion/push/KalaReachMessagingService;',
      'member0',
      'member1',
      'to.kala.reach.push'
    ].sort()
  ),
  JSON.stringify([...carried].sort())
)

// -- which packages a build is checked against --------------------------------------------------
// An outputs directory as a tree carries it after several builds. The ages are deliberately
// misleading: the release packages are the newest files in it, the debug APK is as a build that
// has just rewritten it leaves it, and the debug bundle beside it is the oldest file there, as a
// packaging task with nothing to do leaves its own output. Anything that decided by time would
// answer wrongly below.

const outputs = join(work, 'outputs')
const OLD = new Date('2024-01-01T00:00:00Z')
const REWRITTEN = new Date('2025-01-01T00:00:00Z')
const NEW = new Date('2026-01-01T00:00:00Z')

function apkOutput(flavour, profile, when, variant = null) {
  const directory = join(outputs, 'apk', flavour, profile)
  mkdirSync(directory, { recursive: true })
  const name = `app-${flavour}-${profile}.apk`
  const path = join(directory, name)
  writeFileSync(path, zip([filler, { name: 'classes.dex', bytes: code }]))
  writeFileSync(
    join(directory, 'output-metadata.json'),
    JSON.stringify({
      version: 3,
      variantName: variant ?? `${flavour}${profile[0].toUpperCase()}${profile.slice(1)}`,
      elements: [{ type: 'SINGLE', outputFile: name }]
    })
  )
  utimesSync(path, when, when)
}

function bundleOutput(variant, names, when) {
  const directory = join(outputs, 'bundle', variant)
  mkdirSync(directory, { recursive: true })
  for (const name of names) {
    const path = join(directory, name)
    writeFileSync(path, zip([filler, { name: 'base/dex/classes.dex', bytes: code }]))
    utimesSync(path, when, when)
  }
}

apkOutput('universal', 'debug', REWRITTEN)
apkOutput('universal', 'release', NEW)
// The flavour a build asks for by `--target i686`, left behind by a release build.
apkOutput('x86', 'debug', NEW, 'x86Release')
bundleOutput('universalDebug', ['app-universal-debug.aab'], OLD)
bundleOutput('universalRelease', ['app-universal-release.aab'], NEW)
bundleOutput('armDebug', ['app-arm-debug.aab', 'app-arm-debug-renamed.aab'], NEW)

/** States which packages a build with these arguments must be checked against. */
function expectPackages(what, argv, chosen) {
  let answer
  try {
    const request = requestFrom(argv)
    answer = packagesOf(request, outputs)
      .map((path) => relative(outputs, path).replaceAll('\\', '/'))
      .join(', ')
  } catch (failure) {
    answer = `refused: ${failure.message}`
  }
  held(what, chosen, answer)
}

expectPackages(
  'a build that rewrote only its APK is checked against that APK and the bundle it left alone',
  ['--debug', '--target', 'aarch64'],
  'apk/universal/debug/app-universal-debug.apk, bundle/universalDebug/app-universal-debug.aab'
)
expectPackages(
  'a bundle the build had no reason to rewrite is still checked',
  ['--debug', '--aab'],
  'bundle/universalDebug/app-universal-debug.aab'
)
expectPackages(
  'a build asked for APKs alone is not judged against a bundle',
  ['--debug', '--apk'],
  'apk/universal/debug/app-universal-debug.apk'
)
expectPackages(
  'a release build is checked against the release packages',
  [],
  'apk/universal/release/app-universal-release.apk, bundle/universalRelease/app-universal-release.aab'
)
expectPackages(
  'a package the build asked for and did not leave is a failure, not an omission',
  ['--debug', '--split-per-abi', '--target', 'aarch64', '--apk'],
  'refused: this build asked for the arm64Debug APK and left no ' +
    join(outputs, 'apk', 'arm64', 'debug', 'output-metadata.json')
)
expectPackages(
  'a package that belongs to another variant is refused, not read',
  ['--debug', '--split-per-abi', '--target', 'i686', '--apk'],
  `refused: ${join(
    outputs,
    'apk',
    'x86',
    'debug',
    'output-metadata.json'
  )} describes x86Release, not the x86Debug that was built`
)
expectPackages(
  'two bundles in one variant directory are an ambiguity, not a choice',
  ['--debug', '--split-per-abi', '--target', 'armv7', '--aab'],
  `refused: ${join(outputs, 'bundle', 'armDebug')} holds 2 bundles: ` +
    'app-arm-debug-renamed.aab, app-arm-debug.aab'
)
expectPackages(
  'an argument this cannot read stops the check rather than narrowing it',
  ['--debug', '--every-abi'],
  'refused: This build was given --every-abi, which the packaged-class check does not read, so ' +
    'it cannot say which packages the build was asked for. Build with `pnpm -C apps/companion ' +
    'exec tauri android build` and check the package yourself with `pnpm -C apps/companion ' +
    'android:classes <path>`.'
)

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} of the packaged-class checks answered wrongly`)
  process.exit(1)
}
console.log('the packaged-class check answers correctly on every archive and build above')
