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

import { missingFrom, packagesOf, requestFrom } from './android-classes.mjs'

const PRESENT = [
  'to.kala.reach.companion.push.KalaReachMessagingService',
  'to.kala.reach.companion.push.PreviewWorker'
]

/** A uleb128 of a small value. */
function uleb(value) {
  const bytes = []
  do {
    let byte = value & 0x7f
    value >>>= 7
    if (value > 0) byte |= 0x80
    bytes.push(byte)
  } while (value > 0)
  return Buffer.from(bytes)
}

/**
 * A dex file that defines `defined` and names `referenced` without defining it.
 *
 * Both sets reach the string table, which is the point: a reader that searched the strings for a
 * class name could not tell a definition from a mention, and the application would pass a check
 * it should fail. Only `defined` reaches `class_defs`.
 *
 * The three tables are deliberately out of step with one another -- the strings run in one order
 * behind entries that are not class names at all, the type table points into them in another, and
 * `class_defs` points into the type table in a third -- so that a reader that took any one index
 * for any other would answer wrongly here.
 */
function dex({ defined = [], referenced = [] } = {}) {
  const descriptorOf = (name) => `L${name.replaceAll('.', '/')};`
  // Every class the file names. The superclass every real class has comes first, and the merely
  // mentioned ones next, so a class_defs index is never the type index it holds.
  const types = ['java.lang.Object', ...referenced, ...defined].map(descriptorOf)
  // A real string table holds method and field names as well as class names. Enough of them come
  // first here that a descriptor's string index is never its type index, and the descriptors
  // behind them run in the opposite order to the type table.
  const strings = [...types.map((_, index) => `member${index}`), ...[...types].reverse()]
  const typeStringIndex = types.map((descriptor) => strings.indexOf(descriptor))
  const definedTypeIndex = defined.map((name) => types.indexOf(descriptorOf(name)))
  typeStringIndex.forEach((stringIndex, typeIndex) => {
    if (stringIndex === typeIndex) throw new Error('this fixture lines up two of its tables')
  })
  definedTypeIndex.forEach((typeIndex, classIndex) => {
    if (typeIndex === classIndex) throw new Error('this fixture lines up two of its tables')
  })

  const header = Buffer.alloc(112)
  header.write('dex\n035\0', 0, 'latin1')
  const stringIdsAt = 112
  const typeIdsAt = stringIdsAt + strings.length * 4
  const classDefsAt = typeIdsAt + types.length * 4
  const dataAt = classDefsAt + definedTypeIndex.length * 32
  header.writeUInt32LE(strings.length, 0x38)
  header.writeUInt32LE(stringIdsAt, 0x3c)
  header.writeUInt32LE(types.length, 0x40)
  header.writeUInt32LE(typeIdsAt, 0x44)
  header.writeUInt32LE(definedTypeIndex.length, 0x60)
  header.writeUInt32LE(classDefsAt, 0x64)

  const stringIds = Buffer.alloc(strings.length * 4)
  const typeIds = Buffer.alloc(types.length * 4)
  const classDefs = Buffer.alloc(definedTypeIndex.length * 32)
  const data = []
  let at = dataAt
  strings.forEach((text, index) => {
    stringIds.writeUInt32LE(at, index * 4)
    const item = Buffer.concat([uleb(text.length), Buffer.from(text, 'utf8'), Buffer.from([0])])
    data.push(item)
    at += item.length
  })
  typeStringIndex.forEach((stringIndex, index) => typeIds.writeUInt32LE(stringIndex, index * 4))
  definedTypeIndex.forEach((typeIndex, index) => classDefs.writeUInt32LE(typeIndex, index * 32))
  return Buffer.concat([header, stringIds, typeIds, classDefs, ...data])
}

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

/** A zip of `members` ({name, bytes}), stored, with an optional archive comment. */
function zip(members, comment = Buffer.alloc(0)) {
  const pieces = []
  const directory = []
  let at = 0
  for (const member of members) {
    const name = Buffer.from(member.name, 'utf8')
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt32LE(member.bytes.length, 18)
    local.writeUInt32LE(member.bytes.length, 22)
    local.writeUInt16LE(name.length, 26)
    pieces.push(local, name, member.bytes)
    const entry = Buffer.alloc(46)
    entry.writeUInt32LE(0x02014b50, 0)
    entry.writeUInt16LE(20, 6)
    entry.writeUInt32LE(member.bytes.length, 20)
    entry.writeUInt32LE(member.bytes.length, 24)
    entry.writeUInt16LE(name.length, 28)
    entry.writeUInt32LE(at, 42)
    directory.push(entry, name)
    at += 30 + name.length + member.bytes.length
  }
  const body = Buffer.concat(pieces)
  const central = Buffer.concat(directory)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(members.length, 8)
  end.writeUInt16LE(members.length, 10)
  end.writeUInt32LE(central.length, 12)
  end.writeUInt32LE(body.length, 16)
  end.writeUInt16LE(comment.length, 20)
  return Buffer.concat([body, central, end, comment])
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
