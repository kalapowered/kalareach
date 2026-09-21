#!/usr/bin/env node
// Holds the packaged-class check to the answers it must give.
//
// The check reads a packaged Android application and says whether it carries the hand-written
// native classes. Two ways of getting that wrong would be silent: counting a dex the runtime never
// loads as application code, and losing the central directory to an archive comment that happens
// to contain the end-of-directory signature. Neither can be produced by building the application,
// so both are built here, in memory, and fed to the same reader the build uses.
//
// The archives are the smallest ones that exercise the reader: a dex here carries its string,
// type and class tables and nothing else, which is what the reader looks at, and is not a dex any
// runtime would accept.
import { Buffer } from 'node:buffer'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { missingFrom } from './android-classes.mjs'

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

/** A dex file defining exactly `names`, with the tables the reader reads. */
function dex(names) {
  const descriptors = names.map((name) => `L${name.replaceAll('.', '/')};`)
  const header = Buffer.alloc(112)
  header.write('dex\n035\0', 0, 'latin1')
  const stringIdsAt = 112
  const typeIdsAt = stringIdsAt + descriptors.length * 4
  const classDefsAt = typeIdsAt + descriptors.length * 4
  const dataAt = classDefsAt + descriptors.length * 32
  header.writeUInt32LE(descriptors.length, 0x38)
  header.writeUInt32LE(stringIdsAt, 0x3c)
  header.writeUInt32LE(descriptors.length, 0x40)
  header.writeUInt32LE(typeIdsAt, 0x44)
  header.writeUInt32LE(descriptors.length, 0x60)
  header.writeUInt32LE(classDefsAt, 0x64)

  const stringIds = Buffer.alloc(descriptors.length * 4)
  const typeIds = Buffer.alloc(descriptors.length * 4)
  const classDefs = Buffer.alloc(descriptors.length * 32)
  const data = []
  let at = dataAt
  descriptors.forEach((descriptor, index) => {
    stringIds.writeUInt32LE(at, index * 4)
    typeIds.writeUInt32LE(index, index * 4)
    classDefs.writeUInt32LE(index, index * 32)
    const item = Buffer.concat([uleb(descriptor.length), Buffer.from(descriptor, 'utf8'), Buffer.from([0])])
    data.push(item)
    at += item.length
  })
  return Buffer.concat([header, stringIds, typeIds, classDefs, ...data])
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
  if (answer === missing) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${missing}\n        answered: ${answer}`)
}

const code = dex(PRESENT)
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
  'an archive comment holding the end-of-directory signature is still read',
  'commented.apk',
  zip(
    [filler, { name: 'classes.dex', bytes: code }],
    Buffer.concat([Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(40)])
  ),
  'nothing'
)
expect(
  'an application missing the worker is named, not passed',
  'partial.apk',
  zip([filler, { name: 'classes.dex', bytes: dex([PRESENT[0]]) }]),
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

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} of the packaged-class checks answered wrongly`)
  process.exit(1)
}
console.log('the packaged-class check answers correctly on every archive above')
