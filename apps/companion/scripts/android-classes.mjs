#!/usr/bin/env node
// Checks that the hand-written native classes are in the packaged Android application.
//
// The application's Kotlin lives in two places: a Gradle module of plain Kotlin decisions
// (`:krnative`) and the classes that need the Android framework, under
// `native/android/android/src/main/java`. The second tree reaches the application through one
// source-set line in the generated Gradle project. A source-set entry that points at the wrong
// directory compiles nothing while the build still reports success, and the application would then
// carry no push receiver, no background worker and no keystore reader with nothing in the build
// output to say so.
//
// So the packaging is checked rather than assumed. This reads the classes each packaged artefact
// actually defines -- the `class_defs` table of every dex inside the APK or AAB, which lists
// definitions and not references -- and fails by name when one of the classes below is missing.
import { Buffer } from 'node:buffer'
import { inflateRawSync } from 'node:zlib'
import { closeSync, openSync, readSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

/**
 * The classes a packaged application must define, by these exact names.
 *
 * Both are entry points the system itself resolves by name: the first from the manifest, the
 * second from the work request the receiver enqueues. That is what makes them safe to demand of
 * every build. A release build shrinks and renames everything it reaches only from other code, so
 * naming the keystore reader or a decision class here would fail a release artefact that is
 * perfectly correct. Between them the two cover the tree: neither exists at all unless the module
 * compiled it.
 *
 * `--list` prints everything the artefact carries of the hand-written packages, which is what to
 * read when a name is in question.
 */
const REQUIRED = [
  // The service the system starts when a push arrives, declared in the manifest.
  'to.kala.reach.companion.push.KalaReachMessagingService',
  // The work the message callback hands to the platform's scheduler.
  'to.kala.reach.companion.push.PreviewWorker'
]

/** The packages whose classes are listed by `--list`. */
const HAND_WRITTEN = ['to.kala.reach.companion.push.', 'to.kala.reach.companion.mobile.']

const DEX_MEMBER = /(^|\/)classes\d*\.dex$/

// The instrumentation package is a second application built from the test sources, and it carries
// none of this. Checking it would fail a build that is correct.
const NOT_THE_APPLICATION = /(^|\/)androidTest(\/|$)/

function fail(message) {
  console.error(message)
  process.exit(1)
}

// -- the archive ------------------------------------------------------------------------------
// APKs and AABs are zip files. Reading the members this check needs, rather than unpacking the
// archive, keeps it to the standard library and costs a few seeks on a file that is often a
// gigabyte.

/** Reads `length` bytes at `position`. */
function readAt(handle, position, length) {
  const buffer = Buffer.allocUnsafe(length)
  let read = 0
  while (read < length) {
    const step = readSync(handle, buffer, read, length - read, position + read)
    if (step === 0) break
    read += step
  }
  return read === length ? buffer : buffer.subarray(0, read)
}

/** Every member of a zip archive, as name, offset, method and sizes. */
function members(handle, size) {
  // The end-of-central-directory record is last, after a comment of up to 65535 bytes.
  const tailLength = Math.min(size, 0xffff + 22)
  const tail = readAt(handle, size - tailLength, tailLength)
  let end = -1
  for (let at = tail.length - 22; at >= 0; at -= 1) {
    if (tail.readUInt32LE(at) === 0x06054b50) {
      end = at
      break
    }
  }
  if (end < 0) throw new Error('not a zip archive: no end-of-central-directory record')
  const count = tail.readUInt16LE(end + 10)
  const directorySize = tail.readUInt32LE(end + 12)
  const directoryAt = tail.readUInt32LE(end + 16)
  if (count === 0xffff || directoryAt === 0xffffffff || directorySize === 0xffffffff) {
    throw new Error('this archive uses zip64, which this check does not read')
  }
  const directory = readAt(handle, directoryAt, directorySize)
  const found = []
  let at = 0
  for (let index = 0; index < count; index += 1) {
    if (directory.readUInt32LE(at) !== 0x02014b50) {
      throw new Error(`central directory entry ${index} has no header`)
    }
    const nameLength = directory.readUInt16LE(at + 28)
    const extraLength = directory.readUInt16LE(at + 30)
    const commentLength = directory.readUInt16LE(at + 32)
    found.push({
      name: directory.subarray(at + 46, at + 46 + nameLength).toString('utf8'),
      method: directory.readUInt16LE(at + 10),
      compressedSize: directory.readUInt32LE(at + 20),
      uncompressedSize: directory.readUInt32LE(at + 24),
      headerAt: directory.readUInt32LE(at + 42)
    })
    at += 46 + nameLength + extraLength + commentLength
  }
  return found
}

/** One member's bytes. */
function contents(handle, member) {
  const header = readAt(handle, member.headerAt, 30)
  if (header.length !== 30 || header.readUInt32LE(0) !== 0x04034b50) {
    throw new Error(`${member.name}: no local header`)
  }
  const dataAt = member.headerAt + 30 + header.readUInt16LE(26) + header.readUInt16LE(28)
  const raw = readAt(handle, dataAt, member.compressedSize)
  if (member.method === 0) return raw
  if (member.method === 8) return inflateRawSync(raw)
  throw new Error(`${member.name}: compression method ${member.method} is not read here`)
}

// -- the dex ----------------------------------------------------------------------------------
// A dex file's `class_defs` table names every class the file *defines*. The string table also
// holds every class it merely mentions, which is why the table is read rather than the strings.

/** Reads one unsigned LEB128 at `at`, answering the value and the next offset. */
function leb128(dex, at) {
  let value = 0
  let shift = 0
  for (;;) {
    const byte = dex[at]
    at += 1
    value |= (byte & 0x7f) << shift
    if ((byte & 0x80) === 0) return [value >>> 0, at]
    shift += 7
  }
}

/** Every class a dex file defines, in source form (`a.b.C`, with `$` for a nested class). */
function definedClasses(dex) {
  if (dex.length < 112 || dex.subarray(0, 4).toString('latin1') !== 'dex\n') {
    throw new Error('not a dex file')
  }
  const stringIdsAt = dex.readUInt32LE(0x3c)
  const typeIdsAt = dex.readUInt32LE(0x44)
  const classDefsCount = dex.readUInt32LE(0x60)
  const classDefsAt = dex.readUInt32LE(0x64)
  const descriptor = (typeIndex) => {
    const stringIndex = dex.readUInt32LE(typeIdsAt + typeIndex * 4)
    const dataAt = dex.readUInt32LE(stringIdsAt + stringIndex * 4)
    // A string_data_item is its length in UTF-16 units, then modified UTF-8 up to a NUL. Class
    // descriptors are ASCII, so the bytes are read up to that NUL.
    const [, textAt] = leb128(dex, dataAt)
    const end = dex.indexOf(0, textAt)
    return dex.subarray(textAt, end).toString('latin1')
  }
  const classes = []
  for (let index = 0; index < classDefsCount; index += 1) {
    const type = descriptor(dex.readUInt32LE(classDefsAt + index * 32))
    if (type.startsWith('L') && type.endsWith(';')) {
      classes.push(type.slice(1, -1).replaceAll('/', '.'))
    }
  }
  return classes
}

/** Every class the packaged artefact at `path` defines. */
function packagedClasses(path) {
  const handle = openSync(path, 'r')
  try {
    const size = statSync(path).size
    const dexes = members(handle, size).filter((member) => DEX_MEMBER.test(member.name))
    if (dexes.length === 0) throw new Error('the artefact carries no dex file')
    const classes = new Set()
    for (const member of dexes) {
      for (const name of definedClasses(contents(handle, member))) classes.add(name)
    }
    return classes
  } finally {
    closeSync(handle)
  }
}

// -- the check --------------------------------------------------------------------------------

/** Every APK and AAB under a directory. */
function artefacts(root) {
  const found = []
  const walk = (directory) => {
    let entries
    try {
      entries = readdirSync(directory, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) {
        if (!NOT_THE_APPLICATION.test(entry.name)) walk(path)
      } else if (/\.(apk|aab)$/.test(entry.name)) found.push(path)
    }
  }
  walk(root)
  return found.sort()
}

/** Where a build leaves its packaged artefacts. */
export const OUTPUTS = join(
  dirname(import.meta.dirname),
  'src-tauri',
  'gen',
  'android',
  'app',
  'build',
  'outputs'
)

/**
 * Checks one artefact. Answers the classes it is missing.
 */
export function missingFrom(path) {
  const classes = packagedClasses(path)
  return REQUIRED.filter((name) => !classes.has(name))
}

/**
 * Checks every artefact given, or everything a build has left under `outputs`.
 *
 * Answers true when every artefact carries every required class. Says which artefact was read and
 * what was missing, because "the build succeeded" is exactly the answer this check exists to
 * distrust.
 */
export function verify(paths) {
  const found = paths.length > 0 ? paths : artefacts(OUTPUTS)
  if (found.length === 0) {
    console.error(
      `No packaged application to check under ${OUTPUTS}.\n` +
        'Build one first: pnpm -C apps/companion android --debug --target aarch64'
    )
    return false
  }
  let whole = true
  for (const path of found) {
    let missing
    try {
      missing = missingFrom(path)
    } catch (failure) {
      console.error(`${relative(process.cwd(), path)}: ${failure.message}`)
      whole = false
      continue
    }
    if (missing.length === 0) {
      console.log(`${relative(process.cwd(), path)}: all ${REQUIRED.length} native classes present`)
      continue
    }
    whole = false
    console.error(
      `${relative(process.cwd(), path)} is missing ${missing.length} of ${REQUIRED.length} ` +
        'hand-written native classes:\n' +
        missing.map((name) => `  ${name}`).join('\n') +
        '\nThe application module is not compiling ' +
        'apps/companion/native/android/android/src/main/java into this build.'
    )
  }
  return whole
}

/** Lists what a packaged artefact holds of the hand-written packages. */
function list(paths) {
  const found = paths.length > 0 ? paths : artefacts(OUTPUTS)
  for (const path of found) {
    console.log(relative(process.cwd(), path))
    const classes = [...packagedClasses(path)]
      .filter((name) => HAND_WRITTEN.some((prefix) => name.startsWith(prefix)))
      .sort()
    for (const name of classes) console.log(`  ${name}`)
    console.log(`  (${classes.length} classes)`)
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const argv = process.argv.slice(2)
  const listing = argv.includes('--list')
  const paths = argv.filter((each) => each !== '--list')
  try {
    if (listing) list(paths)
    else if (!verify(paths)) process.exit(1)
  } catch (failure) {
    fail(failure.message)
  }
}
