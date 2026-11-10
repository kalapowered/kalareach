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
// Which artefacts a build is judged against comes from the build's own request, not from what is
// newest on disk: see "the packages one build was asked for".
//
// A minified build can also drop a class that nothing but native code reaches. A native library
// finds the Java classes it uses by name, and the minifier, which sees only Java, removes or renames
// a class no Java code refers to: the library still loads, and the application is aborted by the
// runtime the first time the library asks for the class. So the artefact's native libraries are read
// for the names they carry (see `android-native-names.mjs`), and each name must be defined, under
// that name, by the artefact's dex. The libraries come from the artefact itself, so a library that
// is updated brings its new names with it.
import { Buffer } from 'node:buffer'
import { inflateRawSync } from 'node:zlib'
import {
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  statSync
} from 'node:fs'
import { dirname, extname, join, relative, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import { jniMangled, libraryClassNames, libraryNatives, nativeSymbols } from './android-native-names.mjs'

/**
 * The classes a packaged application must define, by these exact names.
 *
 * Each is an entry point something resolves by name: the first from the manifest, the next two from
 * the work requests the receiver enqueues, the last by Tauri from the plugin's class name. That is
 * what makes them safe to demand of every build. A release build may rename or remove a class that
 * only other code reaches, so naming the keystore reader or a decision class here would fail a
 * release artefact that is perfectly correct. Between them they cover both trees: none exists at
 * all unless the module that holds it compiled it.
 *
 * `--list` prints everything the artefact carries of the hand-written packages, which is what to
 * read when a name is in question.
 */
const REQUIRED = [
  // The service the system starts when a push arrives, declared in the manifest.
  'to.kala.reach.companion.push.KalaReachMessagingService',
  // The work the message callback hands to the platform's scheduler: a notification it could not
  // finish showing, and a registration answer it could not finish posting.
  'to.kala.reach.companion.push.PreviewWorker',
  'to.kala.reach.companion.push.ChallengeWorker',
  // The plugin Tauri instantiates by its class name, which the library's consumer rules keep: it
  // carries the native commands the interface calls, and is in no package this check lists.
  'to.kala.reach.platform.PlatformPlugin'
]

/**
 * Where the source of each required class lives, for the failure to name. The service and the
 * workers are the application module's; the plugin is the platform library's, which reaches the
 * application through its own Gradle module and not through that source-set line.
 */
const SOURCES = {
  'to.kala.reach.platform.PlatformPlugin': 'apps/companion/native/platform/android/src/main/java'
}
const APPLICATION_SOURCES = 'apps/companion/native/android/android/src/main/java'

/** The source directories the missing classes belong to, for a failure to say what is not compiling. */
export function sourcesOf(missing) {
  return [...new Set(missing.map((name) => SOURCES[name] ?? APPLICATION_SOURCES))]
}

/** The packages whose classes are listed by `--list`. */
const HAND_WRITTEN = ['to.kala.reach.companion.push.', 'to.kala.reach.companion.mobile.']

/**
 * Where a packaged artefact keeps the code the runtime loads as the application.
 *
 * An APK's application dex files are at its root, and an AAB's are in its base module. A dex
 * anywhere else -- under `assets/`, or in an optional feature module -- is a file the application
 * may never load, so a class found there is no evidence that the application carries it.
 */
const DEX_MEMBER = { '.apk': /^classes\d*\.dex$/, '.aab': /^base\/dex\/classes\d*\.dex$/ }

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

/**
 * The entries of a candidate central directory, or null when it is not one.
 *
 * The entries must fill the candidate exactly. A record that claims the real directory and a few
 * bytes more parses as a prefix of it, and a record that claims more entries than are there runs
 * off the end; both leave the reader with part of the archive and no sign that the rest exists.
 */
function entries(directory, count) {
  const found = []
  let at = 0
  for (let index = 0; index < count; index += 1) {
    if (at + 46 > directory.length || directory.readUInt32LE(at) !== 0x02014b50) return null
    const nameLength = directory.readUInt16LE(at + 28)
    const extraLength = directory.readUInt16LE(at + 30)
    const commentLength = directory.readUInt16LE(at + 32)
    if (at + 46 + nameLength + extraLength + commentLength > directory.length) return null
    found.push({
      name: directory.subarray(at + 46, at + 46 + nameLength).toString('utf8'),
      method: directory.readUInt16LE(at + 10),
      compressedSize: directory.readUInt32LE(at + 20),
      uncompressedSize: directory.readUInt32LE(at + 24),
      headerAt: directory.readUInt32LE(at + 42)
    })
    at += 46 + nameLength + extraLength + commentLength
  }
  return at === directory.length ? found : null
}

/**
 * Every member of a zip archive, as name, offset, method and sizes.
 *
 * The end-of-central-directory record is the last thing in the file, after an archive comment of
 * up to 65535 bytes. Its signature is four bytes, so the same four bytes can sit inside that
 * comment, inside a member's own compressed data or inside a file that is no archive at all. A
 * candidate is therefore read as the format defines it and accepted only when everything it says
 * about itself agrees with where it sits: the comment it declares reaches exactly the end of the
 * file, the central directory it points at ends exactly where the record begins, that directory is
 * large enough for the entries it counts, and those entries parse and fill it exactly. A candidate
 * that fails any of those is not the record, and the search goes on past it.
 */
function members(handle, size) {
  const tailLength = Math.min(size, 0xffff + 22)
  const tailAt = size - tailLength
  const tail = readAt(handle, tailAt, tailLength)
  let zip64 = false
  for (let at = tail.length - 22; at >= 0; at -= 1) {
    if (tail.readUInt32LE(at) !== 0x06054b50) continue
    if (at + 22 + tail.readUInt16LE(at + 20) !== tail.length) continue
    const count = tail.readUInt16LE(at + 10)
    const directorySize = tail.readUInt32LE(at + 12)
    const directoryAt = tail.readUInt32LE(at + 16)
    if (count === 0xffff || directoryAt === 0xffffffff || directorySize === 0xffffffff) {
      // The real record of a zip64 archive keeps these fields in an extension this does not read.
      // Saying so is only right once the scan has found nothing better, because those same values
      // can be crafted into a comment.
      zip64 = true
      continue
    }
    if (directoryAt + directorySize !== tailAt + at) continue
    if (count * 46 > directorySize) continue
    const directory = readAt(handle, directoryAt, directorySize)
    if (directory.length !== directorySize) continue
    const found = entries(directory, count)
    if (found) return found
  }
  if (zip64) throw new Error('this archive uses zip64, which this check does not read')
  throw new Error('not a zip archive: no end-of-central-directory record')
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

/** The dex layouts this reads. Anything else is refused by name rather than guessed at. */
const DEX_VERSIONS = ['035', '037', '038', '039', '040']

/** Refuses a buffer that is not a dex layout this reads. */
function requireDex(dex) {
  const magic = dex.subarray(0, 8).toString('latin1')
  if (dex.length < 112 || !magic.startsWith('dex\n') || magic.charCodeAt(7) !== 0) {
    throw new Error('not a dex file')
  }
  const version = magic.slice(4, 7)
  if (!DEX_VERSIONS.includes(version)) {
    throw new Error(`dex version ${version} is not read here`)
  }
}

/** The string a dex file's string table holds at `stringIndex`. */
function stringAt(dex, stringIndex) {
  const dataAt = dex.readUInt32LE(dex.readUInt32LE(0x3c) + stringIndex * 4)
  // A string_data_item is its length in UTF-16 units, then modified UTF-8 up to a NUL. The
  // modified encoding differs from UTF-8 only for the NUL byte, which terminates here anyway,
  // and for characters outside the basic plane, which a Java identifier may hold but which no
  // name this check looks for does.
  const [, textAt] = leb128(dex, dataAt)
  const end = dex.indexOf(0, textAt)
  return dex.subarray(textAt, end).toString('utf8')
}

/**
 * Every string a dex file's string table holds: names, descriptors and the constants the code
 * carries. A name the code merely mentions is here as well as one it defines.
 */
export function definedStrings(dex) {
  requireDex(dex)
  const count = dex.readUInt32LE(0x38)
  const strings = []
  for (let index = 0; index < count; index += 1) strings.push(stringAt(dex, index))
  return strings
}

/** Every class a dex file defines, in source form (`a.b.C`, with `$` for a nested class). */
export function definedClasses(dex) {
  requireDex(dex)
  const typeIdsAt = dex.readUInt32LE(0x44)
  const classDefsCount = dex.readUInt32LE(0x60)
  const classDefsAt = dex.readUInt32LE(0x64)
  const descriptor = (typeIndex) => stringAt(dex, dex.readUInt32LE(typeIdsAt + typeIndex * 4))
  const classes = []
  for (let index = 0; index < classDefsCount; index += 1) {
    const type = descriptor(dex.readUInt32LE(classDefsAt + index * 32))
    if (type.startsWith('L') && type.endsWith(';')) {
      classes.push(type.slice(1, -1).replaceAll('/', '.'))
    }
  }
  return classes
}

/** The access flag of a method the runtime binds to native code. */
const ACC_NATIVE = 0x100

/**
 * Every class a dex file defines, with the native methods it declares: each one's name, and the
 * runtime's mangling of its argument types, which is what tells one overload from another.
 *
 * The methods are read from each class's own data item and not from the file's method table, which
 * lists the methods the code merely calls as well as the ones a class declares.
 */
export function definedNatives(dex) {
  requireDex(dex)
  const typeIdsAt = dex.readUInt32LE(0x44)
  const protoIdsAt = dex.readUInt32LE(0x4c)
  const methodIdsAt = dex.readUInt32LE(0x5c)
  const classDefsCount = dex.readUInt32LE(0x60)
  const classDefsAt = dex.readUInt32LE(0x64)
  const descriptor = (typeIndex) => stringAt(dex, dex.readUInt32LE(typeIdsAt + typeIndex * 4))
  /** The argument types of the method at `methodIndex`, from its prototype's type list. */
  const argumentsOf = (methodIndex) => {
    const proto = dex.readUInt16LE(methodIdsAt + methodIndex * 8 + 2)
    const listAt = dex.readUInt32LE(protoIdsAt + proto * 12 + 8)
    if (listAt === 0) return ''
    let types = ''
    for (let each = 0; each < dex.readUInt32LE(listAt); each += 1) {
      types += descriptor(dex.readUInt16LE(listAt + 4 + each * 2))
    }
    return types
  }
  const classes = new Map()
  for (let index = 0; index < classDefsCount; index += 1) {
    const classDef = classDefsAt + index * 32
    const type = descriptor(dex.readUInt32LE(classDef))
    if (!type.startsWith('L') || !type.endsWith(';')) continue
    const natives = []
    classes.set(type.slice(1, -1).replaceAll('/', '.'), natives)
    const dataAt = dex.readUInt32LE(classDef + 24)
    if (dataAt === 0) continue
    // The counts of the four lists, then the fields, which are skipped, then the two lists of methods.
    let at = dataAt
    const sizes = []
    for (let list = 0; list < 4; list += 1) {
      const [size, next] = leb128(dex, at)
      sizes.push(size)
      at = next
    }
    for (let skipped = 0; skipped < sizes[0] + sizes[1]; skipped += 1) {
      at = leb128(dex, leb128(dex, at)[1])[1]
    }
    for (const size of [sizes[2], sizes[3]]) {
      let methodIndex = 0
      for (let each = 0; each < size; each += 1) {
        const [step, afterIndex] = leb128(dex, at)
        const [flags, afterFlags] = leb128(dex, afterIndex)
        const [, afterCode] = leb128(dex, afterFlags)
        at = afterCode
        methodIndex += step
        if ((flags & ACC_NATIVE) !== 0) {
          natives.push({
            name: stringAt(dex, dex.readUInt32LE(methodIdsAt + methodIndex * 8 + 4)),
            signature: jniMangled(argumentsOf(methodIndex))
          })
        }
      }
    }
  }
  return classes
}

/**
 * Opens the archive at `path` and hands `visit` its members and a reader of one member's bytes.
 * The archive is closed when `visit` returns.
 */
export function withArchive(path, visit) {
  const handle = openSync(path, 'r')
  try {
    return visit(members(handle, statSync(path).size), (member) => contents(handle, member))
  } finally {
    closeSync(handle)
  }
}

/** The application's dex files in the packaged artefact at `path`, each as its bytes. */
export function applicationDex(path) {
  const application = DEX_MEMBER[extname(path).toLowerCase()]
  if (!application) throw new Error(`${extname(path)} is not a packaged Android application`)
  return withArchive(path, (all, read) => {
    const dexes = all.filter((member) => application.test(member.name))
    if (dexes.length === 0) throw new Error('the artefact carries no application dex file')
    return dexes.map((member) => read(member))
  })
}

/** Every class the packaged artefact at `path` defines as application code. */
function packagedClasses(path) {
  const classes = new Set()
  for (const dex of applicationDex(path)) {
    for (const name of definedClasses(dex)) classes.add(name)
  }
  return classes
}

/** How many problems the command lists before it says how many more there are. */
const MOST_PROBLEMS = 30

/** Where a packaged artefact keeps the native libraries the runtime loads, by ABI. */
const LIBRARY_MEMBER = {
  '.apk': /^lib\/[^/]+\/[^/]+\.so$/,
  '.aab': /^base\/lib\/[^/]+\/[^/]+\.so$/
}

/** `a`, then `b` and `c` as `a, b and c`. */
function and(items) {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`
}

/**
 * What the native libraries of the artefact at `path` find by name, read against the dex.
 *
 * Answers the libraries read, each with the number of classes and native methods it names; how many
 * different classes they name together; how many native methods the check asked a symbol for; the
 * classes that declare natives and were not asked; and the problems. One is a class a library names
 * that no dex file of the application defines under that name. Another is a native method of a
 * class the libraries are bound to, which the libraries of an ABI do not export: the runtime binds a
 * native method to the symbol its class and name make, the short one or, for an overload, the long
 * one that ends in its mangled argument types, and looks it up by that exact spelling, so a method
 * the minifier renamed has no symbol, and the call that reaches it throws. The last is a library
 * that one ABI carries and another lacks.
 *
 * A library is built once for each ABI, so a class is bound by a library, and not by an ABI: when
 * any ABI's copy of a library exports a native method for a class, the copy in every ABI that
 * carries the library is asked for all of the class's natives, whatever else that ABI exports.
 *
 * A class that declares natives and that no library exports a native for, such as the encoder of a
 * codec the library was built without, is not asked for symbols, in any ABI, and neither is a
 * library that registers its methods and exports none. A class some of whose natives a library
 * exports and the rest of which it registers is asked for all of them, and fails: nothing here
 * overrides that, so such a library would need the check told about it.
 */
export function nativeNames(path) {
  const kind = extname(path).toLowerCase()
  if (!DEX_MEMBER[kind]) throw new Error(`${kind} is not a packaged Android application`)
  return withArchive(path, (all, read) => {
    const dexes = all.filter((member) => DEX_MEMBER[kind].test(member.name))
    if (dexes.length === 0) throw new Error('the artefact carries no application dex file')
    const declared = new Map()
    for (const member of dexes) {
      for (const [name, natives] of definedNatives(read(member))) {
        declared.set(name, [...(declared.get(name) ?? []), ...natives])
      }
    }
    const files = all.filter((member) => LIBRARY_MEMBER[kind].test(member.name))
    if (files.length === 0) throw new Error('the artefact carries no native library')
    const libraries = []
    const named = new Map()
    const everyName = new Set()
    // Per ABI: the symbols its libraries export, as spelled, and the libraries it carries.
    const abis = new Map()
    // Per library file name: the ABIs that carry it. And per class: the libraries that export a
    // native method for it, in any ABI.
    const carriedBy = new Map()
    const boundBy = new Map()
    for (const member of files.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      let classes
      let natives
      try {
        const bytes = read(member)
        classes = libraryClassNames(bytes)
        natives = libraryNatives(bytes)
      } catch (failure) {
        throw new Error(`${member.name}: ${failure.message}`, { cause: failure })
      }
      libraries.push({ name: member.name, classes: classes.size, natives: natives.length })
      for (const name of classes) {
        everyName.add(name)
        if (!declared.has(name)) named.set(name, new Set([...(named.get(name) ?? []), member.name]))
      }
      const parts = member.name.split('/')
      const abi = parts.at(kind === '.aab' ? 2 : 1)
      const file = parts.at(-1)
      const there = abis.get(abi) ?? { symbols: new Set(), files: new Set() }
      there.files.add(file)
      carriedBy.set(file, new Set([...(carriedBy.get(file) ?? []), abi]))
      for (const { symbol, cls } of natives) {
        there.symbols.add(symbol)
        boundBy.set(cls, new Set([...(boundBy.get(cls) ?? []), file]))
      }
      abis.set(abi, there)
    }
    const unbound = new Map()
    const asked = new Set()
    const unasked = []
    for (const [name, natives] of declared) {
      const libraryFiles = boundBy.get(name)
      if (natives.length > 0 && !libraryFiles) unasked.push(name)
      if (!libraryFiles) continue
      for (const { name: method, signature } of natives) {
        // An overload is told apart by its arguments, so a class with two of a name says which.
        const overloaded = natives.filter((each) => each.name === method).length > 1
        const label = `${name}.${method}${overloaded ? ` (arguments ${signature || 'none'})` : ''}`
        const wanted = nativeSymbols(name, method, signature)
        for (const [abi, there] of abis) {
          if (![...libraryFiles].some((file) => there.files.has(file))) continue
          asked.add(label)
          if (wanted.some((symbol) => there.symbols.has(symbol))) continue
          unbound.set(label, new Set([...(unbound.get(label) ?? []), abi]))
        }
      }
    }
    const everyAbi = [...abis.keys()].sort()
    const lost = [...carriedBy]
      .filter(([, carrying]) => carrying.size < everyAbi.length)
      .map(([file, carrying]) => [
        file,
        `${and(everyAbi.filter((abi) => carrying.has(abi)))}, not in ${and(everyAbi.filter((abi) => !carrying.has(abi)))}`
      ])
    const byName = ([a], [b]) => (a < b ? -1 : 1)
    const problems = [
      ...[...named]
        .sort(byName)
        .map(([name, from]) => `class ${name} (named by ${and([...from])})`),
      ...[...unbound]
        .sort(byName)
        .map(([label, abiList]) => `native method ${label} (no library of ${and([...abiList])} exports it)`),
      ...lost.sort(byName).map(([file, where]) => `library ${file} (in ${where})`)
    ]
    return {
      libraries,
      classes: everyName.size,
      checked: asked.size,
      unasked: unasked.sort(),
      problems
    }
  })
}

// -- the check --------------------------------------------------------------------------------

/** Every APK and AAB under a directory. */
export function artefacts(root) {
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

// -- the packages one build was asked for -------------------------------------------------------
// A build is checked against the artefacts it asked for, named from the request itself.
//
// The outputs directory keeps every variant a tree has ever built, and a file's age says nothing
// about which variant it belongs to: a debug build would be judged against a release APK a later
// run left behind, an APK-only build against a stale bundle, and a packaging task that had nothing
// to do leaves its own output untouched, so the newest file of a kind need not be this build's at
// all. Each requested variant and format is named below instead, and an artefact the request calls
// for and the build did not leave stops the command rather than dropping out of the check.

/** The product flavour each target name builds, as the project's Gradle plugin declares them. */
const FLAVOURS = { aarch64: 'arm64', armv7: 'arm', i686: 'x86', x86_64: 'x86_64' }

/**
 * The options of `tauri android build` that this reads, and the ones it steps over.
 *
 * A token that is in none of these stops the command before it builds anything, which is what
 * makes reading the arguments safe here: an option this does not know could change which packages
 * a build produces, and narrowing the check silently is the failure the check exists to prevent.
 * (The empty-archive check in `android.mjs` reads no arguments at all, for the opposite reason: a
 * target *it* overlooked would simply go unexamined.)
 */
const FLAGS = new Set([
  '--debug',
  '--verbose',
  '--split-per-abi',
  '--apk',
  '--aab',
  '--open',
  '--ci',
  '--ignore-version-mismatches'
])
/** The short flags that carry no value, alone or bundled: `-dv` is `-d -v`. */
const SHORT_FLAGS = /^-[dvo]+$/
const LIST_OPTIONS = new Set(['-t', '--target', '-f', '--features'])
const VALUE_OPTIONS = new Set(['-c', '--config'])
const USAGE_OPTIONS = new Set(['-h', '--help', '-V', '--version'])

/**
 * What a build was asked to produce, from the arguments it was given.
 *
 * Answers the build type, the package formats and the product flavours, or null when the command
 * was asked for its own usage and will package nothing.
 */
export function requestFrom(argv) {
  let profile = 'release'
  let splitPerAbi = false
  let apk = false
  let aab = false
  const targets = []
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]
    // Everything after a bare `--` is passed on to the runner and is none of this command's.
    if (token === '--') break
    const equals = token.startsWith('--') ? token.indexOf('=') : -1
    const name = equals < 0 ? token : token.slice(0, equals)
    const joined = equals < 0 ? null : token.slice(equals + 1)
    if (USAGE_OPTIONS.has(name)) return null
    if (SHORT_FLAGS.test(name)) {
      if (name.includes('d')) profile = 'debug'
      continue
    }
    if (name === '--debug') profile = 'debug'
    else if (name === '--split-per-abi') splitPerAbi = true
    else if (name === '--apk') apk = true
    else if (name === '--aab') aab = true
    else if (FLAGS.has(name)) continue
    else if (VALUE_OPTIONS.has(name)) {
      if (joined === null) index += 1
    } else if (LIST_OPTIONS.has(name)) {
      const values = []
      if (joined === null) {
        while (index + 1 < argv.length && !argv[index + 1].startsWith('-')) {
          index += 1
          values.push(argv[index])
        }
      } else values.push(joined)
      if (name === '-t' || name === '--target') targets.push(...values)
    } else {
      throw new Error(
        `This build was given ${token}, which the packaged-class check does not read, so it ` +
          'cannot say which packages the build was asked for. Build with `pnpm -C apps/companion ' +
          'exec tauri android build` and check the package yourself with `pnpm -C apps/companion ' +
          'android:classes <path>`.'
      )
    }
  }
  for (const target of targets) {
    if (!Object.hasOwn(FLAVOURS, target)) {
      throw new Error(`${target} is not an Android target of this project`)
    }
  }
  // Without `--split-per-abi` the targets choose the architectures inside one universal package,
  // not which packages are built.
  const flavours = splitPerAbi
    ? [...new Set((targets.length > 0 ? targets : Object.keys(FLAVOURS)).map((t) => FLAVOURS[t]))]
    : ['universal']
  // Asked for neither format, the command builds both.
  const formats = apk || aab ? [...(apk ? ['apk'] : []), ...(aab ? ['aab'] : [])] : ['apk', 'aab']
  return { profile, formats, flavours }
}

/** `universalDebug` from `universal` and `debug`: the variant name the build tools use. */
function variantName(flavour, profile) {
  return `${flavour}${profile[0].toUpperCase()}${profile.slice(1)}`
}

/**
 * The APKs of one variant, from the metadata the packager writes beside them.
 *
 * That record names the variant it belongs to, which is the one thing about a file on disk that
 * says which build asked for it. It is read from the requested variant's own output directory and
 * refused when it describes another.
 */
function apksOf(outputs, flavour, profile) {
  const variant = variantName(flavour, profile)
  const directory = join(outputs, 'apk', flavour, profile)
  const record = join(directory, 'output-metadata.json')
  let text
  try {
    text = readFileSync(record, 'utf8')
  } catch (failure) {
    const why = failure.code === 'ENOENT' ? '' : `: ${failure.message}`
    throw new Error(`this build asked for the ${variant} APK and left no ${record}${why}`, {
      cause: failure
    })
  }
  let metadata
  try {
    metadata = JSON.parse(text)
  } catch (failure) {
    throw new Error(`${record} cannot be read: ${failure.message}`, { cause: failure })
  }
  if (metadata.variantName !== variant) {
    throw new Error(
      `${record} describes ${metadata.variantName}, not the ${variant} that was built`
    )
  }
  const elements = Array.isArray(metadata.elements) ? metadata.elements : []
  if (elements.length === 0) throw new Error(`${record} names no packaged file`)
  return elements.map((element) => {
    if (typeof element.outputFile !== 'string' || element.outputFile === '') {
      throw new Error(`${record} has an output with no file name`)
    }
    const path = resolve(directory, element.outputFile)
    if (!existsSync(path)) {
      throw new Error(`${record} names ${element.outputFile}, which this build did not leave`)
    }
    return path
  })
}

/**
 * The bundle of one variant.
 *
 * A bundle carries no metadata beside it, so the variant's own output directory is what identifies
 * it. More than one bundle there is an ambiguity, and choosing between them is exactly the guess
 * this check is here not to make.
 */
function bundleOf(outputs, variant) {
  const directory = join(outputs, 'bundle', variant)
  let names
  try {
    names = readdirSync(directory)
  } catch {
    throw new Error(`this build asked for the ${variant} bundle and left no ${directory}`)
  }
  const bundles = names.filter((name) => extname(name).toLowerCase() === '.aab').sort()
  if (bundles.length === 0) throw new Error(`${directory} holds no ${variant} bundle`)
  if (bundles.length > 1) {
    throw new Error(`${directory} holds ${bundles.length} bundles: ${bundles.join(', ')}`)
  }
  return join(directory, bundles[0])
}

/**
 * Every package the request calls for, whether or not the build rewrote it.
 *
 * A packaging task with nothing to do is a build that packaged the same thing again, so an
 * untouched artefact is as much this build's answer as a rewritten one and is checked the same.
 */
export function packagesOf(request, outputs = OUTPUTS) {
  const paths = []
  for (const flavour of request.flavours) {
    if (request.formats.includes('apk')) paths.push(...apksOf(outputs, flavour, request.profile))
    if (request.formats.includes('aab')) {
      paths.push(bundleOf(outputs, variantName(flavour, request.profile)))
    }
  }
  return paths
}

/**
 * Checks one artefact. Answers the classes it is missing.
 */
export function missingFrom(path) {
  const classes = packagedClasses(path)
  return REQUIRED.filter((name) => !classes.has(name))
}

/**
 * Checks every artefact given, or, when given none, everything under `outputs`.
 *
 * The directory-wide scan is what this command does when a person runs it by hand to ask what a
 * tree carries; it reads every artefact it finds and reports each one. A build passes the packages
 * it asked for instead; see `packagesOf`.
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
    const shown = relative(process.cwd(), path)
    let missing
    let reading
    try {
      missing = missingFrom(path)
      reading = nativeNames(path)
    } catch (failure) {
      console.error(`${shown}: ${failure.message}`)
      whole = false
      continue
    }
    if (missing.length === 0) {
      console.log(`${shown}: all ${REQUIRED.length} native classes present`)
    } else {
      whole = false
      console.error(
        `${shown} is missing ${missing.length} of ${REQUIRED.length} ` +
          'hand-written native classes:\n' +
          missing.map((name) => `  ${name}`).join('\n') +
          `\nThe build is not compiling ${sourcesOf(missing).join(' and ')} into this application.`
      )
    }
    if (reading.problems.length === 0) {
      console.log(
        `${shown}: its ${reading.libraries.length} native libraries name ${reading.classes} classes, ` +
          `all defined in its dex, and bind the ${reading.checked} native methods it declares in the ` +
          'classes they export natives for' +
          (reading.unasked.length > 0
            ? `; not asked, since no library exports a native of them: ${reading.unasked.join(', ')}`
            : '')
      )
      continue
    }
    whole = false
    const classes = reading.problems.filter((problem) => problem.startsWith('class '))
    const natives = reading.problems.filter((problem) => problem.startsWith('native method '))
    const lost = reading.problems.filter((problem) => problem.startsWith('library '))
    const lines = (problems) => {
      const first = problems.slice(0, MOST_PROBLEMS)
      const more = problems.length - first.length
      return first.map((problem) => `  ${problem}`).join('\n') + (more > 0 ? `\n  and ${more} more` : '')
    }
    console.error(
      `${shown}: its native libraries and its dex do not agree.` +
        (classes.length > 0
          ? `\n${classes.length} classes the libraries name, which the dex does not define under that ` +
            `name:\n${lines(classes)}\nNative code finds a class by name, and a minifier that sees no ` +
            'Java reaching it removes or renames it. Keep it in the rules of the library that carries it.'
          : '') +
        (natives.length > 0
          ? `\n${natives.length} native methods the dex declares, in classes the libraries export natives ` +
            `for, that no library exports:\n${lines(natives)}\nThe runtime binds a native method to the ` +
            'symbol its class, name and arguments make, spelled exactly. A method that has none was ' +
            'renamed, or its library registers its natives and does not export them.'
          : '') +
        (lost.length > 0
          ? `\n${lost.length} libraries that one ABI carries and another lacks:\n${lines(lost)}\n` +
            'A library is built for every ABI the package ships, and an ABI without it has none of its ' +
            'native methods.'
          : '')
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
