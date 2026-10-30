#!/usr/bin/env node
// Holds a store bundle to what the store and the application need of it.
//
// A build that succeeds is not a bundle a store takes. The ways a store build goes wrong without a
// failing build are the ones read here, from the finished file and not from the files that were
// meant to produce it:
//
//   Android  the signer is the upload key and nobody else (a debug key would be refused by Google
//            Play, and a lost upload key cannot be told from a wrong one afterwards); the version
//            code and name are the ones asked for; the manifest is the release's (not debuggable,
//            no cleartext traffic, the targets Google Play requires, the permissions this check
//            lists and the verified sign-in link); the native libraries are the architectures asked for and every
//            one is laid out for 16 KB memory pages; and no secret was packaged.
//   iOS      the version and build number agree across the application and its notification
//            extension (a store refuses an extension whose version differs); the push environment
//            is production; each executable is signed, with the entitlements the application
//            needs; and, for an exported bundle, each profile is an App Store profile of this team
//            and every piece of code under a bundle (each Mach-O file, nested or not) is signed by
//            a distribution certificate of the team, the bundle's own. A layout the check cannot
//            read as code (a symbolic link, a universal binary of several architectures) is refused.
//
// The identifiers (`identifiers.mjs`), the privacy manifest (`privacy-manifest.mjs`) and the debug
// code (`debug-code.mjs`) are read by the checks that own them and are run from here, so one
// command says whether a bundle can go to a store.
//
// A secret is a file whose path is given to `--secret-file`. It is read in this process, every
// decompressed member of the bundle (or every file of the application) is searched for it, and
// only the number of places it was found is printed. It is never part of a command line. It is
// searched for in the forms a file can hold it in (as it is, as a JSON writer escapes it, in hex of
// either case, in base64 and base64url, and with the white space removed, so a secret split across
// lines is found), after every JSON string escape in the searched text has been read, and in the
// names of files and archive members too. Whatever the command prints goes through one filter that
// withholds a message quoting a secret or any part of a signed token (all of them, when a secret
// file can be read and cannot be searched for). Not searched for: percent encoding, XML entities,
// compressed or encrypted copies, a second layer of encoding, hex with separators other than white
// space, a prefix on each line of a split secret, and a JSON escape that a line break cuts in two.
//
// Usage:
//   node scripts/store-bundle.mjs --android <app.aab> --version-code <n> --version-name <v>
//        --certificate <upload-certificate.pem> [--abis arm64-v8a,x86_64] [--secret-file <path> ...]
//        [--firebase <google-services.json>] [--record <store-build.json>] [--note key=value ...]
//   node scripts/store-bundle.mjs --scan-dir <directory> --secret-file <path> [--secret-file <path> ...]
//        (how many files under the directory hold a secret's text; bundles are read by the checks above)
//   node scripts/store-bundle.mjs --redact --secret-file <path> [--secret-file <path> ...]
//        (the text on the standard input, on the standard output once it is safe to show: all of it
//        withheld if it holds a secret, each line that holds a signed token or a part of one
//        withheld, nothing at all if a secret cannot be read)
//   node scripts/store-bundle.mjs --ios <app.ipa | KalaReach.app> --stage archive|export
//        --version-code <n> --version-name <v> [--skip-app-checks] [--secret-file <path> ...] [--record <file>]
//   `--skip-app-checks` leaves out the privacy-manifest and debug-code checks, which a caller runs on its own.
//   The record is written whether the bundle holds or not: it says which, and why.
// Exit 0 when the bundle holds, 1 when it does not, 2 when it could not be read.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { X509Certificate, createHash } from 'node:crypto'
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import { withArchive } from './android-classes.mjs'
import {
  declared,
  entitlementsOf,
  factsFromProto,
  plistValue,
  problemsInBundle,
  problemsInPackage
} from './identifiers.mjs'
import { problemsOfFit } from './sign-ios.mjs'

const SCRIPTS = import.meta.dirname

/** The Android platform levels Google Play and the application require. */
export const ANDROID_MIN_SDK = '29'
export const ANDROID_TARGET_SDK = '36'

/**
 * Every permission the release manifest ends up with once the libraries' own are merged in, in
 * the order they sort: the application's own and the ones its libraries add. A permission that is
 * not listed is a library that started to want one, and the store shows it to the person who
 * installs the application; a listed one that is gone is a change worth a look.
 */
export const ANDROID_PERMISSIONS = [
  'android.permission.ACCESS_NETWORK_STATE',
  'android.permission.CAMERA',
  'android.permission.FOREGROUND_SERVICE',
  'android.permission.FOREGROUND_SERVICE_MICROPHONE',
  'android.permission.INTERNET',
  'android.permission.POST_NOTIFICATIONS',
  'android.permission.READ_PHONE_STATE',
  'android.permission.RECORD_AUDIO',
  'android.permission.RECEIVE_BOOT_COMPLETED',
  'android.permission.USE_BIOMETRIC',
  'android.permission.USE_FINGERPRINT',
  'android.permission.WAKE_LOCK',
  'com.google.android.c2dm.permission.RECEIVE',
  'to.kala.reach.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'
]

// -- reading ---------------------------------------------------------------------------------

/** The SHA-256 of a file, as hex. */
export function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

/** The upper-case, colon-separated SHA-256 of a certificate in PEM form. */
export function certificateFingerprint(pem) {
  return new X509Certificate(pem).fingerprint256
}

/** What a bundle's manifest says, and every member of the bundle with its bytes read on demand. */
function openBundle(path, visit) {
  return withArchive(path, (members, read) => {
    const manifest = members.find((member) => member.name === 'base/manifest/AndroidManifest.xml')
    if (!manifest) throw new Error('the bundle holds no base/manifest/AndroidManifest.xml')
    return visit(factsFromProto(read(manifest)), members, read)
  })
}

// -- Android: the manifest -------------------------------------------------------------------

/** The value of the first attribute `name` of `element`, or undefined. */
function attribute(facts, element, name) {
  return facts.values.find(([each, key]) => each === element && key === name)?.[2]
}

/** Whether one intent filter of the manifest is the application's verified sign-in link. */
export function declaresSignInLink(root) {
  const filters = []
  const walk = (element) => {
    if (element.name === 'intent-filter') filters.push(element)
    element.children.forEach(walk)
  }
  walk(root)
  return filters.some((filter) => {
    const has = (child, name, value) =>
      filter.children.some((each) => each.name === child && each.attributes.some(([key, found]) => key === name && found === value))
    return (
      filter.attributes.some(([key, value]) => key === 'autoVerify' && value === 'true') &&
      has('action', 'name', 'android.intent.action.VIEW') &&
      has('category', 'name', 'android.intent.category.DEFAULT') &&
      has('category', 'name', 'android.intent.category.BROWSABLE') &&
      has('data', 'scheme', 'https') &&
      has('data', 'host', 'reach.kala.to') &&
      has('data', 'path', '/app/oauth/callback')
    )
  })
}

/** What is wrong with the manifest of a release bundle. */
export function problemsInAndroidManifest(facts, want) {
  const problems = []
  const expect = (what, found, wanted) => {
    if (found !== wanted) problems.push(`${what} is ${JSON.stringify(found)}, not ${JSON.stringify(wanted)}`)
  }
  expect('the manifest package', facts.package, want.identifier)
  expect('the version code', attribute(facts, 'manifest', 'versionCode'), String(want.versionCode))
  expect('the version name', attribute(facts, 'manifest', 'versionName'), want.versionName)
  expect('minSdkVersion', attribute(facts, 'uses-sdk', 'minSdkVersion'), ANDROID_MIN_SDK)
  expect('targetSdkVersion', attribute(facts, 'uses-sdk', 'targetSdkVersion'), ANDROID_TARGET_SDK)
  expect('android:usesCleartextTraffic', attribute(facts, 'application', 'usesCleartextTraffic'), 'false')
  for (const flag of ['debuggable', 'testOnly']) {
    const value = attribute(facts, 'application', flag) ?? attribute(facts, 'manifest', flag)
    if (value !== undefined && value !== 'false') problems.push(`the manifest sets ${flag} to ${value}`)
  }
  const permissions = facts.values
    .filter(([element, key]) => /^uses-permission(-sdk-23)?$/.test(element) && key === 'name')
    .map(([, , value]) => value)
  const found = [...new Set(permissions)].sort()
  const wanted = [...ANDROID_PERMISSIONS].sort()
  for (const each of found.filter((name) => !wanted.includes(name))) {
    problems.push(`the manifest asks for ${each}, which this check does not list`)
  }
  for (const each of wanted.filter((name) => !found.includes(name))) {
    problems.push(`the manifest does not ask for ${each}, which this check lists`)
  }
  // The sign-in's answer returns through this verified link; without it the answer opens a browser.
  if (!declaresSignInLink(facts.root)) {
    problems.push('the manifest does not declare the verified sign-in link https://reach.kala.to/app/oauth/callback in one intent filter')
  }
  return problems
}

// -- Android: the native libraries -----------------------------------------------------------

/** What is wrong with the memory layout of one ELF64 little-endian library. */
export function problemsInElf(name, bytes) {
  if (bytes.length < 64 || bytes.readUInt32BE(0) !== 0x7f454c46 || bytes[4] !== 2 || bytes[5] !== 1) {
    return [`${name} is not a 64-bit little-endian ELF library`]
  }
  const headers = Number(bytes.readBigUInt64LE(0x20))
  const size = bytes.readUInt16LE(0x36)
  const count = bytes.readUInt16LE(0x38)
  if (headers === 0 || size < 56 || headers + size * count > bytes.length) {
    return [`${name} has no readable program headers`]
  }
  const problems = []
  let loads = 0
  for (let index = 0; index < count; index += 1) {
    const at = headers + index * size
    if (bytes.readUInt32LE(at) !== 1) continue
    loads += 1
    const alignment = Number(bytes.readBigUInt64LE(at + 48))
    if (alignment < 16384) problems.push(`${name} aligns a loadable segment to ${alignment} bytes, not 16384`)
  }
  if (loads === 0) problems.push(`${name} has no loadable segment`)
  return problems
}

// -- the push gateway the packaged code registers with ------------------------------------------

/**
 * What the companion's build step writes into the library, between two unit separators: this name,
 * then the push gateway the build was given, which is empty for an official build. The library
 * reads its gateway from that same text, so the record cannot disagree with what the library uses.
 * The name is `RECORD_NAME` in `src-tauri/build_push_gateway.rs`.
 */
export const PUSH_GATEWAY_RECORD_NAME = 'kr-push-gateway-origin'

const RECORD_HEAD = Buffer.from(`\x1f${PUSH_GATEWAY_RECORD_NAME}\x1f`)

/** The longest origin a record can hold: 128 bytes after `https://`, with a margin. */
const LONGEST_RECORDED_ORIGIN = 256

/** The records of the push gateway in `bytes`: the origin each holds, or null for one that cannot be read. */
export function pushGatewayRecords(bytes) {
  const records = []
  for (let at = bytes.indexOf(RECORD_HEAD); at !== -1; at = bytes.indexOf(RECORD_HEAD, at + 1)) {
    const start = at + RECORD_HEAD.length
    const end = bytes.indexOf(0x1f, start)
    const value = end === -1 ? null : bytes.subarray(start, end)
    const readable = value !== null && value.length <= LONGEST_RECORDED_ORIGIN && value.every((byte) => byte >= 0x20 && byte <= 0x7e)
    records.push(readable ? value.toString('latin1') : null)
  }
  return records
}

/**
 * What is wrong with the push gateway the code in `bytes` registers with. A store bundle is the
 * official build, which registers with the official gateway and is given none, so its code holds
 * exactly one record and the record is empty. Anything else is a build made around another gateway,
 * or by something other than the companion's build step.
 */
export function problemsInPushGateway(name, bytes) {
  const records = pushGatewayRecords(bytes)
  if (records.length === 0) return [`${name} carries no record of the push gateway it registers with`]
  if (records.length > 1) return [`${name} carries ${records.length} records of the push gateway it registers with, not one`]
  const [origin] = records
  if (origin === null) return [`${name} carries a record of its push gateway that cannot be read`]
  if (origin !== '') return [`${name} registers with the push gateway ${origin}; an official build is given none and registers with the official one`]
  return []
}

/** The library of the companion in an Android bundle: the package's library, `companion_tauri`. */
const ANDROID_COMPANION_LIBRARY = 'libcompanion_tauri.so'

/** The architectures and libraries a bundle packages, and what is wrong with them. */
export function problemsInAndroidLibraries(members, read, abis) {
  const problems = []
  const found = new Map()
  for (const member of members) {
    const match = /^base\/lib\/([^/]+)\/[^/]+\.so$/.exec(member.name)
    if (!match) continue
    if (!found.has(match[1])) found.set(match[1], [])
    found.get(match[1]).push(member)
  }
  const have = [...found.keys()].sort()
  const want = [...abis].sort()
  if (have.join(',') !== want.join(',')) {
    problems.push(`the bundle packages the architectures ${have.join(', ') || 'none'}, not ${want.join(', ')}`)
  }
  for (const [abi, libraries] of found) {
    for (const library of libraries) {
      const label = `${abi}/${library.name.split('/').pop()}`
      const bytes = read(library)
      problems.push(...problemsInElf(label, bytes))
      if (library.name.endsWith(`/${ANDROID_COMPANION_LIBRARY}`)) problems.push(...problemsInPushGateway(label, bytes))
    }
    if (!libraries.some((library) => library.name.endsWith(`/${ANDROID_COMPANION_LIBRARY}`))) {
      problems.push(`the bundle packages no ${ANDROID_COMPANION_LIBRARY} for ${abi}`)
    }
  }
  if (!members.some((member) => member.name.startsWith('base/dex/'))) problems.push('the bundle holds no dex file')
  return problems
}

// -- secrets ---------------------------------------------------------------------------------

/** The shape of a signed token: three base64url parts, the first two of JSON (`eyJ`). */
const TOKEN_SHAPE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/

/** Any part of a signed token that can stand alone: the start of a base64url JSON object. */
const TOKEN_PART = /eyJ[A-Za-z0-9_-]{8,}/

/** No secret to search for. */
const NO_NEEDLES = { forms: [], apart: [], hex: [] }

/** The bytes of the escapes JSON allows a single character after a backslash, and what each stands for. */
const SIMPLE_ESCAPES = new Map([
  [0x22, 0x22],
  [0x5c, 0x5c],
  [0x2f, 0x2f],
  [0x62, 0x08],
  [0x66, 0x0c],
  [0x6e, 0x0a],
  [0x72, 0x0d],
  [0x74, 0x09]
])

/** The value of one hexadecimal digit, or -1. */
function digitOf(byte) {
  if (byte >= 0x30 && byte <= 0x39) return byte - 0x30
  const lower = byte | 0x20
  return lower >= 0x61 && lower <= 0x66 ? lower - 0x61 + 10 : -1
}

/** The value of four hexadecimal digits from `at`, or -1. */
function fourDigits(bytes, at) {
  let value = 0
  for (let index = 0; index < 4; index += 1) {
    const digit = at + index < bytes.length ? digitOf(bytes[at + index]) : -1
    if (digit < 0) return -1
    value = value * 16 + digit
  }
  return value
}

/** Writes a code point as UTF-8 and answers how many bytes it took. */
function putUtf8(out, at, point) {
  if (point < 0x80) {
    out[at] = point
    return 1
  }
  if (point < 0x800) {
    out[at] = 0xc0 | (point >> 6)
    out[at + 1] = 0x80 | (point & 0x3f)
    return 2
  }
  if (point < 0x10000) {
    out[at] = 0xe0 | (point >> 12)
    out[at + 1] = 0x80 | ((point >> 6) & 0x3f)
    out[at + 2] = 0x80 | (point & 0x3f)
    return 3
  }
  out[at] = 0xf0 | (point >> 18)
  out[at + 1] = 0x80 | ((point >> 12) & 0x3f)
  out[at + 2] = 0x80 | ((point >> 6) & 0x3f)
  out[at + 3] = 0x80 | (point & 0x3f)
  return 4
}

/**
 * The bytes with every escape of a JSON string read as a JSON reader reads it (`\"`, `\\`, `\/`, `\n`
 * and the others, `\uXXXX` with a pair of surrogates joined), wherever it sits: in a JSON file whole
 * or in a line of a log, a long file or a short message. Null when there is no escape to read.
 */
function unescaped(bytes) {
  if (!bytes.includes(0x5c)) return null
  const out = Buffer.allocUnsafe(bytes.length)
  let length = 0
  let changed = false
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index]
    if (byte !== 0x5c || index + 1 >= bytes.length) {
      out[length] = byte
      length += 1
      continue
    }
    const next = bytes[index + 1]
    if (SIMPLE_ESCAPES.has(next)) {
      out[length] = SIMPLE_ESCAPES.get(next)
      length += 1
      index += 1
      changed = true
      continue
    }
    const code = next === 0x75 ? fourDigits(bytes, index + 2) : -1
    if (code >= 0) {
      let point = code
      let width = 6
      if (code >= 0xd800 && code <= 0xdbff && bytes[index + 6] === 0x5c && bytes[index + 7] === 0x75) {
        const low = fourDigits(bytes, index + 8)
        if (low >= 0xdc00 && low <= 0xdfff) {
          point = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00)
          width = 12
        }
      }
      length += putUtf8(out, length, point)
      index += width - 1
      changed = true
      continue
    }
    out[length] = byte
    length += 1
  }
  return changed ? out.subarray(0, length) : null
}

/** The bytes as they are, and as a JSON reader would read them when that differs. */
function viewsOf(bytes) {
  const read = unescaped(bytes)
  return read === null ? [bytes] : [bytes, read]
}

/**
 * The bytes with the white space left out, and a backslash that ends a line (the continuation of a
 * properties file, a shell, a C string): a secret that was wrapped, indented or joined across lines
 * is the same secret without them.
 */
function squash(bytes) {
  const kept = Buffer.allocUnsafe(bytes.length)
  let length = 0
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index]
    if (byte === 0x20 || (byte >= 0x09 && byte <= 0x0d)) continue
    if (byte === 0x5c && (bytes[index + 1] === 0x0a || bytes[index + 1] === 0x0d)) continue
    kept[length] = byte
    length += 1
  }
  return kept.subarray(0, length)
}

/** The bytes with the capital letters of ASCII made small: hex digits come in either case, or both. */
function lowered(bytes) {
  const out = Buffer.allocUnsafe(bytes.length)
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index]
    out[index] = byte >= 0x41 && byte <= 0x5a ? byte | 0x20 : byte
  }
  return out
}

/**
 * The forms one piece of a secret takes in a file besides its hex: as it is, and in base64 and
 * base64url. A text inside a longer one encodes differently by where it starts among the groups of
 * three bytes, so each of the three starts is taken, and only the characters that the neighbouring
 * bytes cannot change.
 */
function formsOf(bytes) {
  const forms = [bytes]
  for (let before = 0; before < 3; before += 1) {
    const encoded = Buffer.concat([Buffer.alloc(before), bytes]).toString('base64')
    const core = encoded.slice(Math.ceil((before * 8) / 6), Math.floor(((before + bytes.length) * 8) / 6))
    forms.push(Buffer.from(core), Buffer.from(core.replaceAll('+', '-').replaceAll('/', '_')))
  }
  return forms.filter((form) => form.length >= 8)
}

/**
 * What stands for a secret file in a search: its whole content, trimmed, and each of its lines of 32
 * characters or more, so a key block pasted in pieces is found by any whole line of it. Each piece
 * is taken as it is and as a JSON writer escapes it, and each of those in the forms `formsOf` lists
 * and in hex. A haystack is read as it is and as a JSON reader reads it, and each reading is
 * searched as it is, with its white space left out (`apart`, so a secret split across lines is
 * found) and, for hex, with its capitals made small (`hex`). A secret of fewer than 8 bytes, not counting
 * white space, is refused: it would match anything.
 */
export function secretNeedles(content) {
  const text = content.toString('utf8').trim()
  if (squash(Buffer.from(text, 'utf8')).length < 8) {
    throw new Error('a secret file holds fewer than 8 bytes apart from white space, too few to search for')
  }
  const pieces = new Set([text])
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed.length >= 32 && !trimmed.startsWith('-----')) pieces.add(trimmed)
  }
  for (const piece of [...pieces]) pieces.add(JSON.stringify(piece).slice(1, -1))
  const forms = new Map()
  const hex = new Map()
  for (const piece of pieces) {
    const bytes = Buffer.from(piece, 'utf8')
    for (const form of formsOf(bytes)) forms.set(form.toString('latin1'), form)
    hex.set(bytes.toString('hex'), Buffer.from(bytes.toString('hex')))
  }
  const apart = new Map()
  for (const form of forms.values()) {
    const squashed = squash(form)
    if (squashed.length >= 8) apart.set(squashed.toString('latin1'), squashed)
  }
  return { forms: [...forms.values()], apart: [...apart.values()], hex: [...hex.values()] }
}

/** The needles of several secrets as one. */
function mergeNeedles(list) {
  return { forms: list.flatMap((each) => each.forms), apart: list.flatMap((each) => each.apart), hex: list.flatMap((each) => each.hex) }
}

/** Whether the bytes hold any form of the secret, as they are or as a JSON reader reads them, whole, with the white space gone, or in hex of either case. */
function foundIn(bytes, needles) {
  for (const view of viewsOf(bytes)) {
    if (needles.forms.some((form) => view.includes(form))) return true
    if (needles.apart.length === 0 && needles.hex.length === 0) continue
    const apart = squash(view)
    if (needles.apart.some((form) => apart.includes(form))) return true
    if (needles.hex.length > 0) {
      const small = lowered(apart)
      if (needles.hex.some((form) => small.includes(form))) return true
    }
  }
  return false
}

/** Whether the pattern matches the bytes as they are or as a JSON reader reads them. */
function matches(pattern, bytes) {
  return viewsOf(bytes).some((view) => pattern.test(view.toString('latin1')))
}

/** Whether bytes hold a secret's text or a signed token. */
function holdsSecret(bytes, needles) {
  return foundIn(bytes, needles) || matches(TOKEN_SHAPE, bytes)
}

/** Whether a text that is to be shown or written holds a secret, or any part of a signed token. */
function quotesSecret(text, needles) {
  const bytes = Buffer.from(text, 'utf8')
  return foundIn(bytes, needles) || matches(TOKEN_PART, bytes)
}

/**
 * The first text that does not itself hold the secret: the words this check puts in place of a
 * quotation could be the secret's, and then nothing is printed. A text of fewer than eight
 * characters cannot be one, since no secret is shorter.
 */
function stand(needles, ...candidates) {
  return candidates.find((each) => !quotesSecret(each, needles)) ?? ''
}

/** How many of the buffers hold a secret's text or a signed token. */
export function placesWithSecret(buffers, needles) {
  let places = 0
  for (const bytes of buffers) {
    if (holdsSecret(bytes, needles)) places += 1
  }
  return places
}

/** The needles of every secret file named, or throws if one cannot be read. */
function needlesOf(files) {
  return mergeNeedles(files.map((file) => secretNeedles(readFileSync(file))))
}

/**
 * The needles of the secret files that can be read, and whether one that was read cannot be searched
 * for (too short). A secret that cannot be read cannot be quoted; one that was read and cannot be
 * searched for may be quoted by anything, so nothing is to be printed that could hold it.
 */
function quotableNeedles(secretFiles) {
  let unusable = false
  const list = secretFiles.map((file) => {
    let content
    try {
      content = readFileSync(file)
    } catch {
      return NO_NEEDLES
    }
    try {
      return secretNeedles(content)
    } catch {
      unusable = true
      return NO_NEEDLES
    }
  })
  return { needles: mergeNeedles(list), unusable }
}

// -- Android: the signature and the bundle tool ----------------------------------------------

function run(program, args) {
  const answer = spawnSync(program, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  if (answer.error) throw new Error(`${program} could not run: ${answer.error.message}`)
  return answer
}

/** What is wrong with the bundle's signature: it must verify, and be the upload key's. */
export function problemsInSignature(path, certificatePem) {
  const problems = []
  const verified = run('jarsigner', ['-verify', path])
  if (verified.status !== 0 || !/jar verified/.test(verified.stdout)) {
    problems.push(`jarsigner does not verify the bundle: ${(verified.stdout + verified.stderr).trim().split('\n')[0]}`)
    return { problems, signer: null }
  }
  // `jarsigner -verify` answers "jar verified" for an archive that also holds entries nobody
  // signed, and says so only in a warning.
  if (/unsigned entries/.test(verified.stdout + verified.stderr)) {
    problems.push('the bundle holds entries that are not signed')
  }
  const printed = run('keytool', ['-printcert', '-jarfile', path])
  const signers = [...printed.stdout.matchAll(/SHA256:\s*([0-9A-F:]{95})/g)].map((each) => each[1])
  if (printed.status !== 0 || signers.length === 0) {
    problems.push('keytool printed no signer certificate for the bundle')
    return { problems, signer: null }
  }
  const wanted = certificateFingerprint(certificatePem)
  if (signers.length !== 1) problems.push(`the bundle has ${signers.length} signers, not one`)
  if (!signers.includes(wanted)) problems.push('the bundle is not signed by the upload key (its certificate differs)')
  return { problems, signer: signers[0] }
}

/** What is wrong with the bundle's configuration as `bundletool dump config` prints it. */
export function problemsInBundleConfig(text) {
  return /PAGE_ALIGNMENT_16K/.test(text) ? [] : ['the bundle configuration does not ask for 16 KB page alignment']
}

/** The bundle tool's own validation, and whether it laid the libraries out for 16 KB pages. */
export function problemsInBundletool(path, bundletool) {
  const problems = []
  const checked = run(bundletool, ['validate', `--bundle=${path}`])
  if (checked.status !== 0) {
    problems.push(`bundletool does not validate the bundle: ${(checked.stdout + checked.stderr).trim().split('\n')[0]}`)
  }
  const config = run(bundletool, ['dump', 'config', `--bundle=${path}`])
  if (config.status !== 0) problems.push('bundletool could not print the bundle configuration')
  else problems.push(...problemsInBundleConfig(config.stdout))
  return problems
}

/** The version the bundle tool reports. */
export function bundletoolVersion(bundletool) {
  const answer = run(bundletool, ['version'])
  return answer.status === 0 ? answer.stdout.trim().split('\n')[0] : 'unknown'
}

// -- Android: the whole check ----------------------------------------------------------------

/**
 * Whether the bundle's resource table carries the Firebase configuration of the application: the
 * project and the application the configuration file names. Only a yes or no leaves this function.
 */
export function problemsInFirebase(resources, configuration, identifier) {
  const client = (configuration.client ?? []).find((each) => each?.client_info?.android_client_info?.package_name === identifier)
  const wanted = [configuration.project_info?.project_id, client?.client_info?.mobilesdk_app_id]
  if (wanted.some((each) => typeof each !== 'string' || each === '')) {
    return [`the Firebase configuration names no application ${identifier}`]
  }
  const missing = wanted.filter((each) => !resources.includes(Buffer.from(each, 'utf8')))
  return missing.length === 0 ? [] : ['the bundle does not carry the Firebase configuration of the application']
}

/**
 * A bundle that holds a secret is reported by that fact alone: every other problem quotes values
 * out of the bundle (a version name, a manifest value), and a quoted value could be the secret.
 */
export function suppressedIfSecret(result) {
  if (!(result.facts.secretsFound > 0)) return result
  const found = result.facts.secretsFound
  return { problems: [`a secret file's text is in ${found} place${found === 1 ? '' : 's'} of the bundle; nothing else is reported`], facts: { secretsFound: found } }
}

/**
 * How many files under a directory hold a secret's text or a signed token, a bundle counting once
 * for each member that does (a bundle is compressed, so its bytes are searched member by member).
 * A name is searched like content: the directory's own path, the name of each directory and file
 * under it and of each archive member, since each is printed or written somewhere. `.apks` files hold
 * other packages whole and are left out: each package is read as an `.apk`. A link, or anything that
 * is neither a file nor a directory, is refused: the scan cannot say what it holds.
 */
export function secretsUnder(directory, needles) {
  const tree = treeUnder(directory)
  if (tree.unread.length > 0) {
    throw new Error(`${relative(directory, tree.unread[0])} is a link or a special file, which this scan cannot read`)
  }
  const holds = (text) => holdsSecret(Buffer.from(text, 'utf8'), needles)
  let places = [directory, resolve(directory)].some(holds) ? 1 : 0
  places += tree.folders.filter((folder) => holds(relative(directory, folder))).length
  for (const file of tree.files) {
    if (holds(relative(directory, file))) {
      places += 1
    } else if (/\.apks$/.test(file)) {
      continue
    } else if (/\.(aab|ipa|apk)$/.test(file)) {
      places += withArchive(file, (members, read) => members.filter((member) => holds(member.name) || holdsSecret(read(member), needles)).length)
    } else if (holdsSecret(readFileSync(file), needles)) {
      places += 1
    }
  }
  return places
}

/** A message with nothing of it left when it quotes a secret or any part of a signed token. */
export function withheldIfSecret(message, needles) {
  return quotesSecret(message, needles) ? stand(needles, 'the details are withheld: they quote a secret file', 'withheld') : message
}

/**
 * Text from a log, for a person to read: all of it left out when it holds the secret in any form (a
 * log that holds it at all is not to be trusted with what is left of it), and each line that holds a
 * signed token or any part of one, as written or as a JSON reader reads it.
 */
export function redacted(text, needles) {
  if (foundIn(Buffer.from(text, 'utf8'), needles)) return `${stand(needles, 'the text is withheld: it quotes a secret file', 'withheld')}\n`
  const line = stand(needles, 'a line is withheld: it quotes a signed token', 'withheld')
  const kept = text
    .split('\n')
    .map((each) => (matches(TOKEN_PART, Buffer.from(each, 'utf8')) ? line : each))
    .join('\n')
  // The lines left, with the words put in place of the others, are one text again.
  return foundIn(Buffer.from(kept, 'utf8'), needles) ? `${stand(needles, 'the text is withheld: it quotes a secret file', 'withheld')}\n` : kept
}

/** The fields of a record that the bundle's identity and the result of the check own: no note and no fact may be named like one. */
export const RECORD_FIELDS = ['file', 'platform', 'stage', 'versionName', 'versionCode', 'bytes', 'sha256', 'holds', 'problems']

/**
 * The text of a build's record and its problems. A record that would quote a secret or a signed
 * token anywhere, its identity included, is replaced by one that holds only what is safe of the
 * identity and says why, and that is a problem of its own, so the build does not hold. The record is
 * searched as the text it is written as, in which JSON escapes the secret, and as a JSON reader
 * reads it. A note or a fact named like a field of the record is refused: it would replace that
 * field before the record is searched.
 */
export function recordOf({ identity, problems, facts, notes }, needles) {
  for (const key of Object.keys(facts)) {
    if (RECORD_FIELDS.includes(key)) throw new Error(`a fact of the record is named like a field of the record: ${key}`)
  }
  for (const key of Object.keys(notes)) {
    if (RECORD_FIELDS.includes(key) || Object.hasOwn(facts, key)) throw new Error(`a note of the record is named like a field or a fact of the record: ${key}`)
  }
  const text = (value) => `${JSON.stringify(value, null, 2)}\n`
  const record = (holds, list, who, rest) => ({ ...who, holds, problems: list, ...rest })
  const whole = text(record(problems.length === 0, problems, identity, { ...facts, ...notes }))
  if (!quotesSecret(whole, needles)) return { problems, text: whole }
  const withheld = stand(needles, 'the details are withheld: the record quotes a secret file', 'withheld')
  const safe = (value) => (typeof value === 'string' ? withheldIfSecret(value, needles) : value)
  let replacement = text(record(false, [withheld], { ...identity, file: safe(identity.file), versionName: safe(identity.versionName) }, {}))
  // The rest of the identity is a platform, a stage, two numbers and a digest. Were one of them the
  // secret, or the words above, nothing of the identity is kept, and then nothing but braces.
  if (quotesSecret(replacement, needles)) replacement = text({ holds: false, problems: [withheld] })
  if (quotesSecret(replacement, needles)) replacement = '{}\n'
  return { problems: [...problems, withheld], text: replacement }
}

/**
 * The secret-bearing places of a bundle, before anything else is read from it: the other checks
 * quote values out of the bundle and raise errors that name them.
 */
function secretFirst(places) {
  return suppressedIfSecret({ problems: [], facts: { secretsFound: places } })
}

export function checkAndroid(options) {
  const problems = []
  const facts = {}
  const certificatePem = readFileSync(options.certificate, 'utf8')
  const identifier = declared(dirname(SCRIPTS)).identifier
  const needles = needlesOf(options.secretFiles)
  const first = withArchive(options.path, (members, read) => placesWithSecret(members.flatMap((member) => [Buffer.from(member.name, 'utf8'), read(member)]), needles))
  if (first > 0) return secretFirst(first)
  facts.secretsFound = 0
  openBundle(options.path, (manifest, members, read) => {
    problems.push(
      ...problemsInAndroidManifest(manifest, {
        identifier,
        versionCode: options.versionCode,
        versionName: options.versionName
      })
    )
    problems.push(...problemsInAndroidLibraries(members, read, options.abis))
    facts.members = members.length
    if (options.firebase) {
      const table = members.find((member) => member.name === 'base/resources.pb')
      const problemsOfTable = table
        ? problemsInFirebase(read(table), JSON.parse(readFileSync(options.firebase, 'utf8')), identifier)
        : ['the bundle holds no resource table']
      facts.firebaseConfigured = problemsOfTable.length === 0
      problems.push(...problemsOfTable)
    }
    facts.mapping = members.some((member) => member.name.includes('proguard.map'))
  })
  const signature = problemsInSignature(options.path, certificatePem)
  problems.push(...signature.problems)
  facts.signerSha256 = signature.signer
  if (options.bundletool) {
    problems.push(...problemsInBundletool(options.path, options.bundletool))
    facts.bundletool = bundletoolVersion(options.bundletool)
  }
  problems.push(...problemsInPackage(options.path))
  return suppressedIfSecret({ problems, facts })
}

// -- iOS -------------------------------------------------------------------------------------

/** The bundles of an application: the application, then each extension. */
function iosBundles(app) {
  const bundles = [{ name: 'the application', path: app }]
  const plugins = join(app, 'PlugIns')
  if (existsSync(plugins)) {
    for (const entry of readdirSync(plugins).sort()) {
      if (entry.endsWith('.appex')) bundles.push({ name: entry, path: join(plugins, entry) })
    }
  }
  return bundles
}

/** What is wrong with an App Store provisioning profile's content. */
export function problemsInProfile(profile, { team, identifier, push = true, now = new Date() }) {
  const problems = []
  const entitlements = profile.Entitlements ?? {}
  if (profile.TeamIdentifier?.[0] !== team) problems.push(`its team is ${profile.TeamIdentifier?.[0]}, not ${team}`)
  if (entitlements['application-identifier'] !== `${team}.${identifier}`) {
    problems.push(`its application identifier is ${entitlements['application-identifier']}`)
  }
  // A bundle that receives push needs the production environment; one that does not (the extension
  // is started by the system with the notification and registers for nothing) may carry none.
  const environment = entitlements['aps-environment']
  if (push ? environment !== 'production' : environment !== undefined && environment !== 'production') {
    problems.push('its push environment is not production')
  }
  if (entitlements['get-task-allow'] !== false) problems.push('it lets a debugger attach')
  if (profile.ProvisionedDevices !== undefined) problems.push('it lists devices, so it is not an App Store profile')
  if (profile.ProvisionsAllDevices === true) problems.push('it is an enterprise profile')
  if (!(new Date(profile.ExpirationDate) > now)) problems.push('it has expired')
  return problems
}

/**
 * What a decoded provisioning profile says, key by key. A profile holds data and dates, which a
 * conversion of the whole to JSON refuses, so each value is taken on its own; a key an App Store
 * profile does not have (`ProvisionedDevices`) is simply absent.
 */
export function profileFromXml(xml) {
  const take = (key, format) => {
    const answer = spawnSync('plutil', ['-extract', key, format, '-o', '-', '-'], { input: xml, encoding: 'utf8' })
    if (answer.error || answer.status !== 0) return undefined
    return format === 'json' ? JSON.parse(answer.stdout) : answer.stdout.trim()
  }
  const profile = {
    Name: take('Name', 'raw'),
    UUID: take('UUID', 'raw'),
    TeamIdentifier: take('TeamIdentifier', 'json'),
    ExpirationDate: take('ExpirationDate', 'raw'),
    Entitlements: take('Entitlements', 'json'),
    ProvisionedDevices: take('ProvisionedDevices', 'json'),
    ProvisionsAllDevices: take('ProvisionsAllDevices', 'raw') === 'true' ? true : undefined
  }
  // The certificates a profile lets sign for it, each as the SHA-1 of its DER form.
  profile.CertificateSha1s = []
  for (let at = 0; ; at += 1) {
    const one = spawnSync('plutil', ['-extract', `DeveloperCertificates.${at}`, 'raw', '-o', '-', '-'], { input: xml, encoding: 'utf8' })
    if (one.error || one.status !== 0) break
    profile.CertificateSha1s.push(createHash('sha1').update(Buffer.from(one.stdout.trim(), 'base64')).digest('hex').toUpperCase())
  }
  if (profile.Entitlements === undefined || profile.TeamIdentifier === undefined) {
    throw new Error('a provisioning profile has no entitlements or no team')
  }
  return profile
}

/**
 * What is wrong with the signature of a piece of code inside a bundle: it is signed with a
 * distribution certificate of the team, and the same one as the bundle that holds it, which its own
 * profile has already been held to.
 */
export function problemsInEmbeddedSignature({ described, leafSha1, hostLeafSha1, team }) {
  const problems = []
  if (/Signature=adhoc/.test(described)) problems.push('is signed ad hoc, not with a distribution certificate')
  if (!/Authority=Apple Distribution: /.test(described)) problems.push('is not signed with an Apple Distribution certificate')
  if (!new RegExp(`TeamIdentifier=${team}$`, 'm').test(described)) problems.push(`is not signed under the team ${team}`)
  if (leafSha1 === '' || leafSha1 !== hostLeafSha1) problems.push('is not signed with the certificate of the bundle that holds it')
  return problems
}

/**
 * What kind of code a file is, from its first bytes: `code` for a Mach-O file (one architecture, or a
 * universal file that holds exactly one), `universal` for a universal file of several, which has a
 * signature for each and is read for none, and `none` for anything else.
 */
function kindOfFile(path) {
  const head = Buffer.alloc(8)
  const descriptor = openSync(path, 'r')
  try {
    readSync(descriptor, head, 0, 8, 0)
  } finally {
    closeSync(descriptor)
  }
  const magic = head.readUInt32BE(0)
  if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe) return 'code'
  if (magic === 0xcafebabe || magic === 0xcafebabf) return head.readUInt32BE(4) === 1 ? 'code' : 'universal'
  return 'none'
}

/**
 * Every piece of code under a bundle, wherever it sits (the frameworks and dylibs of `Frameworks`,
 * code nested in them, helpers beside the executable), as the Mach-O files that carry a signature,
 * each with its path inside the bundle. `apart` lists bundles inside this one that are read as
 * bundles of their own. What the check cannot read as code is not skipped but returned as `refused`:
 * a symbolic link may lead anywhere, and a file that is neither a file nor a directory is not
 * something a store takes.
 */
export function codeIn(bundle, apart = []) {
  const code = []
  const refused = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((one, other) => (one.name < other.name ? -1 : 1))) {
      const path = join(directory, entry.name)
      const name = relative(bundle, path)
      if (entry.isSymbolicLink()) {
        refused.push(`${name} is a symbolic link, which this check cannot follow`)
      } else if (apart.includes(path)) {
        continue
      } else if (entry.isDirectory()) {
        walk(path)
      } else if (entry.isFile()) {
        const kind = kindOfFile(path)
        if (kind === 'code') code.push({ name, path })
        if (kind === 'universal') refused.push(`${name} is a universal binary of several architectures, which this check cannot read`)
      } else {
        refused.push(`${name} is neither a file nor a directory`)
      }
    }
  }
  walk(bundle)
  return { code, refused }
}

/** What `codesign` describes of a signed bundle or file, and the SHA-1 of its leaf certificate ('' when it is signed ad hoc). */
export function signerOf(path) {
  const described = run('codesign', ['-dvv', path])
  const certificates = mkdtempSync(join(tmpdir(), 'kr-store-cert-'))
  let leafSha1 = ''
  try {
    run('codesign', ['-d', `--extract-certificates=${join(certificates, 'cert')}`, path])
    leafSha1 = createHash('sha1').update(readFileSync(join(certificates, 'cert0'))).digest('hex').toUpperCase()
  } catch {
    // No certificate to read is an ad hoc signature, which the description names.
  } finally {
    rmSync(certificates, { recursive: true, force: true })
  }
  return { described: described.stderr, leafSha1 }
}

/** What is wrong with the signature an exported bundle carries, given its profile. */
export function problemsInExportSignature({ described, leafSha1, profile, entitlements, team }) {
  const problems = []
  if (/Signature=adhoc/.test(described)) problems.push('is signed ad hoc, not with a distribution certificate')
  if (!/Authority=Apple Distribution: /.test(described)) problems.push('is not signed with an Apple Distribution certificate')
  if (!new RegExp(`TeamIdentifier=${team}$`, 'm').test(described)) problems.push(`is not signed under the team ${team}`)
  if (!(profile.CertificateSha1s ?? []).includes(leafSha1)) problems.push('is signed with a certificate its profile does not list')
  problems.push(...problemsOfFit(entitlements, { entitlements: profile.Entitlements }))
  return problems
}

function readProfile(path) {
  const decoded = run('security', ['cms', '-D', '-i', path])
  if (decoded.status !== 0) throw new Error(`${path} is not a provisioning profile that can be read`)
  return profileFromXml(decoded.stdout)
}

/**
 * The files and the directories under a directory, recursively, and what is neither (a link, a pipe,
 * a socket), which is listed and not followed: it may lead outside the tree, and a scan of the tree
 * cannot say what it holds.
 */
function treeUnder(root) {
  const files = []
  const folders = []
  const unread = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) {
        folders.push(path)
        walk(path)
      } else if (entry.isFile()) {
        files.push(path)
      } else {
        unread.push(path)
      }
    }
  }
  walk(root)
  return { files, folders, unread }
}

/**
 * What is wrong with the application's export-compliance key: it must say that the application needs
 * no export documentation, and carry no code, which Apple issues only for documentation.
 */
export function problemsInEncryptionKey(info) {
  const problems =
    info.ITSAppUsesNonExemptEncryption === false
      ? []
      : ["the application's Info.plist does not carry ITSAppUsesNonExemptEncryption set to false"]
  if (info.ITSEncryptionExportComplianceCode !== undefined) {
    problems.push("the application's Info.plist carries an ITSEncryptionExportComplianceCode, which a key of false has no use for")
  }
  return problems
}

/** The lines a check printed after the one that counts its problems, or its last lines. */
export function failureLines(output) {
  const lines = output.trim().split('\n')
  const counted = lines.findIndex((line) => /^\d+ problems?:?$/.test(line.trim()))
  return (counted < 0 ? lines.slice(-3) : lines.slice(counted + 1)).map((line) => line.trim()).join(' | ')
}

/** What is wrong with the versions of an application and its extensions. */
export function problemsInVersions(infos, want) {
  const problems = []
  for (const [name, info] of infos) {
    if (info.CFBundleVersion !== String(want.versionCode)) {
      problems.push(`${name}'s CFBundleVersion is ${JSON.stringify(info.CFBundleVersion)}, not ${want.versionCode}`)
    }
    if (info.CFBundleShortVersionString !== want.versionName) {
      problems.push(
        `${name}'s CFBundleShortVersionString is ${JSON.stringify(info.CFBundleShortVersionString)}, not ${want.versionName}`
      )
    }
  }
  return problems
}

/** Unpacks an `.ipa` into a fresh directory and answers the application inside it. */
function unpack(ipa) {
  const root = mkdtempSync(join(tmpdir(), 'kr-store-ipa-'))
  const unzipped = run('ditto', ['-x', '-k', ipa, root])
  if (unzipped.status !== 0) {
    rmSync(root, { recursive: true, force: true })
    throw new Error(`${ipa} cannot be unpacked: ${unzipped.stderr.trim()}`)
  }
  const apps = readdirSync(join(root, 'Payload')).filter((entry) => entry.endsWith('.app'))
  if (apps.length !== 1) {
    rmSync(root, { recursive: true, force: true })
    throw new Error(`${ipa} holds ${apps.length} applications, not one`)
  }
  return { root, app: join(root, 'Payload', apps[0]) }
}

export function checkIos(options) {
  const problems = []
  const facts = {}
  const want = declared(dirname(SCRIPTS))
  let unpacked = null
  let app = options.path
  if (options.path.endsWith('.ipa')) {
    unpacked = unpack(options.path)
    app = unpacked.app
  }
  try {
    const needles = needlesOf(options.secretFiles)
    // What is inside the application, names as well as contents. A link or a special file is read by its
    // name only; the export stage refuses it as code the check cannot read.
    const tree = treeUnder(app)
    const named = (path) => Buffer.from(relative(app, path), 'utf8')
    const first = placesWithSecret(
      [...tree.files.flatMap((file) => [named(file), readFileSync(file)]), ...tree.folders.map(named), ...tree.unread.map(named)],
      needles
    )
    if (first > 0) return secretFirst(first)
    facts.secretsFound = 0
    problems.push(...problemsInBundle(app, want))
    const bundles = iosBundles(app)
    const infos = bundles.map((bundle) => [bundle.name, plistValue(join(bundle.path, 'Info.plist'))])
    problems.push(...problemsInVersions(infos, options))
    problems.push(...problemsInEncryptionKey(infos[0][1]))
    facts.bundles = infos.map(([name, info]) => ({ name, identifier: info.CFBundleIdentifier }))

    for (const [index, bundle] of bundles.entries()) {
      const info = infos[index][1]
      const images = entitlementsOf(join(bundle.path, info.CFBundleExecutable))
      const entitlements = images[0] ?? {}
      if (entitlements['get-task-allow'] === true) problems.push(`${bundle.name} lets a debugger attach`)
      if (index === 0) {
        problems.push(...problemsInPushGateway(`${bundle.name}'s executable`, readFileSync(join(bundle.path, info.CFBundleExecutable))))
        if (entitlements['aps-environment'] !== 'production') {
          problems.push(`${bundle.name}'s push environment is ${JSON.stringify(entitlements['aps-environment'])}, not "production"`)
        }
        facts.pushEnvironment = entitlements['aps-environment'] ?? null
      }
      const signed = run('codesign', ['--verify', '--deep', '--strict', bundle.path])
      if (signed.status !== 0) problems.push(`${bundle.name}'s signature does not verify: ${signed.stderr.trim().split('\n')[0]}`)
      if (options.stage === 'export') {
        const { described, leafSha1 } = signerOf(bundle.path)
        // All the code under the bundle is held to the same rules, nested or not: the outer seal
        // covers it, but says nothing of who signed it. The bundle's own executable is held to
        // them below, with its profile, and an extension is read as a bundle of its own.
        const inside = codeIn(bundle.path, bundles.filter((other) => other !== bundle).map((other) => other.path))
        for (const each of inside.refused) problems.push(`${bundle.name} holds code this check cannot read: ${each}`)
        for (const code of inside.code) {
          if (code.path === join(bundle.path, info.CFBundleExecutable)) continue
          const signer = signerOf(code.path)
          for (const each of problemsInEmbeddedSignature({ ...signer, hostLeafSha1: leafSha1, team: want.team })) {
            problems.push(`${code.name} in ${bundle.name} ${each}`)
          }
        }
        const profilePath = join(bundle.path, 'embedded.mobileprovision')
        if (!existsSync(profilePath)) {
          problems.push(`${bundle.name} carries no provisioning profile`)
          continue
        }
        const profile = readProfile(profilePath)
        for (const each of problemsInExportSignature({ described, leafSha1, profile, entitlements, team: want.team })) {
          problems.push(`${bundle.name} ${each}`)
        }
        for (const each of problemsInProfile(profile, { team: want.team, identifier: info.CFBundleIdentifier, push: index === 0 })) {
          problems.push(`${bundle.name}'s profile: ${each}`)
        }
        facts.profiles = [...(facts.profiles ?? []), { bundle: info.CFBundleIdentifier, name: profile.Name, uuid: profile.UUID, expires: profile.ExpirationDate }]
      }
    }

    if (!existsSync(join(app, 'GoogleService-Info.plist'))) problems.push('the application carries no GoogleService-Info.plist')

    if (!options.skipAppChecks) {
      for (const [script, what] of [['privacy-manifest.mjs', 'privacy manifest'], ['debug-code.mjs', 'debug code']]) {
        const answer = run(process.execPath, [join(SCRIPTS, script), app])
        if (answer.status !== 0) problems.push(`the ${what} check fails: ${failureLines(answer.stdout + answer.stderr)}`)
        for (const line of answer.stdout.split('\n')) {
          if (line.startsWith('recorded exception: ')) (facts.recordedExceptions ??= []).push(line.slice('recorded exception: '.length))
        }
      }
    }
  } finally {
    if (unpacked) rmSync(unpacked.root, { recursive: true, force: true })
  }
  return suppressedIfSecret({ problems, facts })
}

// -- the command ----------------------------------------------------------------------------

/** The options that name one value, and what the value is called. */
const VALUE_FLAGS = {
  '--version-code': 'versionCode',
  '--version-name': 'versionName',
  '--certificate': 'certificate',
  '--stage': 'stage',
  '--bundletool': 'bundletool',
  '--record': 'record',
  '--firebase': 'firebase'
}

function parse(argv) {
  const options = { secretFiles: [], notes: {}, abis: ['arm64-v8a', 'x86_64'] }
  const take = (index) => {
    if (index + 1 >= argv.length) throw new Error(`${argv[index]} needs a value`)
    return argv[index + 1]
  }
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index]
    if (flag === '--android' || flag === '--ios') {
      options.platform = flag.slice(2)
      options.path = take(index)
      index += 1
    } else if (VALUE_FLAGS[flag]) {
      options[VALUE_FLAGS[flag]] = take(index)
      index += 1
    } else if (flag === '--scan-dir') {
      options.scanDir = take(index)
      index += 1
    } else if (flag === '--skip-app-checks') {
      options.skipAppChecks = true
    } else if (flag === '--redact') {
      options.redact = true
    } else if (flag === '--abis') {
      options.abis = take(index).split(',')
      index += 1
    } else if (flag === '--secret-file') {
      options.secretFiles.push(take(index))
      index += 1
    } else if (flag === '--note') {
      const [key, ...value] = take(index).split('=')
      if (RECORD_FIELDS.includes(key)) throw new Error(`--note cannot be named like a field of the record: ${key}`)
      options.notes[key] = value.join('=')
      index += 1
    } else {
      throw new Error(`unknown option ${flag}`)
    }
  }
  if (options.redact) {
    if (options.secretFiles.length === 0) throw new Error('--redact needs a --secret-file')
    return options
  }
  if (options.scanDir && options.secretFiles.length === 0) throw new Error('--scan-dir needs a --secret-file')
  if (options.scanDir && !options.platform) return options
  if (!options.platform) throw new Error('give --android <bundle> or --ios <ipa or app>')
  if (!/^[0-9]+$/.test(options.versionCode ?? '')) throw new Error('--version-code must be a whole number')
  if (!options.versionName) throw new Error('--version-name is required')
  if (options.platform === 'android' && !options.certificate) throw new Error('--certificate is required for a bundle')
  if (options.platform === 'ios' && !['archive', 'export'].includes(options.stage)) throw new Error('--stage must be archive or export')
  if (!existsSync(options.path)) throw new Error(`${options.path} does not exist`)
  return options
}

/** The files named by `--secret-file`, taken from the command line before it is understood, so that a command line that is wrong can be answered without quoting a secret too. */
function secretFilesIn(argv) {
  return argv.flatMap((flag, index) => (flag === '--secret-file' && index + 1 < argv.length ? [argv[index + 1]] : []))
}

/**
 * Runs the command and answers its exit status: 0 when the bundle holds, 1 when it does not, 2 when
 * it could not be read or a file could not be written. Whatever it prints, a path, an option or an
 * error text as much as a problem, goes through one filter first, since any of them can hold the
 * secret it was given.
 */
function main(argv) {
  const { needles, unusable } = quotableNeedles(secretFilesIn(argv))
  const shown = (message) => (unusable ? 'the details are withheld: a secret file cannot be searched for' : withheldIfSecret(message, needles))
  const out = (message) => console.log(shown(message))
  const err = (message) => console.error(shown(message))
  try {
    return command(argv, needles, out, err)
  } catch (failure) {
    err(`the check stopped: ${failure.message}`)
    return 2
  }
}

function command(argv, needles, out, err) {
  let options
  try {
    options = parse(argv)
  } catch (failure) {
    err(failure.message)
    return 2
  }
  if (options.redact) {
    // The text of a log on the standard input, on the standard output once it is safe to show. When
    // the secret cannot be read, nothing is shown.
    let shown
    try {
      shown = redacted(readFileSync(0, 'utf8'), needlesOf(options.secretFiles))
    } catch (failure) {
      err(`could not filter the text: ${failure.message}`)
      return 2
    }
    process.stdout.write(shown)
    return 0
  }
  if (options.scanDir && !options.platform) {
    let places
    try {
      places = secretsUnder(options.scanDir, needlesOf(options.secretFiles))
    } catch (failure) {
      err(`could not scan ${options.scanDir}: ${failure.message}`)
      return 2
    }
    if (places > 0) {
      err(`a secret file's text or a signed token is in ${places} place${places === 1 ? '' : 's'} under ${options.scanDir}`)
      return 1
    }
    out(`no secret file's text and no signed token is in the files under ${options.scanDir}`)
    return 0
  }
  let result
  try {
    result = options.platform === 'android' ? checkAndroid(options) : checkIos(options)
  } catch (failure) {
    err(`could not read ${options.path}: ${failure.message}`)
    return 2
  }
  if (options.scanDir && !(result.facts.secretsFound > 0)) {
    let found
    try {
      found = secretsUnder(options.scanDir, needlesOf(options.secretFiles))
    } catch (failure) {
      err(`could not scan ${options.scanDir}: ${failure.message}`)
      return 2
    }
    if (found > 0) result = secretFirst(found)
  }
  // A problem can quote a name or a value out of the bundle, so each goes through the same filter as
  // every other message before it reaches the terminal or the record.
  const shown = withheldIfSecret(relative(process.cwd(), options.path), needles)
  let problems = [...new Set(result.problems.map((each) => withheldIfSecret(each, needles)))]
  let unwritten = null
  if (options.record) {
    const stats = statSync(options.path)
    const identity = {
      file: options.path.split('/').pop(),
      platform: options.platform,
      stage: options.stage ?? null,
      versionName: options.versionName,
      versionCode: Number(options.versionCode),
      bytes: stats.size,
      sha256: stats.isFile() ? sha256(options.path) : null
    }
    const made = recordOf({ identity, problems, facts: result.facts, notes: options.notes }, needles)
    problems = made.problems
    try {
      writeFileSync(options.record, made.text)
    } catch (failure) {
      unwritten = failure
    }
  }
  if (problems.length > 0) err(`${shown}:\n${problems.map((each) => `  ${each}`).join('\n')}`)
  if (unwritten) {
    err(`could not write the record ${options.record}: ${unwritten.message}`)
    return 2
  }
  if (problems.length > 0) return 1
  out(`${shown}: holds for ${options.platform} (version ${options.versionName}, build ${options.versionCode})`)
  return 0
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = main(process.argv.slice(2))
}
