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
//            needs; and, for an exported bundle, each profile is an App Store profile of this team.
//
// The identifiers (`identifiers.mjs`), the privacy manifest (`privacy-manifest.mjs`) and the debug
// code (`debug-code.mjs`) are read by the checks that own them and are run from here, so one
// command says whether a bundle can go to a store.
//
// A secret is a file whose path is given to `--secret-file`. It is read in this process, every
// decompressed member of the bundle (or every file of the application) is searched for it, and
// only the number of places it was found is printed. It is never part of a command line.
//
// Usage:
//   node scripts/store-bundle.mjs --android <app.aab> --version-code <n> --version-name <v>
//        --certificate <upload-certificate.pem> [--abis arm64-v8a,x86_64] [--secret-file <path> ...]
//        [--firebase <google-services.json>] [--record <store-build.json>] [--note key=value ...]
//   node scripts/store-bundle.mjs --scan-dir <directory> --secret-file <path> [--secret-file <path> ...]
//        (how many files under the directory hold a secret's text; bundles are read by the checks above)
//   node scripts/store-bundle.mjs --ios <app.ipa | KalaReach.app> --stage archive|export
//        --version-code <n> --version-name <v> [--skip-app-checks] [--secret-file <path> ...] [--record <file>]
//   `--skip-app-checks` leaves out the privacy-manifest and debug-code checks, which a caller runs on its own.
//   The record is written whether the bundle holds or not: it says which, and why.
// Exit 0 when the bundle holds, 1 when it does not, 2 when it could not be read.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { X509Certificate, createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
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
      problems.push(...problemsInElf(`${abi}/${library.name.split('/').pop()}`, read(library)))
    }
  }
  if (!members.some((member) => member.name.startsWith('base/dex/'))) problems.push('the bundle holds no dex file')
  return problems
}

// -- secrets ---------------------------------------------------------------------------------

/**
 * The strings that stand for a secret file: its whole content, trimmed, and each of its lines of 32
 * characters or more, so a key block pasted in pieces is found by any whole line of it. A secret
 * shorter than 8 characters is refused: it would match anything.
 */
export function secretNeedles(content) {
  const text = content.toString('utf8').trim()
  if (text.length < 8) throw new Error('a secret file holds fewer than 8 characters, too few to search for')
  const needles = new Set([text])
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed.length >= 32 && !trimmed.startsWith('-----')) needles.add(trimmed)
  }
  return [...needles].map((each) => Buffer.from(each, 'utf8'))
}

/** How many of the buffers hold any needle. */
export function placesWithSecret(buffers, needles) {
  let places = 0
  for (const bytes of buffers) {
    if (needles.some((needle) => bytes.includes(needle))) places += 1
  }
  return places
}

/** The needles of every secret file named, or throws if one cannot be read. */
function needlesOf(files) {
  return files.flatMap((file) => secretNeedles(readFileSync(file)))
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

/** The shape of a signed token: three base64url parts, the first two of JSON (`eyJ`). */
const TOKEN_SHAPE = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/

/** Whether bytes hold a secret's text or a token made from one. */
function holdsSecret(bytes, needles) {
  return needles.some((needle) => bytes.includes(needle)) || TOKEN_SHAPE.test(bytes.toString('latin1'))
}

/**
 * How many files under a directory hold a secret's text or a signed token, a bundle counting once
 * for each member that does (a bundle is compressed, so its bytes are searched member by member).
 * `.apks` files hold other packages whole and are left out: each package is read as an `.apk`.
 */
export function secretsUnder(directory, needles) {
  let places = 0
  for (const file of filesUnder(directory)) {
    if (/\.apks$/.test(file)) continue
    if (/\.(aab|ipa|apk)$/.test(file)) {
      places += withArchive(file, (members, read) => members.filter((member) => holdsSecret(read(member), needles)).length)
    } else if (holdsSecret(readFileSync(file), needles)) {
      places += 1
    }
  }
  return places
}

/** A message with nothing of it left when it quotes a secret. */
export function withheldIfSecret(message, needles) {
  const bytes = Buffer.from(message, 'utf8')
  return needles.some((needle) => bytes.includes(needle)) ? 'the details are withheld: they quote a secret file' : message
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
  const first = withArchive(options.path, (members, read) => placesWithSecret(members.map((member) => read(member)), needles))
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

/** The files under a directory, recursively. */
function filesUnder(root) {
  const found = []
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name)
    if (entry.isDirectory()) found.push(...filesUnder(path))
    else if (entry.isFile()) found.push(path)
  }
  return found
}

/** What is wrong with the application's export-compliance key: it must say that the application needs no export documentation. */
export function problemsInEncryptionKey(info) {
  return info.ITSAppUsesNonExemptEncryption === false
    ? []
    : ["the application's Info.plist does not carry ITSAppUsesNonExemptEncryption set to false"]
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
    const first = placesWithSecret(filesUnder(app).map((file) => readFileSync(file)), needles)
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
        if (entitlements['aps-environment'] !== 'production') {
          problems.push(`${bundle.name}'s push environment is ${JSON.stringify(entitlements['aps-environment'])}, not "production"`)
        }
        facts.pushEnvironment = entitlements['aps-environment'] ?? null
      }
      const signed = run('codesign', ['--verify', '--deep', '--strict', bundle.path])
      if (signed.status !== 0) problems.push(`${bundle.name}'s signature does not verify: ${signed.stderr.trim().split('\n')[0]}`)
      if (options.stage === 'export') {
        const profilePath = join(bundle.path, 'embedded.mobileprovision')
        if (!existsSync(profilePath)) {
          problems.push(`${bundle.name} carries no provisioning profile`)
          continue
        }
        const profile = readProfile(profilePath)
        const described = run('codesign', ['-dvv', bundle.path])
        const certificates = mkdtempSync(join(tmpdir(), 'kr-store-cert-'))
        let leafSha1 = ''
        try {
          run('codesign', ['-d', `--extract-certificates=${join(certificates, 'cert')}`, bundle.path])
          leafSha1 = createHash('sha1').update(readFileSync(join(certificates, 'cert0'))).digest('hex').toUpperCase()
        } catch {
          // No certificate to read is an ad hoc signature, which the description names.
        } finally {
          rmSync(certificates, { recursive: true, force: true })
        }
        for (const each of problemsInExportSignature({
          described: described.stderr,
          leafSha1,
          profile,
          entitlements,
          team: want.team
        })) {
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
    } else if (flag === '--abis') {
      options.abis = take(index).split(',')
      index += 1
    } else if (flag === '--secret-file') {
      options.secretFiles.push(take(index))
      index += 1
    } else if (flag === '--note') {
      const [key, ...value] = take(index).split('=')
      options.notes[key] = value.join('=')
      index += 1
    } else {
      throw new Error(`unknown option ${flag}`)
    }
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

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  let options
  try {
    options = parse(process.argv.slice(2))
  } catch (failure) {
    console.error(failure.message)
    process.exit(2)
  }
  if (options.scanDir && !options.platform) {
    let places
    try {
      places = secretsUnder(options.scanDir, needlesOf(options.secretFiles))
    } catch (failure) {
      console.error(`could not scan ${options.scanDir}: ${failure.message}`)
      process.exit(2)
    }
    if (places > 0) {
      console.error(`a secret file's text or a signed token is in ${places} place${places === 1 ? '' : 's'} under ${options.scanDir}`)
      process.exit(1)
    }
    console.log(`no secret file's text and no signed token is in the files under ${options.scanDir}`)
    process.exit(0)
  }
  let result
  try {
    result = options.platform === 'android' ? checkAndroid(options) : checkIos(options)
  } catch (failure) {
    let needles = []
    try {
      needles = needlesOf(options.secretFiles)
    } catch {
      // A secret that cannot be read cannot be quoted.
    }
    console.error(`could not read ${options.path}: ${withheldIfSecret(String(failure.message), needles)}`)
    process.exit(2)
  }
  if (options.scanDir && !(result.facts.secretsFound > 0)) {
    let found = 0
    try {
      found = secretsUnder(options.scanDir, needlesOf(options.secretFiles))
    } catch (failure) {
      console.error(`could not scan ${options.scanDir}: ${failure.message}`)
      process.exit(2)
    }
    if (found > 0) result = secretFirst(found)
  }
  const shown = relative(process.cwd(), options.path)
  const problems = [...new Set(result.problems)]
  if (options.record) {
    const stats = statSync(options.path)
    const record = {
      file: options.path.split('/').pop(),
      platform: options.platform,
      stage: options.stage ?? null,
      versionName: options.versionName,
      versionCode: Number(options.versionCode),
      bytes: stats.size,
      sha256: stats.isFile() ? sha256(options.path) : null,
      holds: problems.length === 0,
      problems,
      ...result.facts,
      ...options.notes
    }
    writeFileSync(options.record, `${JSON.stringify(record, null, 2)}\n`)
  }
  if (problems.length > 0) {
    console.error(`${shown}:\n${problems.map((each) => `  ${each}`).join('\n')}`)
    process.exit(1)
  }
  console.log(`${shown}: holds for ${options.platform} (version ${options.versionName}, build ${options.versionCode})`)
}
