#!/usr/bin/env node
// Holds the store-bundle check to the answers it must give.
//
// The check reads a finished store bundle and says whether a store takes it. What it guards are
// the ways a store build is wrong while the build itself succeeds: signed with the wrong key, a
// version the store already has, a debuggable or cleartext-permitting manifest, a permission a
// library added, a native library laid out for 4 KB pages, a secret packaged, a development push
// environment, an extension whose version differs from its application. Building the application
// cannot produce those on demand, so they are built here, each from a manifest, a library header,
// a profile or a signature written for the purpose. The signature cases sign with a key made for
// the run in a directory removed afterwards; no real key is read.
//
// The cases that need `keytool` and `jarsigner` are reported as not run, never as passed, when the
// tools are missing, and the exit status says so.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { uleb, zip } from './archive-fixtures.mjs'
import { factsFromProto } from './identifiers.mjs'
import { withArchive } from './android-classes.mjs'
import {
  ANDROID_PERMISSIONS,
  certificateFingerprint,
  placesWithSecret,
  problemsInAndroidLibraries,
  problemsInAndroidManifest,
  problemsInElf,
  problemsInFirebase,
  problemsInProfile,
  problemsInSignature,
  problemsInVersions,
  secretNeedles
} from './store-bundle.mjs'
import { ENTITLEMENT_SOURCES, entitlementsOfArchive } from './store-ios-sign.mjs'

let failures = 0
let notRun = 0
let passed = 0

function held(what, expected, found) {
  if (JSON.stringify(expected) === JSON.stringify(found)) {
    passed += 1
    console.log(`ok   ${what}`)
  } else {
    failures += 1
    console.error(`FAIL ${what}\n     expected ${JSON.stringify(expected)}\n     found    ${JSON.stringify(found)}`)
  }
}

/** The problems that mention each fragment, or a fragment that nothing mentioned. */
function heldProblems(what, problems, fragments) {
  const missing = fragments.filter((fragment) => !problems.some((problem) => problem.includes(fragment)))
  held(what, [], missing)
  if (fragments.length === 0) held(`${what} (no problem at all)`, [], problems)
}

const work = mkdtempSync(join(tmpdir(), 'kr-store-selftest-'))

// -- a release manifest, in the form a bundle keeps it in ------------------------------------

const field = (number, payload) => Buffer.concat([uleb(number * 8 + 2), uleb(payload.length), payload])
const text = (number, value) => field(number, Buffer.from(value))
function xmlNode(name, attributes = {}, children = []) {
  return field(
    1,
    Buffer.concat([
      text(3, name),
      ...Object.entries(attributes).map(([key, value]) => field(4, Buffer.concat([text(2, key), text(3, value)]))),
      ...children.map((child) => field(5, child))
    ])
  )
}

const WANT = { identifier: 'to.kala.reach', versionCode: 39800, versionName: '0.1.0' }

function manifest(change = {}) {
  const option = (key, fallback) => (Object.hasOwn(change, key) ? change[key] : fallback)
  const permissions = option('permissions', ANDROID_PERMISSIONS)
  return factsFromProto(
    xmlNode('manifest', { package: 'to.kala.reach', versionCode: option('versionCode', '39800'), versionName: '0.1.0' }, [
      xmlNode('uses-sdk', { minSdkVersion: '29', targetSdkVersion: option('targetSdk', '36') }),
      ...permissions.map((name) => xmlNode('uses-permission', { name })),
      xmlNode('application', {
        usesCleartextTraffic: option('cleartext', 'false'),
        ...(option('debuggable', null) === null ? {} : { debuggable: option('debuggable', null) })
      })
    ])
  )
}

heldProblems('a release manifest passes', problemsInAndroidManifest(manifest(), WANT), [])
heldProblems('a version code the build was not asked for is refused', problemsInAndroidManifest(manifest({ versionCode: '1' }), WANT), [
  'version code is "1"'
])
heldProblems('a debuggable bundle is refused', problemsInAndroidManifest(manifest({ debuggable: 'true' }), WANT), ['debuggable to true'])
heldProblems('a bundle that allows cleartext traffic is refused', problemsInAndroidManifest(manifest({ cleartext: 'true' }), WANT), [
  'usesCleartextTraffic'
])
heldProblems('a target below the store requirement is refused', problemsInAndroidManifest(manifest({ targetSdk: '35' }), WANT), [
  'targetSdkVersion'
])
heldProblems(
  'a permission a library added is refused by name',
  problemsInAndroidManifest(manifest({ permissions: [...ANDROID_PERMISSIONS, 'android.permission.READ_CONTACTS'] }), WANT),
  ['asks for android.permission.READ_CONTACTS']
)
heldProblems(
  'a permission the application declares and the bundle lacks is refused by name',
  problemsInAndroidManifest(manifest({ permissions: ANDROID_PERMISSIONS.filter((each) => !each.endsWith('CAMERA')) }), WANT),
  ['does not ask for android.permission.CAMERA']
)

// -- native libraries --------------------------------------------------------------------------

/** A 64-bit little-endian ELF with one loadable segment aligned as asked. */
function elf(alignment) {
  const file = Buffer.alloc(64 + 56)
  file.writeUInt32BE(0x7f454c46, 0)
  file[4] = 2
  file[5] = 1
  file.writeBigUInt64LE(64n, 0x20)
  file.writeUInt16LE(56, 0x36)
  file.writeUInt16LE(1, 0x38)
  file.writeUInt32LE(1, 64)
  file.writeBigUInt64LE(BigInt(alignment), 64 + 48)
  return file
}
held('a library aligned to 16 KB passes', [], problemsInElf('libapp.so', elf(16384)))
heldProblems('a library aligned to 4 KB is refused', problemsInElf('libapp.so', elf(4096)), ['aligns a loadable segment to 4096'])
heldProblems('a file that is no ELF library is refused', problemsInElf('libapp.so', Buffer.from('not a library')), ['not a 64-bit'])

function bundleOf(name, abis, alignment = 16384) {
  const path = join(work, `${name}.aab`)
  writeFileSync(
    path,
    zip([
      { name: 'base/dex/classes.dex', bytes: Buffer.from('dex') },
      ...abis.map((abi) => ({ name: `base/lib/${abi}/libapp.so`, bytes: elf(alignment) }))
    ])
  )
  return path
}
const libraries = (path, abis) => withArchive(path, (members, read) => problemsInAndroidLibraries(members, read, abis))
held('the requested architectures pass', [], libraries(bundleOf('both', ['arm64-v8a', 'x86_64']), ['arm64-v8a', 'x86_64']))
heldProblems('an architecture nobody asked for is refused', libraries(bundleOf('three', ['arm64-v8a', 'x86_64', 'armeabi-v7a']), ['arm64-v8a', 'x86_64']), [
  'architectures arm64-v8a, armeabi-v7a, x86_64'
])
heldProblems('a bundle with a 4 KB library is refused', libraries(bundleOf('small', ['arm64-v8a'], 4096), ['arm64-v8a']), ['aligns a loadable segment'])

// -- the push configuration ------------------------------------------------------------------

const configuration = {
  project_info: { project_id: 'example-project' },
  client: [{ client_info: { mobilesdk_app_id: '1:123:android:abc', android_client_info: { package_name: 'to.kala.reach' } } }]
}
const table = Buffer.from('xx example-project yy 1:123:android:abc zz')
held('a bundle that carries the application\'s Firebase configuration passes', [], problemsInFirebase(table, configuration, 'to.kala.reach'))
heldProblems('a bundle without the configuration is refused', problemsInFirebase(Buffer.from('nothing'), configuration, 'to.kala.reach'), ['does not carry the Firebase configuration'])
heldProblems('a bundle with only the project is refused', problemsInFirebase(Buffer.from('example-project'), configuration, 'to.kala.reach'), ['does not carry'])
heldProblems('a configuration for another application is refused', problemsInFirebase(table, configuration, 'to.kala.other'), ['names no application to.kala.other'])

// -- secrets -------------------------------------------------------------------------------------

const secret = Buffer.from('-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgabcdefghijklmnop\n-----END PRIVATE KEY-----\n')
const needles = secretNeedles(secret)
held('a secret key block is found by any long line of it', 1, placesWithSecret([Buffer.from(`xx${secret.toString().split('\n')[1]}yy`)], needles))
held('text that is not the secret is not found', 0, placesWithSecret([Buffer.from('MIGTAgEAMBMGB')], needles))
held('a short password file is found whole', 1, placesWithSecret([Buffer.from('prefix-hunter2hunter2-suffix')], secretNeedles(Buffer.from('hunter2hunter2\n'))))

// -- the signature: the upload key and no other ---------------------------------------------------

const tools = ['keytool', 'jarsigner'].map((tool) => spawnSync(tool, ['-help'], { encoding: 'utf8' }))
if (tools.some((answer) => answer.error)) {
  notRun += 1
  console.log('not run: the signature cases need keytool and jarsigner')
} else {
  const keyOf = (name) => {
    const directory = join(work, name)
    mkdirSync(directory)
    const password = join(directory, 'password')
    writeFileSync(password, `${name}-made-for-this-run`)
    const store = join(directory, 'key.p12')
    const generated = spawnSync(
      'keytool',
      ['-genkeypair', '-keystore', store, '-storetype', 'PKCS12', '-alias', 'upload', '-keyalg', 'RSA', '-keysize', '2048',
        '-validity', '2', '-dname', `CN=${name}`, `-storepass:file`, password, `-keypass:file`, password],
      { encoding: 'utf8' }
    )
    if (generated.status !== 0) throw new Error(`keytool could not make a key: ${generated.stderr}`)
    const pem = spawnSync('keytool', ['-exportcert', '-rfc', '-keystore', store, '-storetype', 'PKCS12', '-alias', 'upload', '-storepass:file', password], {
      encoding: 'utf8'
    }).stdout
    return { store, password, pem }
  }
  const upload = keyOf('upload')
  const debug = keyOf('debug')
  const content = join(work, 'content')
  mkdirSync(content)
  writeFileSync(join(content, 'a.txt'), 'bundle')
  const unsigned = join(work, 'unsigned.aab')
  spawnSync('jar', ['cf', unsigned, '-C', content, 'a.txt'])
  const sign = (key, out) => {
    const signed = spawnSync(
      'jarsigner',
      ['-keystore', key.store, '-storetype', 'PKCS12', `-storepass:file`, key.password, '-sigalg', 'SHA256withRSA', '-digestalg', 'SHA-256', '-signedjar', out, unsigned, 'upload'],
      { encoding: 'utf8' }
    )
    if (signed.status !== 0) throw new Error(`jarsigner failed: ${signed.stderr}`)
    return out
  }
  const byUpload = sign(upload, join(work, 'by-upload.aab'))
  const byDebug = sign(debug, join(work, 'by-debug.aab'))
  const fingerprint = certificateFingerprint(upload.pem)
  held('a bundle signed by the upload key passes and reports its fingerprint', { problems: [], signer: fingerprint }, problemsInSignature(byUpload, upload.pem))
  heldProblems('a bundle signed by another key is refused', problemsInSignature(byDebug, upload.pem).problems, ['not signed by the upload key'])
  heldProblems('a bundle with no signature is refused', problemsInSignature(unsigned, upload.pem).problems, ['does not verify'])
}

// -- profiles and versions ----------------------------------------------------------------------

const TEAM = 'L775WGST9V'
const appStore = {
  TeamIdentifier: [TEAM],
  Entitlements: { 'application-identifier': `${TEAM}.to.kala.reach`, 'aps-environment': 'production', 'get-task-allow': false },
  ExpirationDate: '2099-01-01T00:00:00Z'
}
const where = { team: TEAM, identifier: 'to.kala.reach' }
held('an App Store profile of the team passes', [], problemsInProfile(appStore, where))
const development = {
  ...appStore,
  Entitlements: { ...appStore.Entitlements, 'aps-environment': 'development', 'get-task-allow': true },
  ProvisionedDevices: ['00008110-000000000000001E']
}
heldProblems('a development profile is refused', problemsInProfile(development, where), ['push environment', 'debugger', 'lists devices'])
heldProblems('a profile of another team is refused', problemsInProfile({ ...appStore, TeamIdentifier: ['JT6GW3W9W6'] }, where), ['its team is JT6GW3W9W6'])
heldProblems('an expired profile is refused', problemsInProfile({ ...appStore, ExpirationDate: '2020-01-01T00:00:00Z' }, where), ['expired'])

const versions = { versionCode: 39800, versionName: '0.1.0' }
const info = (code, name) => ({ CFBundleVersion: code, CFBundleShortVersionString: name })
held('an application and an extension of one version pass', [], problemsInVersions([['app', info('39800', '0.1.0')], ['ext', info('39800', '0.1.0')]], versions))
heldProblems(
  'an extension whose build number differs from the application is refused',
  problemsInVersions([['app', info('39800', '0.1.0')], ['ext', info('0.1.0', '0.1.0')]], versions),
  ['ext\'s CFBundleVersion is "0.1.0"']
)
heldProblems(
  'a three-part build number is refused where one number is asked',
  problemsInVersions([['app', info('0.1.0.39800', '0.1.0')]], versions),
  ['CFBundleVersion is "0.1.0.39800"']
)

// -- the entitlements an archive is signed with -------------------------------------------------

const app = join(work, 'KalaReach.app')
mkdirSync(join(app, 'PlugIns', 'KalaReachNotificationService.appex'), { recursive: true })
const infoPlist = (identifier) =>
  `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${identifier}</string></dict></plist>`
writeFileSync(join(app, 'Info.plist'), infoPlist('to.kala.reach'))
writeFileSync(join(app, 'PlugIns', 'KalaReachNotificationService.appex', 'Info.plist'), infoPlist('to.kala.reach.notifications'))
const wanted = entitlementsOfArchive(app, TEAM, ENTITLEMENT_SOURCES)
held('the application is signed with the production push environment', 'production', wanted.application['aps-environment'])
held(
  "the application's keychain groups carry the team and its own comes first",
  [`${TEAM}.to.kala.reach`, `${TEAM}.to.kala.reach.shared`],
  wanted.application['keychain-access-groups']
)
held('the application keeps its associated domains', ['applinks:reach.kala.to', 'webcredentials:reach.kala.to'], wanted.application['com.apple.developer.associated-domains'])
held("the extension holds the shared group and nothing else", [`${TEAM}.to.kala.reach.shared`], wanted.extension['keychain-access-groups'])
held('the extension is entitled to no push environment', undefined, wanted.extension['aps-environment'])
held('neither bundle lets a debugger attach', [false, false], [wanted.application['get-task-allow'], wanted.extension['get-task-allow']])

rmSync(work, { recursive: true, force: true })
console.log(`${passed} held, ${failures} failed, ${notRun} not run`)
process.exit(failures > 0 ? 1 : notRun > 0 ? 3 : 0)
