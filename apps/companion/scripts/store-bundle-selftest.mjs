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
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { uleb, zip } from './archive-fixtures.mjs'
import { factsFromProto } from './identifiers.mjs'
import { withArchive } from './android-classes.mjs'
import {
  ANDROID_PERMISSIONS,
  certificateFingerprint,
  declaresSignInLink,
  problemsInBundleConfig,
  problemsInEncryptionKey,
  withheldIfSecret,
  problemsInExportSignature,
  secretsUnder,
  suppressedIfSecret,
  placesWithSecret,
  problemsInAndroidLibraries,
  problemsInAndroidManifest,
  problemsInElf,
  problemsInFirebase,
  problemsInProfile,
  problemsInSignature,
  problemsInVersions,
  profileFromXml,
  secretNeedles
} from './store-bundle.mjs'
import { entitlementsOf } from './identifiers.mjs'
import { ENTITLEMENT_SOURCES, entitlementsOfArchive, signArchive } from './store-ios-sign.mjs'

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

/** The intent filters an activity carries: one complete sign-in link, or a named defect of it. */
function link(kind) {
  const filter = (children, autoVerify = 'true') => xmlNode('intent-filter', { autoVerify }, children)
  const action = xmlNode('action', { name: 'android.intent.action.VIEW' })
  const categories = [xmlNode('category', { name: 'android.intent.category.DEFAULT' }), xmlNode('category', { name: 'android.intent.category.BROWSABLE' })]
  const data = (attributes) => xmlNode('data', attributes)
  const whole = { scheme: 'https', host: 'reach.kala.to', path: '/app/oauth/callback' }
  if (kind === 'no-scheme') return [filter([action, ...categories, data({ host: 'reach.kala.to', path: '/app/oauth/callback' })])]
  if (kind === 'no-browsable') return [filter([action, categories[0], data(whole)])]
  if (kind === 'not-verified') return [filter([action, ...categories, data(whole)], 'false')]
  if (kind === 'split') {
    return [filter([action, ...categories, data({ scheme: 'https', host: 'reach.kala.to' })]), filter([data({ path: '/app/oauth/callback' })])]
  }
  return [filter([action, ...categories, data(whole)])]
}

function manifest(change = {}) {
  const option = (key, fallback) => (Object.hasOwn(change, key) ? change[key] : fallback)
  const permissions = option('permissions', ANDROID_PERMISSIONS)
  return factsFromProto(
    xmlNode('manifest', { package: 'to.kala.reach', versionCode: option('versionCode', '39800'), versionName: '0.1.0' }, [
      xmlNode('uses-sdk', { minSdkVersion: option('minSdk', '29'), targetSdkVersion: option('targetSdk', '36') }),
      ...permissions.map((name) => xmlNode('uses-permission', { name })),
      xmlNode('application', {
        usesCleartextTraffic: option('cleartext', 'false'),
        ...(option('debuggable', null) === null ? {} : { debuggable: option('debuggable', null) }),
        ...(option('testOnly', null) === null ? {} : { testOnly: option('testOnly', null) })
      }, option('link', true) ? [xmlNode('activity', {}, link(option('link', true)))] : [])
    ])
  )
}

heldProblems('a release manifest passes', problemsInAndroidManifest(manifest(), WANT), [])
heldProblems('a version code the build was not asked for is refused', problemsInAndroidManifest(manifest({ versionCode: '1' }), WANT), [
  'version code is "1"'
])
heldProblems('a debuggable bundle is refused', problemsInAndroidManifest(manifest({ debuggable: 'true' }), WANT), ['debuggable to true'])
heldProblems('a test-only bundle is refused', problemsInAndroidManifest(manifest({ testOnly: 'true' }), WANT), ['testOnly to true'])
heldProblems('a lower minimum platform is refused', problemsInAndroidManifest(manifest({ minSdk: '24' }), WANT), ['minSdkVersion'])
heldProblems('a manifest without the verified sign-in link is refused', problemsInAndroidManifest(manifest({ link: false }), WANT), ['verified sign-in link'])
for (const kind of ['no-scheme', 'no-browsable', 'not-verified', 'split']) {
  held(`a sign-in link that is ${kind} is not the link`, false, declaresSignInLink(manifest({ link: kind }).root))
}
held('a complete filter is the link', true, declaresSignInLink(manifest().root))
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

held('a bundle configuration that asks for 16 KB alignment passes', [], problemsInBundleConfig('"alignment": "PAGE_ALIGNMENT_16K"'))
heldProblems('a bundle configuration that does not is refused', problemsInBundleConfig('"alignment": "PAGE_ALIGNMENT_4K"'), ['16 KB'])

// -- secrets -------------------------------------------------------------------------------------

const secret = Buffer.from('-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgabcdefghijklmnop\n-----END PRIVATE KEY-----\n')
const needles = secretNeedles(secret)
held('a secret key block is found by any long line of it', 1, placesWithSecret([Buffer.from(`xx${secret.toString().split('\n')[1]}yy`)], needles))
held('text that is not the secret is not found', 0, placesWithSecret([Buffer.from('MIGTAgEAMBMGB')], needles))
held('a secret of fewer than 8 characters is refused, since it would match anything', 'throws', (() => { try { secretNeedles(Buffer.from('short\n')); return 'returns' } catch { return 'throws' } })())
held('a secret text in a compressed member of a real archive is found', 1, (() => {
  const dir = join(work, 'compressed'); mkdirSync(dir)
  writeFileSync(join(dir, 'a.txt'), 'prefix correct-horse-battery-staple suffix')
  spawnSync('jar', ['cf', join(work, 'compressed.aab'), '-C', dir, 'a.txt'])
  return withArchive(join(work, 'compressed.aab'), (members, read) => placesWithSecret(members.map((member) => read(member)), secretNeedles(Buffer.from('correct-horse-battery-staple\n'))))
})())
const suppressed = suppressedIfSecret({ problems: ['the version name is "the-secret-itself"'], facts: { secretsFound: 1 } })
held('a bundle that holds a secret is reported by its count, with nothing quoted from it', [1, true], [suppressed.facts.secretsFound, !JSON.stringify(suppressed).includes('the-secret-itself')])
held('an error message that quotes a secret is withheld, and one that does not is kept', ['the details are withheld: they quote a secret file', 'no such file'], [withheldIfSecret('could not read /x/the-secret-itself', secretNeedles(Buffer.from('the-secret-itself\n'))), withheldIfSecret('no such file', secretNeedles(Buffer.from('the-secret-itself\n')))])
held('a directory with a secret in a log is found, and a clean one is not', [1, 0], (() => {
  const dirty = join(work, 'dirty'); mkdirSync(dirty); writeFileSync(join(dirty, 'run.log'), 'x correct-horse-battery-staple y')
  const clean = join(work, 'clean'); mkdirSync(clean); writeFileSync(join(clean, 'run.log'), 'nothing here')
  const needles = secretNeedles(Buffer.from('correct-horse-battery-staple\n'))
  return [secretsUnder(dirty, needles), secretsUnder(clean, needles)]
})())
held('a signed token in a log is found though no secret file matches', 1, (() => {
  const logs = join(work, 'tokens'); mkdirSync(logs)
  writeFileSync(join(logs, 'Packaging.log'), '"Authorization" = "Bearer eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhYmMifQ.c2lnbmF0dXJlLXNpZ25hdHVyZQ";')
  return secretsUnder(logs, secretNeedles(Buffer.from('unrelated-secret-text\n')))
})())
held('a secret in a compressed member of a package under the directory is found, and one inside an .apks is left to its own package', [1, 0], (() => {
  const dir = join(work, 'packages'); mkdirSync(dir)
  const inner = join(work, 'inner'); mkdirSync(inner); writeFileSync(join(inner, 'a.txt'), 'x correct-horse-battery-staple y')
  spawnSync('jar', ['cf', join(dir, 'universal.apk'), '-C', inner, 'a.txt'])
  const needles = secretNeedles(Buffer.from('correct-horse-battery-staple\n'))
  const first = secretsUnder(dir, needles)
  rmSync(join(dir, 'universal.apk'))
  spawnSync('jar', ['cf', join(dir, 'set.apks'), '-C', inner, 'a.txt'])
  return [first, secretsUnder(dir, needles)]
})())
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
  const added = join(work, 'added.aab')
  spawnSync('cp', [byUpload, added])
  writeFileSync(join(content, 'later.txt'), 'added after signing')
  spawnSync('jar', ['uf', added, '-C', content, 'later.txt'])
  // The whole command on a signed bundle whose version name is the secret: nothing of it may reach
  // the output, the record or an error.
  const leaked = 'versionname-secret-0001'
  const leakFile = join(work, 'leak-secret'); writeFileSync(leakFile, `${leaked}\n`)
  const leakCertificate = join(work, 'leak.pem'); writeFileSync(leakCertificate, upload.pem)
  const leakUnsigned = join(work, 'leak-unsigned.aab')
  const leakTree = join(work, 'leak-tree')
  mkdirSync(join(leakTree, 'base', 'manifest'), { recursive: true })
  mkdirSync(join(leakTree, 'base', 'dex'))
  writeFileSync(join(leakTree, 'base', 'manifest', 'AndroidManifest.xml'), xmlNode('manifest', { package: 'to.kala.reach', versionName: leaked }))
  writeFileSync(join(leakTree, 'base', 'dex', 'classes.dex'), 'dex')
  spawnSync('jar', ['cf', leakUnsigned, '-C', leakTree, 'base'])
  const leakBundle = join(work, 'leak.aab')
  spawnSync('jarsigner', ['-keystore', upload.store, '-storetype', 'PKCS12', '-storepass:file', upload.password, '-signedjar', leakBundle, leakUnsigned, 'upload'])
  const leakRecord = join(work, 'leak-record.json')
  const leakRun = spawnSync(process.execPath, [join(import.meta.dirname, 'store-bundle.mjs'), '--android', leakBundle, '--version-code', '1', '--version-name', '0.1.0', '--certificate', leakCertificate, '--secret-file', leakFile, '--record', leakRecord], { encoding: 'utf8' })
  const recorded = readFileSync(leakRecord, 'utf8')
  held('a bundle whose version name is the secret fails, and the secret is in no output and no record', [1, false, true, false, 'false'], [leakRun.status, (leakRun.stdout + leakRun.stderr).includes(leaked), /secret file's text is in 1 place/.test(leakRun.stderr), recorded.includes(leaked), String(JSON.parse(recorded).holds)])
  heldProblems('a signed bundle with an entry added after signing is refused', problemsInSignature(added, upload.pem).problems, ['entries that are not signed'])
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

// A profile as Apple makes one: with certificates (data) and dates, which a whole-file conversion to
// JSON refuses, and with no device list.
const profileXml = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Name</key><string>iOS Team Store Provisioning Profile: to.kala.reach</string>
<key>UUID</key><string>70ce149f-4fe0-48f6-b681-f66c63f4421e</string>
<key>TeamIdentifier</key><array><string>${TEAM}</string></array>
<key>CreationDate</key><date>2026-10-28T14:20:40Z</date>
<key>ExpirationDate</key><date>2099-01-01T00:00:00Z</date>
<key>DeveloperCertificates</key><array><data>AAEC</data></array>
<key>Entitlements</key><dict>
<key>application-identifier</key><string>${TEAM}.to.kala.reach</string>
<key>aps-environment</key><string>production</string>
<key>get-task-allow</key><false/>
</dict></dict></plist>`
const extensionProfile = { ...appStore, Entitlements: { 'application-identifier': `${TEAM}.to.kala.reach.notifications`, 'get-task-allow': false } }
held('the extension\'s profile needs no push environment', [], problemsInProfile(extensionProfile, { team: TEAM, identifier: 'to.kala.reach.notifications', push: false }))
heldProblems('the application\'s profile does', problemsInProfile(extensionProfile, { team: TEAM, identifier: 'to.kala.reach.notifications' }), ['push environment'])
const read = profileFromXml(Buffer.from(profileXml))
held('a profile with dates and data is read key by key', [], problemsInProfile(read, where))

const leaf = 'AB'.repeat(20)
const exportedFine = {
  described: 'Authority=Apple Distribution: Kala Holdings Inc (L775WGST9V)\nTeamIdentifier=L775WGST9V\n',
  leafSha1: leaf,
  profile: { ...read, CertificateSha1s: [leaf] },
  entitlements: { 'application-identifier': `${TEAM}.to.kala.reach`, 'aps-environment': 'production', 'get-task-allow': false },
  team: TEAM
}
held('a bundle signed by the profile\'s distribution certificate passes', [], problemsInExportSignature(exportedFine))
heldProblems('an ad hoc signature is refused at export', problemsInExportSignature({ ...exportedFine, described: 'Signature=adhoc\nTeamIdentifier=not set\n' }), ['signed ad hoc', 'not signed with an Apple Distribution', 'not signed under the team'])
heldProblems('a certificate the profile does not list is refused', problemsInExportSignature({ ...exportedFine, leafSha1: 'CD'.repeat(20) }), ['certificate its profile does not list'])
heldProblems(
  'an entitlement the profile does not allow is refused',
  problemsInExportSignature({ ...exportedFine, entitlements: { ...exportedFine.entitlements, 'com.apple.developer.associated-domains': ['applinks:example.com'] } }),
  ['allows no com.apple.developer.associated-domains']
)

held('an application that says it uses encryption passes, and one that is silent or says no does not', [0, 1, 1], [
  problemsInEncryptionKey({ ITSAppUsesNonExemptEncryption: true }).length,
  problemsInEncryptionKey({}).length,
  problemsInEncryptionKey({ ITSAppUsesNonExemptEncryption: false }).length
])

const versions = { versionCode: 39800, versionName: '0.1.0' }
const info = (code, name) => ({ CFBundleVersion: code, CFBundleShortVersionString: name })
held('an application and an extension of one version pass', [], problemsInVersions([['app', info('39800', '0.1.0')], ['ext', info('39800', '0.1.0')]], versions))
heldProblems(
  'an extension whose short version differs from the application is refused',
  problemsInVersions([['app', info('39800', '0.1.0')], ['ext', info('39800', '0.0.9')]], versions),
  ['ext\'s CFBundleShortVersionString is "0.0.9"']
)
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

// -- the ad hoc signature: the entitlements a real archive is sealed with ---------------------------

const codesign = spawnSync('codesign', ['--help'], { encoding: 'utf8' })
if (codesign.error || process.platform !== 'darwin') {
  notRun += 1
  console.log('not run: the ad hoc signing case needs codesign')
} else {
  const signed = join(work, 'Signed.app')
  const extension = join(signed, 'PlugIns', 'KalaReachNotificationService.appex')
  mkdirSync(extension, { recursive: true })
  // One slice of a system program stands for an executable: a signature is read for one architecture.
  for (const executable of [join(signed, 'KalaReach'), join(extension, 'KalaReachNotificationService')]) {
    const thin = spawnSync('lipo', ['/usr/bin/true', '-thin', 'arm64e', '-output', executable])
    if (thin.status !== 0) copyFileSync('/usr/bin/true', executable)
  }
  const bundleInfo = (identifier, executable) =>
    `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${identifier}</string><key>CFBundleExecutable</key><string>${executable}</string></dict></plist>`
  writeFileSync(join(signed, 'Info.plist'), bundleInfo('to.kala.reach', 'KalaReach'))
  writeFileSync(join(extension, 'Info.plist'), bundleInfo('to.kala.reach.notifications', 'KalaReachNotificationService'))
  signArchive(signed, TEAM)
  const sealed = (path) => entitlementsOf(path)[0]
  const application = sealed(join(signed, 'KalaReach'))
  const notification = sealed(join(extension, 'KalaReachNotificationService'))
  held('the application is sealed with production push and its two keychain groups', ['production', [`${TEAM}.to.kala.reach`, `${TEAM}.to.kala.reach.shared`]], [application['aps-environment'], application['keychain-access-groups']])
  held('the extension is sealed with the shared group alone and no push', [[`${TEAM}.to.kala.reach.shared`], undefined], [notification['keychain-access-groups'], notification['aps-environment']])
}

// -- the shell library: the guard that puts the Apple project back, and the build number rules ---

const library = join(import.meta.dirname, '..', '..', '..', 'scripts', 'lib', 'store-build.sh')
const shell = (script, environment = {}) =>
  spawnSync('bash', ['-c', `set -u; . "${library}"; ${script}`], { encoding: 'utf8', env: { ...process.env, ...environment } })
const repository = join(work, 'repository')
const appleDirectory = join(repository, 'apps', 'companion', 'src-tauri', 'gen', 'apple')
mkdirSync(appleDirectory, { recursive: true })
const git = (...args) => spawnSync('git', ['-C', repository, ...args], { encoding: 'utf8' })
git('init', '-q')
git('config', 'user.email', 'selftest@example.com')
git('config', 'user.name', 'selftest')
writeFileSync(join(appleDirectory, 'Info.plist'), 'committed\n')
writeFileSync(join(repository, '.gitignore'), 'Local.xcconfig\n')
git('add', '.')
git('commit', '-q', '-m', 'start')
const guardRun = (script, environment) => shell(`kr_store_guard_begin "${repository}" "${appleDirectory}" || exit 7; ${script}; kr_store_guard_end`, environment)

writeFileSync(join(appleDirectory, 'Info.plist'), 'a person\'s uncommitted edit\n')
const refused = guardRun('true', { KR_STORE_ALLOW_DIRTY: '1' })
held('uncommitted work under the Apple project stops the build, trial override or not', [7, "a person's uncommitted edit\n"], [refused.status, readFileSync(join(appleDirectory, 'Info.plist'), 'utf8')])
git('checkout', '--', '.')

const localConfig = join(appleDirectory, 'Local.xcconfig')
const rewritten = guardRun(`kr_store_guard_write_local "KR_GOOGLE_SERVICE_INFO = /x"; echo rewritten > "${join(appleDirectory, 'Info.plist')}"`)
held(
  'a build that rewrites a tracked file and writes Local.xcconfig leaves both as they were',
  [0, 'committed\n', false],
  [rewritten.status, readFileSync(join(appleDirectory, 'Info.plist'), 'utf8'), shell(`[ -e "${localConfig}" ]`).status === 0]
)
writeFileSync(localConfig, 'KR_SIGN_STYLE = Manual # a person\'s own\n')
const kept = guardRun('kr_store_guard_write_local "KR_GOOGLE_SERVICE_INFO = /x"')
held('a Local.xcconfig that was there is put back byte for byte', [0, "KR_SIGN_STYLE = Manual # a person's own\n"], [kept.status, readFileSync(localConfig, 'utf8')])
rmSync(localConfig, { force: true })

const root = join(work, 'store-root')
const receipts = join(root, 'receipts')
mkdirSync(receipts, { recursive: true })
writeFileSync(join(receipts, 'ios'), '39000\n')
const number = (value) => shell(`kr_store_number ios ${value}`, { KR_STORE_ROOT: root })
held('a build number at or below the receipt is refused', [2, 2], [number(39000).status, number(38999).status])
held('a build number above the receipt is taken', [0, '39001\n'], [number(39001).status, number(39001).stdout])
held('a number of eleven digits, or no number, is refused', [2, 2], [number(12345678901).status, number("'abc'").status])
shell('kr_store_receipt ios 39500; kr_store_receipt ios 39200', { KR_STORE_ROOT: root })
held('the receipt keeps the larger number when two builds finish out of order', '39500\n', readFileSync(join(receipts, 'ios'), 'utf8'))
held('a second claim on one output directory fails', [0, 2], [shell(`kr_store_claim "${join(root, 'out')}"`).status, shell(`kr_store_claim "${join(root, 'out')}"`).status])

const notARepository = join(work, 'not-a-repository'); mkdirSync(join(notARepository, 'gen'), { recursive: true })
held('a place git cannot read is not taken for a clean one', [7, 2], [
  shell(`kr_store_guard_begin "${notARepository}" "${notARepository}/gen" || exit 7`).status,
  shell(`kr_store_clean_tree "${notARepository}"`).status
])

writeFileSync(localConfig, 'KR_SIGN_STYLE = Manual # kept\n')
const stuck = shell(
  `kr_store_guard_begin "${repository}" "${appleDirectory}" || exit 7; kr_store_guard_write_local "KR_GOOGLE_SERVICE_INFO = /x"; chmod 0444 "${localConfig}"; kr_store_guard_end; echo "end=$?"; ls -d "\${TMPDIR:-/tmp}"/kr-store-guard.* | head -1`,
  { TMPDIR: work }
)
const keptCopy = stuck.stdout.trim().split('\n').pop()
held('when the project cannot be put back the guard fails, and keeps the copy and names it', [true, true, "KR_SIGN_STYLE = Manual # kept\n"], [
  stuck.stdout.includes('end=1'),
  stuck.stderr.includes(keptCopy),
  readFileSync(join(keptCopy, 'Local.xcconfig'), 'utf8')
])
spawnSync('chmod', ['0644', localConfig])
rmSync(localConfig, { force: true })

const racing = join(work, 'racing'); mkdirSync(racing)
shell('for n in $(seq 39100 39139); do kr_store_receipt ios $n & done; wait', { KR_STORE_ROOT: racing })
held('forty receipts written at once leave the largest number', '39139\n', readFileSync(join(racing, 'receipts', 'ios'), 'utf8'))
held('a build number claimed once cannot be claimed again, whatever the version, but is free for the other platform', [0, 2, 0], [
  shell('kr_store_claim_number android 39500', { KR_STORE_ROOT: racing }).status,
  shell('kr_store_claim_number android 39500', { KR_STORE_ROOT: racing }).status,
  shell('kr_store_claim_number ios 39500', { KR_STORE_ROOT: racing }).status
])

rmSync(work, { recursive: true, force: true })
console.log(`${passed} held, ${failures} failed, ${notRun} not run`)
process.exit(failures > 0 ? 1 : notRun > 0 ? 3 : 0)
