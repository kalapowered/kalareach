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
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import { uleb, zip } from './archive-fixtures.mjs'
import { factsFromProto } from './identifiers.mjs'
import { withArchive } from './android-classes.mjs'
import {
  ANDROID_PERMISSIONS,
  certificateFingerprint,
  checkIos,
  declaresSignInLink,
  codeIn,
  problemsInBundleConfig,
  problemsInEmbeddedSignature,
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
  recordOf,
  redacted,
  secretNeedles,
  signerOf
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

// A key block made of nothing real, its header and footer put together at run time so that no file
// of the repository holds text shaped like a private key.
const fence = (word) => `${'-'.repeat(5)}${word} PRIVATE KEY${'-'.repeat(5)}`
const pem = (body) => Buffer.from(`${fence('BEGIN')}\n${body}\n${fence('END')}\n`)
const secret = pem(Buffer.from('synthetic body for the self-test, not a key at all').toString('base64'))
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
const TOKEN = `eyJ${'a'.repeat(12)}.eyJ${'b'.repeat(12)}.${'c'.repeat(12)}`
const suppressed = suppressedIfSecret({ problems: ['the version name is "the-secret-itself"'], facts: { secretsFound: 1 } })
held('a bundle that holds a secret is reported by its count, with nothing quoted from it', [1, true], [suppressed.facts.secretsFound, !JSON.stringify(suppressed).includes('the-secret-itself')])
held('an error message that quotes a secret is withheld, and one that does not is kept', ['the details are withheld: they quote a secret file', 'no such file'], [withheldIfSecret('could not read /x/the-secret-itself', secretNeedles(Buffer.from('the-secret-itself\n'))), withheldIfSecret('no such file', secretNeedles(Buffer.from('the-secret-itself\n')))])
held('an error message that quotes a signed token is withheld too', false, withheldIfSecret(`could not read /x/${TOKEN}`, secretNeedles(Buffer.from('the-secret-itself\n'))).includes(TOKEN))
{
  // A member whose name holds the secret and whose compression the reader refuses: its name is
  // searched before it is read, so the scan finds the secret and the reader's own error, which
  // would quote the name, is never raised.
  const scanned = join(work, 'unreadable'); mkdirSync(scanned)
  const named = zip([{ name: 'before-correct-horse-battery-staple-after.txt', bytes: Buffer.from('x') }])
  named.writeUInt16LE(99, named.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])) + 10)
  named.writeUInt16LE(99, 8)
  writeFileSync(join(scanned, 'broken.aab'), named)
  const secretFile = join(work, 'unreadable-secret'); writeFileSync(secretFile, 'correct-horse-battery-staple\n')
  const scan = spawnSync(process.execPath, [join(import.meta.dirname, 'store-bundle.mjs'), '--scan-dir', scanned, '--secret-file', secretFile], { encoding: 'utf8' })
  held('a directory scan that meets a member named with the secret finds it, unread, and prints nothing of it', [1, false], [scan.status, `${scan.stdout}${scan.stderr}`.includes('correct-horse-battery-staple')])
}
{
  const needles = secretNeedles(Buffer.from('correct-horse-battery-staple\n'))
  const identity = { file: 'KalaReach.ipa', platform: 'ios', stage: 'export', versionName: '0.1.0', versionCode: 1, bytes: 1, sha256: 'ab' }
  const clean = recordOf({ identity, problems: [], facts: { pushEnvironment: 'production' }, notes: { commit: 'abc' } }, needles)
  held('a record that quotes nothing secret is kept as it is', [0, true], [clean.problems.length, JSON.parse(clean.text).holds])
  for (const [what, parts] of [
    ['a note', { notes: { leak: TOKEN } }],
    ['a fact', { facts: { leak: 'correct-horse-battery-staple' } }]
  ]) {
    const made = recordOf({ identity, problems: [], facts: {}, notes: {}, ...parts }, needles)
    held(`a record that quotes a secret in ${what} is replaced, and the build does not hold`, [1, false, false], [made.problems.length, JSON.parse(made.text).holds, /correct-horse-battery-staple|eyJ/.test(made.text)])
  }
  held('a file name that quotes a secret never reaches the record', false, recordOf({ identity: { ...identity, file: 'correct-horse-battery-staple.ipa' }, problems: [], facts: {}, notes: {} }, needles).text.includes('correct-horse-battery-staple'))
}
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

// -- a secret in every form the scan meets, and in none of what the command prints ------------------

const HORSE = 'correct-horse-battery-staple'
const horse = secretNeedles(Buffer.from(`${HORSE}\n`))
// A password with a quote and a backslash: a JSON writer escapes both.
const QUOTED = 'pass"word\\back-9f3k'
const quoted = secretNeedles(Buffer.from(`${QUOTED}\n`))
const JSON_QUOTED = JSON.stringify(QUOTED).slice(1, -1)
const bodyLines = Buffer.from(Array.from({ length: 120 }, (_, index) => (index * 37 + 11) % 256)).toString('base64').match(/.{1,64}/g)
const keyText = pem(bodyLines.join('\n'))
const keyNeedles = secretNeedles(keyText)
const squashed = (text) => text.replace(/\s+/g, '')

/** How many places a directory holding these files has, by `secretsUnder`. */
function placesIn(name, files, needles) {
  const directory = join(work, name)
  mkdirSync(directory)
  for (const [file, bytes] of Object.entries(files)) writeFileSync(join(directory, file), bytes)
  return secretsUnder(directory, needles)
}

{
  const identity = { file: 'KalaReach.ipa', platform: 'ios', stage: 'export', versionName: '0.1.0', versionCode: 1, bytes: 1, sha256: 'ab' }
  for (const [what, parts] of [
    ['a file name', { identity: { ...identity, file: `${QUOTED}.ipa` } }],
    ['a version name', { identity: { ...identity, versionName: QUOTED } }],
    ['a note', { notes: { leak: QUOTED } }],
    ['a fact, deep in a list', { facts: { leak: { deeper: ['x', QUOTED] } } }]
  ]) {
    const made = recordOf({ identity, problems: [], facts: {}, notes: {}, ...parts }, quoted)
    held(
      `a record that quotes a secret in ${what} fails the build, and its text holds neither the secret nor its JSON form`,
      [1, false, false, false],
      [made.problems.length, JSON.parse(made.text).holds, made.text.includes(QUOTED), made.text.includes(JSON_QUOTED)]
    )
  }
  const alone = recordOf({ identity: { ...identity, file: `${HORSE}.ipa` }, problems: [], facts: {}, notes: {} }, horse)
  held('a file name that is the secret fails the build, though nothing else is wrong', [1, false], [alone.problems.length, JSON.parse(alone.text).holds])
}

held('a secret written into a JSON file is found whatever the escaping, and other JSON is not', [1, 1, 0], [
  placesIn('json-escaped', { 'a.json': JSON.stringify({ note: QUOTED }) }, quoted),
  placesIn('json-unicode', { 'a.json': '{"note": "pass\\u0022word\\\\back-9f3k"}' }, quoted),
  placesIn('json-other', { 'a.json': JSON.stringify({ note: 'something else' }) }, quoted)
])

{
  // The secret inside a longer text that was encoded whole: the three ways it can sit against the
  // groups of three bytes, in base64 and in its URL form, and in hex.
  const forms = []
  for (const before of [0, 1, 2]) {
    const text = Buffer.from(`${'x'.repeat(before)}${QUOTED}yz`)
    forms.push(text.toString('base64'), text.toString('base64url'), text.toString('hex'), text.toString('hex').toUpperCase())
  }
  held('a secret encoded in base64, base64url or hex is found at every alignment', forms.map(() => 1), forms.map((form, index) => placesIn(`encoded-${index}`, { 'a.txt': `before ${form} after` }, quoted)))
  held('an encoding of something else is not found', 0, placesIn('encoded-other', { 'a.txt': Buffer.from('xx not the secret at all yz').toString('base64') }, quoted))
}

{
  const body = bodyLines.join('')
  const wrapped = (text, width) => text.match(new RegExp(`.{1,${width}}`, 'g')).join('\n')
  held(
    'a secret split across lines is found: wrapped, indented, with other line breaks, or as wrapped base64',
    [1, 1, 1, 1, 1, 1],
    [
      placesIn('split-single', { 'run.log': '    correct-\n    horse-ba\n    ttery-st\n    aple' }, horse),
      placesIn('split-key-fenced', { 'run.log': `${fence('BEGIN')}\n${wrapped(body, 20)}\n${fence('END')}\n` }, keyNeedles),
      placesIn('split-key-body', { 'run.log': wrapped(body, 20) }, keyNeedles),
      placesIn('split-key-crlf', { 'run.log': keyText.toString().replaceAll('\n', '\r\n') }, keyNeedles),
      placesIn('split-key-indented', { 'run.log': keyText.toString().replaceAll('\n', '\n    ') }, keyNeedles),
      placesIn('split-key-base64', { 'run.log': wrapped(keyText.toString('base64'), 76) }, keyNeedles)
    ]
  )
}

{
  // JSON escapes are read wherever they sit: in a log line, in a file of lines, behind white space, in a
  // string on its own, in a file of any size, whatever the writer escapes (a slash, a letter, a symbol,
  // a pair of surrogates).
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const slashLines = [0, 1, 2].map((line) => Array.from({ length: 64 }, (_, index) => alphabet[(index * 5 + line * 13) % 64]).join(''))
  const slashKey = pem(slashLines.join('\n'))
  const slashNeedles = secretNeedles(slashKey)
  const apple = JSON.stringify(slashKey.toString()).replaceAll('/', '\\/')
  const scalar = secretNeedles(Buffer.from('correct-horse-battery-staple\n'))
  const umlaut = secretNeedles(Buffer.from('päss=word&more-9f3k\n'))
  const smile = secretNeedles(Buffer.from('smile😀-secret-9f\n'))
  held(
    'a secret in a JSON string is found whatever escapes it and wherever the string sits',
    [1, 1, 1, 1, 1, 1, 1, 1, 1],
    [
      placesIn('esc-slash-line', { 'run.log': `request body={"key":${apple}}` }, slashNeedles),
      placesIn('esc-ndjson', { 'run.ndjson': `{"a":1}\n{"key":${apple}}\n` }, slashNeedles),
      placesIn('esc-python', { 'run.log': 'user=p\\u00e4ss=word&more-9f3k' }, umlaut),
      placesIn('esc-gson', { 'run.log': 'user=päss\\u003dword\\u0026more-9f3k' }, umlaut),
      placesIn('esc-letter', { 'a.json': '{"password":"\\u0063orrect-horse-battery-staple"}' }, scalar),
      placesIn('esc-spaces', { 'a.json': `${' '.repeat(100)}{"password":"\\u0063orrect-horse-battery-staple"}` }, scalar),
      placesIn('esc-string', { 'a.json': '"\\u0063orrect-horse-battery-staple"' }, scalar),
      placesIn('esc-large', { 'a.json': `{"filler":"${'x'.repeat(17 * 1024 * 1024)}","password":"\\u0063orrect-horse-battery-staple"}` }, scalar),
      placesIn('esc-pair', { 'run.log': 'x smile\\ud83d\\ude00-secret-9f y' }, smile)
    ]
  )
  held(
    'a secret that is escaped and then encoded, or that follows a data backslash, is found',
    [1, 1, 1],
    [
      placesIn('esc-base64', { 'a.txt': Buffer.from(JSON.stringify({ p: QUOTED })).toString('base64') }, quoted),
      placesIn('esc-data-backslash', { 'a.txt': '\\top-secret-\npassword' }, secretNeedles(Buffer.from('top-secret-password\n'))),
      placesIn('esc-split-after-escape', { 'a.json': '{"path":"C:\\\\newpass-\\nword-7731"}' }, secretNeedles(Buffer.from('newpass-word-7731\n')))
    ]
  )
  const jumble = secretNeedles(Buffer.from('jklmnopq\n'))
  held('hex of either case, or of both, is found, also when it is spaced', [1, 1, 1, 1], [
    placesIn('hex-lower', { 'a.txt': '6a6b6c6d6e6f7071' }, jumble),
    placesIn('hex-upper', { 'a.txt': '6A6B6C6D6E6F7071' }, jumble),
    placesIn('hex-mixed', { 'a.txt': '6A6b6C6d6E6f7071' }, jumble),
    placesIn('hex-spaced', { 'a.txt': '6A 6b 6C 6d\n6E 6f 70 71' }, jumble)
  ])
  held('a secret of fewer than eight characters apart from white space is refused', 'throws', (() => { try { secretNeedles(Buffer.from('a b c d e\n')); return 'returns' } catch { return 'throws' } })())
}

{
  // The words this check prints in place of a quotation are never the secret.
  const words = secretNeedles(Buffer.from('secret file\n'))
  const identity = { file: 'KalaReach.ipa', platform: 'ios', stage: 'export', versionName: '0.1.0', versionCode: 1, bytes: 1, sha256: 'ab' }
  const made = recordOf({ identity, problems: [], facts: {}, notes: { leak: 'secret file' } }, words)
  held(
    'when the secret is what the placeholders say, none of them is printed or written',
    [false, false, false, 1],
    [made.text.includes('secret file'), withheldIfSecret('x secret file y', words).includes('secret file'), redacted('a secret file here\n', words).includes('secret file'), made.problems.length]
  )
}

{
  const identity = { file: 'KalaReach.ipa', platform: 'ios', stage: 'export', versionName: '0.1.0', versionCode: 1, bytes: 1, sha256: 'ab' }
  const refuses = (parts) => { try { recordOf({ identity, problems: [], facts: {}, notes: {}, ...parts }, horse); return 'returns' } catch { return 'throws' } }
  held(
    'a note or a fact named like a field of the record is refused, as is a note named like a fact',
    ['throws', 'throws', 'throws', 'throws', 'returns'],
    [refuses({ notes: { file: 'safe.ipa' } }), refuses({ notes: { holds: 'true' } }), refuses({ facts: { problems: [] } }), refuses({ facts: { a: 1 }, notes: { a: 2 } }), refuses({ notes: { commit: 'abc' } })]
  )
}

held('a secret in the name of a file, of an archive member or of the directory itself is found', [1, 1, 1], (() => {
  const archives = join(work, 'archives'); mkdirSync(archives)
  writeFileSync(join(archives, 'named.aab'), zip([{ name: `before-${HORSE}-after.txt`, bytes: Buffer.from('x') }]))
  const empty = join(work, `empty-${HORSE}`); mkdirSync(empty)
  return [placesIn('named-file', { [`before-${HORSE}-after.txt`]: 'x' }, horse), secretsUnder(archives, horse), secretsUnder(empty, horse)]
})())

{
  const scanned = join(work, 'links'); mkdirSync(scanned)
  writeFileSync(join(scanned, 'real.txt'), 'x')
  symlinkSync('real.txt', join(scanned, 'link.txt'))
  const attempt = () => { try { return secretsUnder(scanned, horse) } catch (failure) { return failure.message } }
  held('a directory scan refuses a link, which it cannot read', 'link.txt is a link or a special file, which this scan cannot read', attempt())
  const folders = join(work, 'folders'); mkdirSync(join(folders, `inner-${HORSE}`), { recursive: true })
  held('a directory scan searches the name of a directory that holds no file', 1, secretsUnder(folders, horse))
}

{
  // The command, run as the build scripts run it: nothing it prints holds the secret, whatever the
  // secret has got into (a path, an option, an error).
  const horseFile = join(work, 'horse-secret'); writeFileSync(horseFile, `${HORSE}\n`)
  const cli = (args, input) => spawnSync(process.execPath, [join(import.meta.dirname, 'store-bundle.mjs'), ...args], { encoding: 'utf8', input })
  const leaks = (answer) => `${answer.stdout}${answer.stderr}`.includes(HORSE)
  const named = join(work, `dir-${HORSE}`); mkdirSync(named)
  const scanned = cli(['--scan-dir', named, '--secret-file', horseFile])
  held('a directory scan of a path that holds the secret finds it and prints nothing of it', [1, false], [scanned.status, leaks(scanned)])
  const missing = cli(['--scan-dir', join(work, `missing-${HORSE}`), '--secret-file', horseFile])
  held('a directory scan that cannot read a path that holds the secret prints nothing of it', [2, false], [missing.status, leaks(missing)])
  const clean = join(work, 'dir-with-a-secret-inside'); mkdirSync(clean); writeFileSync(join(clean, 'run.log'), `x ${HORSE} y`)
  const found = cli(['--scan-dir', clean, '--secret-file', horseFile])
  held('a directory scan that finds the secret in a file says how many places and prints nothing of it', [1, false, true], [found.status, leaks(found), /in 1 place under/.test(found.stderr)])
  const unknown = cli([`--bogus-${HORSE}`, '--secret-file', horseFile])
  held('an option that is the secret is refused without printing it', [2, false], [unknown.status, leaks(unknown)])
  const escaped = cli(['--bogus={"password":"\\u0063orrect-horse-battery-staple"}', '--secret-file', horseFile])
  held('an option that holds the secret JSON-escaped is refused without printing it', [2, false], [escaped.status, `${escaped.stdout}${escaped.stderr}`.includes('orrect-horse-battery-staple')])
  const field = cli(['--ios', import.meta.filename, '--stage', 'export', '--version-code', '1', '--version-name', '0.1.0', '--note', 'holds=true', '--secret-file', horseFile])
  held('a note named like a field of the record is refused', [2, true], [field.status, field.stderr.includes('--note cannot be named like a field of the record: holds')])
  const linked = join(work, 'linked-dir'); mkdirSync(linked); symlinkSync(import.meta.filename, join(linked, `link-${HORSE}`))
  const refused = cli(['--scan-dir', linked, '--secret-file', horseFile])
  held('a directory scan that meets a link is refused without printing the link\'s name', [2, false], [refused.status, leaks(refused)])
  const absent = cli(['--ios', join(work, `absent-${HORSE}.ipa`), '--stage', 'export', '--version-code', '1', '--version-name', '0.1.0', '--secret-file', horseFile])
  held('a bundle path that holds the secret and does not exist is refused without printing it', [2, false], [absent.status, leaks(absent)])
  const unreadable = join(work, `unreadable-${HORSE}.aab`); writeFileSync(unreadable, 'not an archive')
  const broken = cli(['--android', unreadable, '--version-code', '1', '--version-name', '0.1.0', '--certificate', import.meta.filename, '--secret-file', horseFile])
  held('a bundle that cannot be read, at a path that holds the secret, is reported without printing it', [2, false], [broken.status, leaks(broken)])

  // What a failing export prints of its log: the secret in no form, and no part of a token.
  const FRAGMENT = 'eyJhbGciOiJFUzI1NiIsImtpZCI6IkFCQ0QifQ'
  const keyFile = join(work, 'tail-key'); writeFileSync(keyFile, keyText)
  const ordinary = ['Export failed: no signing certificate was found', 'Code=1 "provisioning failed"']
  const redact = (lines) => cli(['--redact', '--secret-file', keyFile], `${lines.join('\n')}\n`)
  const plain = redact([...ordinary, `Bearer ${FRAGMENT}`, TOKEN, 'done'])
  held(
    'a log with a token or a part of one keeps its other lines and loses the token',
    [0, true, true, false],
    [plain.status, plain.stdout.includes(ordinary[0]), plain.stdout.includes('done'), plain.stdout.includes('eyJ')]
  )
  const escapedToken = redact([...ordinary, `{"auth":"${TOKEN.replaceAll('eyJ', '\\u0065yJ')}"}`])
  held('a token whose start is JSON-escaped is not printed either', [0, true, false], [escapedToken.status, escapedToken.stdout.includes(ordinary[0]), escapedToken.stdout.includes('a'.repeat(12))])
  const holds = (answer) => squashed(answer.stdout).includes(squashed(bodyLines[0]))
  const keyLines = keyText.toString().trim().split('\n')
  const variants = [
    redact([...ordinary, ...keyLines]),
    redact([...ordinary, ...keyLines.map((line) => `    ${line}`)]),
    redact([...ordinary, ...bodyLines.join('').match(/.{1,20}/g)]),
    redact([...ordinary, `key: ${bodyLines.join('')}`])
  ]
  held(
    'a log that holds the key, as written, indented, rewrapped or on one line, prints none of it',
    [[0, 0, 0, 0], [false, false, false, false]],
    [variants.map((answer) => answer.status), variants.map(holds)]
  )
  const unreadableKey = cli(['--redact', '--secret-file', join(work, 'no-such-key')], `${ordinary[0]}\n`)
  held('a log is printed in full or in part only when the secret could be read', [2, ''], [unreadableKey.status, unreadableKey.stdout])
}

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

const embeddedFine = { described: 'Authority=Apple Distribution: Kala Holdings Inc (L775WGST9V)\nTeamIdentifier=L775WGST9V\n', leafSha1: 'AB'.repeat(20), hostLeafSha1: 'AB'.repeat(20), team: TEAM }
held('a framework signed by its host\'s distribution certificate passes', [], problemsInEmbeddedSignature(embeddedFine))
heldProblems('a framework signed ad hoc is refused', problemsInEmbeddedSignature({ ...embeddedFine, described: 'Signature=adhoc\nTeamIdentifier=not set\n', leafSha1: '' }), ['signed ad hoc', 'not signed with an Apple Distribution', 'not signed under the team'])
heldProblems(
  'a framework signed with a development certificate is refused',
  problemsInEmbeddedSignature({ ...embeddedFine, described: 'Authority=Apple Development: A Person (X)\nTeamIdentifier=L775WGST9V\n', leafSha1: 'CD'.repeat(20) }),
  ['not signed with an Apple Distribution', 'not signed with the certificate of the bundle that holds it']
)
heldProblems('a framework of another team is refused', problemsInEmbeddedSignature({ ...embeddedFine, described: 'Authority=Apple Distribution: Other (ZZZZZZZZZZ)\nTeamIdentifier=ZZZZZZZZZZ\n' }), ['not signed under the team'])
heldProblems('a framework signed with another distribution certificate is refused', problemsInEmbeddedSignature({ ...embeddedFine, leafSha1: 'EF'.repeat(20) }), ['not signed with the certificate of the bundle that holds it'])

{
  // The code of a bundle is read from the first bytes of each file, so headers stand for the files.
  const tree = join(work, 'code-tree')
  mkdirSync(join(tree, 'A.framework', 'Frameworks', 'B.framework'), { recursive: true })
  const header = (...bytes) => Buffer.concat([Buffer.from(bytes), Buffer.alloc(64)])
  const thin = header(0xcf, 0xfa, 0xed, 0xfe)
  writeFileSync(join(tree, 'A.framework', 'A'), thin)
  writeFileSync(join(tree, 'A.framework', 'Frameworks', 'B.framework', 'B'), thin)
  writeFileSync(join(tree, 'one-slice'), header(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1))
  writeFileSync(join(tree, 'two-slices'), header(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2))
  writeFileSync(join(tree, 'notes.txt'), 'text')
  writeFileSync(join(tree, 'empty'), '')
  symlinkSync('notes.txt', join(tree, 'link'))
  spawnSync('mkfifo', [join(tree, 'pipe')])
  const found = codeIn(tree)
  held(
    'the code of a bundle is each Mach-O file at any depth, and a link, a pipe and a universal binary of several architectures are refused, not skipped',
    [
      ['A.framework/A', 'A.framework/Frameworks/B.framework/B', 'one-slice'],
      ['link is a symbolic link, which this check cannot follow', 'pipe is neither a file nor a directory', 'two-slices is a universal binary of several architectures, which this check cannot read']
    ],
    [found.code.map((each) => each.name), found.refused]
  )
  held('a bundle part that is read on its own is left out of the bundle that holds it', ['A.framework/Frameworks/B.framework/B', 'one-slice'], codeIn(tree, [join(tree, 'A.framework', 'A')]).code.map((each) => each.name))
  held('a link is refused even when it is named as a part to be read on its own', true, codeIn(tree, [join(tree, 'link')]).refused.some((each) => each.startsWith('link is a symbolic link')))
}

held('an application that says it needs no export documentation passes, and one that is silent or says it does not', [0, 1, 1], [
  problemsInEncryptionKey({ ITSAppUsesNonExemptEncryption: false }).length,
  problemsInEncryptionKey({}).length,
  problemsInEncryptionKey({ ITSAppUsesNonExemptEncryption: true }).length
])
held('a key of false that comes with an export compliance code is refused', 1, problemsInEncryptionKey({ ITSAppUsesNonExemptEncryption: false, ITSEncryptionExportComplianceCode: 'a1b2c3' }).length)

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
  // A piece of code the system makes: one architecture, signed ad hoc.
  const machO = (path) => {
    mkdirSync(dirname(path), { recursive: true })
    const thin = spawnSync('lipo', ['/usr/bin/true', '-thin', 'arm64e', '-output', path])
    if (thin.status !== 0) copyFileSync('/usr/bin/true', path)
    spawnSync('codesign', ['-f', '-s', '-', path])
  }
  const frameworks = join(signed, 'Frameworks'); mkdirSync(join(frameworks, 'Inner.framework'), { recursive: true })
  machO(join(frameworks, 'Plain.dylib'))
  writeFileSync(join(frameworks, 'notes.txt'), 'not code')
  held('the code in a bundle is every Mach-O file under it and nothing else, and an extension is left to its own reading', ['Frameworks/Plain.dylib', 'KalaReach'], codeIn(signed, [extension]).code.map((each) => each.name))
  held('read as a bundle of its own, the extension holds its executable', ['KalaReachNotificationService'], codeIn(extension).code.map((each) => each.name))
  const adHoc = signerOf(join(frameworks, 'Plain.dylib'))
  heldProblems('a real ad hoc signature on embedded code is read and refused', problemsInEmbeddedSignature({ ...adHoc, hostLeafSha1: 'AB'.repeat(20), team: TEAM }), ['signed ad hoc', 'not signed with an Apple Distribution'])
  held('the extension is sealed with the shared group alone and no push', [[`${TEAM}.to.kala.reach.shared`], undefined], [notification['keychain-access-groups'], notification['aps-environment']])
  // The whole export-stage check on this bundle: embedded code that is signed ad hoc is named among its
  // problems, and a bundle without it is not.
  const exportCheck = () => checkIos({ path: signed, stage: 'export', versionCode: '1', versionName: '0.1.0', secretFiles: [], skipAppChecks: true }).problems
  held('the export check names embedded code that is signed ad hoc', true, exportCheck().some((each) => each.startsWith('Frameworks/Plain.dylib in the application is signed ad hoc')))
  // Code that is not a direct entry of Frameworks: inside a framework, in a framework inside a
  // framework, and outside Frameworks altogether. The outer seal does not make it the team's.
  const deeper = [
    'Frameworks/Outer.framework/Outer',
    'Frameworks/Outer.framework/Helper.dylib',
    'Frameworks/Outer.framework/Frameworks/Nested.framework/Nested',
    'Helpers/tool'
  ]
  for (const each of deeper) machO(join(signed, each))
  const nestedProblems = exportCheck()
  held(
    'the export check holds code nested in a framework, and code outside Frameworks, to the signer rules',
    deeper.map(() => true),
    deeper.map((each) => nestedProblems.some((problem) => problem.startsWith(`${each} in the application is signed ad hoc`)))
  )
  // A layout the check cannot read is refused: a link may lead anywhere, and a universal binary of
  // several architectures has a signature for each.
  symlinkSync('Plain.dylib', join(frameworks, 'Link.dylib'))
  writeFileSync(join(frameworks, 'Several.dylib'), Buffer.concat([Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]), Buffer.alloc(64)]))
  const refusals = exportCheck()
  held(
    'a symbolic link, and a universal binary of several architectures, are refused as code the check cannot read',
    [true, true],
    [refusals.some((each) => each.includes('Frameworks/Link.dylib is a symbolic link')), refusals.some((each) => each.includes('Frameworks/Several.dylib is a universal binary'))]
  )
  rmSync(join(frameworks, 'Link.dylib'), { force: true })
  rmSync(join(frameworks, 'Several.dylib'), { force: true })
  rmSync(join(signed, 'Helpers'), { recursive: true, force: true })
  rmSync(join(frameworks, 'Outer.framework'), { recursive: true, force: true })
  // A name in a problem line is quoted out of the bundle like a value is: the command prints it only
  // through the filter, and the record is written the same way.
  const leaking = join(frameworks, 'leak-correct-horse-battery-staple.dylib')
  copyFileSync(join(frameworks, 'Plain.dylib'), leaking)
  const leakSecret = join(work, 'name-secret'); writeFileSync(leakSecret, 'correct-horse-battery-staple\n')
  const leakRecord = join(work, 'name-record.json')
  const named = spawnSync(process.execPath, [join(import.meta.dirname, 'store-bundle.mjs'), '--ios', signed, '--stage', 'export', '--version-code', '1', '--version-name', '0.1.0', '--skip-app-checks', '--secret-file', leakSecret, '--record', leakRecord], { encoding: 'utf8' })
  held(
    'a problem that quotes a file name holding the secret reaches neither the terminal nor the record',
    [1, false, false],
    [named.status, `${named.stdout}${named.stderr}`.includes('correct-horse-battery-staple'), readFileSync(leakRecord, 'utf8').includes('correct-horse-battery-staple')]
  )
  const secretNamed = checkIos({ path: signed, stage: 'export', versionCode: '1', versionName: '0.1.0', secretFiles: [leakSecret], skipAppChecks: true })
  held('a secret in the name of a file of the application is found', true, secretNamed.facts.secretsFound > 0)
  rmSync(leaking, { force: true })
  // A record that cannot be written is an error of the command, and the path that failed is a path
  // like any other: it reaches the output only through the filter.
  const lost = spawnSync(process.execPath, [join(import.meta.dirname, 'store-bundle.mjs'), '--ios', signed, '--stage', 'archive', '--version-code', '1', '--version-name', '0.1.0', '--skip-app-checks', '--secret-file', leakSecret, '--record', join(work, 'no-such-correct-horse-battery-staple', 'record.json')], { encoding: 'utf8' })
  held('a record that cannot be written ends the command with a read error, and prints nothing of the secret in its path', [2, false], [lost.status, `${lost.stdout}${lost.stderr}`.includes('correct-horse-battery-staple')])
  rmSync(frameworks, { recursive: true, force: true })
  held('and names none once the bundle has no embedded code', false, exportCheck().some((each) => each.includes(' in the application ')))
}

// -- the shell library: the guard that puts the Apple project back, and the build number rules ---

const library = join(import.meta.dirname, '..', '..', '..', 'scripts', 'lib', 'store-build.sh')
const shell = (script, environment = {}) =>
  spawnSync('bash', ['-c', `set -u; . "${library}"; ${script}`], { encoding: 'utf8', env: { ...process.env, ...environment }, timeout: 60000, killSignal: 'SIGKILL' })
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
held('a number with a leading zero is refused, since it would claim a number of its own', 2, number('039900').status)
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

// The receipt lock is a kernel lock on a file: a run that holds it keeps it however slow it is, and a
// run that ends, killed or not, cannot leave it held.
const lockCase = (holder) => {
  const base = join(work, `lock-${Math.random().toString(36).slice(2)}`)
  mkdirSync(join(base, 'receipts'), { recursive: true })
  const file = join(base, 'receipts', 'ios.flock')
  const script = `${holder.replaceAll('$FILE', `"${file}"`)}; kr_store_receipt ios 39900; echo "status=$?"; [ -z "\${holder:-}" ] || kill -9 "$holder" 2>/dev/null; true`
  const answer = shell(script, { KR_STORE_ROOT: base, KR_STORE_LOCK_WAIT: '0' })
  let receipt = 'none'
  try { receipt = readFileSync(join(base, 'receipts', 'ios'), 'utf8').trim() } catch { /* no receipt */ }
  return { text: answer.stdout.trim().split('\n').pop(), receipt }
}
// The holder takes the lock in a shell of its own, then becomes `sleep`, so killing it ends the lock.
const holding = '( exec 8>>$FILE; lockf -s -t 0 8 && : >$FILE.ready; exec sleep 30 ) & holder=$!; until [ -e $FILE.ready ]; do sleep 0.1; done'
const held_ = lockCase(holding)
held('a lock that another run holds is refused, and no receipt is written', ['status=2', 'none'], [held_.text, held_.receipt])
const killed = lockCase(`${holding}; kill -9 $holder; wait $holder 2>/dev/null; holder=`)
held('a lock whose holder was killed is free at once (the kernel releases it)', ['status=0', '39900'], [killed.text, killed.receipt])
const badWait = shell('kr_store_receipt ios 39900', { KR_STORE_ROOT: join(work, 'bad-wait'), KR_STORE_LOCK_WAIT: '1.5' })
held('a wait that is not a whole number of seconds is refused', 2, badWait.status)
const free = lockCase('true')
held('a lock nobody holds is taken', ['status=0', '39900'], [free.text, free.receipt])

// The logs Xcode keeps request tokens in: Packaging.log beside the export, and a log bundle in the
// temporary directory that the export log names.
const tokenLogs = (temporary, where, naming = true) => {
  const base = mkdtempSync(join(work, 'tokens-'))
  mkdirSync(join(base, 'export'), { recursive: true })
  writeFileSync(join(base, 'export', 'Packaging.log'), 'a token')
  const bundle = where(base)
  mkdirSync(bundle, { recursive: true }); writeFileSync(join(bundle, 'IDEDistribution.log'), 'a token')
  writeFileSync(join(base, 'export.log'), naming ? `Created bundle at path "${bundle}".\n` : 'Export started.\n')
  const answer = shell(`${temporary}; kr_store_remove_token_logs "${base}"; echo "status=$?"`, {})
  const exists = (path) => spawnSync('test', ['-e', path]).status === 0
  const removed = answer.stdout.trim().split('\n').pop()
  const result = [removed, exists(join(base, 'export', 'Packaging.log')), exists(bundle)]
  rmSync(bundle, { recursive: true, force: true })
  return result
}
const userTemporary = spawnSync('getconf', ['DARWIN_USER_TEMP_DIR'], { encoding: 'utf8' }).stdout.trim()
const temporaryHere = join(work, 'xcode-temp'); mkdirSync(temporaryHere)
held('Xcode\'s two token logs are removed when the temporary directory is named', ['status=0', false, false], tokenLogs(`export TMPDIR="${temporaryHere}"`, () => join(temporaryHere, 'a.xcdistributionlogs')))
held('Xcode\'s two token logs are removed when TMPDIR is not set', ['status=0', false, false], tokenLogs('unset TMPDIR', () => join(userTemporary, `kr-selftest-${process.pid}.xcdistributionlogs`)))
held('an export log that names no log bundle fails the cleanup, since tokens may remain', ['status=2', false, true], tokenLogs(`export TMPDIR="${temporaryHere}"`, () => join(temporaryHere, 'b.xcdistributionlogs'), false))
held('a log bundle outside the temporary directory is kept, and the cleanup fails', ['status=2', false, true], tokenLogs(`export TMPDIR="${temporaryHere}"`, (base) => join(base, 'elsewhere', 'a.xcdistributionlogs')))

// What a failed export shows of its log: the last lines, indented, through the checker, which leaves
// out the secret in any form and any part of a token, and prints nothing when it cannot read the secret.
{
  const key = join(work, 'show-key'); writeFileSync(key, keyText)
  const log = join(work, 'show-export.log')
  const trail = [
    'Export failed: no signing certificate was found',
    `Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IkFCQ0QifQ`,
    `"Authorization" = "Bearer ${TOKEN}";`,
    'Code=1 "provisioning failed"'
  ]
  writeFileSync(log, [...Array.from({ length: 25 }, (_, index) => `line ${index}`), ...trail].join('\n'))
  const shown = shell(`kr_store_show_tail "${log}" "${key}"`)
  held(
    'the tail of a log is shown indented, without a token or a part of one',
    [0, true, true, false, false],
    [shown.status, shown.stdout.includes('    Export failed: no signing certificate was found'), shown.stdout.includes('    Code=1 "provisioning failed"'), shown.stdout.includes('eyJ'), shown.stdout.includes(bodyLines[0])]
  )
  // A log that holds the key anywhere, above the lines that would be shown too, is shown not at all.
  writeFileSync(log, [...keyText.toString().trim().split('\n'), ...Array.from({ length: 25 }, (_, index) => `line ${index}`), ...trail].join('\n'))
  const kept = shell(`kr_store_show_tail "${log}" "${key}"`).stdout
  held('a log that holds the key above its tail is not shown at all', [false, false], [kept.includes('Export failed'), kept.includes(bodyLines[0])])
  const horseKey = join(work, 'show-horse'); writeFileSync(horseKey, 'correct-horse-battery-staple\n')
  writeFileSync(log, ['first', 'a correct-horse-', 'battery-staple', ...Array.from({ length: 19 }, (_, index) => `line ${index}`)].join('\n'))
  held('a secret split across the first line of the tail is not shown', false, shell(`kr_store_show_tail "${log}" "${horseKey}"`).stdout.includes('battery-staple'))
  writeFileSync(log, [...Array.from({ length: 5 }, (_, index) => `line ${index}`), ...bodyLines.join('').match(/.{1,20}/g)].join('\n'))
  held('a tail that holds the key rewrapped is not shown', false, shell(`kr_store_show_tail "${log}" "${key}"`).stdout.replace(/\s+/g, '').includes(bodyLines[0]))
  held('a tail is not shown when the secret cannot be read', '', shell(`kr_store_show_tail "${log}" "${join(work, 'no-such-key')}"`).stdout)
}

// A path a message is about to print is searched for the secret first: a build root whose name holds
// the password stops the build before the first message names it.
{
  const horseFile = join(work, 'path-secret'); writeFileSync(horseFile, 'correct-horse-battery-staple\n')
  const stop = (...paths) => shell(`kr_store_refuse_secret_in "${horseFile}" ${paths.map((each) => `"${each}"`).join(' ')}; echo "status=$?"`)
  const clean = stop('/var/store', '/var/other')
  const dirty = stop('/var/store', '/var/correct-horse-battery-staple/out')
  const unreadable = shell(`kr_store_refuse_secret_in "${join(work, 'no-such-key')}" /var/store; echo "status=$?"`)
  held(
    'a path that holds the secret, or a secret that cannot be read, stops the build and prints nothing of the path',
    ['status=0', 'status=2', false, 'status=2'],
    [clean.stdout.trim().split('\n').pop(), dirty.stdout.trim().split('\n').pop(), `${dirty.stdout}${dirty.stderr}`.includes('correct-horse-battery-staple'), unreadable.stdout.trim().split('\n').pop()]
  )
}

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
