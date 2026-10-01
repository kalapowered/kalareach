#!/usr/bin/env node
// Holds the identifier check to the answers it must give.
//
// The check reads a built companion and says whether every identifier in it agrees. A build that
// declares the right identifier can still package the wrong one, and the check exists for the
// ways that happens without a failing build: a team the signed-in Xcode account chose, a keychain
// group in the wrong order, an extension filed under another application, a name an earlier
// identifier left in an executable, in a dex file, in a library or in a manifest. Building the
// application cannot produce those on demand, so they are built here: a bundle as `tauri ios
// build` leaves one, with property lists and Mach-O executables written for the purpose; a bundle
// of the kind Google Play takes, with its manifest in the form a bundle keeps it in; and the
// Android manifest's own names as `aapt2` prints them.
//
// The iOS half reads property lists with `plutil` and signatures with `codesign`, which only macOS
// has. Where they are missing those cases are reported as not run, never as passed, and the exit
// status says so.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { dex, uleb, zip } from './archive-fixtures.mjs'
import {
  aapt2In,
  attributesFromTree,
  declared,
  entitlementsOf,
  factsFromAapt,
  problemsInBundle,
  problemsInDex,
  problemsInManifest,
  problemsInPackage,
  retiredTokens
} from './identifiers.mjs'

const work = mkdtempSync(join(tmpdir(), 'kr-identifiers-'))
let failures = 0
let notRun = 0

/** Says what the check answered, and whether that is what it had to answer. */
function held(what, expected, answer) {
  if (answer === expected) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${expected}\n        answered: ${answer}`)
}

/** States that `problems` holds a problem with each fragment, or none at all for no fragment. */
function heldProblems(what, problems, fragments) {
  const joined = problems.join('\n')
  const missing = fragments.filter((fragment) => !joined.includes(fragment))
  const unexpected = fragments.length === 0 && problems.length > 0
  held(what, 'as expected', missing.length === 0 && !unexpected ? 'as expected' : joined || 'none')
}

/** What a call answers, or the failure it threw. */
function answer(call) {
  try {
    return call()
  } catch (failure) {
    return `refused: ${failure.message}`
  }
}

// -- what the sources declare ----------------------------------------------------------------------

/** A source tree that declares `identifier` and the Apple teams in `project`. */
function sources(name, identifier, project) {
  const root = join(work, name)
  mkdirSync(join(root, 'src-tauri', 'gen', 'apple'), { recursive: true })
  writeFileSync(join(root, 'src-tauri', 'tauri.conf.json'), JSON.stringify({ identifier }))
  writeFileSync(join(root, 'src-tauri', 'gen', 'apple', 'project.yml'), project)
  return root
}

const TEAM = 'L775WGST9V'
const WANT = declared(
  sources('good', 'to.kala.reach', `settings:\n  base:\n    DEVELOPMENT_TEAM: ${TEAM}\n`)
)

held(
  'the names follow from the identifier and the team the sources declare',
  JSON.stringify({
    identifier: 'to.kala.reach',
    extension: 'to.kala.reach.notifications',
    team: TEAM,
    privateGroup: `${TEAM}.to.kala.reach`,
    sharedGroup: `${TEAM}.to.kala.reach.shared`
  }),
  JSON.stringify(WANT)
)

const NO_TEAM = 'refused: src-tauri/gen/apple/project.yml must name one Apple team, as ten characters'
held(
  'sources that name no Apple team are refused rather than checked against none',
  NO_TEAM,
  answer(() => declared(sources('no-team', 'to.kala.reach', 'settings:\n  base: {}\n')))
)
held(
  'sources that name two Apple teams are refused rather than one of them chosen',
  NO_TEAM,
  answer(() =>
    declared(
      sources(
        'two-teams',
        'to.kala.reach',
        'DEVELOPMENT_TEAM: L775WGST9V\n    DEVELOPMENT_TEAM: JT6GW3W9W6\n'
      )
    )
  )
)

// -- the names of an earlier identifier ------------------------------------------------------------

for (const [what, text, expected] of [
  ['a name under the kept namespace is found whole', 'to.kala.reach.companion.push', ['to.kala.reach.companion.push']],
  ['a name inside an address is found without the address', 'content://to.kala.reach.companion.share', ['to.kala.reach.companion.share']],
  ['the identifier an earlier build declared is found', 'to.kala.companion', ['to.kala.companion']],
  ['a name that follows the identifier is not found', 'to.kala.reach.push', []],
  ['the application identifier itself is not found', 'to.kala.reach', []],
  ['a name that only begins like the kept namespace is not found', 'to.kala.reach.companionship', []],
  // Java reads `to.kala.reach.companion_preferences` as a name under `to.kala.reach`, so it is no
  // name under the earlier namespace.
  ['a name that continues with an underscore is not found', 'to.kala.reach.companion_preferences', []],
  ['a name that continues with a dollar is not found', 'to.kala.reach.companion$Inner', []]
]) {
  held(what, JSON.stringify(expected), JSON.stringify(retiredTokens(text)))
}

const cut = retiredTokens(`to.kala.companion.${'a'.repeat(3000)}`)
held(
  'a name cut off at the reach is marked, so that it is never taken for a class that is defined',
  'true',
  String(cut.length === 1 && cut[0].endsWith('\u2026'))
)

// -- the dex files of an application ---------------------------------------------------------------

const WORKER = 'to.kala.reach.companion.push.PreviewWorker'
heldProblems(
  'a class the dex defines under the kept namespace is correct, and so is a name that follows the identifier',
  problemsInDex([dex({ defined: [WORKER], constants: ['to.kala.reach.push', WORKER] })]),
  []
)
heldProblems(
  'a constant under the kept namespace is a name that did not follow the identifier',
  problemsInDex([dex({ defined: [WORKER], constants: ['to.kala.reach.companion.push'] })]),
  ['the name to.kala.reach.companion.push']
)
heldProblems(
  'an address that holds a name under the kept namespace is refused',
  problemsInDex([dex({ constants: ['content://to.kala.reach.companion.share/files'] })]),
  ['the name to.kala.reach.companion.share']
)
heldProblems(
  'a class that one dex file defines is a class when another dex file names it',
  problemsInDex([dex({ constants: [WORKER] }), dex({ defined: [WORKER] })]),
  []
)
heldProblems(
  'a name no dex file defines is refused even when every dex file is read',
  problemsInDex([dex({ constants: [WORKER] }), dex({ defined: ['to.kala.reach.push.Other'] })]),
  [`the name ${WORKER}`]
)
heldProblems(
  'a class defined under the identifier before the namespace was kept is still refused',
  problemsInDex([dex({ defined: ['to.kala.companion.MainActivity'] })]),
  ['the name to.kala.companion.MainActivity']
)
heldProblems(
  'a sentence that names a defined class is not a stale name',
  problemsInDex([dex({ defined: [WORKER], constants: [`failed: ${WORKER} was not found`] })]),
  []
)

// -- the manifest of an application ----------------------------------------------------------------

const values = (...each) => each
const GOOD = {
  package: 'to.kala.reach',
  values: values(
    ['manifest', 'package', 'to.kala.reach'],
    ['permission', 'name', 'to.kala.reach.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'],
    ['provider', 'authorities', 'to.kala.reach.fileprovider'],
    ['service', 'name', WORKER]
  )
}
const KNOWN = new Set([WORKER])
const without = (element, attribute) =>
  GOOD.values.filter(([each, name]) => each !== element || name !== attribute)
const withValue = (...added) => ({ ...GOOD, values: [...GOOD.values, ...added] })

heldProblems(
  'a manifest whose package and names follow the identifier is whole',
  problemsInManifest(GOOD, WANT, KNOWN),
  []
)
heldProblems(
  'a component the manifest names must be a class the application defines',
  problemsInManifest(GOOD, WANT),
  [`holds ${WORKER}, which is not a class`]
)
heldProblems(
  'a manifest filed under another package is refused',
  problemsInManifest({ ...GOOD, package: 'to.kala.reach.companion' }, WANT, KNOWN),
  ['package is to.kala.reach.companion, not to.kala.reach']
)
heldProblems(
  'a provider authority under the kept namespace is refused',
  problemsInManifest(
    { ...GOOD, values: [...without('provider', 'authorities'), ['provider', 'authorities', 'to.kala.reach.companion.fileprovider']] },
    WANT,
    KNOWN
  ),
  ['provider authorities to.kala.reach.companion.fileprovider does not follow to.kala.reach']
)
heldProblems(
  'a second authority after a semicolon is held to the identifier too',
  problemsInManifest(
    withValue(['provider', 'authorities', 'to.kala.reach.files;com.example.files']),
    WANT,
    KNOWN
  ),
  ['provider authorities com.example.files does not follow to.kala.reach']
)
heldProblems(
  'a permission under another application is refused',
  problemsInManifest(withValue(['permission', 'name', 'to.kala.other.READ']), WANT, KNOWN),
  ['permission name to.kala.other.READ does not follow to.kala.reach']
)
heldProblems(
  'a name of the kept namespace in any other attribute is refused unless it is a class',
  problemsInManifest(
    withValue(
      ['meta-data', 'value', 'to.kala.reach.companion.push.Alerts'],
      ['action', 'name', 'to.kala.reach.companion.voice.START']
    ),
    WANT,
    KNOWN
  ),
  [
    'meta-data value holds to.kala.reach.companion.push.Alerts, which is not a class',
    'action name holds to.kala.reach.companion.voice.START, which is not a class'
  ]
)
heldProblems(
  'a manifest with no provider authority is refused rather than passed',
  problemsInManifest({ package: 'to.kala.reach', values: without('provider', 'authorities') }, WANT, KNOWN),
  ['declares no provider authority']
)

const TREE = `
    E: manifest (line=2)
      A: package="to.kala.reach" (Raw: "to.kala.reach")
      E: permission (line=56)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="to.kala.reach.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" (Raw: "x")
      E: application (line=62)
        E: provider (line=125)
          A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="to.kala.reach.fileprovider" (Raw: "x")
          A: http://schemas.android.com/apk/res/android:exported(0x01010010)=false
        E: service (line=130)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="to.kala.reach.companion.push.PreviewWorker" (Raw: "x")
`
held(
  'a manifest dump gives up the package and every attribute of every element, in order',
  JSON.stringify([
    ['manifest', 'package', 'to.kala.reach'],
    ['permission', 'name', 'to.kala.reach.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'],
    ['provider', 'authorities', 'to.kala.reach.fileprovider'],
    ['service', 'name', WORKER]
  ]),
  JSON.stringify(attributesFromTree(TREE))
)
const QUOTED = `
    E: manifest (line=2)
      E: application (line=62)
        E: meta-data (line=70)
          A: http://schemas.android.com/apk/res/android:value(0x01010024)="{"id":"to.kala.reach.companion.old"}" (Raw: "{"id":"to.kala.reach.companion.old"}")
          A: http://schemas.android.com/apk/res/android:exported(0x01010010)=false
`
held(
  'a value that holds quotes of its own is read whole',
  JSON.stringify([['meta-data', 'value', '{"id":"to.kala.reach.companion.old"}']]),
  JSON.stringify(attributesFromTree(QUOTED))
)
heldProblems(
  'a name of an earlier identifier inside such a value is found',
  problemsInManifest(
    { package: 'to.kala.reach', values: [...GOOD.values, ...attributesFromTree(QUOTED)] },
    WANT,
    KNOWN
  ),
  ['meta-data value holds to.kala.reach.companion.old, which is not a class']
)
held(
  'the package comes from the badging line',
  'to.kala.reach',
  String(factsFromAapt("package: name='to.kala.reach' versionCode='1000'\n", TREE).package)
)

// -- the tool that reads an APK --------------------------------------------------------------------

const sdk = join(work, 'sdk')
for (const version of ['35.0.0', '9.0.0', '36.0.0']) {
  mkdirSync(join(sdk, 'build-tools', version), { recursive: true })
  writeFileSync(join(sdk, 'build-tools', version, 'aapt2'), '')
}
mkdirSync(join(sdk, 'build-tools', '37.0.0'), { recursive: true })
writeFileSync(join(sdk, 'build-tools', '37.0.0', 'aapt2.exe'), '')
held(
  'the newest build tools that carry aapt2 are used, by version and not by name',
  join(sdk, 'build-tools', '36.0.0', 'aapt2'),
  String(aapt2In(sdk, 'darwin'))
)
held(
  'on Windows the tool is aapt2.exe, and a build tools directory without one is passed over',
  join(sdk, 'build-tools', '37.0.0', 'aapt2.exe'),
  String(aapt2In(sdk, 'win32'))
)
held('an SDK with no build tools has no aapt2', 'null', String(aapt2In(join(work, 'none'), 'darwin')))

// -- a bundle, as Google Play takes it -------------------------------------------------------------

/** One protocol-buffer length-delimited field. */
const field = (number, payload) =>
  Buffer.concat([uleb(number * 8 + 2), uleb(payload.length), payload])
const text = (number, value) => field(number, Buffer.from(value))

/** An `XmlNode` holding an element: its name, attributes and child elements. */
function xmlNode(name, attributes = {}, children = []) {
  const element = Buffer.concat([
    text(3, name),
    ...Object.entries(attributes).map(([key, value]) =>
      field(4, Buffer.concat([text(2, key), text(3, value)]))
    ),
    ...children.map((child) => field(5, child))
  ])
  return field(1, element)
}

/** The manifest of a bundle, in the form a bundle keeps it in. */
function manifestOfBundle({
  identifier = 'to.kala.reach',
  authority = 'to.kala.reach.fileprovider',
  service = WORKER,
  metadata = null
} = {}) {
  return xmlNode('manifest', { package: identifier }, [
    ...(metadata === null ? [] : [xmlNode('meta-data', { value: metadata })]),
    xmlNode('permission', { name: 'to.kala.reach.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION' }),
    xmlNode('application', {}, [
      xmlNode('provider', { authorities: authority }),
      xmlNode('service', { name: service })
    ])
  ])
}

/** A bundle as the build leaves one; every part a case changes is an option. */
function packagedBundle(name, change = {}) {
  const option = (key, fallback) => (Object.hasOwn(change, key) ? change[key] : fallback)
  const path = join(work, `${name}.aab`)
  writeFileSync(
    path,
    zip([
      ...(Object.hasOwn(change, 'noManifest')
        ? []
        : [{ name: 'base/manifest/AndroidManifest.xml', bytes: option('manifest', manifestOfBundle()) }]),
      { name: 'base/dex/classes.dex', bytes: dex({ defined: [WORKER] }) },
      { name: 'base/dex/classes2.dex', bytes: dex({ constants: option('constants', []) }) },
      { name: 'base/assets/index.js', bytes: Buffer.from(option('page', 'console.log("hello")')) },
      { name: 'base/lib/arm64-v8a/libapp.so', bytes: Buffer.from(option('library', 'ELF')) },
      {
        name: 'base/root/META-INF/services/example.Loader',
        bytes: Buffer.from(option('services', `${WORKER}\n`))
      },
      { name: 'base/root/META-INF/CERT.RSA', bytes: Buffer.from('to.kala.companion signed') },
      {
        name: 'BUNDLE-METADATA/map/proguard.map',
        bytes: Buffer.from(`${WORKER} -> a.b:`)
      }
    ])
  )
  return path
}

/** What a bundle must be told it is wrong about: every fragment, and nothing when none. */
function expectBundle(what, change, fragments) {
  const path = packagedBundle(what.replaceAll(/\W+/g, '-').slice(0, 40), change)
  let problems
  try {
    problems = problemsInPackage(path, WANT)
  } catch (failure) {
    problems = [`refused: ${failure.message}`]
  }
  heldProblems(what, problems, fragments)
}

expectBundle('a bundle whose manifest, code and files agree is whole', {}, [])
expectBundle(
  'a bundle filed under another package is refused, from its own manifest',
  { manifest: manifestOfBundle({ identifier: 'to.kala.reach.companion' }) },
  ["package is to.kala.reach.companion, not to.kala.reach"]
)
expectBundle(
  'a bundle whose provider authority is under the kept namespace is refused',
  { manifest: manifestOfBundle({ authority: 'to.kala.reach.companion.fileprovider' }) },
  ['provider authorities to.kala.reach.companion.fileprovider does not follow']
)
expectBundle(
  'a name an earlier identifier left in a second dex file is refused',
  { constants: ['to.kala.reach.companion.attention'] },
  ['the application\'s code carries the name to.kala.reach.companion.attention']
)
expectBundle(
  'the identifier before it was renamed, in the interface the bundle carries, is refused',
  { page: 'application_id: "to.kala.companion"' },
  ['base/assets/index.js carries to.kala.companion']
)
expectBundle(
  'a JNI name an earlier identifier left in a native library is refused',
  { library: 'Java_to_kala_reach_companion_Bridge_start' },
  ['base/lib/arm64-v8a/libapp.so carries to_kala_reach_companion']
)
expectBundle(
  'the earlier Apple team in a bundle file is refused',
  { page: 'team JT6GW3W9W6' },
  ['base/assets/index.js carries JT6GW3W9W6']
)
expectBundle(
  'a bundle whose manifest names a component no dex file defines is refused',
  { manifest: manifestOfBundle({ service: 'to.kala.reach.companion.push.Missing' }) },
  ['service name holds to.kala.reach.companion.push.Missing, which is not a class']
)
expectBundle(
  'a name of an earlier identifier inside a value that holds quotes is found in a bundle manifest',
  { manifest: manifestOfBundle({ metadata: '{"id":"to.kala.reach.companion.old"}' }) },
  ['meta-data value holds to.kala.reach.companion.old, which is not a class']
)
expectBundle(
  'a bundle whose manifest is empty is refused rather than passed',
  { manifest: Buffer.alloc(0) },
  ['the bundle manifest holds no element']
)
expectBundle(
  'a bundle with no manifest is refused rather than passed',
  { noManifest: true },
  ['the bundle holds no base/manifest/AndroidManifest.xml']
)
expectBundle(
  'a manifest cut short in a fixed-width field is refused rather than read as far as it goes',
  { manifest: Buffer.concat([manifestOfBundle(), Buffer.from([0x09, 0x01])]) },
  ['a protocol-buffer field runs past its message']
)
expectBundle(
  'a protocol-buffer number that does not fit in 64 bits is refused',
  { manifest: Buffer.from([0x08, ...Array(9).fill(0xff), 0x7f]) },
  ['a protocol-buffer number is too large']
)
expectBundle(
  'a native method of a class in a package of the kept namespace is not a stale name',
  { library: 'Java_to_kala_reach_companion_push_Bridge_start' },
  []
)
expectBundle(
  'a service file that names a class the application defines is not a stale name',
  { services: `${WORKER}\n` },
  []
)
expectBundle(
  'a service file that names another class of the kept namespace is refused',
  { services: 'to.kala.reach.companion.push.Gone\n' },
  ['base/root/META-INF/services/example.Loader carries to.kala.reach.companion.push.Gone']
)
expectBundle(
  'the identifier before the namespace was kept is found in a file as UTF-16 text',
  { page: Buffer.from('to.kala.companion', 'utf16le') },
  ['base/assets/index.js carries to.kala.companion (as UTF-16)']
)
expectBundle(
  'a class the application defines is not a stale name in a file as UTF-16 text either',
  { page: Buffer.from(WORKER, 'utf16le') },
  []
)
expectBundle(
  'a name that only begins like the kept namespace is not a stale name as UTF-16 text',
  { page: Buffer.from('to.kala.reach.companionship', 'utf16le') },
  []
)
expectBundle(
  'a name that only begins like the kept namespace is not a stale name in a file',
  { page: 'to.kala.reach.companionship' },
  []
)

// -- an iOS application bundle ---------------------------------------------------------------------

const hasPlutil = !spawnSync('plutil', ['-help'], { encoding: 'utf8' }).error
const hasCodesign = !spawnSync('codesign', ['-h'], { encoding: 'utf8' }).error

/** A property list, as XML. */
function plist(value) {
  const escape = (each) => each.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  const node = (each) => {
    if (Array.isArray(each)) return `<array>${each.map(node).join('')}</array>`
    if (typeof each === 'string') return `<string>${escape(each)}</string>`
    if (typeof each === 'boolean') return each ? '<true/>' : '<false/>'
    const entries = Object.entries(each).map(
      ([key, inner]) => `<key>${escape(key)}</key>${node(inner)}`
    )
    return `<dict>${entries.join('')}</dict>`
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">${node(value)}</plist>\n`
}

/**
 * A thin 64-bit Mach-O image with one `__TEXT,__entitlements` section holding `entitlements`, or
 * none when it is null, followed by `after` as the rest of the file. `claimed` is the length the
 * section says it has, which is the length of the data unless a case lies about it.
 */
function image(entitlements, after = '', claimed = null) {
  const data = entitlements === null ? Buffer.alloc(0) : Buffer.from(plist(entitlements))
  const sections = entitlements === null ? 0 : 1
  const commandSize = 72 + sections * 80
  const header = Buffer.alloc(32)
  header.writeUInt32LE(0xfeedfacf, 0)
  header.writeUInt32LE(0x0100000c, 4)
  header.writeUInt32LE(2, 12)
  header.writeUInt32LE(1, 16)
  header.writeUInt32LE(commandSize, 20)
  const command = Buffer.alloc(commandSize)
  command.writeUInt32LE(0x19, 0)
  command.writeUInt32LE(commandSize, 4)
  command.write('__TEXT', 8, 'latin1')
  command.writeUInt32LE(sections, 64)
  if (sections === 1) {
    command.write('__entitlements', 72, 'latin1')
    command.write('__TEXT', 88, 'latin1')
    command.writeBigUInt64LE(BigInt(claimed ?? data.length), 72 + 40)
    command.writeUInt32LE(32 + commandSize, 72 + 48)
  }
  return Buffer.concat([header, command, data, Buffer.from(after)])
}

/** A fat executable of the images given, as the notification extension is built. */
function fat(...images) {
  const header = Buffer.alloc(8 + images.length * 20)
  header.writeUInt32BE(0xcafebabe, 0)
  header.writeUInt32BE(images.length, 4)
  let at = 4096
  const placed = []
  images.forEach((each, index) => {
    header.writeUInt32BE(0x0100000c + index, 8 + index * 20)
    header.writeUInt32BE(at, 16 + index * 20)
    header.writeUInt32BE(each.length, 20 + index * 20)
    placed.push([at, each])
    at += each.length + 4096
  })
  const file = Buffer.alloc(at)
  header.copy(file, 0)
  for (const [offset, each] of placed) each.copy(file, offset)
  return file
}

const SHARED = `${TEAM}.to.kala.reach.shared`
const PRIVATE = `${TEAM}.to.kala.reach`
const DOMAINS = ['applinks:reach.kala.to', 'webcredentials:reach.kala.to']

/** A bundle as the build leaves one; every field a case changes is an option. */
function bundle(name, change = {}) {
  const option = (key, fallback) => (Object.hasOwn(change, key) ? change[key] : fallback)
  const app = join(work, `${name}.app`)
  const extension = join(app, 'PlugIns', 'KalaReachNotificationService.appex')
  mkdirSync(extension, { recursive: true })
  mkdirSync(join(app, 'assets'))
  writeFileSync(
    join(app, 'Info.plist'),
    plist({
      CFBundleIdentifier: option('appId', 'to.kala.reach'),
      CFBundleExecutable: 'KalaReach',
      KRPrivateKeychainGroup: option('privateGroup', PRIVATE),
      KRSharedKeychainGroup: option('sharedGroup', SHARED)
    })
  )
  writeFileSync(
    join(app, 'KalaReach'),
    option(
      'appExecutable',
      image(
        {
          'application-identifier': PRIVATE,
          'aps-environment': 'development',
          'com.apple.developer.associated-domains': option('domains', DOMAINS),
          'keychain-access-groups': option('groups', [PRIVATE, SHARED])
        },
        option('appTail', '')
      )
    )
  )
  writeFileSync(join(app, 'assets', 'index.js'), option('page', 'console.log("hello")'))
  writeFileSync(
    join(extension, 'Info.plist'),
    plist({
      CFBundleIdentifier: option('extensionId', 'to.kala.reach.notifications'),
      CFBundleExecutable: 'KalaReachNotificationService',
      KRSharedKeychainGroup: SHARED,
      NSExtension: {
        NSExtensionPointIdentifier: option('extensionPoint', 'com.apple.usernotifications.service')
      }
    })
  )
  const entitlements = {
    'application-identifier': `${TEAM}.to.kala.reach.notifications`,
    'keychain-access-groups': option('extensionGroups', [SHARED])
  }
  writeFileSync(
    join(extension, 'KalaReachNotificationService'),
    option('extensionExecutable', fat(image(entitlements), image(entitlements)))
  )
  return app
}

/** States what a bundle must be told it is wrong about: every fragment, and nothing when none. */
function expectApp(what, change, fragments) {
  if (!hasPlutil) {
    notRun += 1
    console.log(`not run  ${what} (plutil is not available)`)
    return
  }
  let problems
  try {
    problems = problemsInBundle(bundle(what.replaceAll(/\W+/g, '-').slice(0, 40), change), WANT)
  } catch (failure) {
    problems = [`refused: ${failure.message}`]
  }
  heldProblems(what, problems, fragments)
}

const EXTENSION = "KalaReachNotificationService.appex's keychain access groups: found "
expectApp('a bundle whose every identifier agrees is whole', {}, [])
expectApp(
  'keychain groups under another team than the project names are refused',
  { privateGroup: 'JT6GW3W9W6.to.kala.reach', sharedGroup: 'JT6GW3W9W6.to.kala.reach.shared' },
  [
    'own keychain group: found JT6GW3W9W6.to.kala.reach, expected L775WGST9V.to.kala.reach',
    'shared keychain group: found JT6GW3W9W6.to.kala.reach.shared'
  ]
)
expectApp(
  'entitlements under another team than the project names are refused',
  {
    groups: ['JT6GW3W9W6.to.kala.reach', 'JT6GW3W9W6.to.kala.reach.shared'],
    extensionGroups: ['JT6GW3W9W6.to.kala.reach.shared']
  },
  ['the application\'s keychain access groups: found ["JT6GW3W9W6.to.kala.reach"', EXTENSION]
)
expectApp(
  'an application filed under another identifier is refused',
  { appId: 'to.kala.reach.companion' },
  ['bundle identifier: found to.kala.reach.companion, expected to.kala.reach']
)
expectApp(
  'a notification extension that is not under the application is refused',
  { extensionId: 'to.kala.other.notifications' },
  ['is to.kala.other.notifications, which is not under to.kala.reach']
)
expectApp(
  'a notification extension named other than the identifier says is refused',
  { extensionId: 'to.kala.reach.push' },
  ['bundle identifier: found to.kala.reach.push, expected to.kala.reach.notifications']
)
expectApp(
  'a bundle with no notification extension is refused',
  { extensionPoint: 'com.apple.widget-extension' },
  ['carries 0 notification service extensions']
)
expectApp(
  "the shared group listed before the application's own is refused",
  { groups: [SHARED, PRIVATE] },
  ['keychain access groups: found ["L775WGST9V.to.kala.reach.shared","L775WGST9V.to.kala.reach"]']
)
expectApp(
  "an extension entitled to the application's own group is refused",
  {
    extensionExecutable: (() => {
      const own = image({
        'application-identifier': `${TEAM}.to.kala.reach.notifications`,
        'keychain-access-groups': [SHARED, PRIVATE]
      })
      return fat(own, own)
    })()
  },
  [`${EXTENSION}["L775WGST9V.to.kala.reach.shared","L775WGST9V.to.kala.reach"]`]
)
expectApp(
  'an application with a missing universal link association is refused',
  { domains: ['webcredentials:reach.kala.to'] },
  ['associated domains: found ["webcredentials:reach.kala.to"]']
)
expectApp(
  'an application whose executable carries no entitlements is refused',
  { appExecutable: image(null) },
  ['the application carries no entitlements']
)
expectApp(
  'one architecture of a fat executable disagreeing is refused',
  {
    extensionExecutable: fat(
      image({
        'application-identifier': `${TEAM}.to.kala.reach.notifications`,
        'keychain-access-groups': [SHARED]
      }),
      image({
        'application-identifier': `${TEAM}.to.kala.reach.notifications`,
        'keychain-access-groups': ['JT6GW3W9W6.to.kala.reach.shared']
      })
    )
  },
  [`${EXTENSION}["JT6GW3W9W6.to.kala.reach.shared"]`]
)
expectApp(
  'a name an earlier identifier left in the executable is refused',
  { appTail: '\0to.kala.reach.companion.notification-preview\0' },
  ['KalaReach carries to.kala.reach.companion']
)
expectApp(
  'the earlier Apple team in the executable is refused',
  { appTail: '\0JT6GW3W9W6\0' },
  ['KalaReach carries JT6GW3W9W6']
)
expectApp(
  'the identifier before it was renamed, in the interface the bundle carries, is refused',
  { page: 'application_id: "to.kala.companion"' },
  ['assets/index.js carries to.kala.companion']
)
expectApp(
  'an executable whose entitlements run past the file is refused rather than read short',
  { appExecutable: image({ 'application-identifier': PRIVATE }, '', 1 << 20) },
  ['the entitlements run past the image']
)

// -- executables that are not what they claim ---------------------------------------------------

/** What `entitlementsOf` answers for an executable written for the purpose. */
function entitlementsFrom(name, bytes) {
  const path = join(work, name)
  writeFileSync(path, bytes)
  return answer(() => JSON.stringify(entitlementsOf(path)))
}

{
  held(
    'a fat executable that lists no image is refused rather than read as having nothing to say',
    'refused: a fat executable lists no image',
    entitlementsFrom('fat-none', fat())
  )
  const truncated = fat(image(null))
  held(
    'a fat executable whose image runs past the file is refused',
    'refused: a fat executable image runs past the file',
    entitlementsFrom('fat-short', truncated.subarray(0, 4100))
  )
  const long = image({ 'application-identifier': PRIVATE })
  long.writeUInt32LE(0xfffffff0, 32 + 4)
  held(
    'a load command whose size runs past the image is refused although its section fits',
    'refused: a Mach-O load command runs past the image',
    entitlementsFrom('command-long', long)
  )
  const crowded = image({ 'application-identifier': PRIVATE })
  crowded.writeUInt32LE(40, 32 + 64)
  held(
    'a segment that counts more sections than its command holds is refused',
    'refused: a Mach-O segment runs past its command',
    entitlementsFrom('segment-crowded', crowded)
  )
  const unsigned = image(null)
  held(
    'an executable that is unsigned and carries no entitlements has none, not a refusal',
    'null',
    entitlementsFrom('plain', unsigned).replace('[null]', 'null')
  )
  held(
    'a fat executable with no entitlements of its own is not read through one architecture',
    'refused: a fat executable carries no entitlements of its own and its signature is read for one architecture only',
    entitlementsFrom('fat-plain', fat(image(null), image(null)))
  )
}

if (hasPlutil && hasCodesign) {
  // A signed build keeps its entitlements in the signature and has no copy in the executable. The
  // executable here is a system tool copied and signed ad hoc with entitlements of its own.
  const signed = join(work, 'signed-tool')
  const archs = spawnSync('lipo', ['-archs', '/usr/bin/true'], { encoding: 'utf8' }).stdout.trim()
  const thin =
    archs.includes(' ')
      ? spawnSync('lipo', ['/usr/bin/true', '-thin', archs.split(' ').at(-1), '-output', signed], {
          encoding: 'utf8'
        })
      : { status: 0, stderr: '' }
  if (!archs.includes(' ')) copyFileSync('/usr/bin/true', signed)
  if (thin.status !== 0) {
    failures += 1
    console.error(`FAIL  the fixture executable could not be made thin: ${thin.stderr}`)
  }
  const list = join(work, 'signed.entitlements')
  writeFileSync(list, plist({ 'keychain-access-groups': [PRIVATE, SHARED] }))
  const signing = spawnSync('codesign', ['--force', '--sign', '-', '--entitlements', list, signed], {
    encoding: 'utf8'
  })
  if (signing.status === 0) {
    held(
      'entitlements a signature seals are read when the executable carries no copy',
      JSON.stringify([[PRIVATE, SHARED]]),
      answer(() => JSON.stringify(entitlementsOf(signed).map((each) => each['keychain-access-groups'])))
    )
  } else {
    failures += 1
    console.error(`FAIL  the fixture executable could not be signed: ${signing.stderr}`)
  }
} else {
  notRun += 1
  console.log('not run  entitlements sealed in a signature (codesign is not available)')
}

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} of the identifier checks answered wrongly`)
  process.exit(1)
}
if (notRun > 0) {
  console.error(`${notRun} identifier cases were not run: this needs plutil and codesign (macOS)`)
  process.exit(3)
}
console.log('the identifier check answers correctly on every bundle, manifest and executable above')
