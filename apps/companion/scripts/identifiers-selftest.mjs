#!/usr/bin/env node
// Holds the identifier check to the answers it must give.
//
// The check reads a built companion and says whether every identifier in it agrees. A build that
// declares the right identifier can still package the wrong one, and the check exists for the
// ways that happens without a failing build: a team the signed-in Xcode account chose, a keychain
// group in the wrong order, an extension filed under another application, a name an earlier
// identifier left in an executable. Building the application cannot produce those on demand, so
// they are built here: a bundle as `tauri ios build` leaves one, with property lists and Mach-O
// executables written for the purpose, and the Android manifest's own names as `aapt2` prints them.
//
// The iOS half reads property lists with `plutil`, which only macOS has. Where it is missing the
// iOS cases are reported as not run, never as passed.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { declared, isRetired, ownNames, problemsInBundle } from './identifiers.mjs'

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

// -- what the sources declare --------------------------------------------------------------------

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

/** What `declared` says about sources that do not declare one team. */
function declaredFrom(name, project) {
  try {
    return declared(sources(name, 'to.kala.reach', project)).team
  } catch (failure) {
    return `refused: ${failure.message}`
  }
}
held(
  'sources that name no Apple team are refused rather than checked against none',
  'refused: src-tauri/gen/apple/project.yml must name one Apple team, as ten characters',
  declaredFrom('no-team', 'settings:\n  base: {}\n')
)
held(
  'sources that name two Apple teams are refused rather than one of them chosen',
  'refused: src-tauri/gen/apple/project.yml must name one Apple team, as ten characters',
  declaredFrom('two-teams', 'DEVELOPMENT_TEAM: L775WGST9V\n    DEVELOPMENT_TEAM: JT6GW3W9W6\n')
)

// -- the Android manifest's own names --------------------------------------------------------------

const MANIFEST = `
    E: manifest (line=2)
      A: package="to.kala.reach" (Raw: "to.kala.reach")
      E: permission (line=56)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="to.kala.reach.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" (Raw: "x")
      E: uses-permission (line=60)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.permission.INTERNET" (Raw: "x")
      E: application (line=62)
        E: provider (line=125)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="androidx.core.content.FileProvider" (Raw: "x")
          A: http://schemas.android.com/apk/res/android:authorities(0x01010018)="to.kala.reach.companion.fileprovider" (Raw: "x")
        E: service (line=130)
          A: http://schemas.android.com/apk/res/android:name(0x01010003)="to.kala.reach.companion.push.KalaReachMessagingService" (Raw: "x")
`
held(
  'a manifest gives up its provider authorities and the permissions it defines, and no other name',
  JSON.stringify([
    ['permission', 'to.kala.reach.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'],
    ['provider authority', 'to.kala.reach.companion.fileprovider']
  ]),
  JSON.stringify(ownNames(MANIFEST))
)

const classes = new Set(['to.kala.reach.companion.push.PreviewWorker'])
for (const [what, text, retired] of [
  ['a class the dex defines under the kept namespace is correct', 'to.kala.reach.companion.push.PreviewWorker', false],
  ['a constant under the kept namespace is a name that did not follow the identifier', 'to.kala.reach.companion.push', true],
  ['a notification channel under the kept namespace is refused', 'to.kala.reach.companion.attention', true],
  ['the identifier an earlier build declared is refused', 'to.kala.companion', true],
  ['a name that follows the identifier is correct', 'to.kala.reach.push', false],
  ['the application identifier itself is correct', 'to.kala.reach', false],
  ['a name that only begins like the kept namespace is not under it', 'to.kala.reach.companionship', false]
]) {
  held(what, String(retired), String(isRetired(text, classes)))
}

// -- an iOS application bundle ---------------------------------------------------------------------

const plutil = spawnSync('plutil', ['-help'], { encoding: 'utf8' })
const hasPlutil = !plutil.error

/** A property list, as XML. */
function plist(value) {
  const escape = (text) => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
  const node = (each) => {
    if (Array.isArray(each)) return `<array>${each.map(node).join('')}</array>`
    if (typeof each === 'string') return `<string>${escape(each)}</string>`
    if (typeof each === 'boolean') return each ? '<true/>' : '<false/>'
    const entries = Object.entries(each).map(([key, inner]) => `<key>${escape(key)}</key>${node(inner)}`)
    return `<dict>${entries.join('')}</dict>`
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">${node(value)}</plist>\n`
}

/**
 * A thin 64-bit Mach-O image with one `__TEXT,__entitlements` section holding `entitlements`, or
 * none when it is null, followed by `after` as the rest of the file.
 */
function image(entitlements, after = '') {
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
    command.writeBigUInt64LE(BigInt(data.length), 72 + 40)
    command.writeUInt32LE(32 + commandSize, 72 + 48)
  }
  return Buffer.concat([header, command, data, Buffer.from(after)])
}

/** A fat executable of two images, as the notification extension is built. */
function fat(first, second) {
  const header = Buffer.alloc(8 + 2 * 20)
  header.writeUInt32BE(0xcafebabe, 0)
  header.writeUInt32BE(2, 4)
  const offset = 4096
  header.writeUInt32BE(0x0100000c, 8)
  header.writeUInt32BE(offset, 16)
  header.writeUInt32BE(first.length, 20)
  header.writeUInt32BE(0x01000007, 28)
  header.writeUInt32BE(offset + 4096 + first.length, 36)
  header.writeUInt32BE(second.length, 40)
  const padded = Buffer.alloc(offset + 4096 + first.length + second.length)
  header.copy(padded, 0)
  first.copy(padded, offset)
  second.copy(padded, offset + 4096 + first.length)
  return padded
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
        NSExtensionPointIdentifier: option(
          'extensionPoint',
          'com.apple.usernotifications.service'
        )
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
function expectBundle(what, change, fragments) {
  if (!hasPlutil) {
    notRun += 1
    console.log(`not run  ${what} (plutil is not available)`)
    return
  }
  const name = what.replaceAll(/\W+/g, '-').slice(0, 40)
  let problems
  try {
    problems = problemsInBundle(bundle(name, change), WANT)
  } catch (failure) {
    problems = [`refused: ${failure.message}`]
  }
  const joined = problems.join('\n')
  const missing = fragments.filter((fragment) => !joined.includes(fragment))
  const unexpected = fragments.length === 0 && problems.length > 0
  held(what, 'as expected', missing.length === 0 && !unexpected ? 'as expected' : `${joined || 'no problem'}`)
}

expectBundle('a bundle whose every identifier agrees is whole', {}, [])
expectBundle(
  'keychain groups under another team than the project names are refused',
  {
    privateGroup: 'JT6GW3W9W6.to.kala.reach',
    sharedGroup: 'JT6GW3W9W6.to.kala.reach.shared'
  },
  [
    'own keychain group: found JT6GW3W9W6.to.kala.reach, expected L775WGST9V.to.kala.reach',
    'shared keychain group: found JT6GW3W9W6.to.kala.reach.shared'
  ]
)
expectBundle(
  'entitlements under another team than the project names are refused',
  {
    groups: ['JT6GW3W9W6.to.kala.reach', 'JT6GW3W9W6.to.kala.reach.shared'],
    extensionGroups: ['JT6GW3W9W6.to.kala.reach.shared']
  },
  [
    'the application\'s keychain access groups: found ["JT6GW3W9W6.to.kala.reach"',
    'KalaReachNotificationService.appex\'s keychain access groups: found ["JT6GW3W9W6.to.kala.reach.shared"]'
  ]
)
expectBundle(
  'an application filed under another identifier is refused',
  { appId: 'to.kala.reach.companion' },
  ['bundle identifier: found to.kala.reach.companion, expected to.kala.reach']
)
expectBundle(
  'a notification extension that is not under the application is refused',
  { extensionId: 'to.kala.other.notifications' },
  ['is to.kala.other.notifications, which is not under to.kala.reach']
)
expectBundle(
  'a notification extension named other than the identifier says is refused',
  { extensionId: 'to.kala.reach.push' },
  ['bundle identifier: found to.kala.reach.push, expected to.kala.reach.notifications']
)
expectBundle(
  'a bundle with no notification extension is refused',
  { extensionPoint: 'com.apple.widget-extension' },
  ['carries 0 notification service extensions']
)
expectBundle(
  'the shared group listed before the application\'s own is refused',
  { groups: [SHARED, PRIVATE] },
  ['keychain access groups: found ["L775WGST9V.to.kala.reach.shared","L775WGST9V.to.kala.reach"]']
)
expectBundle(
  'an extension entitled to the application\'s own group is refused',
  {
    extensionExecutable: (() => {
      const own = image({
        'application-identifier': `${TEAM}.to.kala.reach.notifications`,
        'keychain-access-groups': [SHARED, PRIVATE]
      })
      return fat(own, own)
    })()
  },
  [
    'KalaReachNotificationService.appex\'s keychain access groups: found ' +
      '["L775WGST9V.to.kala.reach.shared","L775WGST9V.to.kala.reach"]'
  ]
)
expectBundle(
  'an application with a missing universal link association is refused',
  { domains: ['webcredentials:reach.kala.to'] },
  ['associated domains: found ["webcredentials:reach.kala.to"]']
)
expectBundle(
  'an application whose executable carries no entitlements is refused',
  { appExecutable: image(null) },
  ['the application carries no entitlements']
)
expectBundle(
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
  [
    'KalaReachNotificationService.appex\'s keychain access groups: found ' +
      '["JT6GW3W9W6.to.kala.reach.shared"]'
  ]
)
expectBundle(
  'a name an earlier identifier left in the executable is refused',
  { appTail: '\0to.kala.reach.companion.notification-preview\0' },
  ['KalaReach carries to.kala.reach.companion']
)
expectBundle(
  'the identifier before it was renamed, in the interface the bundle carries, is refused',
  { page: 'application_id: "to.kala.companion"' },
  ['assets/index.js carries to.kala.companion']
)

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} of the identifier checks answered wrongly`)
  process.exit(1)
}
console.log(
  notRun > 0
    ? `${notRun} identifier cases were not run; every case that ran answered correctly`
    : 'the identifier check answers correctly on every bundle and manifest above'
)
