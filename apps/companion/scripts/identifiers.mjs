#!/usr/bin/env node
// Reads a built companion and says whether every identifier in it agrees.
//
// The application identifier is declared once, in `src-tauri/tauri.conf.json`, and everything the
// platforms need follows from it: the iOS bundle and its notification extension, the keychain
// groups, the Android package and the names the native code files its own state under. Declaring
// an identifier correctly does not make the packaged application carry it, so this reads the built
// product instead of the files that were meant to produce it:
//
//   iOS      the bundle's and the extension's Info.plist, the entitlements the executables carry,
//            and every file in the bundle, for a name an earlier identifier left behind.
//   Android  the package the packaged manifest declares, the authority of the file provider, and
//            the strings in the application's dex files, for the same leftovers.
//
// The team prefix of a keychain group comes from the Apple team the iOS project names. A build
// that resolved its team from whoever happened to be signed in to Xcode would pass a check that
// only compared suffixes, and its groups would belong to a team the application is not registered
// under.
//
// The Kotlin and Java package `to.kala.reach.companion` is a code namespace, not the application
// identifier, and the manifest names its classes by it. A class the application defines under it is
// correct; a string under it that is not one of those classes is a name that should have followed
// the identifier.
//
// Usage:
//   node scripts/identifiers.mjs --ios [KalaReach.app]
//   node scripts/identifiers.mjs --android [app.apk | app.aab ...]
// With no path, the iOS check reads the application `tauri ios build` left under
// `src-tauri/gen/apple/build`, and the Android check reads every package under the Gradle outputs.
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

import { OUTPUTS, applicationDex, definedClasses, definedStrings } from './android-classes.mjs'

const ROOT = dirname(import.meta.dirname)

/** The universal link and the credentials association the application's entitlements declare. */
export const ASSOCIATED_DOMAINS = ['applinks:reach.kala.to', 'webcredentials:reach.kala.to']

/** The code namespace the Android sources keep: it names classes, never the application. */
const KEPT_NAMESPACE = 'to.kala.reach.companion'

/** The names an earlier identifier gave this application, which no build may carry. */
const RETIRED = [KEPT_NAMESPACE, 'to.kala.companion']

/**
 * What the sources declare: the identifier, the names that follow from it and the Apple team.
 *
 * Read from the files rather than written here, so there is one place to change an identifier and
 * this check follows it.
 */
export function declared(root = ROOT) {
  const configuration = JSON.parse(readFileSync(join(root, 'src-tauri', 'tauri.conf.json'), 'utf8'))
  const identifier = configuration.identifier
  if (typeof identifier !== 'string' || identifier === '') {
    throw new Error('src-tauri/tauri.conf.json declares no application identifier')
  }
  const project = readFileSync(join(root, 'src-tauri', 'gen', 'apple', 'project.yml'), 'utf8')
  const teams = [...project.matchAll(/^\s*DEVELOPMENT_TEAM:\s*(\S+)\s*$/gm)].map((each) => each[1])
  if (teams.length !== 1 || !/^[A-Z0-9]{10}$/.test(teams[0])) {
    throw new Error('src-tauri/gen/apple/project.yml must name one Apple team, as ten characters')
  }
  return {
    identifier,
    extension: `${identifier}.notifications`,
    team: teams[0],
    privateGroup: `${teams[0]}.${identifier}`,
    sharedGroup: `${teams[0]}.${identifier}.shared`
  }
}

// -- iOS ---------------------------------------------------------------------------------------

/** A property list (XML or binary), as the value it holds. */
function plistValue(path, input) {
  const answer = spawnSync('plutil', ['-convert', 'json', '-o', '-', '--', path ?? '-'], {
    encoding: 'utf8',
    input
  })
  if (answer.error || answer.status !== 0) {
    throw new Error(`${path ?? 'a property list'} cannot be read: ${answer.stderr || answer.error}`)
  }
  return JSON.parse(answer.stdout)
}

const MH_MAGIC_64 = 0xfeedfacf
const FAT_MAGIC = 0xcafebabe
const LC_SEGMENT_64 = 0x19

/** The entitlements one thin Mach-O image carries in its `__TEXT,__entitlements` section. */
function entitlementsOfImage(image) {
  if (image.length < 32 || image.readUInt32LE(0) !== MH_MAGIC_64) {
    throw new Error('not a 64-bit Mach-O image')
  }
  const commands = image.readUInt32LE(16)
  let at = 32
  for (let index = 0; index < commands; index += 1) {
    const command = image.readUInt32LE(at)
    const size = image.readUInt32LE(at + 4)
    if (command === LC_SEGMENT_64) {
      const sections = image.readUInt32LE(at + 64)
      for (let section = 0; section < sections; section += 1) {
        const header = at + 72 + section * 80
        const name = image.subarray(header, header + 16).toString('latin1').replace(/\0+$/, '')
        const segment = image
          .subarray(header + 16, header + 32)
          .toString('latin1')
          .replace(/\0+$/, '')
        if (segment === '__TEXT' && name === '__entitlements') {
          const length = Number(image.readBigUInt64LE(header + 40))
          const offset = image.readUInt32LE(header + 48)
          return plistValue(null, image.subarray(offset, offset + length))
        }
      }
    }
    at += size
  }
  return null
}

/**
 * The entitlements every image of an executable carries, one entry per architecture.
 *
 * A simulator build does not seal its entitlements into the signature: the simulator reads the
 * copy the linker put in the executable, which is therefore the one to read. An entry is null for
 * an image that carries none.
 */
export function entitlementsOf(path) {
  const file = readFileSync(path)
  if (file.length >= 8 && file.readUInt32BE(0) === FAT_MAGIC) {
    const count = file.readUInt32BE(4)
    const images = []
    for (let index = 0; index < count; index += 1) {
      const entry = 8 + index * 20
      const offset = file.readUInt32BE(entry + 8)
      const size = file.readUInt32BE(entry + 12)
      images.push(entitlementsOfImage(file.subarray(offset, offset + size)))
    }
    return images
  }
  return [entitlementsOfImage(file)]
}

/** Every regular file under a directory, as a path. */
function filesUnder(directory) {
  const found = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) found.push(...filesUnder(path))
    else if (entry.isFile()) found.push(path)
  }
  return found
}

/** The retired names a file's bytes contain. */
function retiredIn(bytes) {
  return RETIRED.filter((name) => bytes.includes(name))
}

const show = (value) => (typeof value === 'string' ? value : JSON.stringify(value))

/** Records what a built product carries where it differs from what the sources declare. */
function compare(problems, what, found, expected) {
  const same = Array.isArray(expected)
    ? Array.isArray(found) && found.length === expected.length && found.every((v, i) => v === expected[i])
    : found === expected
  if (!same) problems.push(`${what}: found ${show(found)}, expected ${show(expected)}`)
}

/**
 * What the entitlements of every image of an executable must say. `groups` is exact and ordered:
 * an application lists its own group first, because an item written without a group is filed
 * under the first one, and the extension is entitled to the shared group alone, so that the
 * device authorisation key is out of its reach.
 */
function compareEntitlements(problems, name, images, expected) {
  for (const image of images) {
    if (image === null) {
      problems.push(`${name} carries no entitlements`)
      continue
    }
    compare(problems, `${name}'s application-identifier entitlement`, image['application-identifier'], expected.id)
    compare(problems, `${name}'s keychain access groups`, image['keychain-access-groups'], expected.groups)
    if (expected.domains) {
      const domains = image['com.apple.developer.associated-domains']
      compare(problems, `${name}'s associated domains`, domains, expected.domains)
    }
  }
}

/**
 * Checks one built application bundle. Answers what is wrong with it, one sentence each.
 */
export function problemsInBundle(app, want = declared()) {
  const problems = []
  const application = plistValue(join(app, 'Info.plist'))
  compare(problems, "the application's bundle identifier", application.CFBundleIdentifier, want.identifier)
  compare(problems, "the application's own keychain group", application.KRPrivateKeychainGroup, want.privateGroup)
  compare(problems, "the application's shared keychain group", application.KRSharedKeychainGroup, want.sharedGroup)
  compareEntitlements(
    problems,
    'the application',
    entitlementsOf(join(app, application.CFBundleExecutable ?? '')),
    {
      id: want.privateGroup,
      groups: [want.privateGroup, want.sharedGroup],
      domains: ASSOCIATED_DOMAINS
    }
  )

  const plugins = join(app, 'PlugIns')
  const extensions = existsSync(plugins)
    ? readdirSync(plugins).filter((name) => name.endsWith('.appex'))
    : []
  const notification = []
  for (const name of extensions) {
    const folder = join(plugins, name)
    const info = plistValue(join(folder, 'Info.plist'))
    if (!String(info.CFBundleIdentifier).startsWith(`${want.identifier}.`)) {
      problems.push(`${name} is ${info.CFBundleIdentifier}, which is not under ${want.identifier}`)
    }
    if (info.NSExtension?.NSExtensionPointIdentifier === 'com.apple.usernotifications.service') {
      notification.push([name, folder, info])
    }
  }
  if (notification.length !== 1) {
    problems.push(`the application carries ${notification.length} notification service extensions`)
  } else {
    const [name, folder, info] = notification[0]
    compare(problems, `${name}'s bundle identifier`, info.CFBundleIdentifier, want.extension)
    compare(problems, `${name}'s shared keychain group`, info.KRSharedKeychainGroup, want.sharedGroup)
    compareEntitlements(problems, name, entitlementsOf(join(folder, info.CFBundleExecutable)), {
      id: `${want.team}.${want.extension}`,
      groups: [want.sharedGroup]
    })
  }

  // Nothing in the bundle may carry a name an earlier identifier gave the application.
  for (const path of filesUnder(app)) {
    const names = retiredIn(readFileSync(path))
    if (names.length > 0) {
      problems.push(`${relative(app, path)} carries ${names.join(' and ')}`)
    }
  }
  return [...new Set(problems)]
}

// -- Android -----------------------------------------------------------------------------------

/** The newest `aapt2` of the installed build tools, or null. */
function aapt2() {
  const sdk = process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT
  if (!sdk) return null
  const tools = join(sdk, 'build-tools')
  if (!existsSync(tools)) return null
  const versions = readdirSync(tools)
    .filter((name) => existsSync(join(tools, name, 'aapt2')))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
  return versions.length === 0 ? null : join(tools, versions.at(-1), 'aapt2')
}

/** What `aapt2 dump` printed for an APK, or throws. */
function dump(apk, ...arguments_) {
  const tool = aapt2()
  if (!tool) {
    throw new Error(
      'ANDROID_HOME names no build tools with aapt2, which this needs to read the APK manifest'
    )
  }
  const answer = spawnSync(tool, ['dump', ...arguments_, apk], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024
  })
  if (answer.status !== 0) throw new Error(`aapt2 could not read ${apk}: ${answer.stderr}`)
  return answer.stdout
}

/** Whether a dex string is a name the retired identifier left rather than a class that exists. */
export function isRetired(text, classes) {
  return RETIRED.some((name) => text === name || text.startsWith(`${name}.`)) && !classes.has(text)
}

/**
 * The names a manifest gives itself that must follow the package: every provider authority and
 * every permission it defines. Read from `aapt2 dump xmltree`, which prints each element and then
 * its attributes.
 */
export function ownNames(tree) {
  const names = []
  let element = null
  for (const line of tree.split('\n')) {
    const started = /^\s*E: (\S+)/.exec(line)
    if (started) {
      element = started[1]
      continue
    }
    const attribute = /^\s*A: \S*?:?(\w+)\([^)]*\)="([^"]*)"/.exec(line)
    if (!attribute) continue
    if (element === 'provider' && attribute[1] === 'authorities') {
      names.push(['provider authority', attribute[2]])
    } else if (element === 'permission' && attribute[1] === 'name') {
      names.push(['permission', attribute[2]])
    }
  }
  return names
}

/**
 * Checks one packaged Android application. Answers what is wrong with it.
 *
 * The manifest is read from an APK; a bundle keeps its manifest in another format, and is held to
 * its dex files here and to its manifest by the APK the same build produced.
 */
export function problemsInPackage(path, want = declared()) {
  const problems = []
  if (path.toLowerCase().endsWith('.apk')) {
    const badging = dump(path, 'badging')
    const named = /^package: name='([^']*)'/m.exec(badging)?.[1]
    if (named !== want.identifier) {
      problems.push(`the manifest's package is ${named}, not ${want.identifier}`)
    }
    // What the manifest names for itself follows the package: the file provider's and the
    // startup provider's authorities, and the permission a library defines for the application.
    // Each is written as `${applicationId}` plus a suffix, so reading them back shows the build
    // substituted the identifier rather than a name left in a source file.
    for (const [kind, name] of ownNames(dump(path, 'xmltree', '--file', 'AndroidManifest.xml'))) {
      if (!name.startsWith(`${want.identifier}.`)) {
        problems.push(`the manifest's ${kind} ${name} is not under ${want.identifier}`)
      }
    }
  }
  const stale = new Set()
  for (const dex of applicationDex(path)) {
    const classes = new Set(definedClasses(dex))
    for (const text of definedStrings(dex)) if (isRetired(text, classes)) stale.add(text)
  }
  for (const text of [...stale].sort()) {
    problems.push(`the application's code carries the name ${text}`)
  }
  return problems
}

// -- the command -------------------------------------------------------------------------------

/** Every APK and AAB under the Gradle outputs. */
function packagedArtefacts() {
  const found = []
  const walk = (directory) => {
    if (!existsSync(directory)) return
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (/\.(apk|aab)$/.test(entry.name)) found.push(path)
    }
  }
  walk(OUTPUTS)
  return found.sort()
}

/** The application `tauri ios build` left, or null. */
function builtBundle() {
  const root = join(ROOT, 'src-tauri', 'gen', 'apple', 'build')
  if (!existsSync(root)) return null
  const apps = bundlesUnder(root)
  return apps.length === 1 ? apps[0] : null
}

/** The application bundles directly beside each other under the build folder. */
function bundlesUnder(root) {
  const apps = []
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name.endsWith('.app')) apps.push(join(root, entry.name))
    else if (entry.isDirectory() && !entry.name.endsWith('.xcarchive')) {
      apps.push(...bundlesUnder(join(root, entry.name)))
    }
  }
  return apps
}

/**
 * Prints what each thing checked answered, and whether all of them held.
 *
 * `check` answers the problems found in one path; a path that cannot be read at all is a problem
 * of its own and not a skipped one.
 */
export function report(paths, check) {
  let whole = true
  for (const path of paths) {
    let problems
    try {
      problems = check(path)
    } catch (failure) {
      problems = [failure.message]
    }
    const shown = relative(process.cwd(), path)
    if (problems.length === 0) {
      console.log(`${shown}: every identifier agrees`)
      continue
    }
    whole = false
    console.error(`${shown}:\n${problems.map((each) => `  ${each}`).join('\n')}`)
  }
  return whole
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const [mode, ...paths] = process.argv.slice(2)
  let ok = false
  if (mode === '--ios') {
    const found = paths.length > 0 ? paths : [builtBundle()].filter(Boolean)
    if (found.length === 0) {
      console.error('No built application: pass the KalaReach.app that `tauri ios build` left.')
    } else ok = report(found, problemsInBundle)
  } else if (mode === '--android') {
    const found = paths.length > 0 ? paths : packagedArtefacts()
    if (found.length === 0) {
      console.error(`No packaged application to check under ${OUTPUTS}.`)
    } else ok = report(found, problemsInPackage)
  } else {
    console.error('usage: identifiers.mjs --ios [KalaReach.app] | --android [app.apk | app.aab ...]')
  }
  process.exit(ok ? 0 : 1)
}
