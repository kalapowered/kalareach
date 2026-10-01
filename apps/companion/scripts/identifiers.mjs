#!/usr/bin/env node
// Reads a built companion and says whether every identifier in it agrees.
//
// The application identifier is declared once, in `src-tauri/tauri.conf.json`, and everything the
// platforms need follows from it: the iOS bundle and its notification extension, the keychain
// groups, the Android package and the names the native code files its own state under. Declaring
// an identifier correctly does not make the packaged application carry it, so this reads the built
// product instead of the files that were meant to produce it:
//
//   iOS      the bundle's and the extension's Info.plist, the entitlements each executable carries
//            (a simulator build keeps them in the executable, a signed build in its signature), and
//            every file in the bundle, for a name an earlier identifier or team left behind.
//   Android  the package the packaged manifest declares (an APK's, or a bundle's own), the
//            authorities and permissions it defines for itself, the strings in the application's
//            dex files, and the assets, resources and native libraries, for the same leftovers.
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
// Every question here fails closed: a tool that is missing, a file that cannot be read and a layout
// this does not understand are problems of their own, never a pass.
//
// Usage:
//   node scripts/identifiers.mjs --ios [KalaReach.app]
//   node scripts/identifiers.mjs --android [app.apk | app.aab ...]
// With no path, the iOS check reads the application `tauri ios build` left under
// `src-tauri/gen/apple/build`, and the Android check reads every package under the Gradle outputs.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  OUTPUTS,
  applicationDex,
  artefacts,
  definedClasses,
  definedStrings,
  withArchive
} from './android-classes.mjs'

const ROOT = dirname(import.meta.dirname)

/** The universal link and the credentials association the application's entitlements declare. */
export const ASSOCIATED_DOMAINS = ['applinks:reach.kala.to', 'webcredentials:reach.kala.to']

/** The code namespace the Android sources keep: it names classes, never the application. */
const KEPT_NAMESPACE = 'to.kala.reach.companion'

/** The names an earlier identifier gave this application, as dotted names and their JNI form. */
const RETIRED_NAMES = [KEPT_NAMESPACE, 'to.kala.companion']
const RETIRED_JNI = RETIRED_NAMES.map((name) => name.replaceAll('.', '_'))

/** The Apple team the application used to be filed under. */
const RETIRED_TEAMS = ['JT6GW3W9W6']

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

// -- names an earlier identifier left ------------------------------------------------------------

/**
 * The dotted names in `text` that belong to an earlier identifier, whole: `content://` followed by
 * `to.kala.reach.companion.share` answers `to.kala.reach.companion.share`. A name that only begins
 * like one (`to.kala.reach.companionship`) is not one.
 */
export function retiredTokens(text) {
  return text.match(/[\w$.]*to\.kala\.(?:reach\.)?companion(?![\w$])[\w$.]*/g) ?? []
}

/** The earlier names, teams and JNI spellings a file's bytes contain, as UTF-8 or UTF-16. */
function retiredInBytes(bytes, { jni = false } = {}) {
  const needles = [...RETIRED_NAMES, ...RETIRED_TEAMS, ...(jni ? RETIRED_JNI : [])]
  return needles.filter(
    (name) => bytes.includes(name) || bytes.includes(Buffer.from(name, 'utf16le'))
  )
}

// -- iOS -----------------------------------------------------------------------------------------

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
    if (at + 8 > image.length) throw new Error('a Mach-O load command runs past the image')
    const command = image.readUInt32LE(at)
    const size = image.readUInt32LE(at + 4)
    if (size < 8) throw new Error('a Mach-O load command has no size')
    if (command === LC_SEGMENT_64) {
      const sections = image.readUInt32LE(at + 64)
      if (at + 72 + sections * 80 > image.length) {
        throw new Error('a Mach-O segment runs past the image')
      }
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
          if (offset + length > image.length) throw new Error('the entitlements run past the image')
          return plistValue(null, image.subarray(offset, offset + length))
        }
      }
    }
    at += size
  }
  return null
}

/** The entitlements a signature seals an executable with, or null when it seals none. */
function signedEntitlements(path) {
  const answer = spawnSync('codesign', ['-d', '--entitlements', '-', '--xml', path], {
    maxBuffer: 16 * 1024 * 1024
  })
  if (answer.error || answer.status !== 0 || answer.stdout.length === 0) return null
  const sealed = plistValue(null, answer.stdout)
  return Object.keys(sealed).length === 0 ? null : sealed
}

/**
 * The entitlements every image of an executable carries, one entry per architecture, or the one
 * set its signature seals.
 *
 * A simulator build does not seal its entitlements into the signature: the simulator reads the
 * copy the linker put in the executable, which is therefore the one to read. A device or release
 * build has no such copy and carries them in its signature. An entry is null for an image that
 * carries none.
 */
export function entitlementsOf(path) {
  const file = readFileSync(path)
  let images
  if (file.length >= 8 && file.readUInt32BE(0) === FAT_MAGIC) {
    const count = file.readUInt32BE(4)
    if (count === 0 || 8 + count * 20 > file.length) {
      throw new Error('a fat executable lists no image')
    }
    images = []
    for (let index = 0; index < count; index += 1) {
      const entry = 8 + index * 20
      const offset = file.readUInt32BE(entry + 8)
      const size = file.readUInt32BE(entry + 12)
      if (offset + size > file.length) throw new Error('a fat executable image runs past the file')
      images.push(entitlementsOfImage(file.subarray(offset, offset + size)))
    }
  } else {
    images = [entitlementsOfImage(file)]
  }
  if (images.every((image) => image === null)) {
    const sealed = signedEntitlements(path)
    if (sealed) return [sealed]
  }
  return images
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

const show = (value) => (typeof value === 'string' ? value : JSON.stringify(value))

/** Records what a built product carries where it differs from what the sources declare. */
function compare(problems, what, found, expected) {
  const same = Array.isArray(expected)
    ? Array.isArray(found) &&
      found.length === expected.length &&
      found.every((value, index) => value === expected[index])
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
      problems.push(`${name} carries no entitlements, in its executable or in its signature`)
      continue
    }
    const id = image['application-identifier']
    compare(problems, `${name}'s application-identifier entitlement`, id, expected.id)
    const groups = image['keychain-access-groups']
    compare(problems, `${name}'s keychain access groups`, groups, expected.groups)
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
  const own = "the application's"
  compare(problems, `${own} bundle identifier`, application.CFBundleIdentifier, want.identifier)
  compare(problems, `${own} own keychain group`, application.KRPrivateKeychainGroup, want.privateGroup)
  compare(problems, `${own} shared keychain group`, application.KRSharedKeychainGroup, want.sharedGroup)
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

  // Nothing in the bundle may carry a name an earlier identifier or team gave the application.
  for (const path of filesUnder(app)) {
    const names = retiredInBytes(readFileSync(path))
    if (names.length > 0) {
      problems.push(`${relative(app, path)} carries ${names.join(' and ')}`)
    }
  }
  return [...new Set(problems)]
}

// -- Android -------------------------------------------------------------------------------------

/** The newest `aapt2` of the build tools under an Android SDK, or null. */
export function aapt2In(sdk, platform = process.platform) {
  const tools = join(sdk, 'build-tools')
  if (!existsSync(tools)) return null
  const executable = platform === 'win32' ? 'aapt2.exe' : 'aapt2'
  const versions = readdirSync(tools)
    .filter((name) => existsSync(join(tools, name, executable)))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
  return versions.length === 0 ? null : join(tools, versions.at(-1), executable)
}

/** What `aapt2 dump` printed for an APK, or throws. */
function dump(apk, ...arguments_) {
  const sdk = process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT
  const tool = sdk ? aapt2In(sdk) : null
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

/** What an APK's manifest says, from `aapt2 dump badging` and `aapt2 dump xmltree`. */
export function factsFromAapt(badging, tree) {
  return {
    package: /^package: name='([^']*)'/m.exec(badging)?.[1],
    names: ownNames(tree)
  }
}

/** The fields of one protocol-buffer message: `{ number, value }`, a buffer or a number. */
function protoFields(bytes) {
  const fields = []
  let at = 0
  const varint = () => {
    let value = 0
    for (let shift = 0; shift < 70; shift += 7) {
      if (at >= bytes.length) throw new Error('a protocol-buffer value runs past its message')
      const byte = bytes[at]
      at += 1
      value += (byte & 0x7f) * 2 ** shift
      if ((byte & 0x80) === 0) return value
    }
    throw new Error('a protocol-buffer number is longer than ten bytes')
  }
  while (at < bytes.length) {
    const tag = varint()
    const number = Math.floor(tag / 8)
    const type = tag % 8
    if (type === 0) {
      fields.push({ number, value: varint() })
    } else if (type === 2) {
      const length = varint()
      if (at + length > bytes.length) {
        throw new Error('a protocol-buffer field runs past its message')
      }
      fields.push({ number, value: bytes.subarray(at, at + length) })
      at += length
    } else if (type === 1 || type === 5) {
      at += type === 1 ? 8 : 4
    } else {
      throw new Error(`a protocol-buffer field has wire type ${type}`)
    }
  }
  return fields
}

/** An element of a bundle's manifest: `XmlElement`'s name, attributes and child elements. */
function protoElement(bytes) {
  const element = { name: '', attributes: {}, children: [] }
  for (const field of protoFields(bytes)) {
    if (field.number === 3) {
      element.name = field.value.toString('utf8')
    } else if (field.number === 4) {
      const attribute = protoFields(field.value)
      const text = (number) =>
        attribute.find((each) => each.number === number)?.value?.toString('utf8')
      element.attributes[text(2) ?? ''] = text(3) ?? ''
    } else if (field.number === 5) {
      const child = protoFields(field.value).find((each) => each.number === 1)
      if (child) element.children.push(protoElement(child.value))
    }
  }
  return element
}

/** What a bundle's manifest says, from the protocol-buffer form a bundle keeps it in. */
export function factsFromProto(bytes) {
  const root = protoFields(bytes).find((each) => each.number === 1)
  if (!root) throw new Error('the bundle manifest holds no element')
  const manifest = protoElement(root.value)
  const names = []
  const walk = (element) => {
    if (element.name === 'provider' && 'authorities' in element.attributes) {
      names.push(['provider authority', element.attributes.authorities])
    } else if (element.name === 'permission' && 'name' in element.attributes) {
      names.push(['permission', element.attributes.name])
    }
    element.children.forEach(walk)
  }
  walk(manifest)
  return { package: manifest.attributes.package, names }
}

/** The manifest of a packaged application: an APK's through `aapt2`, a bundle's from its archive. */
function manifestFacts(path) {
  if (path.toLowerCase().endsWith('.apk')) {
    const badging = dump(path, 'badging')
    return factsFromAapt(badging, dump(path, 'xmltree', '--file', 'AndroidManifest.xml'))
  }
  const bytes = withArchive(path, (all, read) => {
    const manifest = all.find((member) => member.name === 'base/manifest/AndroidManifest.xml')
    if (!manifest) throw new Error('the bundle holds no base/manifest/AndroidManifest.xml')
    return read(manifest)
  })
  return factsFromProto(bytes)
}

/**
 * What is wrong with a manifest. Every name it gives itself follows the package: a provider
 * authority or a permission under the retired namespace is a name that did not.
 */
export function problemsInManifest(facts, want) {
  const problems = []
  if (facts.package !== want.identifier) {
    problems.push(`the manifest's package is ${facts.package}, not ${want.identifier}`)
  }
  let authorities = 0
  for (const [kind, name] of facts.names) {
    if (kind === 'provider authority') authorities += 1
    if (!name.startsWith(`${want.identifier}.`) || retiredTokens(name).length > 0) {
      problems.push(`the manifest's ${kind} ${name} does not follow ${want.identifier}`)
    }
  }
  if (authorities === 0) problems.push('the manifest declares no provider authority')
  return problems
}

/**
 * What is wrong with the strings of an application's dex files, taken together: a dotted name of
 * an earlier identifier that is not a class one of them defines. A class in another dex file than
 * the string that names it is still a class the application defines.
 */
export function problemsInDex(dexFiles) {
  const classes = new Set()
  for (const dex of dexFiles) for (const name of definedClasses(dex)) classes.add(name)
  const stale = new Set()
  for (const dex of dexFiles) {
    for (const text of definedStrings(dex)) {
      for (const token of retiredTokens(text)) if (!classes.has(token)) stale.add(token)
    }
  }
  return [...stale].sort().map((name) => `the application's code carries the name ${name}`)
}

/**
 * What is wrong with everything in a package that is neither code nor manifest: the assets, the
 * resources and the native libraries, where an earlier identifier may sit as text or as a JNI name.
 * The manifest is read for its structure and the dex files for their strings, and a bundle's build
 * metadata and signature files name classes of the kept namespace legitimately.
 */
export function problemsInFiles(path) {
  return withArchive(path, (all, read) => {
    const problems = []
    for (const member of all) {
      if (member.name.endsWith('/')) continue
      if (/\.dex$/.test(member.name) || /(^|\/)AndroidManifest\.xml$/.test(member.name)) continue
      if (/^(META-INF|BUNDLE-METADATA)\//.test(member.name)) continue
      const names = retiredInBytes(read(member), { jni: true })
      if (names.length > 0) problems.push(`${member.name} carries ${names.join(' and ')}`)
    }
    return problems
  })
}

/** Checks one packaged Android application. Answers what is wrong with it. */
export function problemsInPackage(path, want = declared()) {
  return [
    ...problemsInManifest(manifestFacts(path), want),
    ...problemsInDex(applicationDex(path)),
    ...problemsInFiles(path)
  ]
}

// -- the command ---------------------------------------------------------------------------------

/** The application `tauri ios build` left, or null. */
function builtBundle() {
  const root = join(ROOT, 'src-tauri', 'gen', 'apple', 'build')
  if (!existsSync(root)) return null
  const apps = bundlesUnder(root)
  return apps.length === 1 ? apps[0] : null
}

/** The application bundles under the build folder, leaving the archive's own copy out. */
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
    const found = paths.length > 0 ? paths : artefacts(OUTPUTS)
    if (found.length === 0) {
      console.error(`No packaged application to check under ${OUTPUTS}.`)
    } else ok = report(found, problemsInPackage)
  } else {
    console.error('usage: identifiers.mjs --ios [KalaReach.app] | --android [app.apk | app.aab ...]')
  }
  process.exit(ok ? 0 : 1)
}
