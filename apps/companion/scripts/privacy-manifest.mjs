#!/usr/bin/env node
// Holds an iOS application's privacy manifest to the application that was built.
//
// Apple asks each app, and each framework or extension inside it, to declare the categories of
// required reason API its code uses, with a reason for each, in a `PrivacyInfo.xcprivacy` file. A
// declaration can go stale without a build ever failing: a library gains a call, a dependency
// changes, a Rust crate starts to read a file's metadata. So this reads the built product and not
// the files that were meant to describe it:
//
//   - every Mach-O in the bundle (the application's executable, each framework, each extension)
//     for the system calls and Foundation names that are in Apple's lists, and
//   - the manifest of the bundle each one belongs to, for the categories and reasons it declares.
//
// The application's executable links its Rust code and its Swift packages statically, so a use in a
// package is a use of the executable. The executable's manifest declares every category any of
// that code uses, whichever package it is in; a package's own manifest, which ships in a resource
// bundle at the root of the application, covers that package's own use as well and is not read for
// this. A framework and an extension are held to their own manifests, since Apple asks for one in
// each bundle that holds such a binary.
//
// What fails, each with the binary and the name that shows it:
//
//   - a category a binary uses that the manifest of its bundle does not declare;
//   - a category the application's manifest declares that its executable does not use;
//   - a category declared with no reason, with a reason that is not Apple's for that category, or
//     with a reason only a third-party SDK may give;
//   - a manifest with a key or a value Apple does not define, or that says the application does
//     not track while it links Apple's advertising or tracking frameworks, or that says a data
//     type is used for tracking while it does not track;
//   - a third-party SDK on Apple's list of SDKs that need a manifest, in a bundle or framework of
//     its own, that ships none. A package linked statically into the executable and shipping no
//     resource bundle has no name in the product to find it by; the report says so.
//
// The release product is what is held to the manifest. A debug build links more (an unstripped
// debug executable keeps functions a release build drops, among them the Rust standard library's
// calls that read the free space of a volume), so a debug product shows categories the application
// does not ship.
//
// Every question here fails closed: a tool that is missing, a file that cannot be read and a layout
// this does not understand are problems of their own, never a pass. What a binary names only at run
// time (a symbol found with `dlsym`, a selector built from a string) is not in any table the check
// reads, so it is not seen.
//
// Usage:
//   node scripts/privacy-manifest.mjs [KalaReach.app]
// With no path, the application `tauri ios build` left under `src-tauri/gen/apple/build` is read.
// Exit 0 when the manifest holds, 1 when it does not, 2 when the check could not run.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { closeSync, existsSync, openSync, readSync, readdirSync, statSync } from 'node:fs'
import { basename, dirname, extname, join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'

const ROOT = dirname(import.meta.dirname)

// -- Apple's lists -------------------------------------------------------------------------------
//
// Read from Apple's documentation of `NSPrivacyAccessedAPIType`, `NSPrivacyCollectedDataType` and
// `NSPrivacyCollectedDataTypePurposes`, and from the page of third-party SDKs that need a privacy
// manifest. They change: read the pages again before trusting a table here.

const PREFIX = 'NSPrivacyAccessedAPICategory'

/**
 * The categories of required reason API, with the reasons Apple lists for each. `sdkOnly` are the
 * reasons only a third-party SDK may declare.
 */
export const CATEGORIES = {
  FileTimestamp: { reasons: ['DDA9.1', 'C617.1', '3B52.1', '0A2A.1'], sdkOnly: ['0A2A.1'] },
  SystemBootTime: { reasons: ['35F9.1', '8FFB.1', '3D61.1'], sdkOnly: [] },
  DiskSpace: { reasons: ['85F4.1', 'E174.1', '7D9E.1', 'B728.1'], sdkOnly: [] },
  ActiveKeyboards: { reasons: ['3EC4.1', '54BD.1'], sdkOnly: [] },
  UserDefaults: { reasons: ['CA92.1', '1C8F.1', 'C56D.1', 'AC6B.1'], sdkOnly: ['C56D.1'] }
}

const FT = 'FileTimestamp'
const BT = 'SystemBootTime'
const DS = 'DiskSpace'
const AK = 'ActiveKeyboards'
const UD = 'UserDefaults'

/** The C functions and Foundation constants a binary imports, by the name the linker gives. */
const IMPORTS = new Map([
  ['stat', [FT]],
  ['fstat', [FT]],
  ['fstatat', [FT]],
  ['lstat', [FT]],
  // Apple lists these three in both categories. A use is covered by either declaration.
  ['getattrlist', [FT, DS]],
  ['fgetattrlist', [FT, DS]],
  ['getattrlistat', [FT, DS]],
  ['getattrlistbulk', [FT]],
  ['statfs', [DS]],
  ['statvfs', [DS]],
  ['fstatfs', [DS]],
  ['fstatvfs', [DS]],
  ['mach_absolute_time', [BT]],
  ['NSFileCreationDate', [FT]],
  ['NSFileModificationDate', [FT]],
  ['NSURLContentModificationDateKey', [FT]],
  ['NSURLCreationDateKey', [FT]],
  ['NSURLVolumeAvailableCapacityKey', [DS]],
  ['NSURLVolumeAvailableCapacityForImportantUsageKey', [DS]],
  ['NSURLVolumeAvailableCapacityForOpportunisticUsageKey', [DS]],
  ['NSURLVolumeTotalCapacityKey', [DS]],
  ['NSFileSystemFreeSize', [DS]],
  ['NSFileSystemSize', [DS]],
  ['OBJC_CLASS_$_NSUserDefaults', [UD]]
])

/**
 * The Swift overlay's accessors for the same information. Swift reaches Foundation's resource
 * values through its own symbols, and a mangled name carries each identifier with its length.
 */
const SWIFT_ACCESSORS = new Map(
  [
    ['creationDate', [FT]],
    ['contentModificationDate', [FT]],
    ['volumeAvailableCapacity', [DS]],
    ['volumeAvailableCapacityForImportantUsage', [DS]],
    ['volumeAvailableCapacityForOpportunisticUsage', [DS]],
    ['volumeTotalCapacity', [DS]]
  ].map(([name, categories]) => [`URLResourceValuesV${name.length}${name}`, categories])
)

/** The selectors a binary names, which is how a message to an object shows in the executable. */
const SELECTORS = new Map([
  ['systemUptime', [BT]],
  ['activeInputModes', [AK]],
  ['fileModificationDate', [FT]]
])

/** Frameworks whose presence says the application takes part in cross-app tracking. */
const TRACKING_FRAMEWORKS = ['AdSupport', 'AppTrackingTransparency']

/** The data types, and the purposes, `NSPrivacyCollectedDataTypes` may name. */
const DATA_TYPES = [
  'Name',
  'EmailAddress',
  'PhoneNumber',
  'PhysicalAddress',
  'OtherUserContactInfo',
  'Health',
  'Fitness',
  'PaymentInfo',
  'CreditInfo',
  'OtherFinancialInfo',
  'PreciseLocation',
  'CoarseLocation',
  'SensitiveInfo',
  'Contacts',
  'EmailsOrTextMessages',
  'PhotosorVideos',
  'AudioData',
  'GameplayContent',
  'CustomerSupport',
  'OtherUserContent',
  'BrowsingHistory',
  'SearchHistory',
  'UserID',
  'DeviceID',
  'PurchaseHistory',
  'ProductInteraction',
  'AdvertisingData',
  'OtherUsageData',
  'CrashData',
  'PerformanceData',
  'OtherDiagnosticData',
  'EnvironmentScanning',
  'Hands',
  'Head',
  'OtherDataTypes'
].map((name) => `NSPrivacyCollectedDataType${name}`)

const PURPOSES = [
  'ThirdPartyAdvertising',
  'DeveloperAdvertising',
  'Analytics',
  'ProductPersonalization',
  'AppFunctionality',
  'Other'
].map((name) => `NSPrivacyCollectedDataTypePurpose${name}`)

/** The SDKs Apple names as needing a privacy manifest and a signature. */
export const SDKS_NEEDING_A_MANIFEST = [
  'Abseil',
  'AFNetworking',
  'Alamofire',
  'AppAuth',
  'BoringSSL',
  'openssl_grpc',
  'Capacitor',
  'Charts',
  'connectivity_plus',
  'Cordova',
  'device_info_plus',
  'DKImagePickerController',
  'DKPhotoGallery',
  'FBAEMKit',
  'FBLPromises',
  'FBSDKCoreKit',
  'FBSDKCoreKit_Basics',
  'FBSDKLoginKit',
  'FBSDKShareKit',
  'file_picker',
  'FirebaseABTesting',
  'FirebaseAuth',
  'FirebaseCore',
  'FirebaseCoreDiagnostics',
  'FirebaseCoreExtension',
  'FirebaseCoreInternal',
  'FirebaseCrashlytics',
  'FirebaseDynamicLinks',
  'FirebaseFirestore',
  'FirebaseInstallations',
  'FirebaseMessaging',
  'FirebaseRemoteConfig',
  'Flutter',
  'flutter_inappwebview',
  'flutter_local_notifications',
  'fluttertoast',
  'FMDB',
  'geolocator_apple',
  'GoogleDataTransport',
  'GoogleSignIn',
  'GoogleToolboxForMac',
  'GoogleUtilities',
  'grpcpp',
  'GTMAppAuth',
  'GTMSessionFetcher',
  'hermes',
  'image_picker_ios',
  'IQKeyboardManager',
  'IQKeyboardManagerSwift',
  'Kingfisher',
  'leveldb',
  'Lottie',
  'MBProgressHUD',
  'nanopb',
  'OneSignal',
  'OneSignalCore',
  'OneSignalExtension',
  'OneSignalOutcomes',
  'OpenSSL',
  'OrderedSet',
  'package_info',
  'package_info_plus',
  'path_provider',
  'path_provider_ios',
  'Promises',
  'Protobuf',
  'Reachability',
  'RealmSwift',
  'RxCocoa',
  'RxRelay',
  'RxSwift',
  'SDWebImage',
  'share_plus',
  'shared_preferences_ios',
  'SnapKit',
  'sqflite',
  'Starscream',
  'SVProgressHUD',
  'SwiftyGif',
  'SwiftyJSON',
  'Toast',
  'UnityFramework',
  'url_launcher',
  'url_launcher_ios',
  'video_player_avfoundation',
  'wakelock',
  'webview_flutter_wkwebview'
]

const SDK_NAMES = new Map(SDKS_NEEDING_A_MANIFEST.map((name) => [name.toLowerCase(), name]))

// -- what a binary uses --------------------------------------------------------------------------

/** What a command printed, or the failure to run it. */
function run(command, args) {
  const answer = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 1 << 30 })
  if (answer.error || answer.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed: ${answer.stderr || answer.error}`)
  }
  return answer.stdout
}

const MACH_O_MAGIC = [
  [0xcf, 0xfa, 0xed, 0xfe], // 64-bit, little endian
  [0xca, 0xfe, 0xba, 0xbe], // universal
  [0xca, 0xfe, 0xba, 0xbf] // universal, 64-bit offsets
]

/** Whether `path` is a Mach-O file, read from its first four bytes. */
function isMachO(path) {
  const head = Buffer.alloc(4)
  const descriptor = openSync(path, 'r')
  try {
    if (readSync(descriptor, head, 0, 4, 0) < 4) return false
  } finally {
    closeSync(descriptor)
  }
  return MACH_O_MAGIC.some((magic) => magic.every((byte, at) => head[at] === byte))
}

/** The architecture to read: arm64 where the file has it, or else its first. */
function architectureOf(path) {
  const archs = run('lipo', ['-archs', path]).trim().split(/\s+/).filter(Boolean)
  if (archs.length === 0) throw new Error(`${path} names no architecture`)
  return archs.includes('arm64') ? 'arm64' : archs[0]
}

/**
 * The category each name in a binary's imports and selectors shows, as a map from the name to the
 * categories it is in (more than one where Apple lists it in more than one).
 *
 * A symbol is compared without its `$INODE64` or `$DARWIN_EXTSN` suffix and without the leading
 * underscore the linker adds.
 */
export function categoriesOfNames({ imports, selectors }) {
  const found = new Map()
  const add = (name, categories) => {
    if (!found.has(name)) found.set(name, categories)
  }
  for (const raw of imports) {
    const name = raw.replace(/^_/, '').replace(/\$(INODE64|DARWIN_EXTSN)$/, '')
    const direct = IMPORTS.get(name)
    if (direct) add(name, direct)
    if (raw.startsWith('_$s10Foundation')) {
      for (const [fragment, categories] of SWIFT_ACCESSORS) {
        if (raw.includes(fragment)) add(fragment.replace(/^URLResourceValuesV\d+/, 'URLResourceValues.'), categories)
      }
    }
  }
  for (const selector of selectors) {
    const categories = SELECTORS.get(selector)
    if (categories) add(selector, categories)
  }
  return found
}

/** The imports and the selectors one Mach-O image names. */
export function namesIn(path) {
  const arch = architectureOf(path)
  const imports = run('nm', ['-arch', arch, '-u', path])
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.endsWith(':'))
  const selectors = run('otool', ['-arch', arch, '-v', '-s', '__TEXT', '__objc_methname', path])
    .split('\n')
    .map((line) => /^[0-9a-f]+\s+(\S+)$/.exec(line.trim())?.[1])
    .filter(Boolean)
  const linked = run('otool', ['-arch', arch, '-L', path])
    .split('\n')
    .slice(1)
    .map((line) => /([^/\s]+)\.framework\//.exec(line)?.[1])
    .filter(Boolean)
  return { imports, selectors, linked }
}

// -- the manifests -------------------------------------------------------------------------------

/** A property list (XML or binary), as the value it holds. */
function plistValue(path) {
  return JSON.parse(run('plutil', ['-convert', 'json', '-o', '-', '--', path]))
}

/** The category an `NSPrivacyAccessedAPIType` value names, or null. */
function categoryOfKey(key) {
  if (typeof key !== 'string' || !key.startsWith(PREFIX)) return null
  const name = key.slice(PREFIX.length)
  return Object.hasOwn(CATEGORIES, name) ? name : null
}

const isStringArray = (value) => Array.isArray(value) && value.every((each) => typeof each === 'string')

/**
 * What a manifest says, or the problems with it. `own` is true for the application's manifest,
 * which may not give a reason only an SDK may give.
 *
 * @returns {{ declared: Map<string, string[]>, problems: string[], tracking: boolean|null }}
 */
export function readManifest(manifest, { own }) {
  const problems = []
  const declared = new Map()
  let tracking = null
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { declared, problems: ['it is not a dictionary'], tracking }
  }
  for (const key of Object.keys(manifest)) {
    if (
      ![
        'NSPrivacyAccessedAPITypes',
        'NSPrivacyCollectedDataTypes',
        'NSPrivacyTracking',
        'NSPrivacyTrackingDomains'
      ].includes(key)
    ) {
      problems.push(`it has the key ${key}, which Apple does not define`)
    }
  }
  if (typeof manifest.NSPrivacyTracking === 'boolean') tracking = manifest.NSPrivacyTracking
  else if (own) problems.push('NSPrivacyTracking is not a boolean (the application must say whether it tracks)')
  else if ('NSPrivacyTracking' in manifest) problems.push('NSPrivacyTracking is not a boolean')
  if ('NSPrivacyTrackingDomains' in manifest) {
    if (!isStringArray(manifest.NSPrivacyTrackingDomains)) {
      problems.push('NSPrivacyTrackingDomains is not a list of domain names')
    } else if (tracking === false && manifest.NSPrivacyTrackingDomains.length > 0) {
      problems.push('it names tracking domains and says it does not track')
    }
  } else if (own) {
    problems.push('NSPrivacyTrackingDomains is missing (an application that does not track says so with an empty list)')
  }
  if (tracking === true && !(manifest.NSPrivacyTrackingDomains ?? []).length) {
    problems.push('it says it tracks and names no tracking domain')
  }
  const apis = manifest.NSPrivacyAccessedAPITypes ?? []
  if (!Array.isArray(apis)) problems.push('NSPrivacyAccessedAPITypes is not a list')
  else {
    for (const entry of apis) {
      const category = categoryOfKey(entry?.NSPrivacyAccessedAPIType)
      if (category === null) {
        problems.push(`it declares ${JSON.stringify(entry?.NSPrivacyAccessedAPIType)}, which is not one of Apple's categories`)
        continue
      }
      const reasons = entry.NSPrivacyAccessedAPITypeReasons
      if (!isStringArray(reasons) || reasons.length === 0) {
        problems.push(`${category} is declared with no reason`)
        continue
      }
      if (declared.has(category)) problems.push(`${category} is declared twice`)
      declared.set(category, reasons)
      for (const reason of reasons) {
        if (!CATEGORIES[category].reasons.includes(reason)) {
          problems.push(`${category} is declared with ${reason}, which is not Apple's reason for that category`)
        } else if (own && CATEGORIES[category].sdkOnly.includes(reason)) {
          problems.push(`${category} is declared with ${reason}, which only a third-party SDK may give`)
        }
      }
    }
  }
  const collected = manifest.NSPrivacyCollectedDataTypes ?? []
  if (!Array.isArray(collected)) problems.push('NSPrivacyCollectedDataTypes is not a list')
  else {
    const seen = new Set()
    for (const entry of collected) {
      const type = entry?.NSPrivacyCollectedDataType
      if (!DATA_TYPES.includes(type)) {
        problems.push(`it collects ${JSON.stringify(type)}, which is not one of Apple's data types`)
        continue
      }
      if (seen.has(type)) problems.push(`${type} is listed twice`)
      seen.add(type)
      if (typeof entry.NSPrivacyCollectedDataTypeLinked !== 'boolean') problems.push(`${type} says nothing of being linked`)
      if (typeof entry.NSPrivacyCollectedDataTypeTracking !== 'boolean') problems.push(`${type} says nothing of tracking`)
      else if (entry.NSPrivacyCollectedDataTypeTracking && tracking === false) {
        problems.push(`${type} is used for tracking and the manifest says it does not track`)
      }
      const purposes = entry.NSPrivacyCollectedDataTypePurposes
      if (!isStringArray(purposes) || purposes.length === 0) problems.push(`${type} names no purpose`)
      else {
        for (const purpose of purposes) {
          if (!PURPOSES.includes(purpose)) problems.push(`${type} names ${purpose}, which is not one of Apple's purposes`)
        }
      }
    }
  }
  return { declared, problems, tracking }
}

// -- the bundle ----------------------------------------------------------------------------------

/** Every Mach-O file under `root`, by path. */
function machOFiles(root) {
  const found = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.isFile() && statSync(path).size >= 4 && isMachO(path)) found.push(path)
    }
  }
  walk(root)
  return found.sort()
}

/** The nearest enclosing bundle of a file inside `app`: the application, a framework or an extension. */
function bundleOf(app, file) {
  let directory = dirname(file)
  while (directory.length >= app.length) {
    if (/\.(app|framework|appex)$/.test(directory) && existsSync(join(directory, 'Info.plist'))) return directory
    directory = dirname(directory)
  }
  return app
}

/** The role a bundle plays in the product, for the report. */
function roleOf(app, bundle) {
  if (bundle === app) return 'application'
  return bundle.endsWith('.appex') ? 'extension' : 'framework'
}

/** The name an SDK on Apple's list goes by, if `name` (a bundle or framework file name) is one. */
export function sdkNamed(name) {
  const stem = basename(name, extname(name))
  for (const part of stem.split('_')) {
    for (const candidate of [part, part.split('-')[0], stem]) {
      const found = SDK_NAMES.get(candidate.toLowerCase())
      if (found) return found
    }
  }
  return null
}

/** The SDK bundles and frameworks of an application that Apple names, and whether each ships a manifest. */
export function sdksIn(app) {
  const found = []
  const look = (directory) => {
    if (!existsSync(directory)) return
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/\.(bundle|framework)$/.test(entry.name)) continue
      const name = sdkNamed(entry.name)
      if (name === null) continue
      found.push({
        sdk: name,
        container: entry.name,
        ships: existsSync(join(directory, entry.name, 'PrivacyInfo.xcprivacy'))
      })
    }
  }
  look(app)
  look(join(app, 'Frameworks'))
  return found.sort((a, b) => a.container.localeCompare(b.container))
}

/**
 * Holds a built application to its manifests.
 *
 * @returns {{ binaries: object[], declarations: object[], sdks: object[], problems: string[] }}
 */
export function examine(app) {
  const problems = []
  const binaries = []
  const declarations = []
  const manifests = new Map()
  const manifestOf = (bundle) => {
    if (manifests.has(bundle)) return manifests.get(bundle)
    const path = join(bundle, 'PrivacyInfo.xcprivacy')
    let answer
    if (!existsSync(path)) answer = { present: false, declared: new Map(), tracking: null, problems: [] }
    else {
      try {
        answer = { present: true, ...readManifest(plistValue(path), { own: bundle === app }) }
      } catch (failure) {
        answer = { present: true, declared: new Map(), tracking: null, problems: [failure.message] }
      }
    }
    manifests.set(bundle, answer)
    return answer
  }

  for (const file of machOFiles(app)) {
    const bundle = bundleOf(app, file)
    const { imports, selectors, linked } = namesIn(file)
    const uses = categoriesOfNames({ imports, selectors })
    binaries.push({ file, bundle, role: roleOf(app, bundle), uses, linked })
  }
  if (binaries.length === 0) problems.push(`${app} holds no Mach-O file`)

  for (const bundle of new Set(binaries.map((each) => each.bundle))) {
    const where = bundle === app ? 'the application' : relative(app, bundle)
    const manifest = manifestOf(bundle)
    declarations.push({ where, present: manifest.present, declared: manifest.declared, tracking: manifest.tracking })
    for (const problem of manifest.problems) problems.push(`the manifest of ${where}: ${problem}`)
    const used = new Set()
    for (const binary of binaries.filter((each) => each.bundle === bundle)) {
      const name = relative(app, binary.file)
      for (const [api, categories] of binary.uses) {
        for (const category of categories) used.add(category)
        if (!categories.some((category) => manifest.declared.has(category))) {
          const need = categories.length > 1 ? `${categories.join(' or ')}` : categories[0]
          problems.push(
            `${name} uses ${need} (${api}) and the manifest of ${where} ${manifest.present ? 'does not declare it' : 'is missing'}`
          )
        }
      }
      const tracks = binary.linked.filter((framework) => TRACKING_FRAMEWORKS.includes(framework))
      if (tracks.length > 0 && manifest.tracking !== true) {
        problems.push(`${name} links ${tracks.join(' and ')} and the manifest of ${where} does not say the application tracks`)
      }
    }
    // Only the application's own manifest is held to what is used: a framework's is its author's.
    if (bundle === app) {
      for (const category of manifest.declared.keys()) {
        if (!used.has(category)) {
          problems.push(`the manifest of the application declares ${category} and no code in its executable uses it`)
        }
      }
    }
  }

  const sdks = sdksIn(app)
  for (const sdk of sdks) {
    if (!sdk.ships) problems.push(`${sdk.container} is ${sdk.sdk}, which Apple lists as needing a privacy manifest, and ships none`)
  }
  return { binaries, declarations, sdks, problems }
}

// -- the command ---------------------------------------------------------------------------------

/** The application `tauri ios build` left, or null. */
function builtBundle() {
  const root = join(ROOT, 'src-tauri', 'gen', 'apple', 'build')
  if (!existsSync(root)) return null
  const apps = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && entry.name.endsWith('.app')) apps.push(join(directory, entry.name))
      else if (entry.isDirectory() && !entry.name.endsWith('.xcarchive')) walk(join(directory, entry.name))
    }
  }
  walk(root)
  return apps.length === 1 ? apps[0] : null
}

/** Prints what was found, and the problems, and answers whether the manifest holds. */
export function report(app, result) {
  console.log(`${relative(process.cwd(), app) || app}`)
  for (const binary of result.binaries) {
    const name = relative(app, binary.file)
    const uses = [...binary.uses].map(([api, categories]) => `${api} (${categories.join(' or ')})`)
    console.log(`  ${binary.role} binary ${name}: ${uses.length === 0 ? 'no required reason API' : uses.join(', ')}`)
  }
  for (const each of result.declarations) {
    const listed = [...each.declared].map(([category, reasons]) => `${category} ${reasons.join(', ')}`)
    console.log(
      `  manifest of ${each.where}: ${each.present ? (listed.length === 0 ? 'declares no category' : listed.join('; ')) : 'missing'}`
    )
  }
  for (const sdk of result.sdks) {
    console.log(`  SDK on Apple's list: ${sdk.sdk} in ${sdk.container}, ${sdk.ships ? 'ships a manifest' : 'ships NO manifest'}`)
  }
  if (result.problems.length === 0) {
    console.log('every category the product uses is declared, and every declaration is used')
    return true
  }
  console.error(`${result.problems.length} problem${result.problems.length === 1 ? '' : 's'}:`)
  for (const problem of result.problems) console.error(`  ${problem}`)
  return false
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const [path] = process.argv.slice(2)
  const app = path ?? builtBundle()
  let code = 2
  if (!app) {
    console.error('No built application: pass the KalaReach.app that `tauri ios build` left.')
  } else if (!existsSync(app) || !statSync(app).isDirectory()) {
    console.error(`${app} is not an application bundle.`)
  } else {
    try {
      code = report(app, examine(app)) ? 0 : 1
    } catch (failure) {
      console.error(`The check could not run: ${failure.message}`)
    }
  }
  process.exit(code)
}
