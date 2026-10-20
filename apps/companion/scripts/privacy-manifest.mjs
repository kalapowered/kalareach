#!/usr/bin/env node
// Holds an iOS application's privacy manifest to the application that was built.
//
// Apple asks each app, and each framework or extension inside it, to declare the categories of
// required reason API its code uses, with a reason for each, in a `PrivacyInfo.xcprivacy` file. A
// declaration can go stale without a build ever failing: a library gains a call, a dependency
// changes, a Rust crate starts to read a file's metadata. So this reads the built product and not
// the files that were meant to describe it:
//
//   - every Mach-O in the bundle (the application's executable, each framework, each extension and
//     each application nested in it) for the system calls and Foundation names that are in Apple's
//     lists, and
//   - the manifest of the bundle each one belongs to, for the categories and reasons it declares.
//
// The application's executable links its Rust code and its Swift packages statically, so a use in a
// package is a use of the executable. The executable's manifest declares every category any of
// that code uses, whichever package it is in. That is a project rule, stricter than anything Apple
// documents: Apple asks each bundle that holds a binary to report that binary's uses, and says
// Xcode combines the manifests of the application and its packages into one report, but it does not
// say what its upload validation does with a package's resource-bundle manifest for code linked
// into the application. A package's own manifest, which ships in a resource bundle at the root of
// the application, is checked for validity and for being there, and is not used to excuse the
// executable. A framework, an extension and a nested application are held to their own manifests;
// the application, the extensions and the nested applications are the project's own and are held
// to the rules for an application's manifest, and a framework or a resource bundle is a package's.
//
// What fails, each with the binary and the name that shows it:
//
//   - a category a binary uses that the manifest of its bundle does not declare;
//   - a category the manifest of the application (or of an extension or a nested application)
//     declares that its executable does not use;
//   - an application with no privacy manifest, whether or not it uses a category (a nested
//     application or an extension with no manifest and no use of a category passes);
//   - a category declared with no reason, with a reason that is not Apple's for that category, or
//     with a reason only a third-party SDK may give;
//   - a manifest with a key or a value Apple does not define (the root, an accessed API dictionary,
//     a collected data dictionary, a tracking domain with a path), that says a data type is used for
//     tracking while it does not track, or that says the application does not track while it links
//     Apple's advertising or tracking frameworks. The application's manifest must also say outright
//     that it does not track, with an empty list of domains: Apple lets a manifest that does not
//     track leave both keys out, and this project does not;
//   - a third-party SDK on Apple's list of SDKs that need a manifest, in a resource bundle or
//     framework of its own, that ships none or ships one that is not valid. A package that is linked
//     statically and ships no resource bundle has no name in the product to find it by, and is not
//     seen;
//   - a bundle with no `Info.plist`, an executable its `Info.plist` names that is not a Mach-O file
//     of that bundle, or a symbolic link. Each is a problem of its own, and none is skipped. A
//     file that cannot be read at all stops the run, with exit 2;
//   - a `PrivacyInfo.xcprivacy` anywhere in the bundle that is not a valid manifest.
//
// One kind of invalid manifest is a note and not a failure: a package's manifest with an empty list
// of accessed APIs. Apple's TN3181 lists an empty list as invalid and Google ships several, which
// applications upload with; the application's own manifest is held to the rule.
//
// Every slice of a universal binary is read, and a use in any of them counts.
//
// The release product is what is held to the manifest. A debug build links more (an unstripped
// debug executable keeps functions a release build drops, among them the Rust standard library's
// calls that read the free space of a volume), so a debug product shows categories the application
// does not ship.
//
// What the check cannot see: a name a binary builds or looks up at run time (a symbol found with
// `dlsym`, a selector made from a string) is in no table it reads. Which attributes a call to
// `getattrlist` asks for is not in the import either, so a declaration of file timestamps hides a
// use of disk space through the same call; Apple lists the three `getattrlist` calls under both
// categories, and a use of one is covered by either declaration. Every question that can fail
// closed does.
//
// Usage:
//   node scripts/privacy-manifest.mjs [KalaReach.app]
// With no path, the application `tauri ios build` left under `src-tauri/gen/apple/build` is read.
// Exit 0 when the manifest holds, 1 when it does not, 2 when the check could not run.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { closeSync, existsSync, openSync, readSync, readdirSync, statSync } from 'node:fs'
import { basename, dirname, extname, join, relative, resolve } from 'node:path'
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
  [0xce, 0xfa, 0xed, 0xfe], // 32-bit, little endian
  [0xfe, 0xed, 0xfa, 0xcf], // 64-bit, big endian
  [0xfe, 0xed, 0xfa, 0xce], // 32-bit, big endian
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

/** Every architecture a Mach-O file holds: one for a thin file, one for each slice of a universal one. */
function architecturesOf(path) {
  const archs = run('lipo', ['-archs', path]).trim().split(/\s+/).filter(Boolean)
  if (archs.length === 0) throw new Error(`${path} names no architecture`)
  return archs
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

/**
 * The imports, the selectors and the linked frameworks one Mach-O file names, in every slice it has:
 * a use in any slice is a use of the file.
 */
export function namesIn(path) {
  const imports = new Set()
  const selectors = new Set()
  const linked = new Set()
  const archs = architecturesOf(path)
  for (const arch of archs) {
    for (const line of run('nm', ['-arch', arch, '-u', path]).split('\n')) {
      const symbol = line.trim()
      if (symbol !== '' && !symbol.endsWith(':')) imports.add(symbol)
    }
    for (const line of run('otool', ['-arch', arch, '-v', '-s', '__TEXT', '__objc_methname', path]).split('\n')) {
      const selector = /^[0-9a-f]+\s+(\S+)$/.exec(line.trim())?.[1]
      if (selector) selectors.add(selector)
    }
    for (const line of run('otool', ['-arch', arch, '-L', path]).split('\n').slice(1)) {
      const framework = /([^/\s]+)\.framework\//.exec(line)?.[1]
      if (framework) linked.add(framework)
    }
  }
  return { imports: [...imports], selectors: [...selectors], linked: [...linked], archs }
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

/** A tracking domain as Apple asks for it: a domain name with its top-level domain, and nothing after it. */
const DOMAIN = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/

/** The keys of an accessed API dictionary, and of a collected data dictionary: exactly these. */
const API_KEYS = ['NSPrivacyAccessedAPIType', 'NSPrivacyAccessedAPITypeReasons']
const DATA_KEYS = [
  'NSPrivacyCollectedDataType',
  'NSPrivacyCollectedDataTypeLinked',
  'NSPrivacyCollectedDataTypeTracking',
  'NSPrivacyCollectedDataTypePurposes'
]

/** What is wrong with the keys of a dictionary that has to have exactly `keys`. */
function strayKeys(entry, keys, what) {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return [`${what} is not a dictionary`]
  const problems = []
  for (const key of Object.keys(entry)) {
    if (!keys.includes(key)) problems.push(`${what} has the key ${key}, which Apple does not define there`)
  }
  return problems
}

const isStringArray = (value) => Array.isArray(value) && value.every((each) => typeof each === 'string')

/**
 * What a manifest says, or the problems with it. `own` is true for the manifest of one of the
 * project's own bundles (the application, its extensions, its nested applications): it has to say
 * outright whether it tracks, may not be an empty list of accessed APIs, and may not give a reason
 * only a third-party SDK may give.
 *
 * @returns {{ declared: Map<string, string[]>, problems: string[], notes: string[], tracking: boolean|null }}
 */
export function readManifest(manifest, { own }) {
  const problems = []
  const notes = []
  const declared = new Map()
  let tracking = null
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { declared, problems: ['it is not a dictionary'], notes, tracking }
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
    } else {
      if (tracking === false && manifest.NSPrivacyTrackingDomains.length > 0) {
        problems.push('it names tracking domains and says it does not track')
      }
      for (const domain of manifest.NSPrivacyTrackingDomains) {
        if (!DOMAIN.test(domain)) {
          problems.push(`the tracking domain ${JSON.stringify(domain)} is not a bare domain name (no path, query or trailing slash)`)
        }
      }
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
    if ('NSPrivacyAccessedAPITypes' in manifest && apis.length === 0) {
      const empty = 'NSPrivacyAccessedAPITypes is an empty list, which Apple\'s TN3181 lists as invalid'
      if (own) problems.push(empty)
      else notes.push(empty)
    }
    for (const entry of apis) {
      const stray = strayKeys(entry, API_KEYS, 'an accessed API entry')
      problems.push(...stray)
      if (stray.length > 0 && (entry === null || typeof entry !== 'object' || Array.isArray(entry))) continue
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
      const stray = strayKeys(entry, DATA_KEYS, 'a collected data entry')
      problems.push(...stray)
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) continue
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
  return { declared, problems, notes, tracking }
}

// -- the bundle ----------------------------------------------------------------------------------

const MANIFEST = 'PrivacyInfo.xcprivacy'

/** Whether `directory` holds an entry named exactly `PrivacyInfo.xcprivacy`, by its listing and not by a lookup that ignores case. */
function holdsManifest(directory) {
  return readdirSync(directory).includes(MANIFEST)
}

/**
 * What a walk of the application found: its Mach-O files, its bundles (the application, each
 * framework, extension and nested application), every `PrivacyInfo.xcprivacy` and what it could
 * not follow.
 */
function walkBundle(app) {
  const machO = []
  const bundles = [app]
  const manifests = []
  const links = []
  const misspelt = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) links.push(path)
      else if (entry.name === MANIFEST) manifests.push(path)
      else if (entry.name.toLowerCase() === MANIFEST.toLowerCase()) misspelt.push(path)
      else if (entry.isDirectory()) {
        if (/\.(app|framework|appex)$/.test(entry.name)) bundles.push(path)
        walk(path)
      } else if (entry.isFile() && statSync(path).size >= 4 && isMachO(path)) machO.push(path)
    }
  }
  walk(app)
  return { machO: machO.sort(), bundles: bundles.sort(), manifests: manifests.sort(), links: links.sort(), misspelt: misspelt.sort() }
}

/**
 * The bundle a file belongs to: the nearest enclosing application, framework or extension. A
 * bundle is told by its name, so one with no `Info.plist` is found and reported, not skipped for
 * the bundle around it.
 */
function bundleOf(app, file) {
  let directory = dirname(file)
  while (directory !== app && directory !== dirname(directory)) {
    if (/\.(app|framework|appex)$/.test(directory)) return directory
    directory = dirname(directory)
  }
  return app
}

/** The role a bundle plays in the product, for the report. */
function roleOf(app, bundle) {
  if (bundle === app) return 'application'
  if (bundle.endsWith('.app')) return 'nested application'
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

/**
 * The SDK bundles and frameworks of an application that Apple names, wherever they are in it (the
 * application, an extension, a framework), and whether each ships a manifest. Whether a manifest is
 * valid is asked of every manifest in the bundle, not only of these.
 */
export function sdksIn(app) {
  const found = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue
      const path = join(directory, entry.name)
      const name = /\.(bundle|framework)$/.test(entry.name) ? sdkNamed(entry.name) : null
      if (name !== null) {
        found.push({
          sdk: name,
          container: relative(app, path),
          ships: holdsManifest(path)
        })
      }
      walk(path)
    }
  }
  walk(app)
  return found.sort((a, b) => a.container.localeCompare(b.container))
}

/**
 * Holds a built application to its manifests.
 *
 * @returns {{ binaries: object[], declarations: object[], sdks: object[], notes: string[], problems: string[] }}
 */
export function examine(path) {
  const app = resolve(path)
  const problems = []
  const notes = []
  const binaries = []
  const declarations = []
  const manifests = new Map()
  // The project's own bundles are the application, the applications nested in it and its
  // extensions; a framework or a resource bundle is a package's.
  const isOwn = (bundle) => bundle === app || /\.(app|appex)$/.test(bundle)
  const manifestOf = (bundle) => {
    if (manifests.has(bundle)) return manifests.get(bundle)
    const path = join(bundle, 'PrivacyInfo.xcprivacy')
    let answer
    if (!holdsManifest(bundle)) answer = { present: false, declared: new Map(), tracking: null, problems: [], notes: [] }
    else {
      try {
        if (!statSync(path).isFile()) throw new Error('it is not a file')
        answer = { present: true, ...readManifest(plistValue(path), { own: isOwn(bundle) }) }
      } catch (failure) {
        answer = { present: true, declared: new Map(), tracking: null, problems: [failure.message.split('\n')[0]], notes: [] }
      }
    }
    manifests.set(bundle, answer)
    return answer
  }

  const found = walkBundle(app)
  for (const link of found.links) {
    problems.push(`${relative(app, link)} is a symbolic link, which this check does not follow`)
  }
  for (const name of found.misspelt) {
    problems.push(`${relative(app, name)} is not spelt ${MANIFEST}, so it is not read as a privacy manifest`)
  }
  for (const file of found.machO) {
    const bundle = bundleOf(app, file)
    const { imports, selectors, linked, archs } = namesIn(file)
    const uses = categoriesOfNames({ imports, selectors })
    binaries.push({ file, bundle, role: roleOf(app, bundle), uses, linked, archs })
  }
  if (binaries.length === 0) problems.push(`${app} holds no Mach-O file`)

  // Each bundle names its executable, and the executable has to be among the Mach-O files read:
  // a bundle whose executable is elsewhere, or missing, has not been held to its manifest.
  for (const bundle of found.bundles) {
    const where = bundle === app ? 'the application' : relative(app, bundle)
    const plist = join(bundle, 'Info.plist')
    if (!existsSync(plist)) {
      problems.push(`${where} has no Info.plist`)
      continue
    }
    let executable
    try {
      executable = plistValue(plist).CFBundleExecutable
    } catch (failure) {
      problems.push(`the Info.plist of ${where} cannot be read: ${failure.message.split('\n')[0]}`)
      continue
    }
    if (typeof executable !== 'string' || executable === '') {
      problems.push(`the Info.plist of ${where} names no CFBundleExecutable`)
    } else if (
      basename(executable) !== executable ||
      !binaries.some((each) => each.file === join(bundle, executable) && each.bundle === bundle)
    ) {
      problems.push(`${where} names the executable ${executable} and it is not a Mach-O file of that bundle`)
    }
  }

  for (const bundle of new Set(binaries.map((each) => each.bundle))) {
    const where = bundle === app ? 'the application' : relative(app, bundle)
    const manifest = manifestOf(bundle)
    if (bundle === app && !manifest.present) {
      problems.push('the application has no privacy manifest (it has to state that it does not track, with or without a use of a category)')
    }
    declarations.push({ where, present: manifest.present, declared: manifest.declared, tracking: manifest.tracking })
    for (const problem of manifest.problems) problems.push(`the manifest of ${where}: ${problem}`)
    for (const note of manifest.notes) notes.push(`the manifest of ${where}: ${note}`)
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
    // The project's own manifests are held to what is used: a framework's is its author's.
    if (isOwn(bundle)) {
      for (const category of manifest.declared.keys()) {
        if (!used.has(category)) {
          problems.push(`the manifest of ${where} declares ${category} and no code in its executable uses it`)
        }
      }
    }
  }

  // Every other manifest in the bundle (a package's, in a resource bundle): it has to be valid
  // wherever it is, whether or not the package is one Apple names.
  const examined = new Set(binaries.map((each) => join(each.bundle, 'PrivacyInfo.xcprivacy')))
  for (const path of found.manifests) {
    if (examined.has(path)) continue
    const where = relative(app, dirname(path))
    try {
      if (!statSync(path).isFile()) throw new Error('it is not a file')
      const read = readManifest(plistValue(path), { own: false })
      for (const problem of read.problems) problems.push(`the manifest in ${where}: ${problem}`)
      for (const note of read.notes) notes.push(`the manifest in ${where}: ${note}`)
    } catch (failure) {
      problems.push(`the manifest in ${where}: ${failure.message.split('\n')[0]}`)
    }
  }

  const sdks = sdksIn(app)
  for (const sdk of sdks) {
    if (!sdk.ships) problems.push(`${sdk.container} is ${sdk.sdk}, which Apple lists as needing a privacy manifest, and ships none`)
  }
  return { binaries, declarations, sdks, notes, problems }
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
    const slices = binary.archs.length > 1 ? ` [${binary.archs.join(', ')}]` : ''
    console.log(`  ${binary.role} binary ${name}${slices}: ${uses.length === 0 ? 'no required reason API' : uses.join(', ')}`)
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
  if (result.notes.length > 0) {
    console.log(`${result.notes.length} note${result.notes.length === 1 ? '' : 's'} (not failures):`)
    for (const note of result.notes) console.log(`  ${note}`)
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
