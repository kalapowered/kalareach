#!/usr/bin/env node
// Holds the privacy manifest check to the answers it must give.
//
// The check reads a built application and says whether its privacy manifests declare what its
// binaries use. Its table of Apple's required reason APIs is only worth anything if the names in it
// are the names a real toolchain writes, so the first half of this compiles small C, Objective-C
// and Swift files for the iOS Simulator, calls every API Apple lists, and holds the check to
// finding each one under the category Apple lists it in. The second half builds an application
// bundle out of such binaries, as `tauri ios build` leaves one, and removes, adds and corrupts
// declarations one at a time: a manifest that holds must pass, and each fault must fail with the
// binary and the name that show it.
//
// It needs macOS with Xcode and the iOS Simulator SDK (`xcrun`, `clang`, `swiftc`, `lipo`, `nm`,
// `otool`, `plutil`). Where those are missing the cases that need them are reported as not run,
// never as passed, and the exit status says so. The cases about a manifest's own structure need
// none of them.
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import {
  CATEGORIES,
  categoriesOfNames,
  examine,
  namesIn,
  readManifest,
  sdkNamed
} from './privacy-manifest.mjs'

const work = mkdtempSync(join(tmpdir(), 'kr-privacy-manifest-'))
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

/** Why the cases that compile for the iOS Simulator cannot run here, or null where they can. */
const toolchain = (() => {
  if (process.platform !== 'darwin') return 'this is not macOS'
  for (const tool of ['xcrun', 'plutil', 'lipo', 'nm', 'otool']) {
    if (spawnSync('which', [tool], { encoding: 'utf8' }).status !== 0) return `${tool} is not available`
  }
  for (const tool of ['clang', 'swiftc']) {
    if (spawnSync('xcrun', ['--sdk', 'iphonesimulator', '--find', tool], { encoding: 'utf8' }).status !== 0) {
      return `${tool} for the iOS Simulator is not available`
    }
  }
  return null
})()

/** Compiles `source` into `out` for the iOS Simulator with `tool`; returns the failure, or null. */
function compile(tool, source, out, extra = []) {
  const flags =
    tool === 'swiftc'
      ? ['-emit-library', '-target', 'arm64-apple-ios17.0-simulator']
      : ['-dynamiclib', '-target', 'arm64-apple-ios17.0-simulator']
  const answer = spawnSync('xcrun', ['--sdk', 'iphonesimulator', tool === 'swiftc' ? 'swiftc' : 'clang', ...flags, ...extra, '-o', out, source], {
    encoding: 'utf8'
  })
  return answer.status === 0 ? null : `${tool} ${source}: ${answer.stderr}`
}

/** Writes `text` to `name` under the work directory. */
function written(name, text) {
  const path = name.startsWith('/') ? name : join(work, name)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, text)
  return path
}

/** A property list file made from a value. */
function plist(path, value) {
  const json = written(`${path}.json`, JSON.stringify(value))
  const answer = spawnSync('plutil', ['-convert', 'xml1', '-o', path, '--', json], { encoding: 'utf8' })
  if (answer.status !== 0) throw new Error(`plutil: ${answer.stderr}`)
}

const PREFIX = 'NSPrivacyAccessedAPICategory'
const declares = (category, ...reasons) => ({
  NSPrivacyAccessedAPIType: `${PREFIX}${category}`,
  NSPrivacyAccessedAPITypeReasons: reasons
})
const manifest = (...apis) => ({
  NSPrivacyTracking: false,
  NSPrivacyTrackingDomains: [],
  NSPrivacyCollectedDataTypes: [],
  NSPrivacyAccessedAPITypes: apis
})

// -- Apple's table ---------------------------------------------------------------------------------

held(
  'the categories are the five Apple lists',
  'ActiveKeyboards DiskSpace FileTimestamp SystemBootTime UserDefaults',
  Object.keys(CATEGORIES).sort().join(' ')
)

held(
  'an SDK on Apple\'s list is found by the name of its resource bundle or framework',
  'FirebaseCore GoogleUtilities nanopb Promises null',
  [
    sdkNamed('Firebase_FirebaseCore.bundle'),
    sdkNamed('GoogleUtilities_GoogleUtilities-Network.bundle'),
    sdkNamed('nanopb_nanopb.bundle'),
    sdkNamed('Promises_FBLPromises.bundle'),
    sdkNamed('WebRTC.framework')
  ]
    .map(String)
    .join(' ')
)

/** The categories the first name in `names` is listed under, written out. */
const listedUnder = (names) => [...categoriesOfNames(names).values()][0].join(',')

held(
  'the Swift overlay\'s accessors and the Foundation constants are listed under Apple\'s categories',
  'FileTimestamp DiskSpace FileTimestamp,DiskSpace',
  [
    listedUnder({ imports: ['_$s10Foundation17URLResourceValuesV12creationDateAA0E0VSgvg'], selectors: [] }),
    listedUnder({ imports: ['_NSFileSystemFreeSize'], selectors: [] }),
    listedUnder({ imports: ['_getattrlist'], selectors: [] })
  ].join(' ')
)

// -- a manifest's own structure --------------------------------------------------------------------

const clean = readManifest(manifest(declares('FileTimestamp', 'C617.1'), declares('UserDefaults', 'CA92.1')), {
  own: true
})
heldProblems('a well-formed manifest has no problem', clean.problems, [])
held('and reads as the categories it declares', 'FileTimestamp UserDefaults', [...clean.declared.keys()].join(' '))

for (const [what, value, fragment] of [
  ['a key Apple does not define', { ...manifest(), NSPrivacyOops: true }, 'NSPrivacyOops'],
  ['a missing NSPrivacyTracking', { NSPrivacyTrackingDomains: [] }, 'NSPrivacyTracking is not a boolean'],
  ['missing tracking domains', { NSPrivacyTracking: false }, 'NSPrivacyTrackingDomains is missing'],
  [
    'tracking domains on an application that says it does not track',
    { ...manifest(), NSPrivacyTrackingDomains: ['ads.example'] },
    'names tracking domains and says it does not track'
  ],
  [
    'tracking with no domain',
    { ...manifest(), NSPrivacyTracking: true },
    'says it tracks and names no tracking domain'
  ],
  ['a category with no reason', manifest(declares('FileTimestamp')), 'FileTimestamp is declared with no reason'],
  [
    'a reason of another category',
    manifest(declares('FileTimestamp', '35F9.1')),
    'FileTimestamp is declared with 35F9.1'
  ],
  [
    'a reason only an SDK may give',
    manifest(declares('UserDefaults', 'C56D.1')),
    'UserDefaults is declared with C56D.1, which only a third-party SDK may give'
  ],
  [
    'a category declared twice',
    manifest(declares('DiskSpace', 'E174.1'), declares('DiskSpace', '85F4.1')),
    'DiskSpace is declared twice'
  ],
  [
    'a category Apple does not define',
    manifest({ NSPrivacyAccessedAPIType: 'NSPrivacyAccessedAPICategoryNetwork', NSPrivacyAccessedAPITypeReasons: ['AAAA.1'] }),
    'not one of Apple\'s categories'
  ],
  [
    'a data type Apple does not define',
    {
      ...manifest(),
      NSPrivacyCollectedDataTypes: [
        {
          NSPrivacyCollectedDataType: 'NSPrivacyCollectedDataTypeMood',
          NSPrivacyCollectedDataTypeLinked: true,
          NSPrivacyCollectedDataTypeTracking: false,
          NSPrivacyCollectedDataTypePurposes: ['NSPrivacyCollectedDataTypePurposeAppFunctionality']
        }
      ]
    },
    'not one of Apple\'s data types'
  ],
  [
    'a data type used for tracking in an application that does not track',
    {
      ...manifest(),
      NSPrivacyCollectedDataTypes: [
        {
          NSPrivacyCollectedDataType: 'NSPrivacyCollectedDataTypeDeviceID',
          NSPrivacyCollectedDataTypeLinked: true,
          NSPrivacyCollectedDataTypeTracking: true,
          NSPrivacyCollectedDataTypePurposes: ['NSPrivacyCollectedDataTypePurposeThirdPartyAdvertising']
        }
      ]
    },
    'is used for tracking and the manifest says it does not track'
  ],
  [
    'a tracking domain with a path',
    { ...manifest(), NSPrivacyTracking: true, NSPrivacyTrackingDomains: ['https://ads.example/track'] },
    'is not a bare domain name'
  ],
  [
    'a key Apple does not define inside an accessed API entry',
    manifest({ ...declares('FileTimestamp', 'C617.1'), NSPrivacyExtra: true }),
    'an accessed API entry has the key NSPrivacyExtra'
  ],
  [
    'a key Apple does not define inside a collected data entry',
    {
      ...manifest(),
      NSPrivacyCollectedDataTypes: [
        {
          NSPrivacyCollectedDataType: 'NSPrivacyCollectedDataTypeDeviceID',
          NSPrivacyCollectedDataTypeLinked: true,
          NSPrivacyCollectedDataTypeTracking: false,
          NSPrivacyCollectedDataTypePurposes: ['NSPrivacyCollectedDataTypePurposeAppFunctionality'],
          NSPrivacyCollectedDataTypeNote: 'kept'
        }
      ]
    },
    'a collected data entry has the key NSPrivacyCollectedDataTypeNote'
  ],
  [
    'an empty list of accessed APIs in the application\'s own manifest',
    manifest(),
    'NSPrivacyAccessedAPITypes is an empty list'
  ],
  [
    'a purpose Apple does not define',
    {
      ...manifest(),
      NSPrivacyCollectedDataTypes: [
        {
          NSPrivacyCollectedDataType: 'NSPrivacyCollectedDataTypeDeviceID',
          NSPrivacyCollectedDataTypeLinked: true,
          NSPrivacyCollectedDataTypeTracking: false,
          NSPrivacyCollectedDataTypePurposes: ['NSPrivacyCollectedDataTypePurposeFun']
        }
      ]
    },
    'not one of Apple\'s purposes'
  ]
]) {
  heldProblems(`${what} is a problem`, readManifest(value, { own: true }).problems, [fragment])
}

held(
  'an empty list of accessed APIs in a package\'s manifest is a note, and not a failure',
  '0 problems, 1 note',
  (() => {
    const read = readManifest(manifest(), { own: false })
    return `${read.problems.length} problems, ${read.notes.length} note`
  })()
)
held(
  'a manifest with no list of accessed APIs at all is not an empty list',
  '0 notes',
  `${readManifest({ NSPrivacyTracking: false, NSPrivacyTrackingDomains: [] }, { own: false }).notes.length} notes`
)

// -- the names a real toolchain writes -------------------------------------------------------------

const C_SOURCE = `
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <mach/mach_time.h>
void *fx_c[] = { (void *)stat, (void *)fstat, (void *)fstatat, (void *)lstat, (void *)getattrlist,
  (void *)getattrlistbulk, (void *)fgetattrlist, (void *)getattrlistat, (void *)statfs,
  (void *)statvfs, (void *)fstatfs, (void *)fstatvfs, (void *)mach_absolute_time };
`

const OBJC_SOURCE = `
#import <UIKit/UIKit.h>
id fx_objc(NSFileManager *files, NSURL *url, UIDocument *document) {
  NSArray *keys = @[ NSURLContentModificationDateKey, NSURLCreationDateKey,
    NSURLVolumeAvailableCapacityKey, NSURLVolumeAvailableCapacityForImportantUsageKey,
    NSURLVolumeAvailableCapacityForOpportunisticUsageKey, NSURLVolumeTotalCapacityKey ];
  NSDictionary *item = @{ NSFileCreationDate: @1, NSFileModificationDate: @2,
    NSFileSystemFreeSize: @3, NSFileSystemSize: @4 };
  (void)keys; (void)item;
  (void)[[NSProcessInfo processInfo] systemUptime];
  (void)[UITextInputMode activeInputModes];
  (void)[document fileModificationDate];
  return [NSUserDefaults standardUserDefaults];
}
`

const SWIFT_SOURCE = `
import Foundation
@_cdecl("fx_swift")
public func fx_swift() {
  let values = try? URL(fileURLWithPath: "/tmp").resourceValues(forKeys: [.creationDateKey])
  _ = values?.creationDate; _ = values?.contentModificationDate
  _ = values?.volumeAvailableCapacity; _ = values?.volumeTotalCapacity
  _ = values?.volumeAvailableCapacityForImportantUsage
  _ = values?.volumeAvailableCapacityForOpportunisticUsage
}
`

/** The names a compiled library shows, by category, or the reason the case did not run. */
function show(name, tool, source, extra = []) {
  const src = written(`${name}.${tool === 'swiftc' ? 'swift' : tool === 'objc' ? 'm' : 'c'}`, source)
  const out = join(work, `${name}.dylib`)
  const failed = compile(tool === 'objc' ? 'clang' : tool, src, out, tool === 'objc' ? ['-framework', 'Foundation', '-framework', 'UIKit', ...extra] : extra)
  if (failed) throw new Error(failed)
  const found = categoriesOfNames(namesIn(out))
  return Object.fromEntries([...found].map(([api, categories]) => [api, categories.join(',')]))
}

/** Holds a compiled library's names to the categories Apple lists them in. */
function heldNames(what, shown, expected) {
  const missing = Object.entries(expected).filter(([api, categories]) => shown[api] !== categories)
  const unexpected = Object.keys(shown).filter((api) => !(api in expected))
  held(
    what,
    'as expected',
    missing.length === 0 && unexpected.length === 0
      ? 'as expected'
      : `missing or wrong: ${JSON.stringify(missing)}; not expected: ${JSON.stringify(unexpected)}`
  )
}

const FT = 'FileTimestamp'
const DS = 'DiskSpace'
if (toolchain) {
  notRun += 1
  console.log(`not run  the names a real toolchain writes, and the bundle cases: ${toolchain}`)
} else {
  heldNames('every C function Apple lists is found under the category it is listed in', show('c', 'c', C_SOURCE), {
    stat: FT,
    fstat: FT,
    fstatat: FT,
    lstat: FT,
    getattrlist: `${FT},${DS}`,
    getattrlistbulk: FT,
    fgetattrlist: `${FT},${DS}`,
    getattrlistat: `${FT},${DS}`,
    statfs: DS,
    statvfs: DS,
    fstatfs: DS,
    fstatvfs: DS,
    mach_absolute_time: 'SystemBootTime'
  })
  heldNames('every Foundation and UIKit name Apple lists is found, in Objective-C', show('o', 'objc', OBJC_SOURCE), {
    NSURLContentModificationDateKey: FT,
    NSURLCreationDateKey: FT,
    NSURLVolumeAvailableCapacityKey: DS,
    NSURLVolumeAvailableCapacityForImportantUsageKey: DS,
    NSURLVolumeAvailableCapacityForOpportunisticUsageKey: DS,
    NSURLVolumeTotalCapacityKey: DS,
    NSFileCreationDate: FT,
    NSFileModificationDate: FT,
    NSFileSystemFreeSize: DS,
    NSFileSystemSize: DS,
    systemUptime: 'SystemBootTime',
    activeInputModes: 'ActiveKeyboards',
    fileModificationDate: FT,
    'OBJC_CLASS_$_NSUserDefaults': 'UserDefaults'
  })
  heldNames('the Swift overlay\'s resource value accessors are found', show('s', 'swiftc', SWIFT_SOURCE), {
    'URLResourceValues.creationDate': FT,
    'URLResourceValues.contentModificationDate': FT,
    'URLResourceValues.volumeAvailableCapacity': DS,
    'URLResourceValues.volumeTotalCapacity': DS,
    'URLResourceValues.volumeAvailableCapacityForImportantUsage': DS,
    'URLResourceValues.volumeAvailableCapacityForOpportunisticUsage': DS,
    NSURLCreationDateKey: FT
  })

  // -- a bundle built of such binaries -------------------------------------------------------------

  const executable = (path, source, extra = []) => {
    const src = written(`${path}.m`, source)
    mkdirSync(dirname(path), { recursive: true })
    const answer = spawnSync(
      'xcrun',
      ['--sdk', 'iphonesimulator', 'clang', '-target', 'arm64-apple-ios17.0-simulator', '-framework', 'Foundation', ...extra, '-o', path, src],
      { encoding: 'utf8' }
    )
    if (answer.status !== 0) throw new Error(`clang ${path}: ${answer.stderr}`)
  }
  const library = (path, source) => {
    const src = written(`${path}.m`, source)
    mkdirSync(dirname(path), { recursive: true })
    const answer = spawnSync(
      'xcrun',
      ['--sdk', 'iphonesimulator', 'clang', '-dynamiclib', '-target', 'arm64-apple-ios17.0-simulator', '-framework', 'Foundation', '-o', path, src],
      { encoding: 'utf8' }
    )
    if (answer.status !== 0) throw new Error(`clang ${path}: ${answer.stderr}`)
  }
  const MAIN = `
    #import <Foundation/Foundation.h>
    #include <sys/stat.h>
    int main(void) { struct stat s; stat("/", &s); (void)[[NSProcessInfo processInfo] systemUptime]; return [NSUserDefaults standardUserDefaults] == nil; }
  `
  const LIB = `
    #include <sys/mount.h>
    int fx_free(void) { struct statfs s; return statfs("/", &s); }
  `
  const EXT = `int main(void) { return 0; }`
  const ATTR = `
    #include <unistd.h>
    #include <sys/attr.h>
    int main(void) { struct attrlist a = {0}; char b[64]; return getattrlist("/", &a, b, sizeof b, 0); }
  `

  /**
   * Builds `source` for the Simulator on both architectures and joins them into one universal file,
   * each slice from its own source: the first for arm64, the second for x86_64.
   */
  function universal(path, arm64Source, x86Source) {
    const slices = []
    for (const [arch, source] of [['arm64', arm64Source], ['x86_64', x86Source]]) {
      const slice = `${path}.${arch}`
      const src = written(`${slice}.m`, source)
      const answer = spawnSync(
        'xcrun',
        ['--sdk', 'iphonesimulator', 'clang', '-target', `${arch}-apple-ios17.0-simulator`, '-framework', 'Foundation', '-o', slice, src],
        { encoding: 'utf8' }
      )
      if (answer.status !== 0) throw new Error(`clang ${slice}: ${answer.stderr}`)
      slices.push(slice)
    }
    const joined = spawnSync('lipo', ['-create', ...slices, '-output', path], { encoding: 'utf8' })
    if (joined.status !== 0) throw new Error(`lipo ${path}: ${joined.stderr}`)
  }

  /**
   * Lays an application out as `tauri ios build` leaves one. Returns its path. `app`, `framework`
   * and `extension` are what each bundle's manifest says (`null`: none). Beside them, a fault can be
   * laid in: `x86` is the source of a second slice of the application's executable, `link` makes a
   * symbolic link, `frameworkInfo: false` leaves the framework no Info.plist, `executable: false`
   * leaves the application's executable out of its bundle, and `root` lists SDK resource bundles.
   */
  function bundle(
    name,
    { app, framework, extension, root = [], x86, link, frameworkInfo = true, executable: hasExecutable = true, nested, named = 'Fx', main = MAIN }
  ) {
    const dir = join(work, name, 'Fx.app')
    mkdirSync(dir, { recursive: true })
    plist(join(dir, 'Info.plist'), { CFBundleExecutable: named, CFBundleIdentifier: 'to.kala.fx' })
    if (!hasExecutable) executable(join(dir, 'Other'), MAIN)
    else if (x86) universal(join(dir, 'Fx'), main, x86)
    else executable(join(dir, 'Fx'), main)
    if (app) plist(join(dir, 'PrivacyInfo.xcprivacy'), app)
    if (framework !== undefined) {
      const fw = join(dir, 'Frameworks', 'Lib.framework')
      mkdirSync(fw, { recursive: true })
      if (frameworkInfo) plist(join(fw, 'Info.plist'), { CFBundleExecutable: 'Lib', CFBundleIdentifier: 'to.kala.fx.lib' })
      library(join(fw, 'Lib'), LIB)
      if (framework) plist(join(fw, 'PrivacyInfo.xcprivacy'), framework)
    }
    if (extension) {
      const ex = join(dir, 'PlugIns', 'Ext.appex')
      mkdirSync(ex, { recursive: true })
      plist(join(ex, 'Info.plist'), { CFBundleExecutable: 'Ext', CFBundleIdentifier: 'to.kala.fx.ext' })
      executable(join(ex, 'Ext'), extension.source ?? EXT, extension.extra ?? [])
      if (extension.manifest) plist(join(ex, 'PrivacyInfo.xcprivacy'), extension.manifest)
      for (const sdk of extension.root ?? []) {
        mkdirSync(join(ex, sdk.name), { recursive: true })
        if (sdk.raw !== undefined) writeFileSync(join(ex, sdk.name, 'PrivacyInfo.xcprivacy'), sdk.raw)
        else if (sdk.manifest) plist(join(ex, sdk.name, 'PrivacyInfo.xcprivacy'), manifest())
      }
    }
    for (const sdk of root) {
      mkdirSync(join(dir, sdk.name), { recursive: true })
      if (sdk.raw !== undefined) writeFileSync(join(dir, sdk.name, sdk.file ?? 'PrivacyInfo.xcprivacy'), sdk.raw)
      else if (sdk.manifest) plist(join(dir, sdk.name, 'PrivacyInfo.xcprivacy'), manifest())
    }
    if (nested) {
      const inner = join(dir, 'Watch', 'W.app')
      mkdirSync(inner, { recursive: true })
      plist(join(inner, 'Info.plist'), { CFBundleExecutable: 'W', CFBundleIdentifier: 'to.kala.fx.watch' })
      executable(join(inner, 'W'), MAIN)
      if (nested.manifest) plist(join(inner, 'PrivacyInfo.xcprivacy'), nested.manifest)
    }
    if (link) symlinkSync(join(dir, 'Fx'), join(dir, 'Alias'))
    return dir
  }
  const whole = manifest(
    declares('FileTimestamp', 'C617.1'),
    declares('SystemBootTime', '35F9.1'),
    declares('UserDefaults', 'CA92.1')
  )
  const library_manifest = manifest(declares('DiskSpace', 'E174.1'))
  const without = (category) => ({
    ...whole,
    NSPrivacyAccessedAPITypes: whole.NSPrivacyAccessedAPITypes.filter(
      (each) => each.NSPrivacyAccessedAPIType !== `${PREFIX}${category}`
    )
  })

  heldProblems(
    'an application whose manifests declare what its binaries use passes',
    examine(bundle('whole', { app: whole, framework: library_manifest })).problems,
    []
  )
  for (const [category, api] of [
    ['FileTimestamp', 'stat'],
    ['SystemBootTime', 'systemUptime'],
    ['UserDefaults', 'OBJC_CLASS_$_NSUserDefaults']
  ]) {
    heldProblems(
      `removing ${category} from the application's manifest fails, naming the executable and ${api}`,
      examine(bundle(`without-${category}`, { app: without(category), framework: library_manifest })).problems,
      [`Fx uses ${category} (${api}) and the manifest of the application does not declare it`]
    )
  }
  heldProblems(
    'an application with no manifest at all fails, saying the manifest is missing',
    examine(bundle('no-manifest', { app: null, framework: library_manifest })).problems,
    ['and the manifest of the application is missing']
  )
  heldProblems(
    'an application that uses no category still needs a manifest of its own',
    examine(bundle('quiet-no-manifest', { app: null, framework: library_manifest, main: EXT })).problems,
    ['the application has no privacy manifest']
  )
  heldProblems(
    'a declared category no code in the executable uses fails',
    examine(
      bundle('unused', {
        app: manifest(...whole.NSPrivacyAccessedAPITypes, declares('ActiveKeyboards', '54BD.1')),
        framework: library_manifest
      })
    ).problems,
    ['declares ActiveKeyboards and no code in its executable uses it']
  )
  heldProblems(
    'a framework that uses a category its own manifest does not declare fails',
    examine(bundle('framework-bare', { app: whole, framework: manifest() })).problems,
    ['Lib uses DiskSpace (statfs) and the manifest of Frameworks/Lib.framework does not declare it']
  )
  heldProblems(
    'a framework with no manifest at all fails, saying so',
    examine(bundle('framework-none', { app: whole, framework: null })).problems,
    ['and the manifest of Frameworks/Lib.framework is missing']
  )
  heldProblems(
    'an extension that uses a category and has no manifest fails',
    examine(bundle('extension-bare', { app: whole, framework: library_manifest, extension: { source: MAIN } })).problems,
    ['Ext uses FileTimestamp (stat)']
  )
  heldProblems(
    'an extension\'s manifest may not give a reason only a package may give',
    examine(
      bundle('extension-sdk-reason', {
        app: whole,
        framework: library_manifest,
        extension: { source: MAIN, manifest: manifest(declares('FileTimestamp', '0A2A.1'), declares('SystemBootTime', '35F9.1'), declares('UserDefaults', 'CA92.1')) }
      })
    ).problems,
    ['the manifest of PlugIns/Ext.appex: FileTimestamp is declared with 0A2A.1, which only a third-party SDK may give']
  )
  heldProblems(
    'an extension that declares a category it does not use fails',
    examine(
      bundle('extension-unused', {
        app: whole,
        framework: library_manifest,
        extension: { manifest: manifest(declares('ActiveKeyboards', '54BD.1')) }
      })
    ).problems,
    ['the manifest of PlugIns/Ext.appex declares ActiveKeyboards and no code in its executable uses it']
  )
  heldProblems(
    'an extension that uses nothing needs no manifest',
    examine(bundle('extension-quiet', { app: whole, framework: library_manifest, extension: {} })).problems,
    []
  )
  heldProblems(
    'a use Apple lists in two categories is covered by either declaration',
    examine(
      bundle('either', {
        app: manifest(declares('FileTimestamp', 'C617.1'), declares('SystemBootTime', '35F9.1'), declares('UserDefaults', 'CA92.1')),
        framework: library_manifest,
        extension: { source: ATTR, manifest: manifest(declares('DiskSpace', 'E174.1')) }
      })
    ).problems,
    []
  )
  heldProblems(
    'an application that links AdSupport while its manifest says it does not track fails',
    examine(
      bundle('tracking', {
        app: whole,
        framework: library_manifest,
        extension: { extra: ['-framework', 'AdSupport'], manifest: manifest() }
      })
    ).problems,
    ['links AdSupport and the manifest of PlugIns/Ext.appex does not say the application tracks']
  )
  heldProblems(
    'a package on Apple\'s list in a bundle of its own that ships no manifest fails',
    examine(
      bundle('sdk-bare', {
        app: whole,
        framework: library_manifest,
        root: [{ name: 'Firebase_FirebaseCore.bundle', manifest: false }, { name: 'nanopb_nanopb.bundle', manifest: true }]
      })
    ).problems,
    ['Firebase_FirebaseCore.bundle is FirebaseCore, which Apple lists as needing a privacy manifest, and ships none']
  )
  heldProblems(
    'a package on Apple\'s list that ships its manifest passes',
    examine(
      bundle('sdk-whole', {
        app: whole,
        framework: library_manifest,
        root: [{ name: 'Firebase_FirebaseCore.bundle', manifest: true }]
      })
    ).problems,
    []
  )
  heldProblems(
    'a use in the second slice of a universal executable is found',
    examine(bundle('second-slice', { app: whole, framework: library_manifest, x86: `#include <sys/mount.h>\n#import <Foundation/Foundation.h>\n#include <sys/stat.h>\nint main(void) { struct statfs s; struct stat t; stat("/", &t); (void)[[NSProcessInfo processInfo] systemUptime]; (void)[NSUserDefaults standardUserDefaults]; return statfs("/", &s); }` })).problems,
    ['Fx uses DiskSpace (statfs) and the manifest of the application does not declare it']
  )
  heldProblems(
    'a symbolic link in the bundle is a problem, not skipped',
    examine(bundle('link', { app: whole, framework: library_manifest, link: true })).problems,
    ['Alias is a symbolic link']
  )
  heldProblems(
    'a framework with no Info.plist is a problem, and does not inherit the application\'s manifest',
    examine(bundle('no-info', { app: whole, framework: null, frameworkInfo: false })).problems,
    [
      'Frameworks/Lib.framework has no Info.plist',
      'Lib uses DiskSpace (statfs) and the manifest of Frameworks/Lib.framework is missing'
    ]
  )
  heldProblems(
    'an application whose executable the Info.plist names is not there fails',
    examine(bundle('no-executable', { app: whole, framework: library_manifest, executable: false })).problems,
    ['the application names the executable Fx and it is not a Mach-O file of that bundle']
  )
  heldProblems(
    'a package\'s manifest that is not a valid property list fails',
    examine(
      bundle('sdk-garbled', {
        app: whole,
        framework: library_manifest,
        root: [{ name: 'Firebase_FirebaseCore.bundle', raw: 'this is not a property list' }]
      })
    ).problems,
    ['the manifest in Firebase_FirebaseCore.bundle']
  )
  heldProblems(
    'a nested application is held to a manifest of its own, not the outer application\'s',
    examine(bundle('nested', { app: whole, framework: library_manifest, nested: {} })).problems,
    ['Watch/W.app/W uses FileTimestamp (stat) and the manifest of Watch/W.app is missing']
  )
  heldProblems(
    'a nested application may not give a reason only a package may give',
    examine(
      bundle('nested-sdk-reason', {
        app: whole,
        framework: library_manifest,
        nested: {
          manifest: manifest(declares('FileTimestamp', '0A2A.1'), declares('SystemBootTime', '35F9.1'), declares('UserDefaults', 'CA92.1'))
        }
      })
    ).problems,
    ['the manifest of Watch/W.app: FileTimestamp is declared with 0A2A.1, which only a third-party SDK may give']
  )
  heldProblems(
    'a nested application that declares a category it does not use fails',
    examine(
      bundle('nested-unused', {
        app: whole,
        framework: library_manifest,
        nested: { manifest: manifest(...whole.NSPrivacyAccessedAPITypes, declares('ActiveKeyboards', '54BD.1')) }
      })
    ).problems,
    ['the manifest of Watch/W.app declares ActiveKeyboards and no code in its executable uses it']
  )
  heldProblems(
    'a nested application that declares what it uses passes',
    examine(bundle('nested-ok', { app: whole, framework: library_manifest, nested: { manifest: whole } })).problems,
    []
  )
  heldProblems(
    'an Info.plist that names another bundle\'s binary as its executable fails',
    examine(
      bundle('executable-elsewhere', {
        app: whole,
        framework: library_manifest,
        executable: false,
        named: 'Frameworks/Lib.framework/Lib'
      })
    ).problems,
    ['the application names the executable Frameworks/Lib.framework/Lib and it is not a Mach-O file of that bundle']
  )
  heldProblems(
    'the same bundle named with a trailing slash, as tab completion writes it, is the same bundle',
    examine(`${bundle('slash', { app: whole, framework: library_manifest })}/`).problems,
    []
  )
  heldProblems(
    'a manifest whose name differs only in case is a problem, not a manifest',
    examine(
      bundle('case', {
        app: whole,
        framework: library_manifest,
        root: [{ name: 'Firebase_FirebaseCore.bundle', raw: 'x', file: 'privacyinfo.xcprivacy' }]
      })
    ).problems,
    ['is not spelt PrivacyInfo.xcprivacy', 'Firebase_FirebaseCore.bundle is FirebaseCore, which Apple lists as needing a privacy manifest, and ships none']
  )
  heldProblems(
    'a manifest that is not valid fails in a bundle that is not on Apple\'s list',
    examine(
      bundle('other-garbled', {
        app: whole,
        framework: library_manifest,
        root: [{ name: 'Other.bundle', raw: 'this is not a property list' }]
      })
    ).problems,
    ['the manifest in Other.bundle']
  )
  heldProblems(
    'a package inside an extension that ships no manifest fails',
    examine(
      bundle('sdk-in-extension', {
        app: whole,
        framework: library_manifest,
        extension: { root: [{ name: 'nanopb_nanopb.bundle', manifest: false }] }
      })
    ).problems,
    ['PlugIns/Ext.appex/nanopb_nanopb.bundle is nanopb']
  )
}

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} case${failures === 1 ? '' : 's'} failed`)
  process.exit(1)
}
if (notRun > 0) {
  console.error('some cases did not run: they need macOS with Xcode')
  process.exit(3)
}
console.log('every case held')
