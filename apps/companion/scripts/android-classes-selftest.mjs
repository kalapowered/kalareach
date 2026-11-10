#!/usr/bin/env node
// Holds the packaged-class check to the answers it must give.
//
// The check reads a packaged Android application and says whether it carries the hand-written
// native classes, and whether it carries what its native libraries find by name. Three ways of
// getting that wrong would be silent: counting a dex the runtime never loads as application code,
// taking a class the code merely mentions for one the code defines, and losing the central
// directory to an archive comment that happens to contain the end-of-directory signature. A fourth
// would be reading the wrong build: checking the package a different variant left behind, or
// passing over one the build was asked for. A fifth is asking too little or too much of the
// libraries: a name the minifier removed and nothing flagged, or a file name, a metric name or a
// platform class taken for a class the application must define. None of them can be produced by
// building the application, so all of them are built here, in memory and in a throwaway outputs
// directory, and fed to the same reader and the same selection the build uses.
//
// The build command's own temporary directory is held here as well, since the command that reads the
// packages back is the one that gives each build its own (see `private-temp.mjs`).
//
// The archives are the smallest ones that exercise the reader: a dex here carries its string,
// type, method and class tables and nothing else, a library carries its dynamic symbols and the
// bytes a case puts in it, and neither is one any runtime would accept.
import { Buffer } from 'node:buffer'
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'

import { dex, elf, zip } from './archive-fixtures.mjs'
import { libraryClassNames } from './android-native-names.mjs'
import { privateTemporary } from './private-temp.mjs'
import {
  definedStrings,
  missingFrom,
  nativeNames,
  packagesOf,
  requestFrom,
  sourcesOf,
  verify
} from './android-classes.mjs'

const PRESENT = [
  'to.kala.reach.companion.push.KalaReachMessagingService',
  'to.kala.reach.companion.push.PreviewWorker',
  'to.kala.reach.companion.push.ChallengeWorker',
  'to.kala.reach.platform.PlatformPlugin'
]

/**
 * The same archive again, with a 22-byte comment shaped like a record that claims the real
 * central directory: `count` entries of it, and `over` bytes more than it holds.
 *
 * This is the comment that hides the rest of an archive. It sits 22 bytes past the real record,
 * so claiming the real directory's offset and 22 more bytes puts its own end exactly where a
 * reader would expect the directory to end, and every other field agrees as well.
 */
function forgedEnd(members, count, over) {
  const whole = zip(members)
  const real = whole.length - 22
  const comment = Buffer.alloc(22)
  comment.writeUInt32LE(0x06054b50, 0)
  comment.writeUInt16LE(count, 8)
  comment.writeUInt16LE(count, 10)
  comment.writeUInt32LE(whole.readUInt32LE(real + 12) + over, 12)
  comment.writeUInt32LE(whole.readUInt32LE(real + 16), 16)
  return zip(members, comment)
}

const work = mkdtempSync(join(tmpdir(), 'kr-android-classes-'))
let failures = 0

/** Says what the check answered, and whether that is what it had to answer. */
function held(what, expected, answer) {
  if (answer === expected) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${expected}\n        answered: ${answer}`)
}

/** Writes one archive and states what the check must answer about it. */
function expect(what, name, bytes, missing) {
  const path = join(work, name)
  writeFileSync(path, bytes)
  let answer
  try {
    answer = missingFrom(path).join(', ') || 'nothing'
  } catch (failure) {
    answer = `refused: ${failure.message}`
  }
  held(what, missing, answer)
}

const code = dex({ defined: PRESENT })
const filler = { name: 'AndroidManifest.xml', bytes: Buffer.from('not a manifest', 'utf8') }

expect(
  'an APK whose application dex carries every class is whole',
  'whole.apk',
  zip([filler, { name: 'classes.dex', bytes: code }]),
  'nothing'
)
expect(
  'a class defined only in an asset dex does not count as application code',
  'asset-only.apk',
  zip([filler, { name: 'assets/classes.dex', bytes: code }]),
  'refused: the artefact carries no application dex file'
)
expect(
  'an AAB is read from its base module',
  'whole.aab',
  zip([filler, { name: 'base/dex/classes.dex', bytes: code }]),
  'nothing'
)
expect(
  'a class defined only in an optional feature does not count',
  'feature-only.aab',
  zip([filler, { name: 'voice/dex/classes.dex', bytes: code }]),
  'refused: the artefact carries no application dex file'
)
expect(
  'a class the dex only mentions is not a class the dex defines',
  'reference-only.apk',
  zip([
    filler,
    {
      name: 'classes.dex',
      bytes: dex({ defined: [PRESENT[0], PRESENT[2], PRESENT[3]], referenced: [PRESENT[1]] })
    }
  ]),
  PRESENT[1]
)
expect(
  'an archive comment holding the end-of-directory signature is still read',
  'commented.apk',
  zip(
    [filler, { name: 'classes.dex', bytes: code }],
    Buffer.concat([Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(40)])
  ),
  'nothing'
)
expect(
  'a 22-byte comment shaped like an empty end-of-directory record is still read',
  'commented-22.apk',
  zip(
    [filler, { name: 'classes.dex', bytes: code }],
    Buffer.concat([Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(18)])
  ),
  'nothing'
)
expect(
  'a comment that claims the real directory and 22 bytes more is not the record',
  'forged-prefix.apk',
  forgedEnd([filler, { name: 'classes.dex', bytes: code }], 1, 22),
  'nothing'
)
expect(
  'a comment that claims more entries than the archive holds is not the record',
  'forged-count.apk',
  forgedEnd([filler, { name: 'classes.dex', bytes: code }], 3, 22),
  'nothing'
)
expect(
  'an application missing only the messaging service is named, not passed',
  'no-service.apk',
  zip([filler, { name: 'classes.dex', bytes: dex({ defined: PRESENT.slice(1) }) }]),
  PRESENT[0]
)
expect(
  'an application missing only the preview worker is named, not passed',
  'no-preview-worker.apk',
  zip([
    filler,
    { name: 'classes.dex', bytes: dex({ defined: [PRESENT[0], PRESENT[2], PRESENT[3]] }) }
  ]),
  PRESENT[1]
)
expect(
  'an application missing only the challenge worker is named, not passed',
  'no-challenge-worker.apk',
  zip([
    filler,
    { name: 'classes.dex', bytes: dex({ defined: [PRESENT[0], PRESENT[1], PRESENT[3]] }) }
  ]),
  PRESENT[2]
)
expect(
  'an application missing only the platform plugin is named, not passed',
  'no-plugin.apk',
  zip([filler, { name: 'classes.dex', bytes: dex({ defined: PRESENT.slice(0, 3) }) }]),
  PRESENT[3]
)
expect(
  'an application that defines only the service is named for everything else',
  'service-only.apk',
  zip([filler, { name: 'classes.dex', bytes: dex({ defined: [PRESENT[0]] }) }]),
  PRESENT.slice(1).join(', ')
)
// The failure names the directory of the class that is missing, and not always the application's.
held(
  'a missing plugin sends the reader to the platform library',
  'apps/companion/native/platform/android/src/main/java',
  sourcesOf([PRESENT[3]]).join(' and ')
)
held(
  'a missing service or worker sends the reader to the application module',
  'apps/companion/native/android/android/src/main/java',
  sourcesOf([PRESENT[0], PRESENT[1], PRESENT[2]]).join(' and ')
)
held(
  'a plugin and a worker missing together name both',
  'apps/companion/native/android/android/src/main/java and apps/companion/native/platform/android/src/main/java',
  sourcesOf([PRESENT[1], PRESENT[3]]).join(' and ')
)
expect(
  'a dex layout this does not read is refused rather than guessed at',
  'future.apk',
  zip([
    filler,
    {
      name: 'classes.dex',
      bytes: (() => {
        const other = Buffer.from(code)
        other.write('dex\n099\0', 0, 'latin1')
        return other
      })()
    }
  ]),
  'refused: dex version 099 is not read here'
)

// -- the strings a dex carries -------------------------------------------------------------------
// The identifier check reads every string, which is how it finds a name the code carries as a
// constant. It must see the constants, the descriptors of the classes and nothing in between.

const carried = definedStrings(dex({ defined: [PRESENT[0]], constants: ['to.kala.reach.push'] }))
held(
  'a constant the code carries is read from the string table',
  'true',
  String(carried.includes('to.kala.reach.push'))
)
held(
  'a class descriptor is read from the string table in its own form',
  'true',
  String(carried.includes('Lto/kala/reach/companion/push/KalaReachMessagingService;'))
)
held(
  'the string table is read whole, and nothing else is taken for part of it',
  JSON.stringify(
    [
      'Ljava/lang/Object;',
      'Lto/kala/reach/companion/push/KalaReachMessagingService;',
      'member0',
      'member1',
      'to.kala.reach.push'
    ].sort()
  ),
  JSON.stringify([...carried].sort())
)

// -- what the native libraries find by name ------------------------------------------------------
// A minified build removes or renames a class that only native code reaches, and the library then
// aborts the process when its start-up asks for the class. The check reads the names the
// libraries carry, from the package itself, and holds the dex to each of them.

const JNI_ZERO = 'org.jni_zero.JniZero'
const FACTORY = 'org.webrtc.PeerConnectionFactory'
const CANDIDATE = 'org.webrtc.IceCandidate'
const NESTED = 'org.webrtc.PeerConnection$Observer'
const RAW = 'org.webrtc.NamedByFindClass'
const MEDIA = 'lib/arm64-v8a/libmedia.so'

/** What a media library carries: a dotted name, a descriptor, a slashed name and a native method. */
function mediaLibrary(more = {}) {
  return elf({
    exports: ['Java_org_webrtc_PeerConnectionFactory_nativeCreate', 'JNI_OnLoad'],
    blobs: [
      Buffer.from(
        `\x00\x3e${JNI_ZERO}\x00(ILorg/webrtc/IceCandidate;)V\x00` +
          `L${NESTED.replaceAll('.', '/')};\x00org/webrtc/NamedByFindClass\x00`,
        'latin1'
      )
    ],
    ...more
  })
}

/** The dex that defines everything `mediaLibrary` names, and the native method it exports. */
function mediaDex(without = [], methods = null) {
  const defined = [JNI_ZERO, FACTORY, CANDIDATE, NESTED, RAW].filter((name) => !without.includes(name))
  return dex({
    defined,
    methods: methods ?? { [FACTORY]: [{ name: 'nativeCreate', native: true }] }
  })
}

/** Writes one package and states what the check must say its libraries find by name. */
function expectNames(what, name, members, problems) {
  const path = join(work, name)
  writeFileSync(path, zip([filler, ...members]))
  let answer
  try {
    answer = nativeNames(path).problems.join('; ') || 'nothing'
  } catch (failure) {
    answer = `refused: ${failure.message}`
  }
  held(what, problems, answer)
}

const library = (bytes = mediaLibrary(), name = MEDIA) => ({ name, bytes })
const application = (bytes = mediaDex()) => ({ name: 'classes.dex', bytes })

expectNames(
  'an application that defines every name its library carries, and the natives it is bound to, is whole',
  'names-whole.apk',
  [application(), library()],
  'nothing'
)
expectNames(
  'a class the library finds by name that the dex lacks is named, as the minifier left it',
  'names-no-jni-zero.apk',
  [application(mediaDex([JNI_ZERO])), library()],
  `class ${JNI_ZERO} (named by ${MEDIA})`
)
expectNames(
  'a class the dex only mentions is not a class the dex defines',
  'names-mentioned-only.apk',
  [
    application(
      dex({
        defined: [FACTORY, CANDIDATE, NESTED, RAW],
        referenced: [JNI_ZERO],
        methods: { [FACTORY]: [{ name: 'nativeCreate', native: true }] }
      })
    ),
    library()
  ],
  `class ${JNI_ZERO} (named by ${MEDIA})`
)
expectNames(
  'a class named in a type descriptor is asked for, with the primitive before it left alone',
  'names-descriptor.apk',
  [application(mediaDex([CANDIDATE])), library()],
  `class ${CANDIDATE} (named by ${MEDIA})`
)
expectNames(
  'a nested class named in a descriptor is asked for under its own name',
  'names-nested.apk',
  [application(mediaDex([NESTED])), library()],
  `class ${NESTED} (named by ${MEDIA})`
)
expectNames(
  'a class named the way FindClass takes it is asked for',
  'names-find-class.apk',
  [application(mediaDex([RAW])), library()],
  `class ${RAW} (named by ${MEDIA})`
)
expectNames(
  'every class that is missing is named, in order, and not only the first',
  'names-all-missing.apk',
  [application(dex({ defined: [FACTORY], methods: { [FACTORY]: [{ name: 'nativeCreate', native: true }] } })), library()],
  [JNI_ZERO, CANDIDATE, RAW, NESTED].map((name) => `class ${name} (named by ${MEDIA})`).join('; ')
)
expectNames(
  'names that are no class the application defines are not asked for',
  'names-noise.apk',
  [
    application(dex({ defined: [] })),
    library(
      elf({
        blobs: [
          Buffer.from(
            [
              'java.lang.String',
              'Ljava/lang/String;',
              'Landroid/content/Context;',
              'android/content/Intent',
              'WebRTC.Video.Encoder.CodecType',
              'a.J',
              'libjingle_peerconnection_so.so',
              'third_party/jni_zero/jni_zero',
              'org/webrtc/Packed runs into the next string',
              'com.example.someFile.cc',
              'Encoded.Qp.Vp8.S1',
              'keys/notification-preview/recovery/seedauthority/grants/revoked/EmptyInvalidDigit'
            ]
              .map((text) => `\x00${text}`)
              .join('') + '\x00',
            'latin1'
          )
        ]
      })
    )
  ],
  'nothing'
)
expectNames(
  'a name that runs into the next string has no end to read, so it is not asked for',
  'names-packed.apk',
  [
    application(dex({ defined: [] })),
    library(
      elf({
        blobs: [Buffer.from('org.webrtc.PackedRunningIntoMoreText and org/webrtc/Packed!', 'latin1')]
      })
    )
  ],
  'nothing'
)

// A library too large to read as one string is read in pieces, and the pieces must not change the
// answer: a name that crosses the end of a piece is neither lost nor read twice, and the tail of it
// that starts a piece is not taken for a name.
const whole = [...libraryClassNames(mediaLibrary())].sort().join(',')
const different = []
for (let chunk = 1; chunk <= 80; chunk += 1) {
  const answer = [...libraryClassNames(mediaLibrary(), { chunk, overlap: 64 })].sort().join(',')
  if (answer !== whole) different.push(chunk)
}
held(
  'a library read in pieces of any size names the same classes as one read whole',
  '',
  different.join(',')
)

// -- the native methods the dex declares --------------------------------------------------------
// The runtime binds a native method to the symbol its class and name make. A method the minifier
// renamed has no symbol, and the call that reaches it throws.

expectNames(
  'a native method that a library exports under another name is named, as a renamed one is',
  'natives-renamed.apk',
  [application(mediaDex([], { [FACTORY]: [{ name: 'a', native: true }] })), library()],
  `native method ${FACTORY}.a (no library of arm64-v8a exports it)`
)
expectNames(
  'a class none of whose natives a library exports is not one the libraries are bound to',
  'natives-unbound.apk',
  [
    application(
      dex({
        defined: [JNI_ZERO, FACTORY, CANDIDATE, NESTED, RAW, 'org.webrtc.Other'],
        methods: {
          [FACTORY]: [{ name: 'nativeCreate', native: true }],
          'org.webrtc.Other': [{ name: 'nativeOther', native: true }]
        }
      })
    ),
    library()
  ],
  'nothing'
)
expectNames(
  'a native method no library exports, in a class some other of its natives is exported for, is named',
  'natives-partly-bound.apk',
  [
    application(
      mediaDex([], {
        [FACTORY]: [
          { name: 'nativeCreate', native: true },
          { name: 'nativeOther', native: true }
        ]
      })
    ),
    library()
  ],
  `native method ${FACTORY}.nativeOther (no library of arm64-v8a exports it)`
)
expectNames(
  'a static native method is bound the same as an instance one',
  'natives-static.apk',
  [application(mediaDex([], { [FACTORY]: [{ name: 'nativeCreate', native: true, static: true }] })), library()],
  'nothing'
)
expectNames(
  'a method that is not native needs no symbol',
  'natives-plain.apk',
  [application(mediaDex([], { [FACTORY]: [{ name: 'create' }] })), library()],
  'nothing'
)
expectNames(
  'a native method the library exports and the dex dropped is no problem, as nothing calls it',
  'natives-dropped.apk',
  [application(mediaDex([], { [FACTORY]: [{ name: 'other' }] })), library()],
  'nothing'
)
expectNames(
  'a symbol the library only refers to binds no class, so its natives are not asked for',
  'natives-imported.apk',
  [
    application(),
    library(mediaLibrary({ exports: [], imports: ['Java_org_webrtc_PeerConnectionFactory_nativeCreate'] }))
  ],
  'nothing'
)
expectNames(
  'an escaped underscore and an overloaded method are decoded to the names the class declares',
  'natives-mangled.apk',
  [
    application(
      dex({
        defined: ['org.webrtc.Peer_Connection'],
        methods: { 'org.webrtc.Peer_Connection': [{ name: 'native_call', native: true }] }
      })
    ),
    library(elf({ exports: ['Java_org_webrtc_Peer_1Connection_native_1call__ILjava_lang_String_2'] }))
  ],
  'nothing'
)
expectNames(
  'a native method may be bound by any library of the ABI, not only by one that names classes',
  'natives-other-library.apk',
  [
    application(),
    library(mediaLibrary({ exports: [] })),
    library(elf({ exports: ['Java_org_webrtc_PeerConnectionFactory_nativeCreate'] }), 'lib/arm64-v8a/libother.so')
  ],
  'nothing'
)
expectNames(
  'each ABI is held to its own libraries, and the one that lacks the symbol is the one named',
  'natives-one-abi.apk',
  [
    application(),
    library(),
    library(
      mediaLibrary({ exports: ['Java_org_webrtc_PeerConnectionFactory_other'] }),
      'lib/x86_64/libmedia.so'
    )
  ],
  `native method ${FACTORY}.nativeCreate (no library of x86_64 exports it)`
)
expectNames(
  'a 32-bit library is read as well as a 64-bit one',
  'natives-narrow.apk',
  [
    application(mediaDex([], { [FACTORY]: [{ name: 'a', native: true }] })),
    library(mediaLibrary({ wide: false }), 'lib/armeabi-v7a/libmedia.so')
  ],
  `native method ${FACTORY}.a (no library of armeabi-v7a exports it)`
)

// -- which libraries are read --------------------------------------------------------------------

expectNames(
  'a library of each ABI is read, and a name missing from the dex is reported against both',
  'libraries-two-abis.apk',
  [
    application(mediaDex([JNI_ZERO])),
    library(mediaLibrary(), 'lib/x86_64/libmedia.so'),
    library()
  ],
  `class ${JNI_ZERO} (named by ${MEDIA} and lib/x86_64/libmedia.so)`
)
expectNames(
  'a bundle is read from its base module',
  'libraries.aab',
  [
    { name: 'base/dex/classes.dex', bytes: mediaDex([JNI_ZERO]) },
    library(mediaLibrary(), 'base/lib/arm64-v8a/libmedia.so')
  ],
  `class ${JNI_ZERO} (named by base/lib/arm64-v8a/libmedia.so)`
)
expectNames(
  'a library in an optional feature of a bundle is not read',
  'libraries-feature.aab',
  [
    { name: 'base/dex/classes.dex', bytes: mediaDex([JNI_ZERO], {}) },
    library(mediaLibrary(), 'voice/lib/arm64-v8a/libmedia.so'),
    library(elf(), 'base/lib/arm64-v8a/libother.so')
  ],
  'nothing'
)
expectNames(
  'a library under the assets of an APK is not one the runtime loads',
  'libraries-assets.apk',
  [
    application(mediaDex([JNI_ZERO], {})),
    library(mediaLibrary(), 'assets/lib/arm64-v8a/libmedia.so'),
    library(elf(), 'lib/arm64-v8a/libother.so')
  ],
  'nothing'
)
expectNames(
  'a package with no native library is refused, not passed',
  'libraries-none.apk',
  [application()],
  'refused: the artefact carries no native library'
)
expectNames(
  'a library that is no ELF file is refused by name',
  'libraries-not-elf.apk',
  [application(), library(Buffer.from('not a library'))],
  `refused: ${MEDIA}: not an ELF library`
)

/** What `verify` says and answers about one package, with its output kept out of this one's. */
function verified(name, members) {
  const path = join(work, name)
  writeFileSync(path, zip(members))
  const output = []
  const { log, error } = console
  console.log = (text) => output.push(text)
  console.error = (text) => output.push(text)
  let whole
  try {
    whole = verify([path])
  } finally {
    console.log = log
    console.error = error
  }
  return { whole, said: output.join('\n') }
}

const withLibrary = (defined) => [
  filler,
  {
    name: 'classes.dex',
    bytes: dex({
      defined: [...PRESENT, ...defined],
      methods: { [FACTORY]: [{ name: 'nativeCreate', native: true }] }
    })
  },
  library()
]
const passing = verified('verify-whole.apk', withLibrary([JNI_ZERO, FACTORY, CANDIDATE, NESTED, RAW]))
held('the check passes a package whose dex holds what its libraries find', 'true', String(passing.whole))
const failing = verified('verify-missing.apk', withLibrary([FACTORY, CANDIDATE, NESTED, RAW]))
held('the check fails a package whose dex lacks a class its library finds', 'false', String(failing.whole))
held('and says which class and which library', 'true', String(failing.said.includes(JNI_ZERO) && failing.said.includes(MEDIA)))

// -- the build's own temporary directory -------------------------------------------------------
// Two builds of the application at once share the options file the command line tool leaves in the
// temporary directory, and cross: each must be given a directory of its own, and leave none behind.

const first = privateTemporary({ KEEP: 'this', TMPDIR: '/elsewhere' })
const second = privateTemporary()
writeFileSync(join(first.directory, 'to.kala.reach-server-addr'), '127.0.0.1:1')
held(
  'two builds are given two different temporary directories, both made',
  'true',
  String(first.directory !== second.directory && existsSync(first.directory) && existsSync(second.directory))
)
held(
  'the directory is the temporary directory of the environment a build is given, whichever name its platform reads',
  'true',
  String(
    first.env.TMPDIR === first.directory &&
      first.env.TEMP === first.directory &&
      first.env.TMP === first.directory &&
      first.env.KEEP === 'this'
  )
)
held(
  'the directory of one build does not hold the options file of the other',
  'false',
  String(existsSync(join(second.directory, 'to.kala.reach-server-addr')))
)
first.remove()
second.remove()
held(
  'removing a build\'s directory removes what the build left in it, and only that directory',
  'false',
  String(existsSync(first.directory) || existsSync(second.directory))
)

// -- which packages a build is checked against --------------------------------------------------
// An outputs directory as a tree carries it after several builds. The ages are deliberately
// misleading: the release packages are the newest files in it, the debug APK is as a build that
// has just rewritten it leaves it, and the debug bundle beside it is the oldest file there, as a
// packaging task with nothing to do leaves its own output. Anything that decided by time would
// answer wrongly below.

const outputs = join(work, 'outputs')
const OLD = new Date('2024-01-01T00:00:00Z')
const REWRITTEN = new Date('2025-01-01T00:00:00Z')
const NEW = new Date('2026-01-01T00:00:00Z')

function apkOutput(flavour, profile, when, variant = null) {
  const directory = join(outputs, 'apk', flavour, profile)
  mkdirSync(directory, { recursive: true })
  const name = `app-${flavour}-${profile}.apk`
  const path = join(directory, name)
  writeFileSync(path, zip([filler, { name: 'classes.dex', bytes: code }]))
  writeFileSync(
    join(directory, 'output-metadata.json'),
    JSON.stringify({
      version: 3,
      variantName: variant ?? `${flavour}${profile[0].toUpperCase()}${profile.slice(1)}`,
      elements: [{ type: 'SINGLE', outputFile: name }]
    })
  )
  utimesSync(path, when, when)
}

function bundleOutput(variant, names, when) {
  const directory = join(outputs, 'bundle', variant)
  mkdirSync(directory, { recursive: true })
  for (const name of names) {
    const path = join(directory, name)
    writeFileSync(path, zip([filler, { name: 'base/dex/classes.dex', bytes: code }]))
    utimesSync(path, when, when)
  }
}

apkOutput('universal', 'debug', REWRITTEN)
apkOutput('universal', 'release', NEW)
// The flavour a build asks for by `--target i686`, left behind by a release build.
apkOutput('x86', 'debug', NEW, 'x86Release')
bundleOutput('universalDebug', ['app-universal-debug.aab'], OLD)
bundleOutput('universalRelease', ['app-universal-release.aab'], NEW)
bundleOutput('armDebug', ['app-arm-debug.aab', 'app-arm-debug-renamed.aab'], NEW)

/** States which packages a build with these arguments must be checked against. */
function expectPackages(what, argv, chosen) {
  let answer
  try {
    const request = requestFrom(argv)
    answer = packagesOf(request, outputs)
      .map((path) => relative(outputs, path).replaceAll('\\', '/'))
      .join(', ')
  } catch (failure) {
    answer = `refused: ${failure.message}`
  }
  held(what, chosen, answer)
}

expectPackages(
  'a build that rewrote only its APK is checked against that APK and the bundle it left alone',
  ['--debug', '--target', 'aarch64'],
  'apk/universal/debug/app-universal-debug.apk, bundle/universalDebug/app-universal-debug.aab'
)
expectPackages(
  'a bundle the build had no reason to rewrite is still checked',
  ['--debug', '--aab'],
  'bundle/universalDebug/app-universal-debug.aab'
)
expectPackages(
  'a build asked for APKs alone is not judged against a bundle',
  ['--debug', '--apk'],
  'apk/universal/debug/app-universal-debug.apk'
)
expectPackages(
  'a release build is checked against the release packages',
  [],
  'apk/universal/release/app-universal-release.apk, bundle/universalRelease/app-universal-release.aab'
)
expectPackages(
  'a package the build asked for and did not leave is a failure, not an omission',
  ['--debug', '--split-per-abi', '--target', 'aarch64', '--apk'],
  'refused: this build asked for the arm64Debug APK and left no ' +
    join(outputs, 'apk', 'arm64', 'debug', 'output-metadata.json')
)
expectPackages(
  'a package that belongs to another variant is refused, not read',
  ['--debug', '--split-per-abi', '--target', 'i686', '--apk'],
  `refused: ${join(
    outputs,
    'apk',
    'x86',
    'debug',
    'output-metadata.json'
  )} describes x86Release, not the x86Debug that was built`
)
expectPackages(
  'two bundles in one variant directory are an ambiguity, not a choice',
  ['--debug', '--split-per-abi', '--target', 'armv7', '--aab'],
  `refused: ${join(outputs, 'bundle', 'armDebug')} holds 2 bundles: ` +
    'app-arm-debug-renamed.aab, app-arm-debug.aab'
)
expectPackages(
  'an argument this cannot read stops the check rather than narrowing it',
  ['--debug', '--every-abi'],
  'refused: This build was given --every-abi, which the packaged-class check does not read, so ' +
    'it cannot say which packages the build was asked for. Build with `pnpm -C apps/companion ' +
    'exec tauri android build` and check the package yourself with `pnpm -C apps/companion ' +
    'android:classes <path>`.'
)

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} of the packaged-class checks answered wrongly`)
  process.exit(1)
}
console.log('the packaged-class check answers correctly on every archive and build above')
