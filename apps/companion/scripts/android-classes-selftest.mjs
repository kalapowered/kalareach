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
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'

import { dex, elf, zip } from './archive-fixtures.mjs'
import { libraryClassNames } from './android-native-names.mjs'
import { refusal as iosRefusal } from './ios.mjs'
import { privateTemporary } from './private-temp.mjs'
import {
  definedClasses,
  definedNatives,
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

expectNames(
  'a nested class named with dots, and a class of a library the application brings, are asked for',
  'names-nested-dotted.apk',
  [
    application(dex({ defined: [] })),
    library(
      elf({
        blobs: [Buffer.from('\x00org.webrtc.Outer$Inner\x00androidx.camera.core.ImageProcessingUtil\x00', 'latin1')]
      })
    )
  ],
  'class androidx.camera.core.ImageProcessingUtil (named by lib/arm64-v8a/libmedia.so); ' +
    'class org.webrtc.Outer$Inner (named by lib/arm64-v8a/libmedia.so)'
)
expectNames(
  'a string of many nested parts that is no name is read without trouble',
  'names-many-parts.apk',
  [
    application(dex({ defined: [] })),
    library(elf({ blobs: [Buffer.from(`\x00org.webrtc.Foo${'$a'.repeat(200)}!\x00`, 'latin1')] }))
  ],
  'nothing'
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
        methods: {
          'org.webrtc.Peer_Connection': [
            { name: 'native_call', native: true, params: ['I', 'Ljava/lang/String;'] }
          ]
        }
      })
    ),
    library(elf({ exports: ['Java_org_webrtc_Peer_1Connection_native_1call__ILjava_lang_String_2'] }))
  ],
  'nothing'
)
expectNames(
  'an overload with no symbol of its own is named, as the long name of the other does not bind it',
  'natives-overload-missing.apk',
  [
    application(
      mediaDex([], {
        [FACTORY]: [
          { name: 'call', native: true, params: ['I'] },
          { name: 'call', native: true, params: ['J'] }
        ]
      })
    ),
    library(elf({ exports: ['Java_org_webrtc_PeerConnectionFactory_call__I'] }))
  ],
  `native method ${FACTORY}.call (arguments J) (no library of arm64-v8a exports it)`
)
expectNames(
  'overloads each bound by a long name are bound',
  'natives-overloads-bound.apk',
  [
    application(
      mediaDex([], {
        [FACTORY]: [
          { name: 'call', native: true, params: ['I'] },
          { name: 'call', native: true, params: ['J'] }
        ]
      })
    ),
    library(
      elf({
        exports: [
          'Java_org_webrtc_PeerConnectionFactory_call__I',
          'Java_org_webrtc_PeerConnectionFactory_call__J'
        ]
      })
    )
  ],
  'nothing'
)
expectNames(
  'overloads of a name that a library exports by its short name are bound to it',
  'natives-overloads-short.apk',
  [
    application(
      mediaDex([], {
        [FACTORY]: [
          { name: 'call', native: true, params: ['I'] },
          { name: 'call', native: true, params: ['J'] }
        ]
      })
    ),
    library(elf({ exports: ['Java_org_webrtc_PeerConnectionFactory_call'] }))
  ],
  'nothing'
)
expectNames(
  'a native method with an argument of a class is bound by the class as the runtime writes it',
  'natives-class-argument.apk',
  [
    application(
      mediaDex([], {
        [FACTORY]: [{ name: 'call', native: true, params: ['I', 'Lorg/webrtc/IceCandidate;', 'J'] }]
      })
    ),
    library(elf({ exports: ['Java_org_webrtc_PeerConnectionFactory_call__ILorg_webrtc_IceCandidate_2J'] }))
  ],
  'nothing'
)
expectNames(
  'a class that has fields before its methods is read through them',
  'natives-fields.apk',
  [
    application(
      dex({
        defined: [JNI_ZERO, FACTORY, CANDIDATE, NESTED, RAW],
        fields: { [FACTORY]: [2, 3] },
        methods: { [FACTORY]: [{ name: 'a', native: true }] }
      })
    ),
    library(mediaLibrary())
  ],
  `native method ${FACTORY}.a (no library of arm64-v8a exports it)`
)
expectNames(
  'a class with a static native and an instance native is read for both',
  'natives-both-lists.apk',
  [
    application(
      mediaDex([], {
        [FACTORY]: [
          { name: 'nativeCreate', native: true },
          { name: 'make', native: true, static: true },
          { name: 'a', native: true, static: true }
        ]
      })
    ),
    library(mediaLibrary({ exports: ['Java_org_webrtc_PeerConnectionFactory_nativeCreate', 'Java_org_webrtc_PeerConnectionFactory_make'] }))
  ],
  `native method ${FACTORY}.a (no library of arm64-v8a exports it)`
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

// A library whose symbols cannot be found is refused, and a symbol no other library can find does
// not bind a method: neither may excuse a class from its symbols.
for (const wide of [true, false]) {
  const width = wide ? '64-bit' : '32-bit'
  expectNames(
    `a ${width} library's local symbol does not bind a method of a class its other symbols bind`,
    `natives-local-${width}.apk`,
    [
      application(mediaDex([], { [FACTORY]: [{ name: 'nativeCreate', native: true }] })),
      library(
        mediaLibrary({
          wide,
          exports: ['Java_org_webrtc_PeerConnectionFactory_other'],
          locals: ['Java_org_webrtc_PeerConnectionFactory_nativeCreate']
        })
      )
    ],
    `native method ${FACTORY}.nativeCreate (no library of arm64-v8a exports it)`
  )
  expectNames(
    `a ${width} library's hidden symbol does not bind a method of a class its other symbols bind`,
    `natives-hidden-${width}.apk`,
    [
      application(mediaDex([], { [FACTORY]: [{ name: 'nativeCreate', native: true }] })),
      library(
        mediaLibrary({
          wide,
          exports: ['Java_org_webrtc_PeerConnectionFactory_other'],
          hidden: ['Java_org_webrtc_PeerConnectionFactory_nativeCreate']
        })
      )
    ],
    `native method ${FACTORY}.nativeCreate (no library of arm64-v8a exports it)`
  )
}
expectNames(
  'overloads whose argument classes differ only in case are told apart, as the runtime looks a symbol up exactly',
  'natives-overloads-case.apk',
  [
    application(
      mediaDex([], {
        [FACTORY]: [
          { name: 'call', native: true, params: ['Lorg/example/URL;'] },
          { name: 'call', native: true, params: ['Lorg/example/Url;'] }
        ]
      })
    ),
    library(elf({ exports: ['Java_org_webrtc_PeerConnectionFactory_call__Lorg_example_URL_2'] }))
  ],
  `native method ${FACTORY}.call (arguments Lorg_example_Url_2) (no library of arm64-v8a exports it)`
)
expectNames(
  'a symbol whose argument types are spelled in the wrong case does not bind the method',
  'natives-wrong-case.apk',
  [
    application(mediaDex([], { [FACTORY]: [{ name: 'call', native: true, params: ['I'] }] })),
    library(elf({ exports: ['Java_org_webrtc_PeerConnectionFactory_call__i'] }))
  ],
  `native method ${FACTORY}.call (no library of arm64-v8a exports it)`
)
// The runtime looks a native method up by the exact spelling of its symbol: a character outside
// ASCII is written `_0` and four hex digits, in lower case. A symbol with the same digits in upper
// case names the same method to a reader that decodes it, and no method to the runtime.
const SPELLED = 'Java_org_webrtc_PeerConnectionFactory_m_000e9'
expectNames(
  'a native method whose name has a character outside ASCII is bound by the symbol the runtime looks for',
  'natives-escaped-method.apk',
  [
    application(mediaDex([], { [FACTORY]: [{ name: 'mé', native: true }] })),
    library(elf({ exports: [SPELLED] }))
  ],
  'nothing'
)
expectNames(
  'a symbol that spells that escape in upper case is not the symbol the runtime looks for',
  'natives-escaped-method-upper.apk',
  [
    application(mediaDex([], { [FACTORY]: [{ name: 'mé', native: true }] })),
    library(elf({ exports: [SPELLED.replace('000e9', '000E9')] }))
  ],
  `native method ${FACTORY}.mé (no library of arm64-v8a exports it)`
)
expectNames(
  'a class whose name has a character outside ASCII is bound by the symbol the runtime looks for',
  'natives-escaped-class.apk',
  [
    application(
      dex({ defined: ['org.webrtc.Pé'], methods: { 'org.webrtc.Pé': [{ name: 'go', native: true }] } })
    ),
    library(elf({ exports: ['Java_org_webrtc_P_000e9_go'] }))
  ],
  'nothing'
)
expectNames(
  'a class symbol that spells the escape in upper case is not the symbol the runtime looks for',
  'natives-escaped-class-upper.apk',
  [
    application(
      dex({ defined: ['org.webrtc.Pé'], methods: { 'org.webrtc.Pé': [{ name: 'go', native: true }] } })
    ),
    library(elf({ exports: ['Java_org_webrtc_P_000E9_go'] }))
  ],
  'native method org.webrtc.Pé.go (no library of arm64-v8a exports it)'
)
expectNames(
  'a weak symbol binds a method, as the runtime binds it',
  'natives-weak.apk',
  [application(), library(mediaLibrary({ exports: ['Java_org_webrtc_PeerConnectionFactory_other'], weak: ['Java_org_webrtc_PeerConnectionFactory_nativeCreate'] }))],
  'nothing'
)
expectNames(
  'a library whose symbol table is no dynamic one is refused, not read as one that exports nothing',
  'libraries-no-dynsym.apk',
  [application(), library(mediaLibrary({ dynamic: false }))],
  `refused: ${MEDIA}: an ELF library with no dynamic symbol table`
)
expectNames(
  'a library whose symbols name the table of section names is refused',
  'libraries-wrong-strings.apk',
  [application(), library(mediaLibrary({ stringsLink: 3 }))],
  `refused: ${MEDIA}: an ELF library whose dynamic symbols name no dynamic string table`
)
expectNames(
  'a library whose section headers are too small to be headers is refused',
  'libraries-small-headers.apk',
  [
    application(),
    library(
      (() => {
        const small = Buffer.from(mediaLibrary())
        small.writeUInt16LE(8, 0x3a)
        return small
      })()
    )
  ],
  `refused: ${MEDIA}: an ELF library whose section headers are not within the file`
)
expectNames(
  'a library with no section headers is refused, not read as one that exports nothing',
  'libraries-no-headers.apk',
  [application(), library(mediaLibrary({ headers: false }))],
  `refused: ${MEDIA}: an ELF library with no section headers`
)
expectNames(
  'a library whose section headers run past its end is refused',
  'libraries-truncated.apk',
  [
    application(),
    library(
      (() => {
        const whole = mediaLibrary()
        return whole.subarray(0, whole.length - 8)
      })()
    )
  ],
  `refused: ${MEDIA}: an ELF library whose section headers are not within the file`
)
// A symbol table that cannot be read as it stands is refused, never read as one that exports less:
// an entry that is skipped, or a name that runs into other bytes, would excuse the class it is for.
const refusedLibrary = (what, name, bytes, why) =>
  expectNames(what, name, [application(), library(bytes)], `refused: ${MEDIA}: ${why}`)
refusedLibrary(
  'a symbol table whose header gives no entry size is refused',
  'libraries-no-entsize.apk',
  mediaLibrary({ entsize: 0 }),
  'an ELF library whose dynamic symbols are not in entries of the size it reads'
)
refusedLibrary(
  'a 64-bit symbol table with 32-bit entries is refused',
  'libraries-entsize-wide.apk',
  mediaLibrary({ entsize: 16 }),
  'an ELF library whose dynamic symbols are not in entries of the size it reads'
)
refusedLibrary(
  'a 32-bit symbol table with 64-bit entries is refused',
  'libraries-entsize-narrow.apk',
  mediaLibrary({ wide: false, entsize: 24 }),
  'an ELF library whose dynamic symbols are not in entries of the size it reads'
)
refusedLibrary(
  'a symbol table that ends in part of an entry is refused, not read without it',
  'libraries-partial-entry.apk',
  mediaLibrary({ tail: Buffer.alloc(8) }),
  'an ELF library whose dynamic symbol table does not divide into entries'
)
refusedLibrary(
  'a symbol whose name is past the end of its string table is refused, not read as an empty name',
  'libraries-name-beyond.apk',
  mediaLibrary({ nameBeyond: true }),
  'an ELF library with a symbol whose name is not within its string table'
)
refusedLibrary(
  'a name with no NUL inside its string table is refused, not ended by whatever follows the table',
  'libraries-name-unterminated.apk',
  mediaLibrary({ unterminated: true }),
  'an ELF library with a symbol name that has no end within its string table'
)
refusedLibrary(
  'a 64-bit library shorter than its header is refused by name',
  'libraries-short-header.apk',
  mediaLibrary().subarray(0, 60),
  'an ELF library cut short within its header'
)
refusedLibrary(
  'a library with its magic and little else is refused by name',
  'libraries-magic-only.apk',
  mediaLibrary().subarray(0, 8),
  'an ELF library cut short within its header'
)
refusedLibrary(
  'a 32-bit library shorter than its header is refused by name',
  'libraries-short-header-narrow.apk',
  mediaLibrary({ wide: false }).subarray(0, 50),
  'an ELF library cut short within its header'
)
expectNames(
  'a bundle holds each ABI to its own libraries',
  'libraries-two-abis.aab',
  [
    { name: 'base/dex/classes.dex', bytes: mediaDex() },
    library(mediaLibrary(), 'base/lib/arm64-v8a/libmedia.so'),
    library(mediaLibrary({ exports: ['Java_org_webrtc_PeerConnectionFactory_other'] }), 'base/lib/x86_64/libmedia.so')
  ],
  `native method ${FACTORY}.nativeCreate (no library of x86_64 exports it)`
)

// -- the libraries of every ABI ------------------------------------------------------------------
// A library is built once for each ABI, so the natives it exports for a class are the same in every
// ABI that carries it, and an ABI that lacks a library another one carries has none of its natives.

expectNames(
  'an ABI whose library exports nothing of a class that another ABI exports is held to its natives',
  'abis-lost-exports.apk',
  [application(), library(), library(mediaLibrary({ exports: ['JNI_OnLoad'] }), 'lib/x86_64/libmedia.so')],
  `native method ${FACTORY}.nativeCreate (no library of x86_64 exports it)`
)
expectNames(
  'the ABI that lost the exports is named whichever of the two comes first',
  'abis-lost-exports-first.apk',
  [application(), library(mediaLibrary({ exports: ['JNI_OnLoad'] })), library(mediaLibrary(), 'lib/x86_64/libmedia.so')],
  `native method ${FACTORY}.nativeCreate (no library of arm64-v8a exports it)`
)
expectNames(
  'a library that one ABI lacks completely is a failure',
  'abis-lost-library.apk',
  [
    application(),
    library(),
    library(elf(), 'lib/arm64-v8a/libother.so'),
    library(mediaLibrary(), 'lib/x86_64/libmedia.so')
  ],
  'library libother.so (in arm64-v8a, not in x86_64)'
)
expectNames(
  'a library missing from the ABI that would have carried the exports is a failure, and so is the one only that ABI has',
  'abis-different-libraries.apk',
  [application(), library(), library(elf(), 'lib/x86_64/libother.so')],
  'library libmedia.so (in arm64-v8a, not in x86_64); library libother.so (in x86_64, not in arm64-v8a)'
)
expectNames(
  'a bundle is held to the same libraries in each ABI',
  'abis-lost-library.aab',
  [
    { name: 'base/dex/classes.dex', bytes: mediaDex() },
    library(mediaLibrary(), 'base/lib/arm64-v8a/libmedia.so'),
    library(elf(), 'base/lib/x86_64/libother.so')
  ],
  'library libmedia.so (in arm64-v8a, not in x86_64); library libother.so (in x86_64, not in arm64-v8a)'
)
expectNames(
  'the same libraries in every ABI, each exporting the same natives, are whole',
  'abis-whole.apk',
  [
    application(),
    library(),
    library(mediaLibrary(), 'lib/x86_64/libmedia.so'),
    library(elf(), 'lib/arm64-v8a/libother.so'),
    library(elf(), 'lib/x86_64/libother.so')
  ],
  'nothing'
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
function verified(name, members, outputsDirectory = undefined) {
  const path = join(work, name)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, zip(members))
  const output = []
  const { log, error } = console
  console.log = (text) => output.push(text)
  console.error = (text) => output.push(text)
  let whole
  try {
    whole = verify([path], outputsDirectory)
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
const lostLibrary = verified('verify-lost-library.apk', [
  ...withLibrary([JNI_ZERO, FACTORY, CANDIDATE, NESTED, RAW]),
  library(elf(), 'lib/arm64-v8a/libother.so'),
  library(mediaLibrary(), 'lib/x86_64/libmedia.so')
])
held('the check fails a package one of whose ABIs lacks a library', 'false', String(lostLibrary.whole))
held(
  'and says which library and which ABI lacks it',
  'true',
  String(lostLibrary.said.includes('library libother.so (in arm64-v8a, not in x86_64)'))
)

// -- a member the archive cannot give in full -----------------------------------------------------
// A member whose bytes the archive does not hold, or whose size is not the one its directory gives,
// is not the member it names: reading what is there and going on would check a part of it.

const FULL = mediaLibrary().length
const PAST = 10_000_000
expectNames(
  'a stored library that the archive ends inside is refused, not read as the bytes that are there',
  'members-cut-library.apk',
  [
    application(),
    { ...library(), claimCompressed: FULL + PAST, claimUncompressed: FULL + PAST }
  ],
  `refused: ${MEDIA}: the archive ends inside this member`
)
expect(
  'a stored dex that the archive ends inside is refused',
  'members-cut-dex.apk',
  zip([
    filler,
    { name: 'classes.dex', bytes: code, claimCompressed: code.length + PAST, claimUncompressed: code.length + PAST }
  ]),
  'refused: classes.dex: the archive ends inside this member'
)
expectNames(
  'a stored member whose directory gives another size than the bytes it holds is refused',
  'members-misdeclared-stored.apk',
  [application(), { ...library(), claimUncompressed: FULL + 1 }],
  `refused: ${MEDIA}: the member is ${FULL} bytes, and its directory gives ${FULL + 1}`
)
expectNames(
  'a compressed member that inflates to another size than its directory gives is refused',
  'members-misdeclared-deflated.apk',
  [application(), { ...library(), deflate: true, claimUncompressed: FULL + 1 }],
  `refused: ${MEDIA}: the member is ${FULL} bytes, and its directory gives ${FULL + 1}`
)
{
  // The stream that ends too soon is refused by the decompressor, whose message says nothing of the
  // member: the refusal has to name it.
  const path = join(work, 'members-cut-stream.apk')
  writeFileSync(path, zip([filler, application(), { ...library(), deflate: true, cutBy: 8 }]))
  held(
    'a compressed member whose stream ends too soon is refused with the member named',
    'true',
    String(readAs(nativeNames, path).startsWith(`${MEDIA}: `))
  )
}
expectNames(
  'a compressed member whose directory is right is read',
  'members-deflated.apk',
  [{ ...application(), deflate: true }, { ...library(), deflate: true }],
  'nothing'
)

// -- a dex file that cannot be read in full ------------------------------------------------------
// An offset, an index or a count that runs off the end of the file reads as zeros, and a class
// whose data reads as zeros declares no natives: the reader has to refuse the file by name.

/** What reading `bytes` with `read` answered: `read`, or the message it refused with. */
function readAs(read, bytes) {
  try {
    read(bytes)
    return 'read'
  } catch (failure) {
    return failure.message
  }
}

/**
 * A dex file with one class that declares one native method (with these argument types), and the
 * place of its class data.
 */
function classWithData(params = []) {
  const bytes = Buffer.from(
    dex({
      defined: [FACTORY],
      methods: { [FACTORY]: [{ name: 'nativeCreate', native: true, params }] }
    })
  )
  const classDef = bytes.readUInt32LE(0x64)
  return { bytes, classDef, data: bytes.readUInt32LE(classDef + 24) }
}
{
  const refuses = (what, read, mutate, why, { params = [] } = {}) => {
    const { bytes, classDef, data } = classWithData(params)
    mutate(bytes, classDef, data)
    held(what, why, readAs(read, bytes))
  }
  refuses(
    'a class whose data lies past the end of the file is refused, not read as a class with no natives',
    definedNatives,
    (bytes, classDef) => bytes.writeUInt32LE(bytes.length + 10, classDef + 24),
    'a dex file with class data past its end'
  )
  refuses(
    'a number of more than five bytes is refused',
    definedNatives,
    (bytes, classDef, data) => bytes.set([0x80, 0x80, 0x80, 0x80, 0x80, 0x01], data),
    'a dex file with a number larger than 32 bits'
  )
  refuses(
    'a number whose fifth byte holds more than the last four bits of a 32-bit value is refused',
    definedNatives,
    (bytes, classDef, data) => bytes.set([0x80, 0x80, 0x80, 0x80, 0x10], data),
    'a dex file with a number larger than 32 bits'
  )
  refuses(
    'a number that the end of the file cuts is refused',
    definedNatives,
    (bytes, classDef) => {
      bytes[bytes.length - 1] = 0x80
      bytes.writeUInt32LE(bytes.length - 1, classDef + 24)
    },
    'a dex file cut short inside a number'
  )
  refuses(
    'a class that counts more fields than the file has room for is refused',
    definedNatives,
    (bytes, classDef, data) => bytes.set([0xff, 0x7f], data),
    'a dex file whose class data counts more than it holds'
  )
  refuses(
    'a class that counts more methods than the file has room for is refused',
    definedNatives,
    (bytes, classDef, data) => bytes.set([0xff, 0x7f], data + 3),
    'a dex file whose class data counts more than it holds'
  )
  refuses(
    'a string table that is not within the file is refused',
    definedNatives,
    (bytes) => bytes.writeUInt32LE(bytes.length + 8, 0x3c),
    'a dex file whose string table is not within it'
  )
  refuses(
    'a class table that counts more classes than the file holds is refused',
    definedNatives,
    (bytes) => bytes.writeUInt32LE(100000, 0x60),
    'a dex file whose class table is not within it'
  )
  refuses(
    'a class whose type is past the type table is refused',
    definedClasses,
    (bytes, classDef) => bytes.writeUInt32LE(5000, classDef),
    'a dex file with an index past its table'
  )
  refuses(
    'a prototype whose type list lies past the end of the file is refused',
    definedNatives,
    (bytes) => bytes.writeUInt32LE(bytes.length + 20, bytes.readUInt32LE(0x4c) + 8),
    'a dex file with an offset past its end'
  )
  refuses(
    'a prototype whose type list counts more types than the file holds is refused',
    definedNatives,
    (bytes) => bytes.writeUInt32LE(0x7fffffff, bytes.readUInt32LE(bytes.readUInt32LE(0x4c) + 8)),
    'a dex file with a type list past its end',
    { params: ['I', 'I'] }
  )
  const plain = Buffer.from(dex({ defined: [FACTORY] }))
  const stringAtIndex = (bytes, index) => bytes.readUInt32LE(bytes.readUInt32LE(0x3c) + index * 4)
  const endless = Buffer.from(plain)
  endless[endless.length - 1] = 0x41
  held(
    'a string with no NUL before the end of the file is refused, not read to the last byte but one',
    'a dex file with a string that has no end',
    readAs(definedStrings, endless)
  )
  const misdeclared = Buffer.from(plain)
  misdeclared[stringAtIndex(misdeclared, 0)] = 0x7f
  held(
    'a string whose length differs from the one it declares is refused',
    'a dex file with a string whose length is not the one it declares',
    readAs(definedStrings, misdeclared)
  )
  const marked = Buffer.from(dex({ constants: ['\u0001\u0001\u0001\u0001'] }))
  const markedAt = marked.indexOf(Buffer.from([4, 1, 1, 1, 1, 0])) + 1
  held('the marked string is found', 'true', String(markedAt > 0))
  for (const [what, bytes] of [
    ['a four-byte UTF-8 character, which modified UTF-8 does not have,', [0xf0, 0x9f, 0x98, 0x80]],
    ['a three-byte group that a byte cuts short', [0xe2, 0x82, 0x01, 0x01]],
    ['a lead byte with no byte after it that continues it', [0xc3, 0x01, 0x01, 0x01]]
  ]) {
    const damaged = Buffer.from(marked)
    damaged.set(bytes, markedAt)
    held(`${what} is refused`, 'a dex file with a string that is not modified UTF-8', readAs(definedStrings, damaged))
  }
  const written = definedStrings(
    dex({ constants: ['a\u0000b', 'café', '€', '\u{1f600}'] })
  )
  held(
    'strings in modified UTF-8 are read as they are written: the NUL as two bytes, a character outside the basic plane as two units',
    'true',
    String(['a\u0000b', 'café', '€', '\u{1f600}'].every((text) => written.includes(text)))
  )
}
expectNames(
  'a native method whose name has a character outside the basic plane is bound by the symbol of its two units',
  'natives-astral-method.apk',
  [
    application(mediaDex([], { [FACTORY]: [{ name: 'm\u{1f600}', native: true }] })),
    library(elf({ exports: ['Java_org_webrtc_PeerConnectionFactory_m_0d83d_0de00'] }))
  ],
  'nothing'
)

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
// The command line tool and Gradle each run in a directory of their own, so a directory given to
// them by a relative path would be a different one for each.
{
  const here = process.cwd()
  // The names a platform reads its temporary directory from: Unix reads the first, Windows the others.
  const names = ['TMPDIR', 'TEMP', 'TMP']
  const was = names.map((name) => process.env[name])
  process.chdir(work)
  mkdirSync('relative-tmp')
  for (const name of names) process.env[name] = 'relative-tmp'
  let fromRelative
  try {
    fromRelative = privateTemporary()
  } finally {
    names.forEach((name, index) => {
      if (was[index] === undefined) delete process.env[name]
      else process.env[name] = was[index]
    })
  }
  const where = resolve('relative-tmp')
  process.chdir(here)
  held(
    'a relative temporary directory of the environment is made absolute before it is given to a build',
    'true',
    String(
      isAbsolute(fromRelative.directory) &&
        dirname(fromRelative.directory) === where &&
        fromRelative.env.TMPDIR === fromRelative.directory &&
        existsSync(fromRelative.directory)
    )
  )
  fromRelative.remove()
}

// What the success line counts: the different classes the libraries name (once, however many ABIs
// carry the library), the native methods a symbol was asked for, and the classes not asked.
const counted = verified('verify-counts.apk', [
  filler,
  {
    name: 'classes.dex',
    bytes: dex({
      defined: [...PRESENT, JNI_ZERO, FACTORY, CANDIDATE, NESTED, RAW, 'org.webrtc.Other'],
      methods: {
        [FACTORY]: [
          { name: 'nativeCreate', native: true },
          { name: 'nativeSecond', native: true }
        ],
        'org.webrtc.Other': [{ name: 'nativeOther', native: true }]
      }
    })
  },
  library(
    mediaLibrary({
      exports: [
        'Java_org_webrtc_PeerConnectionFactory_nativeCreate',
        'Java_org_webrtc_PeerConnectionFactory_nativeSecond'
      ]
    })
  ),
  library(
    mediaLibrary({
      exports: [
        'Java_org_webrtc_PeerConnectionFactory_nativeCreate',
        'Java_org_webrtc_PeerConnectionFactory_nativeSecond'
      ]
    }),
    'lib/x86_64/libmedia.so'
  )
])
held(
  'the success line counts each class once across ABIs, the natives asked, and names the classes not asked',
  'true',
  String(
    counted.whole &&
      counted.said.includes('its 2 native libraries name 4 classes, all defined in its dex') &&
      counted.said.includes('bind the 2 native methods it declares') &&
      counted.said.includes('org.webrtc.Other')
  )
)

// The wrapper for the iOS build runs the build, and not a build that opens Xcode.app, which the
// system starts with the person's own temporary directory and not the one made for the build.
{
  const refused = (argv) => iosRefusal(argv) !== null
  held(
    'the iOS build is run as it is given',
    'false',
    String(refused(['build', '--debug', '--ci', '--target', 'aarch64-sim']))
  )
  held(
    'an iOS build with a configuration given as JSON and archive options is run as it is given',
    'false',
    String(refused(['build', '--config', '{"build":{"frontendDist":"../dist"}}', '--archive-only', '--no-sign']))
  )
  // Short options are read as the command line tool reads them, left to right in a bundle: `d`, `v`
  // and `o` take no value, and the first `t`, `f` or `c` takes the rest of the bundle as its value.
  for (const argv of [
    ['build', '-t', 'aarch64-sim'],
    ['build', '-fopus'],
    ['build', '-dv', '--target', 'x86_64'],
    ['build', '--', '-o'],
    ['build', '--ci', '--', '--open']
  ]) {
    held(`\`pnpm ios ${argv.join(' ')}\` is run as it is given`, 'false', String(refused(argv)))
  }
  for (const argv of [[], ['dev'], ['open'], ['run', '--debug']]) {
    held(`\`pnpm ios ${argv.join(' ')}\` is refused, since only the build is run`, 'true', String(refused(argv)))
  }
  for (const argv of [
    ['build', '--open'],
    ['build', '--ope'],
    ['build', '--o'],
    ['build', '-o'],
    ['build', '-do'],
    ['build', '-otaarch64-sim'],
    ['build', '-dotaarch64'],
    ['build', '-otx86_64'],
    ['build', '-ot=aarch64-sim'],
    ['build', '--ci', '-o']
  ]) {
    held(`\`pnpm ios ${argv.join(' ')}\` is refused, since it would open Xcode.app`, 'true', String(refused(argv)))
  }
  // Started by a path that holds a symbolic link, the wrapper still runs, and so still refuses: the
  // command line tool is never started by this case.
  const link = join(work, 'scripts-link')
  symlinkSync(import.meta.dirname, link)
  const started = spawnSync(process.execPath, [join(link, 'ios.mjs'), 'dev'], { encoding: 'utf8' })
  held(
    'the wrapper started through a symbolic link still runs, and refuses a command that is not the build',
    '2 true',
    `${started.status} ${started.stderr.includes('pnpm ios runs')}`
  )
}

// -- the rule files the Rust build writes --------------------------------------------------------
// The minifier takes its rule files when Gradle configures, and two of them are written by the Rust
// build, which keep what the Rust library calls by name that no Java reaches. A minified build whose
// merged rules do not name them left those classes to the minifier, whatever the check of the
// libraries found: the library's own calls by name cannot be read from it.

const RULES = 'outputs-rules'
// What a debug build is held to depends on the environment `KR_MINIFY_DEBUG` was run in, so these
// cases set it themselves and put back what they found.
const minifyWas = process.env.KR_MINIFY_DEBUG
delete process.env.KR_MINIFY_DEBUG
const section = (file) =>
  `# The proguard configuration file for the following section is /build/${file}\n-keep class x.Y\n\n`
const BOTH =
  section('app/proguard-rules.pro') +
  section('app/proguard-tauri.pro') +
  section('app/src/main/java/to/kala/reach/generated/proguard-wry.pro')
const passingPackage = withLibrary([JNI_ZERO, FACTORY, CANDIDATE, NESTED, RAW])

/** Verifies a package placed in an outputs directory, with the merged rules its variant left. */
function withRules(place, variant, configuration, members = passingPackage) {
  const mapping = join(work, RULES, 'mapping', variant)
  mkdirSync(mapping, { recursive: true })
  const file = join(mapping, 'configuration.txt')
  rmSync(file, { force: true })
  if (configuration !== null) writeFileSync(file, configuration)
  return verified(`${RULES}/${place}`, members, join(work, RULES))
}
const release = 'apk/universal/release/app-universal-release.apk'

const named = withRules(release, 'universalRelease', BOTH)
held('a minified release build whose merged rules name both generated files passes', 'true', String(named.whole))
const noWry = withRules(
  release,
  'universalRelease',
  section('app/proguard-rules.pro') + section('app/proguard-tauri.pro')
)
held('a release build whose merged rules lack the web view library\'s file fails', 'false', String(noWry.whole))
held(
  'and names that file, and not the other',
  'true',
  String(noWry.said.includes('proguard-wry.pro') && !noWry.said.includes('proguard-tauri.pro'))
)
const noGenerated = withRules(release, 'universalRelease', section('app/proguard-rules.pro'))
held(
  'a release build whose merged rules name neither fails, naming both',
  'true',
  String(
    !noGenerated.whole &&
      noGenerated.said.includes('proguard-tauri.pro') &&
      noGenerated.said.includes('proguard-wry.pro')
  )
)
const mentioned = withRules(
  release,
  'universalRelease',
  section('app/proguard-rules.pro') +
    '# written by the Rust build to /app/proguard-tauri.pro and /app/generated/proguard-wry.pro\n'
)
held('a mention of the files that is no section of the merged rules does not count', 'false', String(mentioned.whole))
const noConfiguration = withRules(release, 'universalRelease', null)
held('a release build that left no merged rules fails, since the release build is always minified', 'false', String(noConfiguration.whole))
held(
  'and says there is no merged configuration to read',
  'true',
  String(noConfiguration.said.includes('universalRelease') && noConfiguration.said.includes('configuration.txt'))
)
const debugPlain = withRules('apk/universal/debug/app-universal-debug.apk', 'universalDebug', null)
held('a debug build that is not minified needs no merged rules', 'true', String(debugPlain.whole))
process.env.KR_MINIFY_DEBUG = '1'
try {
  const debugMinified = withRules(
    'apk/universal/debug/app-universal-debug.apk',
    'universalDebug',
    section('app/proguard-rules.pro')
  )
  held('a debug build that was asked to be minified is held to the same rules', 'false', String(debugMinified.whole))
} finally {
  delete process.env.KR_MINIFY_DEBUG
}
if (minifyWas !== undefined) process.env.KR_MINIFY_DEBUG = minifyWas
const bundle = withRules(
  'bundle/universalRelease/app-universal-release.aab',
  'universalRelease',
  section('app/proguard-rules.pro'),
  [
    filler,
    { name: 'base/dex/classes.dex', bytes: passingPackage[1].bytes },
    library(mediaLibrary(), 'base/lib/arm64-v8a/libmedia.so')
  ]
)
held('a bundle is held to the rules of its variant', 'false', String(bundle.whole))

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
