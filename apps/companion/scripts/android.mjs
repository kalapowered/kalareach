#!/usr/bin/env node
// Builds the Android application with the toolchain's own archive tools.
//
// One dependency builds a C library from source and runs whatever `ar`, `ranlib` and `nm` it
// finds. On a developer's machine those are the host's, and the host's archiver produces an empty
// archive for this target: the application then installs and fails at start with an undefined
// symbol, and nothing in the build output says why. The tools are resolved here, before anything
// runs, so a build started from the command line cannot get it wrong.
//
// It also refuses to build against an archive a previous run left empty, because that build
// script does not notice that the tools have changed and would hand the same empty archive over
// again.
//
// After the build it reads the packaged application back and refuses one that is missing the
// hand-written native classes.
import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { packagesOf, requestFrom, verify } from './android-classes.mjs'
import { toolPath } from './tools.mjs'

/** Every Android target this build could be asked for. */
const ANDROID_TARGETS = {
  aarch64: 'aarch64-linux-android',
  armv7: 'armv7-linux-androideabi',
  i686: 'i686-linux-android',
  x86_64: 'x86_64-linux-android'
}

/** The toolchain's binaries, from whichever variable names the toolchain. */
function archiveTools() {
  const ndk =
    process.env.NDK_HOME ?? process.env.ANDROID_NDK_HOME ?? process.env.ANDROID_NDK_ROOT ?? null
  if (!ndk) return null
  const prebuilt = join(ndk, 'toolchains', 'llvm', 'prebuilt')
  if (!existsSync(prebuilt)) return null
  for (const host of readdirSync(prebuilt)) {
    const bin = join(prebuilt, host, 'bin')
    if (existsSync(join(bin, 'llvm-ar'))) return bin
  }
  return null
}

/**
 * Where Cargo is actually putting its output.
 *
 * The environment variable is one of three answers and the least likely: a configuration file or
 * the workspace's own directory decides it otherwise. Cargo will say which, so it is asked.
 */
function cargoTargetDirectory() {
  const manifest = join(dirname(import.meta.dirname), 'src-tauri', 'Cargo.toml')
  const answer = spawnSync(
    'cargo',
    ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', manifest],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
  )
  if (answer.status !== 0 || !answer.stdout) return process.env.CARGO_TARGET_DIR ?? null
  try {
    return JSON.parse(answer.stdout).target_directory ?? null
  } catch {
    return process.env.CARGO_TARGET_DIR ?? null
  }
}

/**
 * Archives a previous run left empty, which this build must not link against.
 *
 * Every Android target is checked, whatever this invocation asked for. Reading the arguments would
 * mean writing a second parser for the command line tool's own options -- long, short, joined,
 * repeated, bundled with other flags -- and a target that parser missed is a target whose archive
 * goes unexamined, which is the failure this whole file exists to prevent. Looking at all four
 * costs four directory reads.
 */
function emptyArchives() {
  const root = cargoTargetDirectory()
  if (!root) return []
  const found = []
  for (const triple of Object.values(ANDROID_TARGETS)) {
    for (const profile of ['debug', 'release']) {
      const builds = join(root, triple, profile, 'build')
      if (!existsSync(builds)) continue
      for (const entry of readdirSync(builds)) {
        if (!entry.startsWith('libsodium-sys')) continue
        const archive = join(builds, entry, 'out', 'installed', 'lib', 'libsodium.a')
        // An archive with no members is a few dozen bytes of header and nothing else.
        if (existsSync(archive) && statSync(archive).size < 1024) found.push({ triple, archive })
      }
    }
  }
  return found
}

// What this build will be asked for, read before anything is built: the packages it produces are
// checked afterwards by name, and arguments that leave that in doubt are worth refusing before a
// build rather than after one.
let request
try {
  request = requestFrom(process.argv.slice(2))
} catch (failure) {
  console.error(failure.message)
  process.exit(2)
}

const tools = archiveTools()
if (!tools) {
  console.error(
    'Point NDK_HOME at an Android toolchain before building: the C dependency in this graph ' +
      'needs that toolchain to make its archive, and the host tools produce an empty one.'
  )
  process.exit(2)
}

const stale = emptyArchives()
if (stale.length > 0) {
  const triples = [...new Set(stale.map((each) => each.triple))]
  console.error(
    'A previous build left an empty libsodium archive, and the build script that made it will ' +
      'not notice the tools have changed. Remove it first:\n' +
      triples
        .map((triple) => `  cargo clean -p libsodium-sys-stable --target ${triple}`)
        .join('\n') +
      '\n' +
      stale.map((each) => `  (${each.archive})`).join('\n')
  )
  process.exit(2)
}

// The project is named rather than searched for. The command line tool takes `TAURI_APP_PATH` as
// the project to build when the environment carries one, and the packages are read back from this
// application's own output directory, so an inherited value would let the build and the check look
// at two different trees. This command builds this application; naming it here is what makes the
// two the same tree.
const project = join(dirname(import.meta.dirname), 'src-tauri')

const result = spawnSync(
  process.execPath,
  [toolPath('@tauri-apps/cli'), 'android', 'build', ...process.argv.slice(2)],
  {
    stdio: 'inherit',
    env: {
      ...process.env,
      TAURI_APP_PATH: project,
      AR: join(tools, 'llvm-ar'),
      RANLIB: join(tools, 'llvm-ranlib'),
      NM: join(tools, 'llvm-nm'),
      STRIP: join(tools, 'llvm-strip')
    }
  }
)
if (result.error) {
  console.error(result.error.message)
  process.exit(1)
}
if (result.status !== 0) process.exit(result.status ?? 1)

// A successful Android build is not the same as a complete application. The hand-written native
// sources reach the module through a source-set entry, and a source directory that resolves
// nowhere is an empty one to Gradle: the build reports success and packages none of it. So what
// was packaged is read back before this command claims to have built anything -- every package
// this build asked for, named from the request rather than found by age, and a missing one is a
// failure.
//
// A run that only asked for usage built nothing and has nothing to read back.
if (!request) process.exit(0)
let packages
try {
  packages = packagesOf(request)
} catch (failure) {
  console.error(failure.message)
  process.exit(1)
}
process.exit(verify(packages) ? 0 : 1)
