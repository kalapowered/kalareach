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
import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

import { toolPath } from './tools.mjs'

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

/** An archive a previous run left empty, which this build must not link against. */
function emptyArchives() {
  const target = process.env.CARGO_TARGET_DIR
  if (!target) return []
  const found = []
  for (const profile of ['debug', 'release']) {
    const builds = join(target, 'aarch64-linux-android', profile, 'build')
    if (!existsSync(builds)) continue
    for (const entry of readdirSync(builds)) {
      if (!entry.startsWith('libsodium-sys')) continue
      const archive = join(builds, entry, 'out', 'installed', 'lib', 'libsodium.a')
      // An archive with no members is a few dozen bytes of header and nothing else.
      if (existsSync(archive) && statSync(archive).size < 1024) found.push(archive)
    }
  }
  return found
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
  console.error(
    'A previous build left an empty libsodium archive, and the build script that made it will ' +
      'not notice the tools have changed. Remove it first:\n' +
      '  cargo clean -p libsodium-sys-stable --target aarch64-linux-android\n' +
      stale.map((path) => `  (${path})`).join('\n')
  )
  process.exit(2)
}

const result = spawnSync(
  process.execPath,
  [toolPath('@tauri-apps/cli'), 'android', 'build', ...process.argv.slice(2)],
  {
    stdio: 'inherit',
    env: {
      ...process.env,
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
process.exit(result.status ?? 0)
