#!/usr/bin/env node
// Holds the desktop bundle build's entry to what it must give and refuse.
//
// The entry runs the desktop bundle build with Tauri's static Visual C++ runtime (a hybrid whose program
// imports the universal runtime) turned off on Windows, where the command line tool turns it on and the
// package's build script refuses that build. None of
// these cases runs a build: the decision about a command's arguments and the environment a build is
// given are functions that take the platform and the environment in, so each platform's answer is held
// here on whichever machine this runs on. The last cases start the command itself, with arguments it
// refuses before anything is run.
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { archiveDirectory, buildPlan, childArguments, childEnvironment, placeArchive, refusal } from './desktop.mjs'

const REPOSITORY = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
// What the build is given for the project it builds, the directory its interface is built in and its mode.
const COMPANION = join(REPOSITORY, 'apps', 'companion')
const OWN = { TAURI_APP_PATH: join(COMPANION, 'src-tauri'), TAURI_FRONTEND_PATH: COMPANION, NODE_ENV: 'production' }
const UNSET = { TAURI_APP_PATH: undefined, TAURI_FRONTEND_PATH: undefined, NODE_ENV: undefined }

let failures = 0

/** Records a case whose answer is not the expected one. */
function held(what, expected, answer) {
  if (answer === expected) return
  failures += 1
  console.error(`${what}\n  expected: ${expected}\n  answered: ${answer}`)
}

const refused = (argv, platform = 'darwin', env = {}) => String(refusal(argv, platform, env) !== null)

// What is run as it is given, on every platform.
for (const platform of ['darwin', 'linux', 'win32']) {
  for (const argv of [
    ['build'],
    ['build', '--no-sign', '--bundles', 'app'],
    ['build', '-b', 'app,dmg', '--ci'],
    ['build', '--debug', '--features', 'a', 'b', '--bundles', 'nsis'],
    ['build', '--ignore-version-mismatches'],
    ['build', '--target', 'aarch64-apple-darwin'],
    ['build', '-t', 'universal-apple-darwin', '--no-sign'],
    // What follows a bare `--` is passed on to cargo when it changes no output (see the words after it below).
    ['build', '--', '--locked'],
    ['build', '--ci', '--', '--locked', '--offline']
  ]) {
    held(`\`pnpm desktop ${argv.join(' ')}\` is run as it is given on ${platform}`, 'false', refused(argv, platform))
  }
}

// Only the build is run.
for (const argv of [[], ['dev'], ['info'], ['bundle'], ['--no-sign'], ['android', 'build']]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` is refused, since only the build is run`, 'true', refused(argv))
}

// A runner other than cargo is a program that the setting this gives the build may not reach.
// Short options are read left to right in a bundle: `d` takes no value, and the first of `r`, `t`,
// `f`, `b` and `c` takes the rest of the bundle as its value.
for (const argv of [
  ['build', '--runner', 'cargo-xwin'],
  ['build', '--runner=cross'],
  ['build', '-r', 'cargo-xwin'],
  ['build', '-rcross'],
  ['build', '-dr', 'cross'],
  ['build', '--no-sign', '-r=cross'],
  ['build', '--r', 'cross'],
  ['build', '--features', '--runner', 'cross'],
  ['build', '--bundles', '--runner', 'cross']
]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` is refused, since it names a runner`, 'true', refused(argv))
}
// A value that merely spells a runner's flag is not one.
for (const argv of [
  ['build', '-fr'],
  ['build', '-t', 'x86_64-unknown-linux-gnu']
]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` names no runner`, 'false', refused(argv))
}

// A build with no bundle makes nothing to read.
for (const argv of [
  ['build', '--no-bundle'],
  ['build', '--no-b'],
  ['build', '--ci', '--no-bundle', '--debug'],
  ['build', '--features', 'a', '--no-bundle']
]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` is refused, since it makes no bundle`, 'true', refused(argv))
}

// A build with no bundle selected makes nothing to read, whatever the form of the option.
for (const argv of [
  ['build', '--bundles'],
  ['build', '-b'],
  ['build', '--bundles', '--ci'],
  ['build', '-b', '--no-sign'],
  ['build', '--bundles='],
  ['build', '--bundles', '--', 'app']
]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` is refused, since it selects no bundle`, 'true', refused(argv))
}
for (const argv of [['build', '--bundles', 'app'], ['build', '-bapp'], ['build', '-b', 'app,dmg'], ['build', '--bundles=nsis', '--ci']]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` selects a bundle`, 'false', refused(argv))
}

// The setting is made for the machine this runs on, so a Windows target is built on Windows only.
const WINDOWS_TARGETS = [
  ['build', '--target', 'x86_64-pc-windows-msvc'],
  ['build', '--target=aarch64-pc-windows-msvc'],
  ['build', '-t', 'x86_64-pc-windows-gnu'],
  ['build', '-tx86_64-pc-windows-msvc'],
  ['build', '-t=i686-pc-windows-msvc'],
  ['build', '-dt', 'x86_64-pc-windows-msvc'],
  ['build', '--tar', 'x86_64-pc-windows-msvc'],
  ['build', '--bundles', 'nsis', '--target', 'aarch64-pc-windows-gnullvm']
]
for (const platform of ['darwin', 'linux']) {
  for (const argv of WINDOWS_TARGETS) {
    held(`\`pnpm desktop ${argv.join(' ')}\` is refused on ${platform}`, 'true', refused(argv, platform))
  }
}
// On Windows the MSVC targets are the two that `.cargo/config.toml` gives the `crt-static` target feature,
// and any other is refused: its link would not carry the static C runtime.
for (const argv of [
  ['build', '--target', 'x86_64-pc-windows-msvc'],
  ['build', '--target=aarch64-pc-windows-msvc'],
  ['build', '-t', 'x86_64-pc-windows-gnu'],
  ['build', '-tx86_64-pc-windows-msvc'],
  ['build', '--bundles', 'nsis', '--target', 'aarch64-pc-windows-gnullvm']
]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` is run on Windows`, 'false', refused(argv, 'win32'))
}
for (const argv of [
  ['build', '-t=i686-pc-windows-msvc'],
  ['build', '--target', 'i686-pc-windows-msvc'],
  ['build', '--tar', 'x86_64-uwp-windows-msvc'],
  ['build', '-dt', 'thumbv7a-pc-windows-msvc']
]) {
  held(`\`pnpm desktop ${argv.join(' ')}\` is refused on Windows, since .cargo/config.toml gives it no crt-static`, 'true', refused(argv, 'win32'))
}
// The command line tool does not read `CARGO_BUILD_TARGET`, and cargo builds for it into the directory of
// that target, so the bundle would be made from the program of another build: it is refused on every
// platform, with any value, an empty one included, and in any spelling of the name on Windows.
for (const [platform, name, value] of [
  ['win32', 'CARGO_BUILD_TARGET', 'i686-pc-windows-msvc'],
  ['win32', 'cargo_build_target', 'x86_64-pc-windows-msvc'],
  ['win32', 'CARGO_BUILD_TARGET', 'aarch64-pc-windows-msvc'],
  ['win32', 'Cargo_Build_Target', ''],
  ['darwin', 'CARGO_BUILD_TARGET', 'x86_64-pc-windows-msvc'],
  ['darwin', 'CARGO_BUILD_TARGET', 'aarch64-apple-darwin'],
  ['linux', 'CARGO_BUILD_TARGET', 'x86_64-unknown-linux-gnu'],
  ['linux', 'CARGO_BUILD_TARGET', '']
]) {
  const answer = refusal(['build'], platform, { PATH: 'x', [name]: value })
  held(`${name}=${JSON.stringify(value)} on ${platform} is refused`, 'true', String(answer !== null))
  held(`the refusal for ${name} on ${platform} names the variable`, 'true', String(answer?.includes('CARGO_BUILD_TARGET') ?? false))
}
// Names that only look like it are no matter, and neither is the variable's absence.
held('a variable that contains it is no matter', 'false', refused(['build'], 'linux', { CARGO_BUILD_TARGET_DIR: 'x', MY_CARGO_BUILD_TARGET: 'y' }))
held('on macOS the name is read as it is spelled', 'false', refused(['build'], 'darwin', { cargo_build_target: 'x' }))

// What follows a bare `--` goes to cargo, which reads there what the checks above do not: `--config` can set the
// environment and the flags of the build (the variable that the entry gives, `env.STATIC_VCRUNTIME` forced to
// `true`, among them), `--target`, `--manifest-path`, `--lib`, `-p` and `--workspace` choose what is built (or
// nothing, with exit 0, so that the bundle holds an earlier program), and `--release` and `--profile` choose the
// build that is held. So only the words that change no output are taken, and every other word is refused on every
// platform, with a message that names the word and says which words are taken.
for (const platform of ['darwin', 'linux', 'win32']) {
  for (const argv of [
    ['build', '--', '--config', 'env.STATIC_VCRUNTIME.value="true"'],
    ['build', '--', '--config=env.STATIC_VCRUNTIME.force=true'],
    ['build', '--ci', '--', '--locked', '--config', 'build.rustflags=[]'],
    ['build', '--', '--target', 'x86_64-pc-windows-msvc'],
    ['build', '--', '--target=aarch64-apple-darwin'],
    ['build', '--features', 'a', '--', '--target', 'x'],
    ['build', '--', '--profile', 'dev'],
    ['build', '--', '--profile=release-lto'],
    ['build', '--', '--release'],
    ['build', '--ci', '--', '-r'],
    ['build', '--', '-rv'],
    ['build', '--', '-vr'],
    ['build', '--', '-qr'],
    ['build', '--', '-vvr'],
    ['build', '--debug', '--', '-vr'],
    ['build', '--', '--', '-rv'],
    ['build', '--', '--', '--locked'],
    ['build', '--', '--target-dir', 'C:/cached-target'],
    ['build', '--', '--target-dir=target-other'],
    ['build', '--', '--manifest-path', 'other/Cargo.toml'],
    ['build', '--', '--profile-x=dev'],
    ['build', '--', '--profile-x'],
    ['build', '--', '--releases'],
    ['build', '--', '--configuration'],
    ['build', '--', '--config-x=env.A=b'],
    ['build', '--', '--targets'],
    ['build', '--', '--target-dirs=other'],
    ['build', '--', '--manifest-pathx', 'other/Cargo.toml'],
    ['build', '--', '-m', 'other/Cargo.toml'],
    ['build', '--', '-mCargo.toml'],
    ['build', '--', '-mother/Cargo.toml'],
    ['build', '--', '-vm'],
    ['build', '--', '-vm', 'other/Cargo.toml'],
    // The words that make cargo build something else, or nothing, and exit 0.
    ['build', '--', '--lib'],
    ['build', '--', '-p', 'companion-tauri'],
    ['build', '--', '-pcompanion-tauri'],
    ['build', '--', '--package', 'companion-tauri'],
    ['build', '--', '--workspace', '--exclude', 'companion-tauri'],
    ['build', '--', '--bins'],
    ['build', '--', '--bin', 'x'],
    ['build', '--', '--all-targets'],
    ['build', '--', '-h'],
    ['build', '--', '--help'],
    ['build', '--', '--runner', 'x'],
    ['build', '--ci', '--', '--no-bundle', '--locked', '--offline'],
    // A value letter takes the rest of the word, so a package, a feature or a job count named `r` is still a word
    // that is not taken.
    ['build', '--', '-pr'],
    ['build', '--', '-pm'],
    ['build', '--', '-prelease'],
    ['build', '--', '-p', 'mr'],
    ['build', '--', '-vpr'],
    ['build', '--', '-Fr'],
    ['build', '--', '-jr'],
    ['build', '--', '-Zunstable-options'],
    // A value that follows an option is read with it: a word that is no value is refused with the option.
    ['build', '--', '--color', '--release'],
    ['build', '--', '--color'],
    ['build', '--', '--color', 'sometimes'],
    ['build', '--', '--message-format', '--release'],
    ['build', '--', '--message-format=xml'],
    ['build', '--', '-j'],
    ['build', '--', '-j', 'many'],
    ['build', '--', '-j', '--release'],
    ['build', '--', '--jobs=x'],
    ['build', '--', '--jobs', '4x'],
    ['build', '--', '--timings=json'],
    ['build', '--', '-vq'],
    ['build', '--', '-v=1'],
    ['build', '--', '--locked=true'],
    ['build', '--', '--LOCKED'],
    ['build', '--', 'x'],
    ['build', '--', '--locked', 'x'],
    // The name of an inherited property of an object is a word like any other.
    ['build', '--', 'constructor'],
    ['build', '--', 'constructor', 'x'],
    ['build', '--', '__proto__', '--locked'],
    ['build', '--', 'toString', '4']
  ]) {
    held(`\`pnpm desktop ${argv.join(' ')}\` is refused on ${platform}, since cargo would be given a word that is not taken`, 'true', refused(argv, platform))
  }
  // The words that change no output, with the forms of their values that cargo 1.97.1 takes.
  for (const argv of [
    ['build', '--', '--locked'],
    ['build', '--', '--offline', '--frozen'],
    ['build', '--', '--keep-going', '--timings'],
    ['build', '--', '-v'],
    ['build', '--', '-vv'],
    ['build', '--', '-q'],
    ['build', '--', '-v', '--locked'],
    ['build', '--', '-j', '4'],
    ['build', '--', '-j4'],
    ['build', '--', '-j=4'],
    ['build', '--', '--jobs', '4'],
    ['build', '--', '--jobs=4'],
    ['build', '--', '-j', 'default'],
    ['build', '--', '-j', '-1'],
    ['build', '--', '--jobs=default'],
    ['build', '--', '--color', 'always'],
    ['build', '--', '--color=never'],
    ['build', '--', '--message-format', 'json'],
    ['build', '--', '--message-format=short'],
    ['build', '--ci', '--', '--locked', '--color', 'auto', '-j', '2', '--message-format=json-render-diagnostics']
  ]) {
    held(`\`pnpm desktop ${argv.join(' ')}\` is run as it is given on ${platform}`, 'false', refused(argv, platform))
  }
  // The message names the word that is not taken and says that only the words that change no output are.
  for (const [argv, named] of [
    [['build', '--', '--lib'], '`--lib`'],
    [['build', '--', '--locked', '-p', 'companion-tauri'], '`-p`'],
    [['build', '--', '--color', '--release'], '`--color --release`'],
    [['build', '--', '--color'], '`--color`']
  ]) {
    const answer = refusal(argv, platform, {})
    held(`the refusal of \`pnpm desktop ${argv.join(' ')}\` names ${named}`, 'true', String(answer?.includes(`does not pass ${named} on`) ?? false))
    held(`and says that only the words that change no output are taken on ${platform}`, 'true', String(answer?.includes('takes only') && answer?.includes('--locked') && answer?.includes('--message-format') ? true : false))
  }
}

// Tauri's own configuration, given as `--config` (or `-c`) or in `TAURI_CONFIG`, is merged over the
// repository's, and can switch the bundle off (`bundle.active`), name another command to run before the
// build, or change what the bundle holds. This build takes the repository's configuration alone: the
// refusal is on every platform, in every form of the option, and for the variable in any spelling on Windows.
for (const platform of ['darwin', 'linux', 'win32']) {
  for (const argv of [
    ['build', '--config', '{"bundle":{"active":false}}'],
    ['build', '--config={"bundle":{"active":false}}'],
    ['build', '-c', 'tauri.other.json'],
    ['build', '-ctauri.other.json'],
    ['build', '-c=tauri.other.json'],
    ['build', '-dc', 'tauri.other.json'],
    ['build', '--conf', 'x.json'],
    ['build', '--ci', '--config', 'x.json', '--bundles', 'nsis']
  ]) {
    held(`\`pnpm desktop ${argv.join(' ')}\` is refused on ${platform}, since it merges a configuration over the repository's`, 'true', refused(argv, platform))
  }
  held(`TAURI_CONFIG is refused on ${platform}`, 'true', refused(['build'], platform, { TAURI_CONFIG: '{"bundle":{"active":false}}' }))
  held(`the refusal for TAURI_CONFIG on ${platform} names it`, 'true', String(refusal(['build'], platform, { TAURI_CONFIG: '{}' })?.includes('TAURI_CONFIG') ?? false))
}
held('Windows reads TAURI_CONFIG without regard to case', 'true', refused(['build'], 'win32', { tauri_config: '{}' }))
held('macOS reads TAURI_CONFIG as it is spelled', 'false', refused(['build'], 'darwin', { tauri_config: '{}', TAURI_CONFIG_DEPTH: '2', MY_TAURI_CONFIG: '{}' }))

// The linker reads `LINK` before the options it is given and `_LINK_` after them, and either can name
// runtime libraries to add or leave out. Only Windows has the linker. Names that contain them are no matter.
for (const name of ['LINK', 'link', '_LINK_', '_link_', 'Link']) {
  for (const value of ['/DEFAULTLIB:msvcrt', '']) {
    const answer = refusal(['build'], 'win32', { PATH: 'x', [name]: value })
    held(`${name}=${JSON.stringify(value)} is refused on Windows`, 'true', String(answer !== null))
    held(`the refusal for ${name} names the variable`, 'true', String(answer?.includes(name.toUpperCase()) ?? false))
  }
  held(`${name} is no matter on macOS`, 'false', refused(['build'], 'darwin', { [name]: '/DEFAULTLIB:msvcrt' }))
  held(`${name} is no matter on Linux`, 'false', refused(['build'], 'linux', { [name]: '/DEFAULTLIB:msvcrt' }))
}
held('names that only contain LINK are no matter on Windows', 'false', refused(['build'], 'win32', { LINKER: 'x', CARGO_LINK: 'x', MY_LINK_: 'x', LINK_X: 'x' }))

// The C compiler reads `CL` before the options it is given and `_CL_` after them, and either can change the
// runtime that the C objects of the build ask for. Only Windows has that compiler.
for (const name of ['CL', 'cl', '_CL_', '_cl_']) {
  for (const value of ['/MD', '']) {
    const answer = refusal(['build'], 'win32', { PATH: 'x', [name]: value })
    held(`${name}=${JSON.stringify(value)} is refused on Windows`, 'true', String(answer !== null))
    held(`the refusal for ${name} names the variable`, 'true', String(answer?.includes(name.toUpperCase()) ?? false))
  }
  held(`${name} is no matter on macOS`, 'false', refused(['build'], 'darwin', { [name]: '/MD' }))
}
held('names that only contain CL are no matter on Windows', 'false', refused(['build'], 'win32', { CLANG: 'x', CL_X: 'x', MYCL: 'x', CARGO_CL_: 'x' }))

// The `cc` crate, which compiles the C of the dependencies, adds the flags of `CFLAGS` and `CXXFLAGS` last,
// after its own runtime option, with the host, target and per-target spellings of the name, so a flag there
// can change the runtime that an object asks for. They are refused on Windows for the two MSVC targets.
for (const name of [
  'CFLAGS',
  'cflags',
  'CXXFLAGS',
  'HOST_CFLAGS',
  'TARGET_CFLAGS',
  'host_cxxflags',
  'TARGET_CXXFLAGS',
  'CFLAGS_x86_64_pc_windows_msvc',
  'CFLAGS_x86_64-pc-windows-msvc',
  'CXXFLAGS_aarch64_pc_windows_msvc',
  'cxxflags_aarch64-pc-windows-msvc'
]) {
  for (const value of ['-MD', '']) {
    const answer = refusal(['build'], 'win32', { PATH: 'x', [name]: value })
    held(`${name}=${JSON.stringify(value)} is refused on Windows`, 'true', String(answer !== null))
    held(`the refusal for ${name} names the variable`, 'true', String(answer?.includes(name.toUpperCase()) ?? false))
  }
  held(`${name} is no matter on macOS`, 'false', refused(['build'], 'darwin', { [name]: '-MD' }))
  held(`${name} is no matter on Linux`, 'false', refused(['build'], 'linux', { [name]: '-MD' }))
}
held(
  'names that only contain CFLAGS, or that are for another target, are no matter on Windows',
  'false',
  refused(['build'], 'win32', { MYCFLAGS: 'x', CFLAGS2: 'x', CFLAGS_aarch64_linux_android: 'x', CXXFLAGS_i686_pc_windows_msvc: 'x', RUST_CFLAGS: 'x' })
)

// The crate that links libsodium takes a library directory (`SODIUM_LIB_DIR`) or a system's library
// (`SODIUM_USE_PKG_CONFIG`) before it reads the archive that a digest holds, and links whatever those name.
// Both are refused on Windows in any spelling, whatever their value; they are no matter elsewhere.
for (const name of ['SODIUM_LIB_DIR', 'sodium_lib_dir', 'SODIUM_USE_PKG_CONFIG', 'Sodium_Use_Pkg_Config']) {
  for (const value of ['C:\\sodium', '']) {
    const answer = refusal(['build'], 'win32', { PATH: 'x', [name]: value })
    held(`${name}=${JSON.stringify(value)} is refused on Windows`, 'true', String(answer !== null))
    held(`the refusal for ${name} names the variable`, 'true', String(answer?.includes(name.toUpperCase()) ?? false))
  }
  held(`${name} is no matter on Linux`, 'false', refused(['build'], 'linux', { [name]: '/x' }))
}

// A Windows build is started only with libsodium's archive placed by the script that holds its size and
// digest, and the build is given the directory the script compared. Another directory in the caller's
// environment is the one the script is run on, in every spelling of the name.
{
  const SCRIPT = 'scripts/place-libsodium-archive.sh'
  const without = buildPlan(['build'], 'win32', { PATH: 'C:\\x' })
  held('a plan for Windows with no placed archive is a refusal', 'true', String(typeof without.problem === 'string' && without.args === undefined && without.env === undefined))
  held('that refusal names the script and the variable', 'true', String(without.problem?.includes(SCRIPT) && without.problem?.includes('SODIUM_DIST_DIR')))
  const placed = buildPlan(['build', '--bundles', 'nsis'], 'win32', { PATH: 'C:\\x', Sodium_Dist_Dir: 'D:\\other', SODIUM_DIST_DIR: '' }, 'C:/Users/a/key')
  held('a plan for Windows with the archive placed has no problem', 'null', String(placed.problem))
  held('the build is given the directory that was compared', 'C:/Users/a/key', placed.env?.SODIUM_DIST_DIR)
  held('no other spelling of the variable goes on', 'SODIUM_DIST_DIR', Object.keys(placed.env ?? {}).filter((key) => key.toUpperCase() === 'SODIUM_DIST_DIR').join(','))
  const mac = buildPlan(['build'], 'darwin', { PATH: '/usr/bin' })
  held('a plan for macOS needs no archive and gives none', 'false', String('SODIUM_DIST_DIR' in (mac.env ?? { SODIUM_DIST_DIR: 1 })))
  held('a plan for macOS cleans nothing', 'null', String(mac.clean))

  // The crate's build script does not run again when the directory changes, so a target directory that
  // already holds the crate's build keeps what that build linked. The plan removes that build, for the
  // profile and the target the bundle is built for, before the bundle is built.
  const clean = (argv) => JSON.stringify(buildPlan(argv, 'win32', { PATH: 'x' }, 'C:/k').clean)
  held('the release build removes the release build of the crate', JSON.stringify(['clean', '-p', 'libsodium-sys-stable', '--release']), clean(['build']))
  held('a debug build removes the debug build', JSON.stringify(['clean', '-p', 'libsodium-sys-stable']), clean(['build', '--debug']))
  held('a short debug option does the same', JSON.stringify(['clean', '-p', 'libsodium-sys-stable']), clean(['build', '-d', '--ci']))
  held('a target is kept', JSON.stringify(['clean', '-p', 'libsodium-sys-stable', '--release', '--target', 'aarch64-pc-windows-msvc']), clean(['build', '--target', 'aarch64-pc-windows-msvc']))
  held('a target in a bundle of short options is kept', JSON.stringify(['clean', '-p', 'libsodium-sys-stable', '--target', 'x86_64-pc-windows-msvc']), clean(['build', '-dt', 'x86_64-pc-windows-msvc']))

  // The directory: the one the caller named, else one in the home directory that is named by the digests
  // the script holds, so that a directory is never shared by two sets of bytes.
  held('the directory the caller named is kept', 'D:/cache/libsodium', archiveDirectory({ SODIUM_DIST_DIR: 'D:\\cache\\libsodium' }, 'C:\\Users\\a', 'key', 'win32'))
  held('a name in another spelling is read on Windows', 'D:/c', archiveDirectory({ sodium_dist_dir: 'D:/c' }, 'C:\\Users\\a', 'key', 'win32'))
  held('with no name the directory is in the home directory and named by the key', 'C:/Users/a/key', archiveDirectory({}, 'C:\\Users\\a', 'key', 'win32'))
  held('an empty name is no name', 'C:/Users/a/key', archiveDirectory({ SODIUM_DIST_DIR: '' }, 'C:\\Users\\a', 'key', 'win32'))
  // The placing script reads a relative name from the repository's root and the crate's build script from
  // its own directory, and a name that starts with a separator but names no drive is read from the root of
  // the current drive by a Windows program (the build script) and from Git's mount table by the bash of Git
  // for Windows (`/c/cache` is `C:\cache` there, `C:\c\cache` for the build script). The name is therefore
  // resolved by the rule of the platform that runs, from where the command was started, into a path with
  // a drive or a server in it, which the bash and the build script read alike.
  const windowsName = (name, cwd = 'C:\\work\\app') => archiveDirectory({ SODIUM_DIST_DIR: name }, 'C:\\Users\\a', 'key', 'win32', cwd)
  const posixName = (name, cwd = '/work/app') => archiveDirectory({ SODIUM_DIST_DIR: name }, '/home/a', 'key', 'linux', cwd)
  held('a relative name is made absolute on Windows', 'C:/work/app/archives', windowsName('archives'))
  held('a name with a dot is resolved on Windows', 'C:/work/cache', windowsName('..\\cache'))
  held('a name on a drive is kept', 'D:/c', windowsName('D:\\c'))
  held(
    'a Windows temporary path is kept',
    'C:/Users/runneradmin/AppData/Local/Temp/desktop-archive-x/named',
    windowsName('C:\\Users\\runneradmin\\AppData\\Local\\Temp\\desktop-archive-x\\named', 'D:\\a\\app\\apps\\companion')
  )
  held('a name from a server share is kept', '//server/share/cache', windowsName('\\\\server\\share\\cache'))
  held('a name from the drive root is on the drive of the working directory', 'C:/c/cache', windowsName('/c/cache'))
  held('a name from the drive root follows the drive of the working directory', 'D:/c/cache', windowsName('/c/cache', 'D:\\a\\app'))
  held('a backslash name from the drive root is the same', 'C:/tmp', windowsName('\\tmp'))
  held('a name with a UNC share is kept in both spellings', '//s/sh/x', windowsName('//s/sh/x'))
  // A name with a drive and no separator after it is relative to the current directory of that drive, which the
  // working directory, the placing script and the build do not read alike: it is refused, not resolved.
  for (const name of ['C:cache', 'd:x', 'C:..\\x', 'C:']) {
    held(`the name \`${name}\`, relative to the current directory of a drive, is no directory`, 'null', String(windowsName(name)))
  }
  held('a name with a drive and a separator is no such name', 'C:/x', windowsName('C:/x'))
  for (const name of ['/c/cache', '/tmp/x', '\\x', 'x', '..\\x', 'D:\\x', 'd:/x', '\\\\s\\sh\\x', '//s/sh/x']) {
    held(
      `the name \`${name}\` is given to both readers with a drive or a server`,
      'true',
      String(/^([A-Za-z]:\/|\/\/[^/])/.test(windowsName(name)))
    )
  }
  held('a relative name is made absolute elsewhere', '/work/app/archives', posixName('archives'))
  held('a name with a dot is resolved elsewhere', '/work/cache', posixName('../cache'))
  held('a name from the root is kept elsewhere', '/c/cache', posixName('/c/cache'))
  held('a Windows temporary path is a relative name elsewhere', '/work/app/C:/Users/a/named', posixName('C:\\Users\\a\\named'))
  held('a name with a drive and no separator is a relative name elsewhere', '/work/app/C:cache', posixName('C:cache'))

  // The script itself, run for real on directories that hold other bytes: it compares what is in a
  // directory before anything is fetched, and refuses, so no network is needed and nothing is placed.
  const root = mkdtempSync(join(tmpdir(), 'desktop-archive-'))
  try {
    // The script is started by its path from the repository's root, as the entry starts it: it finds the
    // repository from the way it was named.
    const key = spawnSync('bash', [SCRIPT, '--key'], { cwd: REPOSITORY, encoding: 'utf8' }).stdout.trim()
    held('the script prints a key that holds digests', 'true', String(/^libsodium-archive-[0-9.]+-[0-9a-f]{12}-[0-9a-f]{12}$/.test(key)))
    const wrong = (directory) => {
      mkdirSync(directory, { recursive: true })
      writeFileSync(join(directory, 'libsodium-1.0.22-stable-msvc.zip'), 'not the archive')
    }
    const named = join(root, 'named')
    wrong(named)
    const byName = placeArchive({ SODIUM_DIST_DIR: named }, root, process.platform)
    held('a named directory that holds other bytes is refused', 'null', String(byName.directory))
    held('the refusal names the script and the variable', 'true', String(byName.problem?.includes(SCRIPT) && byName.problem?.includes('SODIUM_DIST_DIR')))
    held('the refusal carries the script\'s own words', 'true', String(byName.problem?.includes('refused libsodium-1.0.22-msvc.zip')))
    // A drive-relative name is refused with its own words before anything is placed.
    const relativeToDrive = placeArchive({ SODIUM_DIST_DIR: 'C:cache' }, root, 'win32')
    held('a name relative to the current directory of a drive is refused', 'null', String(relativeToDrive.directory))
    held('and the refusal says why', 'true', String(relativeToDrive.problem?.includes('current directory of a drive') && relativeToDrive.problem?.includes('C:cache')))
    wrong(join(root, key))
    const byDefault = placeArchive({}, root, process.platform)
    held('the default directory that holds other bytes is refused too', 'null', String(byDefault.directory))
    held('and it is the directory in the home directory that was compared', 'true', String(byDefault.problem?.includes(key)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// The command line tool takes the runner from the build's configuration unless it is given one, and a
// configuration file can name another program: the build is given cargo.
held('the build is given cargo as its runner, right after the build', JSON.stringify(['build', '--runner', 'cargo']), JSON.stringify(childArguments(['build'])))
held(
  'what the caller gave follows the runner as it was given',
  JSON.stringify(['build', '--runner', 'cargo', '--ci', '--bundles', 'nsis', '--', '--locked']),
  JSON.stringify(childArguments(['build', '--ci', '--bundles', 'nsis', '--', '--locked']))
)

// On Windows an environment that gives the compiler flags is refused, in every spelling of the name and
// with any value, an empty one included. `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` replace the `crt-static`
// target feature and the link options of the configuration (an empty value leaves cargo no flags from its
// configuration either); the other two add to them or are ignored, and are refused as a second source.
for (const name of [
  'RUSTFLAGS',
  'rustflags',
  'CARGO_ENCODED_RUSTFLAGS',
  'CARGO_BUILD_RUSTFLAGS',
  'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS',
  'Cargo_Target_Aarch64_Pc_Windows_Msvc_Rustflags'
]) {
  for (const value of ['-Ctarget-cpu=native', '']) {
    const answer = refusal(['build'], 'win32', { PATH: 'x', [name]: value })
    held(`${name}=${JSON.stringify(value)} is refused on Windows`, 'true', String(answer !== null))
    held(`the refusal for ${name} names the variable`, 'true', String(answer?.includes(name.toUpperCase()) ?? false))
  }
  held(`${name} is no matter on macOS`, 'false', refused(['build'], 'darwin', { [name]: '-Ctarget-cpu=native' }))
  held(`${name} is no matter on Linux`, 'false', refused(['build'], 'linux', { [name]: '-Ctarget-cpu=native' }))
}
for (const env of [{}, { PATH: 'x', RUSTC_WRAPPER: 'sccache', CARGO_BUILD_JOBS: '4', CARGO_TARGET_DIR: 'x', STATIC_VCRUNTIME: 'true' }]) {
  held('an environment with no compiler flags is run on Windows', 'false', refused(['build'], 'win32', env))
}

// What a run does is what the plan says: the arguments and the environment that the command line tool is
// started with, and nothing of them for a run that is refused.
{
  const plan = buildPlan(['build', '--bundles', 'nsis'], 'win32', { PATH: 'C:\\x', STATIC_VCRUNTIME: 'true' }, 'C:/k')
  held('a plan for Windows starts the build with cargo as its runner', JSON.stringify(['build', '--runner', 'cargo', '--bundles', 'nsis']), JSON.stringify(plan.args))
  held('a plan for Windows starts the build with the variable false', 'false', plan.env?.STATIC_VCRUNTIME)
  held('a plan for Windows keeps the rest of the environment', 'C:\\x', plan.env?.PATH)
  held('a plan for Windows says the value it replaced', 'true', String(plan.said?.includes('`true`') ?? false))
  held('a plan for a run that is allowed has no problem', 'null', String(plan.problem))
  const refusedPlan = buildPlan(['build', '--no-bundle'], 'darwin', { PATH: '/usr/bin' })
  held('a refused run has its reason and starts nothing', 'true', String(typeof refusedPlan.problem === 'string' && refusedPlan.args === undefined && refusedPlan.env === undefined))
  const mac = buildPlan(['build', '--no-sign'], 'darwin', { PATH: '/usr/bin' })
  held(
    'a plan for macOS gives cargo as the runner and the environment with this application\'s own project, interface and mode',
    JSON.stringify([['build', '--runner', 'cargo', '--no-sign'], { PATH: '/usr/bin', ...OWN }, null]),
    JSON.stringify([mac.args, mac.env, mac.said])
  )
}

// On Windows the build gets `STATIC_VCRUNTIME=false`, whatever the caller's environment held.
function windowsBuild(env) {
  const { env: given, said } = childEnvironment('win32', env, 'C:/k')
  return { given, said }
}
{
  const other = { PATH: 'C:\\x', CARGO_TARGET_DIR: 'D:\\t' }
  const none = windowsBuild(other)
  held('Windows: an environment with no setting gets false', 'false', none.given.STATIC_VCRUNTIME)
  held('Windows: nothing is said when no value was replaced', 'null', String(none.said))
  held('Windows: the rest of the environment is kept', JSON.stringify(other), JSON.stringify({ ...none.given, STATIC_VCRUNTIME: undefined, SODIUM_DIST_DIR: undefined, ...UNSET }))

  const already = windowsBuild({ ...other, STATIC_VCRUNTIME: 'false' })
  held('Windows: false stays false', 'false', already.given.STATIC_VCRUNTIME)
  held('Windows: nothing is said when the value was false', 'null', String(already.said))

  for (const value of ['true', '1', '', 'False']) {
    const replaced = windowsBuild({ ...other, STATIC_VCRUNTIME: value })
    held(`Windows: ${JSON.stringify(value)} is replaced by false`, 'false', replaced.given.STATIC_VCRUNTIME)
    held(
      `Windows: replacing ${JSON.stringify(value)} is said in one line that names the old value`,
      'true',
      String(
        replaced.said !== null &&
          !replaced.said.includes('\n') &&
          replaced.said.includes('STATIC_VCRUNTIME') &&
          replaced.said.includes(`\`${value}\``) &&
          replaced.said.includes('`false`')
      )
    )
  }

  // Windows names variables without regard to case: the child's environment holds one spelling of the
  // name, and it is the value that the build was given.
  const spelled = windowsBuild({ ...other, Static_Vcruntime: 'true', static_vcruntime: 'true' })
  const names = Object.keys(spelled.given).filter((key) => key.toUpperCase() === 'STATIC_VCRUNTIME')
  held('Windows: every spelling of the name is replaced by the one', 'STATIC_VCRUNTIME', names.join(','))
  held('Windows: the value of the one is false', 'false', spelled.given.STATIC_VCRUNTIME)
  held('Windows: a value in another spelling is said', 'true', String(spelled.said?.includes('`true`') ?? false))

  const untouched = { ...other, STATIC_VCRUNTIME: 'true' }
  windowsBuild(untouched)
  held('Windows: the caller\'s environment is not changed', 'true', untouched.STATIC_VCRUNTIME)
}

// On the other platforms the build gets the caller's environment as it is, with this application's own project,
// interface and mode (below) and nothing else added, and a value of this variable is none of this command's.
for (const platform of ['darwin', 'linux']) {
  const env = { PATH: '/usr/bin', APPLE_SIGNING_IDENTITY: '-', CI: 'true' }
  const { env: given, said } = childEnvironment(platform, env)
  held(`${platform}: the rest of the environment is the caller's`, JSON.stringify(env), JSON.stringify({ ...given, ...UNSET }))
  held(`${platform}: no value of STATIC_VCRUNTIME is added`, 'false', String('STATIC_VCRUNTIME' in given))
  held(`${platform}: nothing is said`, 'null', String(said))
  const asked = childEnvironment(platform, { ...env, STATIC_VCRUNTIME: 'true' })
  held(`${platform}: a value of STATIC_VCRUNTIME is left as it was`, 'true', asked.env.STATIC_VCRUNTIME)
  held(`${platform}: leaving it is not said`, 'null', String(asked.said))
}

// Variables that change WHAT the bundle holds or WHERE it is read from, on every platform. Tauri's command line
// builds the project that `TAURI_APP_PATH` names (an older checkout's, for one) and runs the interface's build in
// the directory `TAURI_FRONTEND_PATH` names; the interface's build writes the harness's output to another
// directory than the one the bundle takes its interface from when `KR_COMPANION_HARNESS` is `1`, and builds a
// development bundle when `NODE_ENV` says so. The build is given this application's own project, directory and
// mode, and not the harness's variable, whatever the caller's environment holds.
for (const platform of ['darwin', 'linux', 'win32']) {
  const own = (env) => childEnvironment(platform, env, 'C:/k')
  const elsewhere = platform === 'win32' ? 'D:\\older\\apps\\companion' : '/older/apps/companion'
  for (const name of ['TAURI_APP_PATH', 'TAURI_FRONTEND_PATH']) {
    const wanted = OWN[name]
    const another = name === 'TAURI_APP_PATH' ? `${elsewhere}/src-tauri` : elsewhere
    const replaced = own({ PATH: 'x', [name]: another })
    held(`${platform}: a caller's ${name} that names another directory does not reach the build`, wanted, replaced.env[name])
    held(`${platform}: replacing ${name} is said in one line that names the old value`, 'true', String(replaced.said !== null && !replaced.said.includes('\n') && replaced.said.includes(name) && replaced.said.includes(`\`${another}\``)))
    held(`${platform}: ${name} with no value is set to this application's and nothing is said`, 'true', String(own({ PATH: 'x' }).env[name] === wanted && own({ PATH: 'x' }).said === null))
    held(`${platform}: ${name} that is already this application's is not said`, 'null', String(own({ PATH: 'x', [name]: wanted }).said))
  }
  for (const value of ['development', 'test', '', 'Production']) {
    const replaced = own({ PATH: 'x', NODE_ENV: value })
    held(`${platform}: NODE_ENV=${JSON.stringify(value)} is replaced by production`, 'production', replaced.env.NODE_ENV)
    held(`${platform}: replacing NODE_ENV=${JSON.stringify(value)} is said in one line`, 'true', String(replaced.said !== null && !replaced.said.includes('\n') && replaced.said.includes('NODE_ENV') && replaced.said.includes('production')))
  }
  held(`${platform}: NODE_ENV=production is not said`, 'null', String(own({ PATH: 'x', NODE_ENV: 'production' }).said))
  for (const value of ['1', 'true']) {
    const harness = own({ PATH: 'x', KR_COMPANION_HARNESS: value })
    held(`${platform}: KR_COMPANION_HARNESS=${value} does not reach the build`, 'false', String('KR_COMPANION_HARNESS' in harness.env))
    held(
      `${platform}: dropping KR_COMPANION_HARNESS=${value} is ${value === '1' ? '' : 'not '}said`,
      String(value === '1'),
      String(harness.said !== null && harness.said.includes('KR_COMPANION_HARNESS') && harness.said.includes('dist') && !harness.said.includes('\n'))
    )
  }
  held(`${platform}: the harness's variable is not there when the caller gave none`, 'false', String('KR_COMPANION_HARNESS' in own({ PATH: 'x' }).env))
  // Every one at once: each is said on a line of its own, and the rest of the environment is kept.
  const all = own({ PATH: 'x', CI: 'true', TAURI_APP_PATH: `${elsewhere}/src-tauri`, TAURI_FRONTEND_PATH: elsewhere, NODE_ENV: 'development', KR_COMPANION_HARNESS: '1' })
  held(`${platform}: every replaced value is said on a line of its own`, 'true', String((all.said ?? '').split('\n').filter((line) => /TAURI_APP_PATH|TAURI_FRONTEND_PATH|NODE_ENV|KR_COMPANION_HARNESS/.test(line)).length >= 4))
  held(`${platform}: the rest of the environment is kept beside them`, JSON.stringify({ PATH: 'x', CI: 'true' }), JSON.stringify({ ...all.env, ...UNSET, KR_COMPANION_HARNESS: undefined, SODIUM_DIST_DIR: undefined, STATIC_VCRUNTIME: undefined }))
  const caller = { PATH: 'x', TAURI_APP_PATH: `${elsewhere}/src-tauri`, KR_COMPANION_HARNESS: '1' }
  own(caller)
  held(`${platform}: the caller's environment is not changed`, 'true', String(caller.KR_COMPANION_HARNESS === '1' && caller.TAURI_APP_PATH === `${elsewhere}/src-tauri`))
  // The plan carries them, for the build's own cargo command (which cleans a crate for the profile) as well.
  const plan = buildPlan(['build'], platform, { PATH: 'x', TAURI_APP_PATH: `${elsewhere}/src-tauri`, KR_COMPANION_HARNESS: '1' }, 'C:/k')
  held(`${platform}: a plan starts the build with this application's own project`, OWN.TAURI_APP_PATH, plan.env?.TAURI_APP_PATH)
  held(`${platform}: a plan starts the build without the harness's variable`, 'false', String('KR_COMPANION_HARNESS' in (plan.env ?? {})))
  held(`${platform}: a plan says what it replaced`, 'true', String(plan.said?.includes('TAURI_APP_PATH') && plan.said?.includes('KR_COMPANION_HARNESS')))
}
// Windows names variables without regard to case: every spelling is replaced by the one that Tauri reads, and a
// spelling of the harness's variable is dropped. On the other platforms another spelling is another variable.
{
  const spelled = childEnvironment('win32', { PATH: 'C:\\x', tauri_app_path: 'D:\\o\\src-tauri', Tauri_App_Path: 'D:\\p', node_env: 'development', kr_companion_harness: '1' }, 'C:/k')
  const names = (pattern) => Object.keys(spelled.env).filter((key) => pattern.test(key))
  held('Windows: every spelling of TAURI_APP_PATH is replaced by the one', 'TAURI_APP_PATH', names(/^tauri_app_path$/i).join(','))
  held('Windows: every spelling of NODE_ENV is replaced by the one', 'NODE_ENV', names(/^node_env$/i).join(','))
  held('Windows: every spelling of the harness\'s variable is dropped', '', names(/^kr_companion_harness$/i).join(','))
  const other = childEnvironment('linux', { PATH: '/usr/bin', node_env: 'development', kr_companion_harness: '1' })
  held('Linux: another spelling is another variable and is left as it is', 'development,1', [other.env.node_env, other.env.kr_companion_harness].join(','))
}

// The command itself: arguments it refuses are refused before anything is run, with the exit code 2
// and the reason on the error stream, and the build's output is not started.
{
  const command = join(dirname(fileURLToPath(import.meta.url)), 'desktop.mjs')
  for (const [argv, said] of [
    [['dev'], 'runs `tauri build` and nothing else'],
    [['build', '--no-bundle'], '`--no-bundle` leaves none to read'],
    [['build', '--runner', 'cargo-xwin'], 'gives the build cargo as its runner']
  ]) {
    const run = spawnSync(process.execPath, [command, ...argv], { encoding: 'utf8' })
    held(`\`pnpm desktop ${argv.join(' ')}\` ends with 2`, '2', String(run.status))
    held(`\`pnpm desktop ${argv.join(' ')}\` says why`, 'true', String(run.stderr.includes(said)))
    held(`\`pnpm desktop ${argv.join(' ')}\` starts no build`, '', run.stdout)
  }
}

if (failures > 0) {
  console.error(`${failures} of the desktop bundle entry's cases answered wrongly`)
  process.exit(1)
}
console.log("the desktop bundle entry gives and refuses what it must on every platform's case above")
