#!/usr/bin/env node
// Holds the desktop bundle build's entry to what it must give and refuse.
//
// The entry runs the desktop bundle build with the static Visual C++ runtime turned off on Windows,
// where the command line tool turns it on and the package's build script refuses that build. None of
// these cases runs a build: the decision about a command's arguments and the environment a build is
// given are functions that take the platform and the environment in, so each platform's answer is held
// here on whichever machine this runs on. The last cases start the command itself, with arguments it
// refuses before anything is run.
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildPlan, childArguments, childEnvironment, refusal } from './desktop.mjs'

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
    ['build', '--config', '{"build":{"frontendDist":"../dist"}}', '--ignore-version-mismatches'],
    ['build', '--target', 'aarch64-apple-darwin'],
    ['build', '-t', 'universal-apple-darwin', '--no-sign'],
    // What follows a bare `--` is passed on to cargo, whatever it looks like.
    ['build', '--', '--runner', 'x'],
    ['build', '--ci', '--', '--no-bundle', '--locked', '--offline']
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
  ['build', '-t', 'x86_64-unknown-linux-gnu'],
  ['build', '--config', 'runner.json'],
  ['build', '-c', 'r.json']
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
// On Windows the MSVC targets are the two that the link options of `.cargo/config.toml` name, and any
// other is refused: the static runtime would not be left out of its link.
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
  held(`\`pnpm desktop ${argv.join(' ')}\` is refused on Windows, since its link has no options that leave the static runtime out`, 'true', refused(argv, 'win32'))
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

// What follows a bare `--` goes to cargo, whose own `--config` can set the environment and the flags of the
// build (the variable that the entry gives, `env.STATIC_VCRUNTIME` forced to `true`, among them) and whose
// `--target` is read by none of the checks: both are refused on every platform, in every form.
for (const platform of ['darwin', 'linux', 'win32']) {
  for (const argv of [
    ['build', '--', '--config', 'env.STATIC_VCRUNTIME.value="true"'],
    ['build', '--', '--config=env.STATIC_VCRUNTIME.force=true'],
    ['build', '--ci', '--', '--locked', '--config', 'build.rustflags=[]'],
    ['build', '--', '--target', 'x86_64-pc-windows-msvc'],
    ['build', '--', '--target=aarch64-apple-darwin'],
    ['build', '--features', 'a', '--', '--target', 'x']
  ]) {
    held(`\`pnpm desktop ${argv.join(' ')}\` is refused on ${platform}, since cargo would be given its own setting`, 'true', refused(argv, platform))
  }
  for (const argv of [['build', '--', '--locked'], ['build', '--', '--offline', '--frozen'], ['build', '--', '--target-dir', 'x'], ['build', '--', '--configuration']]) {
    held(`\`pnpm desktop ${argv.join(' ')}\` is run as it is given on ${platform}`, 'false', refused(argv, platform))
  }
}

// The command line tool takes the runner from the build's configuration unless it is given one, and a
// configuration that the caller passes can name another program: the build is given cargo.
held('the build is given cargo as its runner, right after the build', JSON.stringify(['build', '--runner', 'cargo']), JSON.stringify(childArguments(['build'])))
held(
  'what the caller gave follows the runner as it was given',
  JSON.stringify(['build', '--runner', 'cargo', '--config', '{"build":{"runner":"cargo-xwin"}}', '--', '--locked']),
  JSON.stringify(childArguments(['build', '--config', '{"build":{"runner":"cargo-xwin"}}', '--', '--locked']))
)

// On Windows an environment that gives the compiler flags is refused, in every spelling of the name and
// with any value, an empty one included. `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` replace the link
// options that keep the static runtime out of the link (an empty value leaves cargo no flags from its
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
  const plan = buildPlan(['build', '--bundles', 'nsis'], 'win32', { PATH: 'C:\\x', STATIC_VCRUNTIME: 'true' })
  held('a plan for Windows starts the build with cargo as its runner', JSON.stringify(['build', '--runner', 'cargo', '--bundles', 'nsis']), JSON.stringify(plan.args))
  held('a plan for Windows starts the build with the variable false', 'false', plan.env?.STATIC_VCRUNTIME)
  held('a plan for Windows keeps the rest of the environment', 'C:\\x', plan.env?.PATH)
  held('a plan for Windows says the value it replaced', 'true', String(plan.said?.includes('`true`') ?? false))
  held('a plan for a run that is allowed has no problem', 'null', String(plan.problem))
  const refusedPlan = buildPlan(['build', '--no-bundle'], 'darwin', { PATH: '/usr/bin' })
  held('a refused run has its reason and starts nothing', 'true', String(typeof refusedPlan.problem === 'string' && refusedPlan.args === undefined && refusedPlan.env === undefined))
  const mac = buildPlan(['build', '--no-sign'], 'darwin', { PATH: '/usr/bin' })
  held('a plan for macOS gives cargo as the runner and the environment as it is', JSON.stringify([['build', '--runner', 'cargo', '--no-sign'], { PATH: '/usr/bin' }, null]), JSON.stringify([mac.args, mac.env, mac.said]))
}

// On Windows the build gets `STATIC_VCRUNTIME=false`, whatever the caller's environment held.
function windowsBuild(env) {
  const { env: given, said } = childEnvironment('win32', env)
  return { given, said }
}
{
  const other = { PATH: 'C:\\x', CARGO_TARGET_DIR: 'D:\\t' }
  const none = windowsBuild(other)
  held('Windows: an environment with no setting gets false', 'false', none.given.STATIC_VCRUNTIME)
  held('Windows: nothing is said when no value was replaced', 'null', String(none.said))
  held('Windows: the rest of the environment is kept', JSON.stringify(other), JSON.stringify({ ...none.given, STATIC_VCRUNTIME: undefined }))

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

// On the other platforms the build gets the caller's environment as it is: nothing is added, and a
// value of this variable is none of this command's.
for (const platform of ['darwin', 'linux']) {
  const env = { PATH: '/usr/bin', APPLE_SIGNING_IDENTITY: '-', CI: 'true' }
  const { env: given, said } = childEnvironment(platform, env)
  held(`${platform}: the environment is the caller's`, JSON.stringify(env), JSON.stringify(given))
  held(`${platform}: no value of STATIC_VCRUNTIME is added`, 'false', String('STATIC_VCRUNTIME' in given))
  held(`${platform}: nothing is said`, 'null', String(said))
  const asked = childEnvironment(platform, { ...env, STATIC_VCRUNTIME: 'true' })
  held(`${platform}: a value of STATIC_VCRUNTIME is left as it was`, 'true', asked.env.STATIC_VCRUNTIME)
  held(`${platform}: leaving it is not said`, 'null', String(asked.said))
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
