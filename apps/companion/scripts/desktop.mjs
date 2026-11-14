#!/usr/bin/env node
// Runs the desktop bundle build (`pnpm desktop build ...`): `tauri build` for the machine it runs on,
// with the one setting that build needs on Windows.
//
// The application links the dynamic Visual C++ runtime. `.cargo/config.toml` leaves the static one out
// of the x86-64 and ARM64 MSVC links, because the C library this workspace vendors asks for the static
// runtime and the two must not both be linked. The command line tool sets `STATIC_VCRUNTIME=true` for a desktop build
// unless the variable is already `false`, the Tauri build step reads it before the attribute this
// package gives it, and the package's build script then refuses the build. So on Windows this gives
// the build `STATIC_VCRUNTIME=false`, whatever the caller's environment holds, and says so when it
// replaces another value. On the other platforms the build gets the caller's environment as it is.
//
// On Windows the build also starts only after libsodium's prebuilt archive is placed by
// `scripts/place-libsodium-archive.sh`, which compares both files with the size and SHA-256 it holds
// and refuses any other bytes. Without a directory that script filled, the crate's build script
// fetches upstream's replaceable archive and holds it by its signature alone. The script is run on
// the directory `SODIUM_DIST_DIR` names, or on one in the home directory that is named by the digests,
// and the build is given exactly that directory. The crate's build script does not run again when the
// directory changes, so the build of the crate that an earlier build left in the target directory is
// removed first. Placing the archive here, and not only refusing a build that lacks it, is what makes
// the build unable to link other bytes: a directory that the caller names is compared too.
//
// Only the bundle build is run, with cargo as its runner (a build's configuration can name another
// runner, and the command line tool takes that one unless it is given one), and what would change what
// it holds is refused:
//
// - a runner of the caller's own: the setting above is read by cargo's build step;
// - `--config` and `TAURI_CONFIG`: Tauri merges a configuration given there over the repository's, and it
//   can switch the bundle off, name another command to run before the build, or change what the bundle
//   holds;
// - `--no-bundle`, and `--bundles` with no value: they leave no bundle to read (a list of formats that
//   the platform cannot make leaves none either, and is not read here);
// - a Windows target on a machine that is not Windows, and on Windows an MSVC target that the
//   link options of `.cargo/config.toml` do not name (x86-64 and ARM64): the setting is made for the
//   machine this runs on, and those options are what keep the static runtime out of the link;
// - after a bare `--`, cargo's own `--config` and `--target`: either can set the environment, the
//   flags or the target that this command holds;
// - `CARGO_BUILD_TARGET`: the command line tool does not read it, so cargo would build for it into the
//   directory of that target and the bundle would be made from the program of another build; a target
//   is given as `--target`;
// - on Windows, an environment that gives the compiler flags (`RUSTFLAGS` and the like):
//   `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` replace the link options of `.cargo/config.toml`, after
//   which the link only warns, and the others are a second source of flags that this build does not take;
// - on Windows, `LINK` and `_LINK_`, which the linker reads before and after its options and which can
//   add or leave out the runtime libraries of the link, and `SODIUM_LIB_DIR` and `SODIUM_USE_PKG_CONFIG`,
//   with which libsodium's crate links the library they name and not the archive that was compared.
import { spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { startedAs } from './entry-point.mjs'

import { toolPath } from './tools.mjs'

const WINDOWS = 'win32'
const RUNTIME_VARIABLE = 'STATIC_VCRUNTIME'
const ARCHIVE_VARIABLE = 'SODIUM_DIST_DIR'
const ARCHIVE_SCRIPT = 'scripts/place-libsodium-archive.sh'
const REPOSITORY = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

/** The long options of `tauri build`, each with whether it takes the one value that must follow it. */
const LONG = new Map([
  ['runner', true],
  ['target', true],
  ['config', true],
  // These two take any number of values, so the next word is not necessarily theirs.
  ['features', false],
  ['bundles', false],
  ['debug', false],
  ['no-bundle', false],
  ['ci', false],
  ['skip-stapling', false],
  ['ignore-version-mismatches', false],
  ['no-sign', false],
  ['verbose', false],
  ['help', false],
  ['version', false]
])

/** The options that take any number of values, none included. */
const MANY = new Set(['features', 'bundles'])

/** The MSVC targets that the link options of `.cargo/config.toml` name. */
const LINKED_MSVC = new Set(['x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc'])

/** The short options that take a value (the rest of their bundle, or the next word), with their long names. */
const SHORT = new Map([
  ['r', 'runner'],
  ['t', 'target'],
  ['f', 'features'],
  ['b', 'bundles'],
  ['c', 'config']
])

/**
 * The long option a word names: its exact name, or the one option it is the start of. The command
 * line tool reads exact names today; reading a start as well keeps a later tool that accepts one from
 * being a way round a refusal. A start of two options names neither.
 */
function longName(word) {
  if (LONG.has(word)) return word
  const starts = [...LONG.keys()].filter((name) => name.startsWith(word))
  return starts.length === 1 ? starts[0] : null
}

/**
 * The options of a build in the order given, as `{ name, value }` (a value is null when none was
 * given with the option). What follows a bare `--` is passed on to the build's runner, and is none of
 * this command's. A short option is one of a bundle (`-dt`), read from left to right: `d` takes no
 * value, and the first of `r`, `t`, `f`, `b` and `c` takes the rest of the bundle as its value.
 */
function optionsOf(words) {
  const found = []
  // The next word is the value of an option that takes one, unless it is another option.
  const following = (i) => (i + 1 < words.length && !words[i + 1].startsWith('-') ? i + 1 : null)
  for (let i = 0; i < words.length; i++) {
    const word = words[i]
    if (word === '--') break
    if (word.startsWith('--')) {
      const [given, ...attached] = word.slice(2).split('=')
      const name = longName(given)
      let value = attached.length > 0 ? attached.join('=') : null
      if (value === null && name !== null && LONG.get(name) && following(i) !== null) {
        value = words[(i = following(i))]
      }
      // The options that take any number of values keep their first one, and the word is not consumed.
      if (value === null && MANY.has(name) && following(i) !== null) value = words[following(i)]
      found.push({ name: name ?? given, value })
    } else if (word.length > 1 && word.startsWith('-')) {
      for (let k = 1; k < word.length; k++) {
        if (word[k] === 'd') {
          found.push({ name: 'debug', value: null })
          continue
        }
        const name = SHORT.get(word[k])
        if (name === undefined) continue
        let value = word.slice(k + 1)
        if (value.startsWith('=')) value = value.slice(1)
        if (value === '' && LONG.get(name) && following(i) !== null) value = words[(i = following(i))]
        if (value === '' && MANY.has(name) && following(i) !== null) value = words[following(i)]
        found.push({ name, value: value === '' ? null : value })
        break
      }
    }
  }
  return found
}

/** Whether a Windows environment variable name gives the compiler flags of a build. */
function givesCompilerFlags(name) {
  return /^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_.+_RUSTFLAGS)$/.test(
    name.toUpperCase()
  )
}

/** Whether a Windows environment variable name gives the linker options of a build (it reads both). */
function givesLinkerOptions(name) {
  return ['LINK', '_LINK_'].includes(name.toUpperCase())
}

/** Whether a Windows environment variable name makes libsodium's crate link another library than the archive. */
function givesAnotherSodium(name) {
  return /^SODIUM_(LIB_DIR|USE_PKG_CONFIG)$/.test(name.toUpperCase())
}

/** The value of an environment variable, with Windows naming variables without regard to case. */
function environmentValue(env, name, platform) {
  const key = Object.keys(env).find((k) => (platform === WINDOWS ? k.toUpperCase() === name : k === name))
  return key === undefined ? undefined : env[key]
}

/**
 * Why a target cannot be built here, or null. A Windows target needs a Windows machine, since the
 * setting this gives the build is made for the machine it runs on; and on Windows an MSVC target is
 * one that the link options of `.cargo/config.toml` name, since those keep the static runtime out.
 */
function targetProblem(triple, platform) {
  if (platform !== WINDOWS) {
    return /-windows(-|$)/.test(triple) ? 'it builds a Windows bundle on Windows only' : null
  }
  if (/-windows-msvc$/.test(triple) && !LINKED_MSVC.has(triple)) {
    return (
      'the link options that keep the static Visual C++ runtime out of the link are set for ' +
      `${[...LINKED_MSVC].join(' and ')} only`
    )
  }
  return null
}

/**
 * What is wrong with the arguments, or with the environment, that this was given, or null when it can
 * run them. The platform and the environment are passed in, so that each platform's answer can be held
 * on any machine.
 */
export function refusal(argv, platform = process.platform, env = process.env) {
  const [command, ...rest] = argv
  const given = argv.join(' ')
  if (command !== 'build') {
    return `pnpm desktop runs \`tauri build\` and nothing else (it was given \`${given}\`).`
  }
  const options = optionsOf(rest)
  if (options.some((option) => option.name === 'runner')) {
    return (
      `pnpm desktop gives the build cargo as its runner and does not take another (it was given \`${given}\`): ` +
      "the setting it gives the build is read by cargo's build step."
    )
  }
  if (options.some((option) => option.name === 'no-bundle')) {
    return (
      `pnpm desktop makes the bundles, and \`--no-bundle\` leaves none to read (it was given \`${given}\`): ` +
      'build the program alone with `cargo build -p companion-tauri --release --features custom-protocol`.'
    )
  }
  if (options.some((option) => option.name === 'bundles' && (option.value ?? '') === '')) {
    return `pnpm desktop makes the bundles, and \`--bundles\` with no value selects none (it was given \`${given}\`).`
  }
  // A configuration given here is merged over the repository's. It can switch the bundle off, name
  // another command to run before the build, or change what the bundle holds, and the checks of this
  // command read the repository's configuration alone.
  if (options.some((option) => option.name === 'config')) {
    return (
      `pnpm desktop builds with the repository's Tauri configuration alone and does not take \`--config\` (it was given \`${given}\`): ` +
      'a configuration given on the command line is merged over it and can switch the bundle off or change what the bundle holds.'
    )
  }
  if (environmentValue(env, 'TAURI_CONFIG', platform) !== undefined) {
    return (
      'pnpm desktop does not run a build with TAURI_CONFIG in the environment: it is merged over the ' +
      "repository's Tauri configuration like `--config`, and can switch the bundle off or change what the bundle holds."
    )
  }
  // What follows a bare `--` goes to cargo, whose own `--config` can set the environment and the flags
  // of the build and whose `--target` is read by none of the checks here.
  const cargo = rest.includes('--') ? rest.slice(rest.indexOf('--') + 1) : []
  const own = cargo.find((word) => /^--(config|target)(=|$)/.test(word))
  if (own !== undefined) {
    return (
      `pnpm desktop does not pass \`${own}\` on to cargo (it was given \`${given}\`): it can change the environment, ` +
      'the compiler flags or the target that this command holds. Give a target as `--target` before the `--`.'
    )
  }
  for (const option of options) {
    const why = option.name === 'target' && option.value !== null ? targetProblem(option.value, platform) : null
    if (why !== null) {
      return `pnpm desktop does not build for \`${option.value}\` here (it was given \`${given}\`): ${why}.`
    }
  }
  if (environmentValue(env, 'CARGO_BUILD_TARGET', platform) !== undefined) {
    return (
      'pnpm desktop does not run a build with CARGO_BUILD_TARGET in the environment: the command line tool does not ' +
      'read it, so cargo would build into the directory of that target and the bundle would be made from the ' +
      'program of another build. Give the target as `--target`.'
    )
  }
  if (platform !== WINDOWS) return null
  const flags = Object.keys(env).find(givesCompilerFlags)
  if (flags !== undefined) {
    return (
      `pnpm desktop does not run a build with ${flags.toUpperCase()} in the environment: the link options of ` +
      '.cargo/config.toml keep the static Visual C++ runtime out of the link, and this build takes its ' +
      'compiler flags from that file alone, as far as the environment reaches (RUSTFLAGS and ' +
      'CARGO_ENCODED_RUSTFLAGS replace those options, and the link then only warns of two runtimes).'
    )
  }
  const linker = Object.keys(env).find(givesLinkerOptions)
  if (linker !== undefined) {
    return (
      `pnpm desktop does not run a build with ${linker.toUpperCase()} in the environment: the linker reads \`LINK\` ` +
      'before the options it is given and `_LINK_` after them, and either can add or leave out the runtime libraries of the link.'
    )
  }
  const sodium = Object.keys(env).find(givesAnotherSodium)
  if (sodium !== undefined) {
    return (
      `pnpm desktop does not run a build with ${sodium.toUpperCase()} in the environment: libsodium's crate then links ` +
      `what that names and not the archive that ${ARCHIVE_SCRIPT} places, whose bytes a digest holds.`
    )
  }
  return null
}

/**
 * The arguments of the command line tool: the build, with cargo as its runner. A configuration that
 * the caller gives can name another runner, and the tool takes that one only when it is not given one.
 */
export function childArguments(argv) {
  const [command, ...rest] = argv
  return [command, '--runner', 'cargo', ...rest]
}

/**
 * The directory libsodium's archive is placed in: the one the caller's environment names, else one in
 * the home directory that is named by the digests the placing script holds (its `--key`), so that no
 * directory is shared by two sets of bytes. It is written with forward slashes, as the script and the
 * crate's build script both read a path.
 */
export function archiveDirectory(env, home, key, platform = process.platform) {
  const named = environmentValue(env, ARCHIVE_VARIABLE, platform)
  const directory = named !== undefined && named !== '' ? named : `${home}/${key}`
  return directory.replaceAll('\\', '/')
}

/**
 * Places libsodium's prebuilt archive through the repository's script, which compares both files with
 * the size and SHA-256 it holds, a file already in the directory as much as one it fetches, and refuses
 * any other bytes. The answer is the directory it compared, or the reason it could not place one. The
 * build is given that directory and no other, so what it links is what the script held to its digests.
 */
export function placeArchive(env, home = homedir(), platform = process.platform) {
  const refused = (why) => ({
    directory: null,
    problem:
      `pnpm desktop starts no Windows build before libsodium's archive is placed: ${ARCHIVE_SCRIPT} could not make ` +
      `a directory for ${ARCHIVE_VARIABLE} whose files match the size and digest it holds (${why}). ` +
      'It needs bash (the one that comes with Git for Windows), curl and cargo.'
  })
  const key = spawnSync('bash', [ARCHIVE_SCRIPT, '--key'], { cwd: REPOSITORY, encoding: 'utf8' })
  if (key.error || key.status !== 0) {
    return refused(key.error ? key.error.message : `\`--key\` ended with ${key.status}: ${key.stderr.trim()}`)
  }
  const directory = archiveDirectory(env, home, key.stdout.trim(), platform)
  const placed = spawnSync('bash', [ARCHIVE_SCRIPT, directory], {
    cwd: REPOSITORY,
    encoding: 'utf8',
    stdio: ['ignore', 'inherit', 'pipe']
  })
  if (placed.error || placed.status !== 0) {
    return refused(
      `${directory}: ${placed.error ? placed.error.message : `it ended with ${placed.status}`}; ${(placed.stderr ?? '').trim()}`
    )
  }
  return { directory, problem: null }
}

/**
 * The environment the build gets on a platform, and the line to say when it replaced a value: on
 * Windows `STATIC_VCRUNTIME=false` whatever the caller's environment held (Windows names variables
 * without regard to case, so every spelling of the name is replaced by the one) and the directory
 * that holds libsodium's archive, and on the other platforms the caller's environment as it is.
 */
export function childEnvironment(platform, env, archive = null) {
  if (platform !== WINDOWS) return { env: { ...env }, said: null }
  const given = (name) => Object.keys(env).filter((key) => key.toUpperCase() === name)
  const named = given(RUNTIME_VARIABLE)
  const replaced = named.map((key) => env[key]).find((value) => value !== 'false')
  const dropped = [...named, ...given(ARCHIVE_VARIABLE)]
  const kept = Object.fromEntries(Object.entries(env).filter(([key]) => !dropped.includes(key)))
  return {
    env: { ...kept, [RUNTIME_VARIABLE]: 'false', [ARCHIVE_VARIABLE]: archive },
    said:
      replaced === undefined
        ? null
        : `pnpm desktop: ${RUNTIME_VARIABLE} was \`${replaced}\` in the environment, and this build gets \`false\`, ` +
          'since the application links the dynamic Visual C++ runtime.'
  }
}

/**
 * The cargo command that removes the build of libsodium's crate that the bundle's build would reuse.
 * The crate's build script reruns when its own files or the few variables it names change, and the
 * directory of the archive is not one of them: a target directory that holds the crate's earlier build
 * keeps the archive that build linked. The build is removed for the profile and the target the bundle is
 * built for, so that it is made again from the directory that was compared.
 */
export function cleanArguments(argv) {
  const options = optionsOf(argv.slice(1))
  const target = options.findLast((option) => option.name === 'target' && option.value !== null)?.value
  const debug = options.some((option) => option.name === 'debug')
  return ['clean', '-p', 'libsodium-sys-stable', ...(debug ? [] : ['--release']), ...(target ? ['--target', target] : [])]
}

/**
 * What a run does with the arguments and the environment it is given: the reason to refuse them, or the
 * arguments and the environment of the command line tool, the line to say about the environment, and on
 * Windows the cargo command that goes first. A Windows plan needs the directory that holds libsodium's
 * archive, placed and compared by the script; without it the plan is a refusal and starts nothing.
 * The command below runs exactly what this answers.
 */
export function buildPlan(argv, platform = process.platform, env = process.env, archive = null) {
  const problem = refusal(argv, platform, env)
  if (problem !== null) return { problem }
  if (platform === WINDOWS && archive === null) {
    return {
      problem:
        `pnpm desktop starts no Windows build before libsodium's archive is placed: ${ARCHIVE_SCRIPT} places the files ` +
        `whose size and digest it holds, and ${ARCHIVE_VARIABLE} names their directory.`
    }
  }
  return {
    problem: null,
    args: childArguments(argv),
    ...childEnvironment(platform, env, archive),
    clean: platform === WINDOWS ? cleanArguments(argv) : null
  }
}

// Run only as the command: the entry point is compared by its real path, which is the one Node
// gives the module, so that a start through a symbolic link still runs.
if (startedAs(import.meta.url)) {
  const argv = process.argv.slice(2)
  let archive = null
  // The arguments and the environment are judged before anything is fetched or placed.
  if (refusal(argv) === null && process.platform === WINDOWS) {
    const placed = placeArchive(process.env)
    if (placed.problem !== null) {
      console.error(placed.problem)
      process.exit(2)
    }
    archive = placed.directory
  }
  const plan = buildPlan(argv, process.platform, process.env, archive)
  if (plan.problem !== null) {
    console.error(plan.problem)
    process.exit(2)
  }
  if (plan.said !== null) console.error(plan.said)
  if (plan.clean !== null) {
    const cleaned = spawnSync('cargo', plan.clean, { stdio: 'inherit', env: plan.env })
    if (cleaned.error || cleaned.status !== 0) {
      console.error(cleaned.error ? cleaned.error.message : `cargo ${plan.clean.join(' ')} ended with ${cleaned.status}`)
      process.exit(1)
    }
  }
  const result = spawnSync(process.execPath, [toolPath('@tauri-apps/cli'), ...plan.args], {
    stdio: 'inherit',
    env: plan.env
  })
  if (result.error) {
    console.error(result.error.message)
    process.exit(1)
  }
  process.exit(result.status ?? 1)
}
