#!/usr/bin/env node
// Signs a development build of the application, and its UI-test runner, by hand, and says whether
// the signatures hold.
//
// `tauri ios build --no-sign` and `xcodebuild` with signing off leave bundles with no signature and
// no entitlements. That is what a signer needs when its identity lives in a keychain that Xcode does
// not look in: Xcode finds an identity only in the keychains on the user's search list. The signer
// names the identity by its SHA-1, and this signs inside out (every library and extension, then the
// application), each bundle that a profile covers with that profile as `embedded.mobileprovision`
// and with the entitlements its source file asks for, expanded with the team's prefix.
//
// The identity, the keychain and the profiles are the signer's, and nothing here chooses or makes
// one. Whoever calls this puts the keychain where `codesign` can find the identity and takes it
// away again afterwards.
//
// Usage:
//   node scripts/sign-ios.mjs sign-app    <KalaReach.app> --identity <sha1> --keychain <file>
//        --app-profile <file> --extension-profile <file> --app-entitlements <file> --extension-entitlements <file>
//   node scripts/sign-ios.mjs verify-app  <KalaReach.app> --app-profile <file> --extension-profile <file>
//        --app-entitlements <file> --extension-entitlements <file> [--identity <sha1>]
//   node scripts/sign-ios.mjs sign-runner   <Runner.app> --identity <sha1> --keychain <file> --profile <file>
//   node scripts/sign-ios.mjs verify-runner <Runner.app> --profile <file> [--identity <sha1>]
//
// Exit 0 when it signed or every signature holds, 1 when a signature does not hold, 2 when it could
// not run.
import { Buffer } from 'node:buffer'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { pathToFileURL } from 'node:url'

import { declared, plistValue, problemsInBundle } from './identifiers.mjs'

/** What a profile says: the entitlements it allows, who it is for and until when. */
export function readProfile(path) {
  const decoded = spawnSync('openssl', ['smime', '-inform', 'der', '-verify', '-noverify', '-in', path], {
    maxBuffer: 16 * 1024 * 1024
  })
  if (decoded.error || decoded.status !== 0 || decoded.stdout.length === 0) {
    throw new Error(`${path} is not a provisioning profile that can be read`)
  }
  // The profile holds data and dates, which a conversion of the whole to JSON refuses, so each
  // value is taken on its own.
  const take = (key, format) => {
    const answer = spawnSync('plutil', ['-extract', key, format, '-o', '-', '-'], { input: decoded.stdout, encoding: 'utf8' })
    if (answer.error || answer.status !== 0) throw new Error(`${path} has no ${key}`)
    return format === 'json' ? JSON.parse(answer.stdout) : answer.stdout.trim()
  }
  return {
    path,
    name: take('Name', 'raw'),
    uuid: take('UUID', 'raw'),
    team: take('TeamIdentifier', 'json')[0],
    expires: new Date(take('ExpirationDate', 'raw')),
    devices: take('ProvisionedDevices', 'json'),
    entitlements: take('Entitlements', 'json')
  }
}

/**
 * What a profile does not allow of a set of entitlements, one sentence each. A profile allows a
 * keychain group it names or, written with a trailing `.*`, every group under that prefix, and the
 * associated domains it names or `*`.
 */
export function problemsOfFit(entitlements, profile) {
  const problems = []
  const allowed = profile.entitlements
  for (const [key, value] of Object.entries(entitlements)) {
    if (!(key in allowed)) {
      problems.push(`the profile allows no ${key}`)
      continue
    }
    const grant = allowed[key]
    if (grant === '*') continue
    if (key === 'keychain-access-groups') {
      for (const group of value) {
        const covered = grant.some((each) => each === group || (each.endsWith('.*') && group.startsWith(each.slice(0, -1))))
        if (!covered) problems.push(`the profile allows no keychain group ${group}`)
      }
    } else if (Array.isArray(value)) {
      for (const each of value) {
        if (!Array.isArray(grant) || !grant.includes(each)) problems.push(`the profile does not allow ${key} ${each}`)
      }
    } else if (value !== grant) {
      problems.push(`${key} is ${JSON.stringify(value)} and the profile says ${JSON.stringify(grant)}`)
    }
  }
  return problems
}

/**
 * The entitlements a bundle is signed with: what its source file asks for, with the team's prefix
 * in place of the placeholder, and the three a signing build adds itself.
 */
export function entitlementsFor({ source, team, bundleIdentifier, profile }) {
  const own = source ? plistValue(null, Buffer.from(source.replaceAll('$(AppIdentifierPrefix)', `${team}.`))) : {}
  const entitlements = {
    'application-identifier': `${team}.${bundleIdentifier}`,
    ...own,
    'com.apple.developer.team-identifier': team
  }
  // A development profile lets a debugger attach, and a build signed with one says so.
  if (profile.entitlements['get-task-allow'] === true) entitlements['get-task-allow'] = true
  return entitlements
}

/** The code a bundle holds, deepest first, so that each is signed before what seals it. */
export function nestedCode(bundle) {
  const found = []
  for (const folder of ['Frameworks', 'PlugIns']) {
    const at = join(bundle, folder)
    if (!existsSync(at)) continue
    for (const entry of readdirSync(at).sort()) {
      const path = join(at, entry)
      if (/\.(framework|appex|xctest)$/.test(entry)) {
        found.push(...nestedCode(path), path)
      } else if (entry.endsWith('.dylib')) {
        found.push(path)
      }
    }
  }
  return found
}

/**
 * Everything to sign, in the order to sign it. `bundles` maps the path of each bundle a profile
 * covers (relative to `root`, empty for the root itself) to what it is signed with; anything else
 * nested is a library, signed with the entitlements it has, and an extension is never a library.
 */
export function signingPlan(root, bundles) {
  const items = nestedCode(root).map((path) => {
    const relative = path.slice(root.length + 1)
    // An extension with no profile would be signed as a library and could not run, so it is refused.
    if (relative.endsWith('.appex') && !bundles[relative]) throw new Error(`${relative} has no profile to be signed with`)
    return { path, relative, ...(bundles[relative] ? { covered: bundles[relative] } : { library: true }) }
  })
  items.push({ path: root, relative: '', covered: bundles[''] })
  return items
}

const SHA1 = /^[0-9A-F]{40}$/

function codesign(args) {
  const answer = spawnSync('codesign', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
  if (answer.error) throw answer.error
  return answer
}

/** Signs one item, and fails loudly when the signer does. */
function signItem(item, { identity, keychain }, scratch) {
  const common = ['--force', '--sign', identity, '--timestamp=none']
  if (keychain) common.push('--keychain', keychain)
  let args
  if (item.library) {
    args = [...common, '--preserve-metadata=identifier,entitlements,flags', item.path]
  } else {
    const { profile, entitlements } = item.covered
    copyFileSync(profile.path, join(item.path, 'embedded.mobileprovision'))
    const json = join(scratch, `${basename(item.path)}.json`)
    const plist = join(scratch, `${basename(item.path)}.plist`)
    writeFileSync(json, JSON.stringify(entitlements))
    const converted = spawnSync('plutil', ['-convert', 'xml1', '-o', plist, '--', json], { encoding: 'utf8' })
    if (converted.status !== 0) throw new Error(`the entitlements of ${item.path} cannot be written: ${converted.stderr}`)
    args = [...common, '--generate-entitlement-der', '--entitlements', plist, item.path]
  }
  const answer = codesign(args)
  if (answer.status !== 0) throw new Error(`codesign failed on ${item.path}: ${answer.stderr.trim()}`)
}

/** Signs the whole plan. The identity is a SHA-1 unless the caller says it is ad hoc. */
export function signAll(plan, options) {
  const scratch = mkdtempSync(join(tmpdir(), 'kr-sign-'))
  try {
    for (const item of plan) {
      signItem(item, options, scratch)
      console.log(`signed ${item.relative === '' ? '.' : item.relative}`)
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
}

/**
 * What a signature's description says that is wrong. `adHoc` is for a signature that names no
 * certificate; a real one is the identity's chain under the team, ending in Apple's root.
 */
export function problemsInDescription(text, { identifier, team, adHoc = false }) {
  const problems = []
  const line = (key) => [...text.matchAll(new RegExp(`^${key}=(.*)$`, 'gm'))].map((each) => each[1])
  if (line('Identifier')[0] !== identifier) problems.push(`its identifier is ${line('Identifier')[0]}, expected ${identifier}`)
  if (adHoc) return problems
  if (line('TeamIdentifier')[0] !== team) problems.push(`its team is ${line('TeamIdentifier')[0]}, expected ${team}`)
  const authorities = line('Authority')
  if (authorities.length !== 3) problems.push(`its chain has ${authorities.length} certificates, expected three`)
  else if (!authorities[0].startsWith('Apple Development: ') || authorities[2] !== 'Apple Root CA') {
    problems.push(`its chain is ${authorities.join(' > ')}, expected an Apple Development certificate under Apple's root`)
  }
  return problems
}

/** The SHA-1 of the certificate a path is signed with, in capitals, or null when there is none. */
function leafHash(path) {
  const scratch = mkdtempSync(join(tmpdir(), 'kr-cert-'))
  try {
    const extracted = codesign(['-d', `--extract-certificates=${join(scratch, 'cert')}`, path])
    const leaf = join(scratch, 'cert0')
    if (extracted.status !== 0 || !existsSync(leaf)) return null
    return createHash('sha1').update(readFileSync(leaf)).digest('hex').toUpperCase()
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
}

/** What is wrong with the signatures of a plan, one sentence each. */
export function problemsInSignatures(plan, { team, adHoc = false, now = new Date(), identifiers = {}, device = null, identity = null }) {
  const problems = []
  for (const item of plan) {
    const name = item.relative === '' ? 'the bundle' : item.relative
    const verified = codesign(['--verify', '--strict', ...(item.relative === '' ? ['--deep'] : []), '--verbose=2', item.path])
    if (verified.status !== 0) {
      problems.push(`${name} does not verify: ${verified.stderr.trim().split('\n')[0]}`)
      continue
    }
    const described = codesign(['-dvv', item.path])
    const identifier = identifiers[item.relative]
    if (identifier) {
      problems.push(...problemsInDescription(described.stderr, { identifier, team, adHoc }).map((each) => `${name}: ${each}`))
    }
    if (identity && !adHoc && leafHash(item.path) !== identity) problems.push(`${name} is signed with another certificate than ${identity}`)
    if (!item.covered) continue
    const { profile, entitlements } = item.covered
    const embedded = join(item.path, 'embedded.mobileprovision')
    if (!existsSync(embedded) || !readFileSync(embedded).equals(readFileSync(profile.path))) {
      problems.push(`${name} does not carry the profile ${profile.name} as embedded.mobileprovision`)
    }
    if (profile.expires <= now) problems.push(`the profile ${profile.name} has expired`)
    if (profile.team !== team) problems.push(`the profile ${profile.name} is for team ${profile.team}, expected ${team}`)
    if (device && !profile.devices.includes(device)) problems.push(`the profile ${profile.name} does not list the phone`)
    problems.push(...problemsOfFit(entitlements, profile).map((each) => `${name}: ${each}`))
    const sealed = codesign(['-d', '--entitlements', '-', '--xml', item.path])
    let found
    try {
      found = sealed.stdout ? plistValue(null, Buffer.from(sealed.stdout)) : {}
    } catch {
      problems.push(`${name}'s sealed entitlements cannot be read`)
      continue
    }
    const wanted = JSON.stringify(Object.entries(entitlements).sort())
    if (JSON.stringify(Object.entries(found).sort()) !== wanted) {
      problems.push(`${name} is sealed with ${JSON.stringify(found)}, expected ${JSON.stringify(entitlements)}`)
    }
  }
  return problems
}

// -- the command line ----------------------------------------------------------------------------

function options(argv) {
  const found = {}
  for (let at = 0; at < argv.length; at += 2) {
    if (!argv[at].startsWith('--') || at + 1 >= argv.length) throw new Error(`${argv[at]} needs a value`)
    found[argv[at].slice(2)] = argv[at + 1]
  }
  return found
}

function need(found, ...names) {
  for (const name of names) if (!found[name]) throw new Error(`--${name} is needed`)
}

function bundleIdentifier(bundle) {
  return plistValue(join(bundle, 'Info.plist')).CFBundleIdentifier
}

/** The plan of the application, its extension and what they hold, and what each is signed with. */
function applicationPlan(app, found, team) {
  const own = { path: app, profile: readProfile(found['app-profile']), source: found['app-entitlements'] }
  const extensionPath = join(app, 'PlugIns', 'KalaReachNotificationService.appex')
  const extension = { path: extensionPath, profile: readProfile(found['extension-profile']), source: found['extension-entitlements'] }
  const bundles = {}
  const identifiers = {}
  for (const [relative, each] of [['', own], ['PlugIns/KalaReachNotificationService.appex', extension]]) {
    const identifier = bundleIdentifier(each.path)
    identifiers[relative] = identifier
    bundles[relative] = {
      profile: each.profile,
      entitlements: entitlementsFor({ source: readFileSync(each.source, 'utf8'), team, bundleIdentifier: identifier, profile: each.profile })
    }
  }
  return { plan: signingPlan(app, bundles), identifiers }
}

function runnerPlan(runner, found, team) {
  const profile = readProfile(found.profile)
  const identifier = bundleIdentifier(runner)
  const entitlements = entitlementsFor({ source: null, team, bundleIdentifier: identifier, profile })
  return { plan: signingPlan(runner, { '': { profile, entitlements } }), identifiers: { '': identifier } }
}

function main(argv) {
  const [mode, bundle, ...rest] = argv
  const found = options(rest)
  const team = declared().team
  if (!['sign-app', 'verify-app', 'sign-runner', 'verify-runner'].includes(mode) || !bundle) {
    throw new Error('Usage: sign-ios.mjs sign-app|verify-app|sign-runner|verify-runner <bundle> [options]')
  }
  const application = mode.endsWith('-app')
  if (application) need(found, 'app-profile', 'extension-profile', 'app-entitlements', 'extension-entitlements')
  else need(found, 'profile')
  const { plan, identifiers } = application ? applicationPlan(bundle, found, team) : runnerPlan(bundle, found, team)
  if (found.identity && !SHA1.test(found.identity)) {
    throw new Error('--identity is the SHA-1 of the certificate, forty hexadecimal digits in capitals')
  }
  if (mode.startsWith('sign')) {
    need(found, 'identity', 'keychain')
    signAll(plan, { identity: found.identity, keychain: found.keychain })
  }
  const problems = problemsInSignatures(plan, { team, identifiers, device: found.device ?? null, identity: found.identity ?? null })
  if (application) problems.push(...problemsInBundle(bundle))
  if (problems.length === 0) {
    console.log(`${bundle}: every signature holds`)
    return 0
  }
  console.error(`${bundle}:\n${problems.map((each) => `  ${each}`).join('\n')}`)
  return 1
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    process.exitCode = main(process.argv.slice(2))
  } catch (failure) {
    console.error(failure.message)
    process.exitCode = 2
  }
}
