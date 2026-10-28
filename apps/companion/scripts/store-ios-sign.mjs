#!/usr/bin/env node
// Gives an unsigned iOS archive the entitlements its signature will seal, so that an export can
// carry them into the signed application.
//
// `tauri ios build --no-sign` leaves an archive whose application and notification extension have
// no signature and so no entitlements: no push, no associated domains, no keychain groups. An
// export re-signs every bundle, and it keeps the entitlements it finds in the signature it
// replaces, so an archive with none exports into an application with none (the push entitlement
// is then missing from the build App Store Connect receives, and the keychain groups the
// application and its extension read are empty). This signs the archive ad hoc, inside out, with
// the entitlements of the two source files, the team's prefix in place of the placeholder and the
// production push environment, which is the one a store build has. The signature is replaced by
// the export; it names no certificate and proves nothing about the build.
//
// Usage: node scripts/store-ios-sign.mjs <KalaReach.app> <team> [--print]
// `--print` shows the entitlements each bundle would be signed with and signs nothing.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

import { plistValue } from './identifiers.mjs'
import { entitlementsFor, nestedCode } from './sign-ios.mjs'

const GEN = join(import.meta.dirname, '..', 'src-tauri', 'gen', 'apple')

/** The files the two bundles' entitlements are written in. */
export const ENTITLEMENT_SOURCES = {
  application: join(GEN, 'companion-tauri_iOS', 'companion-tauri_iOS.entitlements'),
  extension: join(GEN, 'KalaReachNotificationService', 'KalaReachNotificationService.entitlements')
}

/** What the application and the extension are signed with. */
export function entitlementsOfArchive(app, team, sources = ENTITLEMENT_SOURCES) {
  const identifier = (folder) => plistValue(join(folder, 'Info.plist')).CFBundleIdentifier
  const noProfile = { entitlements: {} }
  const application = entitlementsFor({
    source: readFileSync(sources.application, 'utf8'),
    team,
    bundleIdentifier: identifier(app),
    profile: noProfile
  })
  // The environment of a store build: development belongs to a build a debugger attaches to.
  application['aps-environment'] = 'production'
  application['get-task-allow'] = false
  const extension = entitlementsFor({
    source: readFileSync(sources.extension, 'utf8'),
    team,
    bundleIdentifier: identifier(join(app, 'PlugIns', 'KalaReachNotificationService.appex')),
    profile: noProfile
  })
  extension['get-task-allow'] = false
  return { application, extension }
}

function codesign(args) {
  const answer = spawnSync('codesign', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
  if (answer.error) throw answer.error
  if (answer.status !== 0) throw new Error(`codesign ${args.at(-1)}: ${answer.stderr.trim()}`)
}

/** Signs everything in the application ad hoc, deepest first. */
export function signArchive(app, team) {
  const wanted = entitlementsOfArchive(app, team)
  const scratch = mkdtempSync(join(tmpdir(), 'kr-store-sign-'))
  try {
    const plistOf = (name, entitlements) => {
      const json = join(scratch, `${name}.json`)
      const plist = join(scratch, `${name}.plist`)
      writeFileSync(json, JSON.stringify(entitlements))
      const converted = spawnSync('plutil', ['-convert', 'xml1', '-o', plist, '--', json], { encoding: 'utf8' })
      if (converted.status !== 0) throw new Error(`the entitlements of ${name} cannot be written: ${converted.stderr}`)
      return plist
    }
    const base = ['--force', '--sign', '-', '--timestamp=none']
    for (const path of nestedCode(app)) {
      if (path.endsWith('.appex')) {
        codesign([...base, '--generate-entitlement-der', '--entitlements', plistOf('extension', wanted.extension), path])
      } else {
        codesign([...base, '--preserve-metadata=identifier,entitlements,flags', path])
      }
    }
    codesign([...base, '--generate-entitlement-der', '--entitlements', plistOf('application', wanted.application), app])
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
  return wanted
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const [app, team, flag] = process.argv.slice(2)
  if (!app || !/^[A-Z0-9]{10}$/.test(team ?? '')) {
    console.error('usage: store-ios-sign.mjs <KalaReach.app> <team> [--print]')
    process.exit(2)
  }
  try {
    const wanted = flag === '--print' ? entitlementsOfArchive(app, team) : signArchive(app, team)
    console.log(JSON.stringify(wanted, null, 2))
  } catch (failure) {
    console.error(failure.message)
    process.exit(2)
  }
}
