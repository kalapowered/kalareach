#!/usr/bin/env node
// Holds the build step that puts Firebase's configuration into the application to its rules.
//
// The configuration belongs to the account that owns the Firebase project and is not in this
// repository, so a build copies it from the path `KR_GOOGLE_SERVICE_INFO` names. Three things must
// hold and none can be seen from a successful build. A debug build without the file runs and says
// it left Firebase alone. A release build without it fails, because a release that cannot receive a
// notification is not one to ship. And a copy an earlier build left in the product never survives
// into a build that has none, which would put one account's configuration in another's build.
// The step is a script of its own so it can be run here, with the variables Xcode gives it.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = join(dirname(fileURLToPath(import.meta.url)), 'copy-firebase-configuration.sh')
const work = mkdtempSync(join(tmpdir(), 'kr-firebase-configuration-'))
let failures = 0

function held(what, expected, answer) {
  if (JSON.stringify(answer) === JSON.stringify(expected)) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${JSON.stringify(expected)}\n        answered: ${JSON.stringify(answer)}`)
}

/** Runs the step the way Xcode does, in a product folder of its own. */
function build({ configuration, plist, leftover }) {
  const product = mkdtempSync(join(work, 'product-'))
  const resources = 'Resources'
  mkdirSync(join(product, resources))
  const copied = join(product, resources, 'GoogleService-Info.plist')
  if (leftover !== undefined) writeFileSync(copied, leftover)
  const environment = {
    PATH: process.env.PATH ?? '',
    TARGET_BUILD_DIR: product,
    UNLOCALIZED_RESOURCES_FOLDER_PATH: resources,
    CONFIGURATION: configuration
  }
  if (plist !== undefined) environment.KR_GOOGLE_SERVICE_INFO = plist
  const result = spawnSync('bash', [script], { env: environment, encoding: 'utf8' })
  return {
    status: result.status,
    output: `${result.stdout}${result.stderr}`,
    copied: existsSync(copied) ? readFileSync(copied, 'utf8') : null
  }
}

const mine = join(work, 'GoogleService-Info.plist')
writeFileSync(mine, '<plist>this account</plist>')

for (const configuration of ['debug', 'release']) {
  const built = build({ configuration, plist: mine })
  held(`a ${configuration} build copies the file the variable names`, 'ok', built.status === 0 && built.copied === '<plist>this account</plist>' ? 'ok' : `status ${built.status}, copied ${built.copied}`)
}

const bare = build({ configuration: 'debug' })
held('a debug build without the variable runs', 0, bare.status)
held('a debug build without the variable carries no file', null, bare.copied)
held('a debug build without the variable says Firebase is left alone', true, /Firebase is left alone/.test(bare.output))

const missing = build({ configuration: 'debug', plist: join(work, 'not-there.plist') })
held('a debug build whose file is not there runs and carries none', 'ok', missing.status === 0 && missing.copied === null ? 'ok' : `status ${missing.status}, copied ${missing.copied}`)

const release = build({ configuration: 'release' })
held('a release build without the variable fails', true, release.status !== 0)
held('a release build without the variable names the variable', true, /KR_GOOGLE_SERVICE_INFO/.test(release.output))
held('a release build without the variable carries no file', null, release.copied)

const releaseMissing = build({ configuration: 'release', plist: join(work, 'not-there.plist') })
held('a release build whose file is not there fails', true, releaseMissing.status !== 0)

const stale = build({ configuration: 'debug', leftover: '<plist>another build</plist>' })
held("a build without a file does not carry an earlier build's", null, stale.copied)
const staleRelease = build({ configuration: 'release', leftover: '<plist>another build</plist>' })
held("a failed release build does not leave an earlier build's file", null, staleRelease.copied)

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`\n${failures} case${failures === 1 ? '' : 's'} failed`)
  process.exit(1)
}
console.log('\nevery case held')
