#!/usr/bin/env node
// Holds the build step that puts Firebase's configuration into the Android application to its rules.
//
// The configuration belongs to the account that owns the Firebase project and is not in this
// repository, so a build makes the resources Firebase reads from the `google-services.json` that
// `KR_GOOGLE_SERVICES_JSON` names. Four things must hold and none can be seen from a successful
// build. A debug build without the file runs and says it left Firebase alone; one told of a file
// that is not there, or that holds nothing for this application, fails, since a mistyped path would
// otherwise give a build that quietly cannot receive a notification. A release build without the
// file fails, because a release that cannot receive a notification is not one to ship. A copy an
// earlier build left never survives into a build that has none, which would put one account's
// configuration in another's build. And the resources are the ones Firebase reads, each with the
// value the file gives it.
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = join(dirname(fileURLToPath(import.meta.url)), 'firebase-android-configuration.mjs')
const work = mkdtempSync(join(tmpdir(), 'kr-firebase-android-'))
const applicationId = 'to.kala.reach'
let failures = 0

function held(what, expected, answer) {
  if (JSON.stringify(answer) === JSON.stringify(expected)) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${JSON.stringify(expected)}\n        answered: ${JSON.stringify(answer)}`)
}

/** Runs the step the way Gradle does, in an output directory of its own. */
function build({ buildType, file, leftover }) {
  const output = mkdtempSync(join(work, 'res-'))
  const written = join(output, 'values', 'firebase.xml')
  if (leftover !== undefined) {
    mkdirSync(join(output, 'values'))
    writeFileSync(written, leftover)
  }
  const environment = { PATH: process.env.PATH ?? '' }
  if (file !== undefined) environment.KR_GOOGLE_SERVICES_JSON = file
  const result = spawnSync(process.execPath, [script, output, buildType, applicationId], { env: environment, encoding: 'utf8' })
  return {
    status: result.status,
    output: `${result.stdout}${result.stderr}`,
    written: existsSync(written) ? readFileSync(written, 'utf8') : null
  }
}

const configuration = (extra = {}) => ({
  project_info: {
    project_number: '123456789012',
    project_id: 'kalareach-test',
    storage_bucket: 'kalareach-test.appspot.com',
    ...extra
  },
  client: [
    {
      client_info: { mobilesdk_app_id: '1:123456789012:android:other', android_client_info: { package_name: 'com.example.other' } },
      api_key: [{ current_key: 'other-key' }]
    },
    {
      client_info: { mobilesdk_app_id: '1:123456789012:android:abcdef', android_client_info: { package_name: applicationId } },
      api_key: [{ current_key: 'AIza-this-key' }]
    }
  ]
})

const mine = join(work, 'google-services.json')
writeFileSync(mine, JSON.stringify(configuration()))

for (const buildType of ['debug', 'release']) {
  const built = build({ buildType, file: mine })
  const text = built.written ?? ''
  held(
    `a ${buildType} build writes the resources Firebase reads, from the client for this application`,
    'ok',
    built.status === 0 &&
      text.includes('<string name="google_app_id" translatable="false">1:123456789012:android:abcdef</string>') &&
      text.includes('<string name="gcm_defaultSenderId" translatable="false">123456789012</string>') &&
      text.includes('<string name="google_api_key" translatable="false">AIza-this-key</string>') &&
      text.includes('<string name="project_id" translatable="false">kalareach-test</string>') &&
      text.includes('<string name="google_storage_bucket" translatable="false">kalareach-test.appspot.com</string>') &&
      !text.includes('other-key') &&
      !text.includes('firebase_database_url')
      ? 'ok'
      : `status ${built.status}, wrote ${text}`
  )
}

{
  const built = build({ buildType: 'debug' })
  held('a debug build with no file runs and says it left Firebase alone', 'ok', built.status === 0 && built.written === null && /Firebase is left alone/.test(built.output) ? 'ok' : `status ${built.status}, ${built.output}`)
}
{
  const built = build({ buildType: 'release' })
  held('a release build with no file fails, naming the variable', 'ok', built.status === 1 && /KR_GOOGLE_SERVICES_JSON/.test(built.output) && built.written === null ? 'ok' : `status ${built.status}, ${built.output}`)
}
for (const buildType of ['debug', 'release']) {
  const built = build({ buildType, file: join(work, 'not-there.json') })
  held(`a ${buildType} build told of a file that is not there fails`, 'ok', built.status === 1 && /is not a file/.test(built.output) && built.written === null ? 'ok' : `status ${built.status}, ${built.output}`)
}
{
  const other = join(work, 'other.json')
  writeFileSync(other, JSON.stringify({ ...configuration(), client: [configuration().client[0]] }))
  const built = build({ buildType: 'debug', file: other })
  held('a file with no client for this application fails and writes nothing', 'ok', built.status === 1 && /holds no client for the application/.test(built.output) && built.written === null ? 'ok' : `status ${built.status}, ${built.output}`)
}
{
  const broken = join(work, 'broken.json')
  writeFileSync(broken, '{ not json')
  const built = build({ buildType: 'debug', file: broken })
  held('a file that is not JSON fails', 'ok', built.status === 1 && /cannot be used/.test(built.output) ? 'ok' : `status ${built.status}, ${built.output}`)
}
for (const buildType of ['debug', 'release']) {
  const built = build({ buildType, leftover: '<resources>another account</resources>' })
  held(`what an earlier build left is removed by a ${buildType} build that has no file`, null, built.written)
}
{
  const withDatabase = join(work, 'database.json')
  writeFileSync(withDatabase, JSON.stringify(configuration({ firebase_url: 'https://kalareach-test.firebaseio.com' })))
  const built = build({ buildType: 'debug', file: withDatabase })
  held('a database address in the file is carried', true, (built.written ?? '').includes('<string name="firebase_database_url" translatable="false">https://kalareach-test.firebaseio.com</string>'))
}
{
  const tricky = join(work, 'tricky.json')
  const value = configuration()
  value.client[1].api_key[0].current_key = `a&b<c>"d'e`
  writeFileSync(tricky, JSON.stringify(value))
  const built = build({ buildType: 'debug', file: tricky })
  held('a value is escaped the way Android reads a resource', true, (built.written ?? '').includes('a&amp;b&lt;c&gt;\\"d\\\'e'))
}

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} check(s) failed`)
  process.exit(1)
}
console.log('every check held')
