#!/usr/bin/env node
// Puts Firebase's configuration into the Android application being built.
//
// The configuration belongs to the account that owns the Firebase project, not to this repository,
// so it is read from the file `KR_GOOGLE_SERVICES_JSON` names, which is the `google-services.json`
// the project's console gives. What the Google Gradle plugin makes of that file is a set of string
// resources Firebase's own initialisation reads at start, and this writes the same resources
// without the plugin, which would be one more thing to fetch. A debug build without the variable
// runs and leaves Firebase alone; a build told of a file that is not usable fails, since a mistyped
// path or a file for another application would otherwise give a build that quietly cannot receive a
// notification; and a release build without the variable fails, because a release that cannot
// receive a notification is not one to ship. What an earlier build wrote into the output directory
// is removed first, so a build without the file never carries another's.
//
//   node scripts/firebase-android-configuration.mjs <output directory> <debug|release> <application id>
//
// The resources are written to `<output directory>/values/firebase.xml`.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { argv, env, exit, stderr, stdout } from 'node:process'
import { pathToFileURL } from 'node:url'

/** The resource names Firebase reads, from the fields of `google-services.json` that give them. */
export function resourcesFor(configuration, applicationId) {
  const info = configuration.project_info ?? {}
  const clients = Array.isArray(configuration.client) ? configuration.client : []
  const client = clients.find((each) => each?.client_info?.android_client_info?.package_name === applicationId)
  if (client === undefined) {
    throw new Error(`the file holds no client for the application ${applicationId}`)
  }
  const appId = client.client_info?.mobilesdk_app_id
  const apiKey = client.api_key?.[0]?.current_key
  const senderId = info.project_number
  const projectId = info.project_id
  for (const [name, value] of [
    ['a mobilesdk_app_id', appId],
    ['an api key', apiKey],
    ['a project_number', senderId],
    ['a project_id', projectId]
  ]) {
    if (typeof value !== 'string' || value === '') throw new Error(`the file's client for ${applicationId} has no ${name}`)
  }
  const resources = {
    gcm_defaultSenderId: senderId,
    google_api_key: apiKey,
    google_app_id: appId,
    google_crash_reporting_api_key: apiKey,
    project_id: projectId
  }
  if (typeof info.firebase_url === 'string' && info.firebase_url !== '') resources.firebase_database_url = info.firebase_url
  if (typeof info.storage_bucket === 'string' && info.storage_bucket !== '') resources.google_storage_bucket = info.storage_bucket
  return resources
}

/** The resource file's text: one `translatable="false"` string for each resource. */
export function resourceFile(resources) {
  const escape = (value) =>
    value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, "\\'").replace(/"/g, '\\"')
  const lines = Object.entries(resources)
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([name, value]) => `    <string name="${name}" translatable="false">${escape(value)}</string>`)
  return `<?xml version="1.0" encoding="utf-8"?>\n<resources>\n${lines.join('\n')}\n</resources>\n`
}

/** Runs the step. Returns the process's exit status and says what it did. */
export function run({ output, buildType, applicationId, file }) {
  const destination = join(output, 'values', 'firebase.xml')
  rmSync(destination, { force: true })
  if (file !== undefined && file !== '') {
    if (!existsSync(file)) {
      stderr.write(`error: KR_GOOGLE_SERVICES_JSON names ${file}, which is not a file\n`)
      return 1
    }
    let resources
    try {
      resources = resourcesFor(JSON.parse(readFileSync(file, 'utf8')), applicationId)
    } catch (failure) {
      stderr.write(`error: KR_GOOGLE_SERVICES_JSON names ${file}, which cannot be used: ${failure.message}\n`)
      return 1
    }
    mkdirSync(join(output, 'values'), { recursive: true })
    writeFileSync(destination, resourceFile(resources))
    return 0
  }
  if (buildType === 'release') {
    stderr.write('error: a release build needs KR_GOOGLE_SERVICES_JSON to name a google-services.json\n')
    return 1
  }
  stdout.write('note: no google-services.json named by KR_GOOGLE_SERVICES_JSON, so Firebase is left alone\n')
  return 0
}

if (import.meta.url === pathToFileURL(argv[1] ?? '').href) {
  const [output, buildType, applicationId] = argv.slice(2)
  if (!output || !['debug', 'release'].includes(buildType) || !applicationId) {
    stderr.write('usage: firebase-android-configuration.mjs <output directory> <debug|release> <application id>\n')
    exit(2)
  }
  exit(run({ output, buildType, applicationId, file: env.KR_GOOGLE_SERVICES_JSON }))
}
