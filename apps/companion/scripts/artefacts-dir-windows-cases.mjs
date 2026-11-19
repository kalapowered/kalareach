#!/usr/bin/env node
// Says whether the evidence directory reader's Windows-only cases ran and passed.
//
// Usage: node scripts/artefacts-dir-windows-cases.mjs <report.json>
//
// <report.json> is what Vitest's JSON reporter wrote for `test/artefacts-dir.test.ts`. Three cases
// of that file run only on Windows and are skipped everywhere else, and a skipped case does not
// fail a run. Vitest's own exit therefore cannot say that they ran on the one platform that exists
// to run them. This reads the report and refuses a run in which any of them is missing, skipped,
// failed or found more than once. Exit 0 when each of them passed exactly once, 1 when one did not,
// and 2 when the report could not be read.
import { readFileSync } from 'node:fs'

/** The test file the report must hold, as the path the report names it by ends. */
const FILE = 'test/artefacts-dir.test.ts'

/**
 * The title of every case in that file that is skipped off Windows, as the file writes it. The
 * conformance suite holds this list to the file's own `skipIf(!windows)` cases.
 */
const WINDOWS_CASES = [
  'takes a runner folder that depends on the current drive for no root',
  'refuses the spellings it does not take, and names those it takes',
  'reads every spelling that a platform gives as the same folder'
]

function unreadable(reason) {
  process.stderr.write(`artefacts-dir-windows-cases: ${reason}\n`)
  process.exit(2)
}

const path = process.argv[2]
if (process.argv.length !== 3 || path === undefined) {
  unreadable('usage: node scripts/artefacts-dir-windows-cases.mjs <report.json>')
}

let report
try {
  report = JSON.parse(readFileSync(path, 'utf8'))
} catch (error) {
  unreadable(`${path} is not a report that can be read: ${error.message}`)
}

const results = Array.isArray(report?.testResults) ? report.testResults : null
if (results === null) unreadable(`${path} holds no testResults list`)

const ofFile = results.filter(
  (result) =>
    typeof result?.name === 'string' && result.name.replaceAll('\\', '/').endsWith(`/${FILE}`)
)
if (ofFile.length !== 1) {
  process.stderr.write(`the report holds ${ofFile.length} results for ${FILE}, not one\n`)
  process.exit(1)
}

const cases = Array.isArray(ofFile[0].assertionResults) ? ofFile[0].assertionResults : []
const refused = []
for (const title of WINDOWS_CASES) {
  const found = cases.filter((one) => one?.title === title)
  if (found.length !== 1) {
    refused.push(`"${title}": found ${found.length} times, not once`)
  } else if (found[0].status !== 'passed') {
    refused.push(`"${title}": ${String(found[0].status)}, not passed`)
  } else {
    process.stdout.write(`passed: ${title}\n`)
  }
}

if (refused.length > 0) {
  process.stderr.write(`the Windows-only cases of ${FILE} did not all pass:\n`)
  for (const line of refused) process.stderr.write(`  ${line}\n`)
  process.exit(1)
}
