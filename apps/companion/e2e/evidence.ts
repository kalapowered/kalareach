/**
 * Where the browser tests keep what they produce.
 *
 * Section 27 puts every test artefact in one platform-resolved directory, `KR_TEST_ARTIFACTS_DIR`,
 * and the landing workflow uploads that directory as the run's evidence. A screenshot written
 * anywhere else is lost with the runner, so every screenshot in these tests takes its path from
 * here. Without the variable the directory is a fixed one under `/tmp`.
 *
 * Declared against `node:process` for the same reason `served.ts` is: the browser tests are
 * type-checked with the interface's own settings, which carry no Node types.
 */

import { env } from 'node:process'

/** The directory for this run's artefacts. */
export const ARTEFACTS: string = env['KR_TEST_ARTIFACTS_DIR'] ?? '/tmp/kr-test-artifacts'

/** The path of the screenshot called `name`, without its extension. */
export function screenshotPath(name: string): string {
  return `${ARTEFACTS}/companion-screenshots/${name}.png`
}
