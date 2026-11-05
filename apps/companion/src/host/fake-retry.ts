/**
 * The retry category a scripted host gives the code of a failure it rejects with.
 *
 * Native code hands the page the category of every code it fails with, as the protocol sorts it,
 * and the page tells a host's definite refusal from one for now by it. A scripted host does the
 * same, so a screen under test reads a failure as it reads one from the application. The codes
 * below are the protocol's transient category; `OUTCOME_UNKNOWN` is its own; any other code is
 * a definite word.
 */

import type { HostError } from './port'

/** The codes the host answers with when it cannot take a request now. */
const TRANSIENT: ReadonlySet<string> = new Set([
  'RENDEZVOUS_UNAVAILABLE',
  'TERMINAL_UNAVAILABLE',
  'TERMINAL_PROBE_FAILED',
  'SESSION_LIMIT',
  'RESOURCE_UNAVAILABLE',
  'ENVIRONMENT_UNAVAILABLE',
  'DESKTOP_UNAVAILABLE',
  'EDITOR_BUSY',
  'UPSTREAM_UNAVAILABLE',
  'RATE_LIMITED',
  'SERVICE_CAPACITY',
  'STORAGE_UNAVAILABLE',
  'PACKAGE_UNAVAILABLE_OFFLINE'
])

/** The retry category of `code`. */
export function fakeRetryOf(code: string): HostError['retry'] {
  if (code === 'OUTCOME_UNKNOWN') return 'outcome_unknown'
  return TRANSIENT.has(code) ? 'transient' : 'no_retry'
}
