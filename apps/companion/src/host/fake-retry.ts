/**
 * The retry category a scripted host gives the code of a failure it rejects with.
 *
 * Native code hands the page the category of every code it fails with, as the protocol sorts it,
 * and the page tells a host's definite refusal from one for now by it. A scripted host does the
 * same, so a screen under test reads a failure as it reads one from the application. The table
 * below is the protocol's category of every code it has; a code the protocol does not have, which
 * a test may invent, is `no_retry`.
 */

import type { HostError } from './port'

/** The protocol's category of each of its codes. */
const CATEGORY = new Map<string, HostError['retry']>([
  // The host cannot take the request now.
  ['RENDEZVOUS_UNAVAILABLE', 'transient'],
  ['TERMINAL_UNAVAILABLE', 'transient'],
  ['TERMINAL_PROBE_FAILED', 'transient'],
  ['SESSION_LIMIT', 'transient'],
  ['RESOURCE_UNAVAILABLE', 'transient'],
  ['ENVIRONMENT_UNAVAILABLE', 'transient'],
  ['DESKTOP_UNAVAILABLE', 'transient'],
  ['EDITOR_BUSY', 'transient'],
  ['UPSTREAM_UNAVAILABLE', 'transient'],
  ['RATE_LIMITED', 'transient'],
  ['SERVICE_CAPACITY', 'transient'],
  ['STORAGE_UNAVAILABLE', 'transient'],
  ['PACKAGE_UNAVAILABLE_OFFLINE', 'transient'],
  // The host cannot say whether the request happened.
  ['OUTCOME_UNKNOWN', 'outcome_unknown'],
  // Retrying the same request cannot succeed until something is changed.
  ['INVALID_ARGUMENT', 'configuration_change'],
  ['UNSUPPORTED_SCHEMA', 'configuration_change'],
  ['UNSUPPORTED_CAPABILITY', 'configuration_change'],
  ['PERMISSION_DENIED', 'configuration_change'],
  ['PAIRING_AUTH_FAILED', 'configuration_change'],
  ['RENDEZVOUS_CONFIG_ERROR', 'configuration_change'],
  ['INPUT_INCOMPATIBLE', 'configuration_change'],
  ['HOST_NOT_CONFIGURED', 'configuration_change'],
  ['CLOCK_UNTRUSTED', 'configuration_change'],
  ['SHELL_INTEGRATION_UNSUPPORTED', 'configuration_change'],
  ['REPOSITORY_UNTRUSTED', 'configuration_change'],
  ['PLUGIN_GRANT_REQUIRED', 'configuration_change'],
  ['PLUGIN_DISABLED', 'configuration_change'],
  ['NOT_IN_KR_SESSION', 'configuration_change'],
  // The view is stale and is read again.
  ['RESYNC_REQUIRED', 'resync'],
  // Retrying the same request is no use; a new action or a new subject version is.
  ['PAIRING_EXPIRED', 'no_retry'],
  ['PAIRING_REJECTED', 'no_retry'],
  ['PAIRING_ATTEMPTS_EXHAUSTED', 'no_retry'],
  ['UNKNOWN_SESSION', 'no_retry'],
  ['AMBIGUOUS_SESSION', 'no_retry'],
  ['AMBIGUOUS_ATTACHMENT', 'no_retry'],
  ['SESSION_CLOSED', 'no_retry'],
  ['STALE_SESSION', 'no_retry'],
  ['LEASE_LOST', 'no_retry'],
  ['GEOMETRY_NOT_OWNER', 'no_retry'],
  ['DRAFT_CONFLICT', 'no_retry'],
  ['ID_CONFLICT', 'no_retry'],
  ['QUOTA_EXCEEDED', 'no_retry'],
  ['ATTACHMENT_INTEGRITY', 'no_retry'],
  ['QUESTION_RESOLVED', 'no_retry'],
  ['QUESTION_EXPIRED', 'no_retry'],
  ['OWNER_CONFIRMATION_REQUIRED', 'no_retry'],
  ['CAUSAL_LIMIT', 'no_retry'],
  ['SOURCE_CHANGED', 'no_retry']
])

/** The retry category of `code`. */
export function fakeRetryOf(code: string): HostError['retry'] {
  return CATEGORY.get(code) ?? 'no_retry'
}
