/**
 * What a capability record says, in the words a person reads.
 *
 * The host writes its answers in the protocol's own vocabulary, which is deliberately finer than
 * the four words the product uses for a person: it separates a tool that is not installed from a
 * permission that is not granted, and it separates "nobody has established this" from "this does
 * not work". Those distinctions matter to the host. Here they become the four states the product
 * names, plus the two the four do not cover, which are shown as themselves rather than pressed
 * into a word that would be untrue.
 *
 * One of the four is not in the record at all. `restart_required` is not a state a host can
 * report, because a host cannot see a grant it does not hold; it is a thing that becomes true
 * between two readings. The person opened the settings pane for a permission, granted it, and the
 * capability still reports that the permission is required. On this platform that is what a grant
 * arriving after a process started looks like, and the answer is to open the application again.
 * That is why [`displayState`] takes what happened as well as what was read.
 */

import type { CapabilityRecord } from '@kalareach/protocol'

/** What one capability is shown as. */
export type DisplayState =
  | 'ready'
  | 'permission_required'
  | 'restart_required'
  | 'desktop_unavailable'
  | 'not_established'
  | 'not_installed'
  | 'not_checked'

/** What happened in this run that a reading alone does not say. */
export interface SinceRead {
  /**
   * Whether every grant that governs this capability has been opened in System Settings and the
   * record has been read again since.
   *
   * Every one of them, not any one. Two grants stand behind sending a keystroke, and a person who
   * has just granted one of them is still waiting on the other: telling them to restart would send
   * them the wrong way.
   */
  readonly grantWasOffered: boolean
}

/**
 * The state one record is shown as.
 *
 * Nothing here upgrades an answer. A record that says the operation has not been performed is
 * shown as one that has not been performed, and never as ready: a capability the host has not
 * established is exactly what the person needs to see.
 */
export function displayState(record: CapabilityRecord, since: SinceRead): DisplayState {
  switch (record.state) {
    case 'qualified_available':
      return 'ready'
    case 'permission_required':
      return since.grantWasOffered ? 'restart_required' : 'permission_required'
    case 'temporarily_unavailable':
      // A check that performed the operation and did not get far enough says so. Calling that a
      // desktop that is not there would send somebody looking for a desktop they are sitting at.
      return record.evidence_source === 'disclosed_probe'
        ? 'not_established'
        : 'desktop_unavailable'
    case 'incompatible':
      return 'desktop_unavailable'
    case 'missing_installation':
      return 'not_installed'
    case 'not_tested':
      return 'not_checked'
  }
}

/** What each state is called on screen. */
export const STATE_LABEL: Readonly<Record<DisplayState, string>> = {
  ready: 'Ready',
  permission_required: 'Permission required',
  restart_required: 'Restart required',
  desktop_unavailable: 'Desktop unavailable',
  not_established: 'Not established',
  not_installed: 'Tool not installed',
  not_checked: 'Not checked'
}

/** The tone each state is drawn in. */
export const STATE_TONE: Readonly<
  Record<DisplayState, 'success' | 'warning' | 'danger' | 'neutral' | 'accent'>
> = {
  ready: 'success',
  permission_required: 'warning',
  restart_required: 'accent',
  desktop_unavailable: 'neutral',
  not_established: 'neutral',
  not_installed: 'neutral',
  not_checked: 'neutral'
}

/**
 * The one sentence a state adds beyond the host's own reason.
 *
 * The host says what it found. This says what it means for the person in front of the machine,
 * which is a different sentence and belongs to the interface.
 *
 * Two of them depend on what produced the answer, because the same state means different things
 * from a check that performed the operation and from a question put to the platform. Saying "this
 * machine did the thing" about an answer nothing performed would be the kind of small untruth this
 * whole screen exists to avoid.
 */
export function stateMeaning(
  state: DisplayState,
  evidence: CapabilityRecord['evidence_source']
): string {
  const probed = evidence === 'disclosed_probe'
  switch (state) {
    case 'ready':
      return probed
        ? 'This machine did the thing and it worked.'
        : 'The operating system says nothing stands in the way. Nothing has done it yet.'
    case 'permission_required':
      return probed
        ? 'macOS refused it. The grant is yours to give.'
        : 'This needs a grant macOS has not given. The grant is yours to give.'
    case 'restart_required':
      return (
        'You have been to every settings pane behind this and the answer has not moved. macOS ' +
        'gives a new grant to a process when it starts, so opening KalaReach again is the next ' +
        'thing to try.'
      )
    case 'desktop_unavailable':
      return 'There is no desktop to do it on right now.'
    case 'not_established':
      return 'This did not get far enough to establish anything. The reason is below.'
    case 'not_installed':
      return 'The tool this uses is not on this machine, so there is nothing to grant.'
    case 'not_checked':
      return 'Nothing has done this yet, so nothing is known about it either way.'
  }
}

/** What produced an answer, in words. */
export const EVIDENCE_LABEL: Readonly<Record<CapabilityRecord['evidence_source'], string>> = {
  disclosed_probe: 'a check that performed the operation',
  platform_query: 'a question to the operating system',
  signed_compatibility_record: 'a signed record about this version',
  not_probed: 'nothing has been run'
}

/** What makes an answer stale, in words. */
export const INVALIDATION_LABEL: Readonly<
  Record<CapabilityRecord['invalidation'][number], string>
> = {
  binary_identity: 'the tool is replaced',
  binding_identity: 'the live binding changes',
  package_schema: 'the package changes',
  os_permission: 'a permission changes',
  desktop_generation: 'you log in again',
  worker_profile: 'the execution profile changes'
}

/** What one capability is called on screen. */
export const CAPABILITY_LABEL: Readonly<Record<string, string>> = {
  'desktop.screen_capture': 'Take a screen image',
  'desktop.input_injection': 'Send a keystroke or a click',
  'desktop.accessibility': 'Read the accessibility tree',
  'desktop.application_launch': 'Open an application',
  'desktop.display_server': 'Reach the display',
  'desktop.authorised_file_read': 'Read a file you authorised'
}

/** The name to show for a capability, falling back to the host's own name. */
export function capabilityLabel(capability: string): string {
  return CAPABILITY_LABEL[capability] ?? capability
}

/** How many capabilities are in each state. */
export interface Tally {
  readonly ready: number
  readonly waiting: number
  readonly unchecked: number
  readonly total: number
}

/**
 * Counts what the records say.
 *
 * Progress is counted from established answers and from nothing else. A capability nobody has
 * performed the operation for counts as unchecked, never as done, because a first-run flow that
 * showed four of four complete on a machine where nothing had been established would be lying to
 * somebody who is about to rely on it.
 */
export function tally(records: readonly CapabilityRecord[], since: SinceRead): Tally {
  let ready = 0
  let waiting = 0
  let unchecked = 0
  for (const record of records) {
    const state = displayState(record, since)
    if (state === 'ready') ready += 1
    else if (state === 'permission_required' || state === 'restart_required') waiting += 1
    else unchecked += 1
  }
  return { ready, waiting, unchecked, total: records.length }
}

/** The line the progress rail shows for the capabilities, which never implies a grant. */
export function tallyLine(counted: Tally): string {
  if (counted.total === 0) return 'Nothing to report yet'
  const parts = [`${counted.ready} of ${counted.total} established`]
  if (counted.waiting > 0) parts.push(`${counted.waiting} waiting on you`)
  if (counted.unchecked > 0) parts.push(`${counted.unchecked} not checked`)
  return parts.join(' · ')
}
