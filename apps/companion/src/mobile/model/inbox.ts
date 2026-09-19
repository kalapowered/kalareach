/**
 * The attention inbox, which is what the phone is for.
 *
 * Section 13 makes this the primary mobile surface across every host and every session, and it
 * names four things it must tell apart: a decision waiting on the person, an action that failed,
 * work that is finished and wants review, and a host nobody can reach.
 *
 * The fourth is the one with a trap in it. Losing contact with a host says nothing whatever about
 * what that host's processes are doing, so nothing here may turn silence into a claim. Elapsed
 * time is reported as elapsed time and never as a failure, a disconnected host is never counted
 * among the failures, and the only words this module produces for a disconnected entry are about
 * contact.
 */

import type { AttentionEntry, AttentionKind, AttentionInbox } from '../../model/pending'

/** How an entry is drawn and where it sorts. */
export interface InboxPresentation {
  /** The entry itself. */
  readonly entry: AttentionEntry
  /** The short word for the kind, which is the row's own label rather than a colour alone. */
  readonly label: string
  /** The tone the row is drawn in. */
  readonly tone: 'warning' | 'danger' | 'success' | 'muted'
  /** What the row says under its title. */
  readonly detail: string
  /** What a screen reader reads for the row, which never leaves the kind to a colour. */
  readonly announcement: string
  /** True when the row offers a decision the person can take here. */
  readonly actionable: boolean
}

/** The order the four kinds are shown in: what is waiting on a person first. */
const KIND_ORDER: Readonly<Record<AttentionKind, number>> = {
  pending_decision: 0,
  failed_action: 1,
  awaiting_review: 2,
  disconnected: 3
}

/** The word the interface uses for each kind. */
const KIND_LABEL: Readonly<Record<AttentionKind, string>> = {
  pending_decision: 'Waiting for you',
  failed_action: 'Action failed',
  awaiting_review: 'Ready to review',
  disconnected: 'Out of contact'
}

const KIND_TONE: Readonly<Record<AttentionKind, InboxPresentation['tone']>> = {
  pending_decision: 'warning',
  failed_action: 'danger',
  awaiting_review: 'success',
  disconnected: 'muted'
}

/**
 * How long contact has been lost, in words.
 *
 * Plain elapsed time, and nothing more. "For 40 minutes" is a fact; "stuck for 40 minutes" is a
 * claim about a process this device has not heard from and cannot make.
 */
export function describeElapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000))
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`
  const days = Math.floor(hours / 24)
  return `${days} day${days === 1 ? '' : 's'}`
}

/** The sentence a row shows under its title. */
export function detailOf(entry: AttentionEntry): string {
  if (entry.kind === 'disconnected') {
    const elapsed =
      typeof entry.out_of_contact_ms === 'number'
        ? `No contact for ${describeElapsed(entry.out_of_contact_ms)}.`
        : 'No contact with this host.'
    // The second sentence is the whole point of the row: absence of contact is not a verdict.
    return `${elapsed} Its sessions may still be running; nothing here says they are not.`
  }
  if (entry.kind === 'failed_action') {
    return entry.error_code ? `${entry.detail} (${entry.error_code})` : entry.detail
  }
  if (entry.kind === 'pending_decision' && entry.command_preview) {
    return entry.command_preview
  }
  return entry.detail
}

/** Where the entry happened, for a row that is shown across every host. */
export function locationOf(entry: AttentionEntry): string {
  if (!entry.session_display_number) return entry.host_label
  const application = entry.application ? ` · ${entry.application}` : ''
  return `${entry.host_label} · Session ${entry.session_display_number}${application}`
}

/** Turns one entry into the row the inbox draws. */
export function present(entry: AttentionEntry): InboxPresentation {
  const label = KIND_LABEL[entry.kind]
  const detail = detailOf(entry)
  return {
    entry,
    label,
    tone: KIND_TONE[entry.kind],
    detail,
    announcement: `${label}. ${entry.title}. ${locationOf(entry)}. ${detail}`,
    // A disconnected host offers nothing to decide, because there is nothing to decide about.
    actionable: entry.kind === 'pending_decision'
  }
}

/**
 * The inbox in the order it is shown.
 *
 * Kind first, because what is waiting on a person outranks what is only waiting; then the most
 * recent within a kind, because a person scanning a list reads the top of it.
 */
export function order(inbox: AttentionInbox): readonly InboxPresentation[] {
  return [...inbox.entries]
    .sort((left, right) => {
      const byKind = KIND_ORDER[left.kind] - KIND_ORDER[right.kind]
      return byKind !== 0 ? byKind : right.raised_at_ms - left.raised_at_ms
    })
    .map(present)
}

/** How many entries of each kind there are, which is what the tab badge counts. */
export interface InboxCounts {
  readonly pending_decision: number
  readonly failed_action: number
  readonly awaiting_review: number
  readonly disconnected: number
  /** What the badge shows: the things a person can act on. A lost host is not one of them. */
  readonly actionable: number
}

/** Counts the inbox by kind. */
export function count(inbox: AttentionInbox): InboxCounts {
  const counts = {
    pending_decision: 0,
    failed_action: 0,
    awaiting_review: 0,
    disconnected: 0
  }
  for (const entry of inbox.entries) counts[entry.kind] += 1
  return { ...counts, actionable: counts.pending_decision + counts.failed_action }
}

/** The filters the inbox offers, which are the four kinds and everything. */
export type InboxFilter = 'all' | AttentionKind

/** Applies one filter. */
export function filter(
  rows: readonly InboxPresentation[],
  chosen: InboxFilter
): readonly InboxPresentation[] {
  return chosen === 'all' ? rows : rows.filter((row) => row.entry.kind === chosen)
}

/** What the inbox says when a filter leaves nothing. */
export function emptyMessage(chosen: InboxFilter): string {
  switch (chosen) {
    case 'pending_decision':
      return 'Nothing is waiting for you.'
    case 'failed_action':
      return 'No action has failed.'
    case 'awaiting_review':
      return 'Nothing is waiting to be reviewed.'
    case 'disconnected':
      return 'Every host is in contact.'
    case 'all':
      return 'Nothing needs you right now.'
  }
}
