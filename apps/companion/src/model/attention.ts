/**
 * The attention inbox, as the host keeps it and as a person reads it.
 *
 * Section 13 names four things the inbox must tell apart: a decision waiting on the person, an
 * action that failed, finished work that wants review, and a host nobody can reach. Section 25's
 * rules raise the items, one rule each, and one more kind stands beside the four: a notice an
 * application printed, which any program writing to a terminal can produce, so it is never a
 * decision and never shown as the host's.
 *
 * The fourth of the four is the one with a trap in it. Losing contact with a host says nothing about
 * what its processes are doing, so nothing here turns silence into a claim. Elapsed time is reported
 * as elapsed time and never as a failure, a lost host is never counted among the failures, and the
 * words for it are about contact.
 */

import type { AttentionItem, AttentionReadResult } from '@kalareach/protocol'

import { failureCode } from '../host/port'

/**
 * How long after one read of the inbox the next starts while it is shown.
 *
 * The host announces no change to the inbox: a view reads the current scoped state again, so this
 * is how soon an item raised or resolved elsewhere reaches a screen that is open.
 */
export const ATTENTION_READ_CADENCE_MS = 5_000

/** The most pages of the inbox one read follows. Sixteen pages hold every item a host retains. */
export const MAX_INBOX_PAGES = 16

/**
 * The whole inbox, page by page, from the oldest item on.
 *
 * `read` asks for the page after one key, or the first page for null. Each page continues after
 * the last item of the one before, until the host says there is no more or the bound is reached,
 * and the answer's `more` then says whether the host holds more than was read. An item can go
 * between two pages, and the host refuses a page that continues after an item it no longer holds:
 * the inbox is then read again from its start, once.
 */
export async function readWholeInbox(
  read: (after: string | null) => Promise<AttentionReadResult>
): Promise<AttentionReadResult> {
  try {
    return await followPages(read)
  } catch (failure: unknown) {
    if (failureCode(failure) !== 'DRAFT_CONFLICT') throw failure
    return await followPages(read)
  }
}

async function followPages(
  read: (after: string | null) => Promise<AttentionReadResult>
): Promise<AttentionReadResult> {
  let page = await read(null)
  const items = [...page.items]
  for (let pages = 1; page.more && pages < MAX_INBOX_PAGES; pages += 1) {
    const last = page.items.at(-1)
    if (last === undefined) break
    page = await read(last.key)
    items.push(...page.items)
  }
  return { ...page, items }
}

/** What an item is asking for, as the inbox tells them apart. */
export type AttentionKind =
  | 'pending_decision'
  | 'failed_action'
  | 'awaiting_review'
  | 'disconnected'
  | 'notice'

/** The kind each of section 25's rules raises. */
export function kindOf(item: AttentionItem): AttentionKind {
  switch (item.rule) {
    case 'attention.pending_approval':
    case 'attention.pending_input':
    case 'attention.input_idle_reminder':
      return 'pending_decision'
    case 'attention.command_failed':
    case 'attention.adapter_failed':
    case 'attention.automation_paused':
    case 'attention.authority_feed_removed':
      return 'failed_action'
    case 'attention.review_ready':
      return 'awaiting_review'
    case 'attention.host_contact_lost':
      return 'disconnected'
    case 'attention.application_notice':
      return 'notice'
  }
}

/** What each rule is about, in words: an item's title when the host withheld its own line. */
const RULE_WORDS: Readonly<Record<AttentionItem['rule'], string>> = {
  'attention.pending_approval': 'An approval is waiting for you',
  'attention.pending_input': 'A question is waiting for an answer',
  'attention.input_idle_reminder': 'A question has been waiting for five minutes',
  'attention.command_failed': 'A command ended with a failure',
  'attention.adapter_failed': 'An integration stopped working',
  'attention.review_ready': 'Finished work is ready to review',
  'attention.host_contact_lost': 'This host is out of contact',
  'attention.application_notice': 'An application asked for your attention',
  'attention.automation_paused': 'An automation stopped at one of its own limits',
  'attention.authority_feed_removed': 'This host no longer learns revocations from its feed'
}

/** The word each kind shows, which is the row's own label rather than a colour alone. */
export const KIND_LABEL: Readonly<Record<AttentionKind, string>> = {
  pending_decision: 'Waiting for you',
  failed_action: 'Did not finish',
  awaiting_review: 'Ready to review',
  disconnected: 'Out of contact',
  notice: 'Application notice'
}

/** How each kind is coloured. */
export const KIND_TONE: Readonly<Record<AttentionKind, 'warning' | 'danger' | 'success' | 'muted'>> =
  {
    pending_decision: 'warning',
    failed_action: 'danger',
    awaiting_review: 'success',
    disconnected: 'muted',
    notice: 'muted'
  }

/** The order the kinds are shown in: what is waiting on a person first. */
const KIND_ORDER: Readonly<Record<AttentionKind, number>> = {
  pending_decision: 0,
  failed_action: 1,
  awaiting_review: 2,
  disconnected: 3,
  notice: 4
}

/**
 * How long, in words: plain elapsed time and nothing more. "For 40 minutes" is a fact; "stuck for
 * 40 minutes" is a claim about a process this device has not heard from and cannot make.
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

/** One item, as the inbox draws it. */
export interface AttentionRow {
  readonly item: AttentionItem
  readonly kind: AttentionKind
  readonly label: string
  readonly tone: 'warning' | 'danger' | 'success' | 'muted'
  /** The item's own line when the host served it, and the rule's words when it withheld it. */
  readonly title: string
  /** What the row says under its title. */
  readonly detail: string
  /** What a screen reader reads for the row, which never leaves the kind to a colour. */
  readonly announcement: string
  /** True when the row waits on a decision this device can take in the session it names. */
  readonly actionable: boolean
}

/** What the row says under its title. */
export function detailOf(item: AttentionItem, nowMs: number): string {
  const sentences: string[] = []
  const kind = kindOf(item)
  if (kind === 'disconnected') {
    const since = nowMs - Number(item.first_seen_ms)
    // The second sentence is the whole point of the row: absence of contact is not a verdict.
    sentences.push(
      `No contact for ${describeElapsed(since)}.`,
      'Its sessions may still be running; nothing here says they are not.'
    )
  } else if (item.summary !== null) {
    // The item's own line is the title; this says which rule raised it.
    sentences.push(`${RULE_WORDS[item.rule]}.`)
  } else {
    sentences.push('The host did not share this item’s text with this device.')
  }
  if (!item.trusted) {
    sentences.push('A program in the session printed it. It is not a request from the host.')
  }
  const occurrences = Number(item.occurrences)
  if (occurrences > 1) sentences.push(`It happened ${occurrences} times.`)
  if (item.uncertain) {
    sentences.push('Some of the host’s records are gone, so it cannot tell whether this was resolved.')
  }
  return sentences.join(' ')
}

/** Turns one item into the row the inbox draws. */
export function present(item: AttentionItem, nowMs: number): AttentionRow {
  const kind = kindOf(item)
  const label = KIND_LABEL[kind]
  const title = item.summary ?? RULE_WORDS[item.rule]
  const detail = detailOf(item, nowMs)
  return {
    item,
    kind,
    label,
    tone: KIND_TONE[kind],
    title,
    detail,
    announcement: `${label}. ${title}. ${detail}`,
    // An approval is answered where the session's worker can say what it offered. A lost host,
    // a notice and finished work offer nothing to decide here.
    actionable: item.rule === 'attention.pending_approval' && item.session_id !== null
  }
}

/**
 * The inbox in the order it is shown: kind first, because what is waiting on a person outranks
 * what is only waiting, then the most recent within a kind.
 */
export function order(inbox: AttentionReadResult, nowMs: number): readonly AttentionRow[] {
  return [...inbox.items]
    .sort((left, right) => {
      const byKind = KIND_ORDER[kindOf(left)] - KIND_ORDER[kindOf(right)]
      if (byKind !== 0) return byKind
      const byTime = BigInt(right.last_seen_ms) - BigInt(left.last_seen_ms)
      return byTime > 0n ? 1 : byTime < 0n ? -1 : 0
    })
    .map((item) => present(item, nowMs))
}

/** How many items of each kind there are, which is what the tab badge counts. */
export interface AttentionCounts {
  readonly pending_decision: number
  readonly failed_action: number
  readonly awaiting_review: number
  readonly disconnected: number
  readonly notice: number
  /** What the badge shows: the things a person can act on. A lost host is not one of them. */
  readonly actionable: number
}

/** Counts the inbox by kind. */
export function count(inbox: AttentionReadResult): AttentionCounts {
  const counts = {
    pending_decision: 0,
    failed_action: 0,
    awaiting_review: 0,
    disconnected: 0,
    notice: 0
  }
  for (const item of inbox.items) counts[kindOf(item)] += 1
  return { ...counts, actionable: counts.pending_decision + counts.failed_action }
}

/** The filters the inbox offers: every kind, and everything. */
export type AttentionFilter = 'all' | AttentionKind

/** Applies one filter. */
export function filter(
  rows: readonly AttentionRow[],
  chosen: AttentionFilter
): readonly AttentionRow[] {
  return chosen === 'all' ? rows : rows.filter((row) => row.kind === chosen)
}

/** What the inbox says when a filter leaves nothing. */
export function emptyMessage(chosen: AttentionFilter): string {
  switch (chosen) {
    case 'pending_decision':
      return 'Nothing is waiting for you.'
    case 'failed_action':
      return 'Nothing has failed.'
    case 'awaiting_review':
      return 'Nothing is waiting to be reviewed.'
    case 'disconnected':
      return 'Every host is in contact.'
    case 'notice':
      return 'No application has asked for attention.'
    case 'all':
      return 'Nothing needs you right now.'
  }
}

/**
 * What the inbox as a whole says beyond its items: items it holds beyond what was read, what the
 * host let go to stay inside its bound, records it can no longer read, and quiet hours. Each is said
 * rather than hidden, because a shorter inbox that looked complete would be a claim nobody made.
 */
export function inboxNotes(inbox: AttentionReadResult): readonly string[] {
  const notes: string[] = []
  if (inbox.more) {
    notes.push('The host holds more items than this list shows.')
  }
  const dropped = Number(inbox.dropped)
  if (dropped > 0) {
    notes.push(
      `The host let ${dropped} older ${dropped === 1 ? 'item' : 'items'} go to stay inside its limit.`
    )
  }
  if (inbox.gaps.length > 0) {
    notes.push(
      'Some of the records these items come from are no longer readable. An item they could have resolved stays here.'
    )
  }
  if (inbox.quiet_now) {
    notes.push('Quiet hours are on. Nothing is dropped; sounds wait until they end.')
  } else if (inbox.quiet_hours !== null && !inbox.quiet_hours_provable) {
    notes.push(
      'This host cannot prove what its clock reads, so it delivers notifications rather than holding them for quiet hours.'
    )
  }
  return notes
}
