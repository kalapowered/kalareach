/**
 * What the interface says about sharing a session, and the arithmetic behind its choices.
 *
 * Every sentence the host states for itself comes from the host (`grant_notices` is the protocol's
 * own table); what is here is the application's words for a role and an action, and the rules that
 * decide which devices an invitation can go to and how long it can last. A pairing bounds
 * everything its device does, so a share cannot outlast it, and the host refuses one that would
 * rather than shortening it: the choices offered here are the ones that fit.
 */

import type { ActionRight, DeviceSummary, GrantSummary } from '@kalareach/protocol'

import type { AttemptView } from '../host/port'

/** The roles the interface offers. Reviewer waits until the host decides diffs under the grant. */
export type OfferedRole = 'viewer' | 'controller' | 'owner'

/** A role, in the person's words. */
export const ROLES: readonly {
  readonly role: OfferedRole
  readonly title: string
  readonly line: string
}[] = [
  { role: 'viewer', title: 'Viewer', line: 'Watches the session.' },
  {
    role: 'controller',
    title: 'Controller',
    line: 'Also types, resizes the terminal, prompts the agent and answers it.'
  },
  { role: 'owner', title: 'Owner', line: 'Also manages sharing and can close the session.' }
]

/** What a role is called. */
export function roleWords(role: string | null): string {
  switch (role) {
    case 'viewer':
      return 'Viewer'
    case 'reviewer':
      return 'Reviewer'
    case 'controller':
      return 'Controller'
    case 'owner':
      return 'Owner'
    default:
      return 'Custom access'
  }
}

/** What each action lets a recipient do, in words. */
export const ACTION_WORDS: Partial<Readonly<Record<ActionRight, string>>> = {
  'session.view': 'See what the session shows and does from when they accept',
  'files.read':
    'Read files. A paired device cannot do this yet, and a host update can turn it on while the share lasts',
  'question.respond': 'Answer the agent’s questions',
  'terminal.input': 'Type into the terminal',
  'terminal.geometry': 'Resize the terminal',
  'agent.prompt': 'Send the agent prompts',
  'agent.cancel': 'Cancel the agent’s turn',
  'agent.approval.respond': 'Answer the agent’s approval requests',
  'session.share': 'Share the session with other devices',
  'session.close': 'Close the session'
}

/** The words for one action, or its name where the interface has none. */
export function actionWords(action: ActionRight): string {
  return ACTION_WORDS[action] ?? action
}

/** How long before an invitation the host claims, its clock and the person's can differ. */
export const CLAIM_MARGIN_MS = 10_000

/** The shortest time a pairing can have left for a share to be worth offering. */
export const SHORTEST_LEFT_MS = 60_000

/** One choice of how long an invitation lasts. */
export interface Lasting {
  readonly key: string
  readonly label: string
  /** How long it lasts from the moment it is issued, in milliseconds. */
  readonly ms: number | 'pairing'
}

const FIXED: readonly (readonly [string, string, number])[] = [
  ['15m', '15 minutes', 15 * 60_000],
  ['1h', '1 hour', 60 * 60_000],
  ['1d', '1 day', 24 * 60 * 60_000],
  ['7d', '7 days', 7 * 24 * 60 * 60_000],
  ['30d', '30 days', 30 * 24 * 60 * 60_000]
]

/** When a device's pairing ends, in milliseconds, or none for one that never ends. */
export function pairingEnd(device: DeviceSummary): number | null {
  return device.grant_expires_at_ms === null ? null : Number(device.grant_expires_at_ms)
}

/** Why an invitation cannot go to a device, or none when it can. */
export function whyNot(device: DeviceSummary, nowMs: number): string | null {
  if (device.revoked) return null
  if (device.manages_host) return 'An owner device already has every session of this host.'
  if (device.all_sessions) return 'Its pairing already opens every session of this host.'
  if (device.grant_expired) return 'Its pairing has ended. Pair it again to share a session with it.'
  const end = pairingEnd(device)
  if (end !== null && end - nowMs < SHORTEST_LEFT_MS) {
    return 'Its pairing ends within a minute. Pair it again to share a session with it.'
  }
  return null
}

/** The lifetimes that fit inside a device's pairing, with the margin for the host's later claim. */
export function lastings(device: DeviceSummary, nowMs: number): readonly Lasting[] {
  const end = pairingEnd(device)
  const fits = (ms: number) => end === null || nowMs + ms + CLAIM_MARGIN_MS <= end
  const chosen: Lasting[] = FIXED.filter(([, , ms]) => fits(ms)).map(([key, label, ms]) => ({
    key,
    label,
    ms
  }))
  const cut = FIXED.some(([, , ms]) => !fits(ms))
  if (end !== null && cut && end - nowMs - CLAIM_MARGIN_MS >= SHORTEST_LEFT_MS / 2) {
    chosen.push({
      key: 'pairing',
      label: `Until its pairing ends (${momentWords(end, nowMs)})`,
      ms: 'pairing'
    })
  }
  return chosen
}

/** The key chosen when none was: an hour when it fits, else until the pairing ends. */
export function defaultLasting(options: readonly Lasting[]): string | null {
  return (
    options.find((each) => each.key === '1h')?.key ??
    options.find((each) => each.key === 'pairing')?.key ??
    options[0]?.key ??
    null
  )
}

/** How long an invitation lasts when it is issued at `nowMs`, in milliseconds. */
export function lifetimeMs(choice: Lasting, device: DeviceSummary, nowMs: number): number {
  if (choice.ms !== 'pairing') return choice.ms
  const end = pairingEnd(device) ?? nowMs
  return Math.max(0, end - nowMs - CLAIM_MARGIN_MS)
}

/** The earlier activity a share can reach back to. */
export const HISTORY_CHOICES = [
  { key: 'none', label: 'None', ms: null },
  { key: 'hour', label: 'Last hour', ms: 60 * 60_000 },
  { key: 'day', label: 'Last day', ms: 24 * 60 * 60_000 },
  { key: 'all', label: 'All retained', ms: Number.POSITIVE_INFINITY }
] as const

/** The cursor an earlier-activity choice selects, or none for the live screen and what follows. */
export function historyFrom(key: string, nowMs: number): string | null {
  const choice = HISTORY_CHOICES.find((each) => each.key === key)
  if (choice === undefined || choice.ms === null) return null
  if (!Number.isFinite(choice.ms)) return '0'
  return String(Math.max(0, nowMs - choice.ms))
}

/** A moment in the person's words: the time today, and the day and time on another day. */
export function momentWords(ms: number, nowMs: number): string {
  const moment = new Date(ms)
  const today = new Date(nowMs)
  const time = moment.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  if (moment.toDateString() === today.toDateString()) return time
  const sameWeek = Math.abs(ms - nowMs) < 6 * 24 * 60 * 60_000
  const day = moment.toLocaleDateString([], sameWeek ? { weekday: 'short' } : { day: 'numeric', month: 'short' })
  return `${day} ${time}`
}

/** The span a pairing has left, in words. */
export function spanWords(ms: number): string {
  const minutes = Math.floor(ms / 60_000)
  if (minutes < 1) return 'less than a minute'
  if (minutes === 1) return '1 minute'
  if (minutes < 120) return `${String(minutes)} minutes`
  if (minutes < 2_880) return `${String(Math.floor(minutes / 60))} hours`
  return `${String(Math.floor(minutes / 1_440))} days`
}

/** What the platform the device runs on is called. */
export function platformWords(platform: string): string {
  switch (platform) {
    case 'ios':
      return 'iPhone or iPad'
    case 'android':
      return 'Android'
    case 'macos':
      return 'Mac'
    case 'windows':
      return 'Windows'
    case 'linux':
      return 'Linux'
    default:
      return 'device'
  }
}

/** The state of a grant in the person's words. */
export function stateWords(state: GrantSummary['state']): string {
  switch (state) {
    case 'pending':
      return 'Waiting to be accepted'
    case 'active':
      return 'Active'
    case 'expired':
      return 'Ended'
    case 'revoked':
      return 'Revoked'
  }
}

/**
 * Whether an attempt can still happen: it is not over, or it is a record the person may still ask
 * the host about.
 */
export function isOpen(attempt: AttemptView): boolean {
  return attempt.phase !== 'closed'
}

/**
 * What an attempt says to the person, in a sentence or two. `nowMs` is the person's clock.
 *
 * An attempt that can still happen says until when; one that is over says how it ended, and never
 * says "not done" for a refusal or an unknown.
 */
export function attemptWords(attempt: AttemptView, nowMs: number): string {
  const until =
    attempt.can_happen_until_ms === null
      ? ''
      : ` It can still happen until ${momentWords(Number(attempt.can_happen_until_ms), nowMs)}.`
  if (attempt.phase === 'asking') return `Waiting for an owner device to confirm: ${attempt.label}.`
  if (attempt.phase !== 'closed') {
    return `Unfinished: ${attempt.label}. The host has not said whether it happened.${until}`
  }
  switch (attempt.outcome) {
    case 'happened':
      return attempt.kind === 'revoke'
        ? `${attempt.label}: done. Whether each session worker has stopped acting under it is not known.`
        : attempt.kind === 'transfer'
          ? `${attempt.label}: done. Whether each session worker has stopped acting under the old access is not known.`
          : `${attempt.label}: done.`
    case 'not_done':
      return `${attempt.label}: it did not happen, as far as the host shows, and it cannot now. It is safe to try again.`
    case 'not_accepted':
      return `${attempt.label}: it was not accepted, as far as the host shows.`
    case 'had_ended':
      return `${attempt.label}: the access had already ended, so this changed nothing.`
    case 'refused':
      return `${attempt.label}: the host refused it.`
    default:
      return `What became of this cannot be told from what the host shows: ${attempt.label}.`
  }
}

/** The rights of a share, named by the widest role they cover. */
export function roleOfRights(actions: readonly ActionRight[]): string {
  if (actions.includes('session.share')) return 'owner'
  if (actions.includes('terminal.input')) return 'controller'
  if (actions.includes('files.read')) return 'reviewer'
  return 'viewer'
}

/**
 * A line of a terminal's screen with its control and bidirectional characters made visible.
 *
 * A screen is untrusted text: an escape, a bell or a character that turns the text round must be
 * seen for what it is, never act on the page that shows it. Control characters appear as their
 * control pictures, and the rest as their code in angle brackets.
 */
export function visibly(line: string): string {
  const unseen = (code: number): boolean =>
    (code >= 0x80 && code <= 0x9f) ||
    code === 0x061c ||
    code === 0x200e ||
    code === 0x200f ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069) ||
    code === 0xfeff
  return Array.from(line, (char) => {
    const code = char.codePointAt(0) ?? 0
    if (code < 0x20) return String.fromCodePoint(0x2400 + code)
    if (code === 0x7f) return '␡'
    if (unseen(code)) return `‹U+${code.toString(16).toUpperCase().padStart(4, '0')}›`
    return char
  }).join('')
}
