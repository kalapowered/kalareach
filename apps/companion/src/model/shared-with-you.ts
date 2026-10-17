/**
 * What the phone says to the device a session is shared with: an invitation before it is accepted,
 * a share it holds, and one the host no longer lists.
 *
 * The host states what an invitation carries (its actions, the consequences those actions bring,
 * where its history begins, whether it includes the live screen and when it ends), and these are
 * that statement put to its recipient. The host's own sentences about a consequence are addressed
 * to the person who issues the share, so each is said again here to the person who receives it,
 * from a table that has one sentence for each consequence the protocol names. Nothing here comes
 * from the invitation's issuer: the offer carries no text they were shown.
 */

import type { ActionRight, AuthorityNotice, HeldShare, ShareOffer } from '@kalareach/protocol'

import { ACTION_WORDS, momentWords, nameWords, roleOfRights, roleWords } from './sharing'

/** What the host is called when this device has no name for it. */
const UNNAMED_HOST = 'The host'

/** What a list says when the read after the last complete one failed. */
export const STALE_WORDS = 'Not refreshed just now. This is what the host last listed.'

/** The host as the sentences name it. */
export function hostWords(name: string | null): string {
  const shown = name === null ? '' : nameWords(name).trim()
  return shown === '' ? UNNAMED_HOST : shown
}

/** The session an invitation or a share is about, as the person reads its number. */
export function sessionWords(displayNumber: string): string {
  return `session ${displayNumber}`
}

/** What an invitation is called: the sentence the row and the card both start with. */
export function offerTitle(host: string | null, offer: ShareOffer): string {
  return `${hostWords(host)} shared ${sessionWords(offer.display_number)} with you.`
}

/**
 * What each action lets the recipient do. Most of the issuer's words already read as an
 * instruction to whoever holds the share; the one about watching is the issuer's own account of
 * when the history begins, which the card states on its own line.
 */
const YOU_CAN: Partial<Readonly<Record<ActionRight, string>>> = {
  ...ACTION_WORDS,
  'session.view': 'See what the session shows and does'
}

/** The actions of an invitation, in the recipient's words, each as the card lists it. */
export function youCan(actions: readonly ActionRight[]): readonly string[] {
  return actions.map((action) => YOU_CAN[action] ?? action)
}

/**
 * What each consequence means to the recipient, with the host named. These are the host's
 * consequences re-addressed, one sentence for each the protocol names, and none of them promises a
 * boundary the host does not enforce.
 */
const CONSEQUENCES: Readonly<Record<AuthorityNotice, (host: string) => string>> = {
  account_access: (host) =>
    `Terminal input runs as the owner’s account on ${host}. Anything you type can do what the owner can do on that machine.`,
  agent_permissions: (host) =>
    `What you send to the agent, including prompts, approvals and answers, is input it may act on under its own permissions on ${host}. This is not a restricted sandbox.`,
  environment_writes: (host) => `You can change files and repositories on ${host}.`,
  delegation: () =>
    'You can pass on what this share holds, narrowed but never enlarged, to somebody else. This phone does not pass shares on.'
}

/** The consequences an invitation carries, said to its recipient. */
export function thisLetsYou(host: string | null, notices: readonly AuthorityNotice[]): readonly string[] {
  return notices.map((notice) => CONSEQUENCES[notice](hostWords(host)))
}

/**
 * What the invitation shows: where the session's history begins, exactly as the host states it,
 * and, when the host says the live view is included, what that is.
 */
export function showsLines(offer: ShareOffer, nowMs: number): readonly string[] {
  const lines = [`What the session does from ${momentWords(Number(offer.history_from_ms), nowMs)}.`]
  if (offer.includes_live_screen) lines.push('The terminal as it is when you open it.')
  return lines
}

/** When an invitation ends, as the host states it, and that it is used once. */
export function endsLine(offer: ShareOffer, nowMs: number): string {
  return `${momentWords(Number(offer.ends_at_ms), nowMs)}. Used once.`
}

/** When an invitation ends, in the row's words. */
export function offerEnds(offer: ShareOffer, nowMs: number): string {
  return `Until ${momentWords(Number(offer.ends_at_ms), nowMs)}`
}

/** The role an invitation or a share is about, in words. */
export function offerRole(offer: ShareOffer): string {
  return roleWords(offer.role ?? roleOfRights(offer.actions))
}

/** The role of a share held. */
export function shareRole(share: HeldShare): string {
  return roleWords(roleOfRights(share.grant.actions))
}

/** How long a share lasts, in the row's words. */
export function shareEnds(share: HeldShare, nowMs: number): string {
  return share.ends_at_ms === null
    ? 'No end set'
    : `Until ${momentWords(Number(share.ends_at_ms), nowMs)}`
}

/** The session a share covers, or none when its grant does not name exactly one. */
export function sessionOfShare(share: HeldShare): string | null {
  const selector = share.grant.session_selector
  if (typeof selector !== 'object') return null
  const sessions = selector.these.session_ids
  return sessions.length === 1 ? (sessions[0] ?? null) : null
}

/** What the toast says when an acceptance is done. */
export function acceptedWords(offer: ShareOffer, nowMs: number): string {
  return `Accepted. ${sentenceCase(sessionWords(offer.display_number))} is shared with you until ${momentWords(Number(offer.ends_at_ms), nowMs)}.`
}

/** What the toast says when an acceptance is found to have happened, from the share it made. */
export function acceptedShareWords(share: HeldShare | undefined, nowMs: number): string {
  if (share === undefined) return 'Accepted.'
  const until =
    share.ends_at_ms === null ? '' : ` until ${momentWords(Number(share.ends_at_ms), nowMs)}`
  return `Accepted. ${sentenceCase(sessionWords(share.display_number))} is shared with you${until}.`
}

/** A phrase that starts a sentence. */
export function sentenceCase(text: string): string {
  return text.slice(0, 1).toUpperCase() + text.slice(1)
}
