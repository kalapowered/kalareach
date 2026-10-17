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

/** What native calls a host that gave it no name this computer could read. */
const UNNAMED_BY_NATIVE = 'your host'

/**
 * What an invitation is called: the sentence the row and the card both start with. A host's name is
 * its owner's own text and starts the sentence as it is written; only the words native puts in
 * place of a name are capitalised.
 */
export function offerTitle(host: string | null, offer: ShareOffer): string {
  const named = hostWords(host)
  const first = named.toLowerCase() === UNNAMED_BY_NATIVE ? sentenceCase(named) : named
  return `${first} shared ${sessionWords(offer.display_number)} with you.`
}

/**
 * What each action lets the recipient do. Most of the issuer's words already read as an instruction
 * to whoever holds the share. Watching is not one of them: the issuer's own account is of when the
 * history begins, which the card states on its own line, and what watching gives depends on whether
 * the live view is included, since a share without it gives no terminal and no live stream.
 */
function youCanDo(action: ActionRight, live: boolean): string {
  if (action === 'session.view') {
    return live
      ? 'See what the session shows and does'
      : 'See what the session’s agent says and asks, but not its terminal'
  }
  return ACTION_WORDS[action] ?? action
}

/**
 * The actions of an invitation, in the recipient's words, each as the card lists it.
 *
 * Without the live view the host gives a share no terminal: an action on the terminal is not one
 * the share can use, so it is not listed as something the recipient can do, and the card says in
 * one line that the terminal is not included.
 */
export function youCan(actions: readonly ActionRight[], live: boolean): readonly string[] {
  const kept = live ? actions : actions.filter((action) => !action.startsWith('terminal.'))
  const lines = kept.map((action) => youCanDo(action, live))
  if (!live && kept.length < actions.length) lines.push('Not the terminal: the live view is not included')
  return lines
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
  // A share that reaches back to the start of what the host kept has no moment to name.
  const from = Number(offer.history_from_ms)
  const lines = [
    from === 0
      ? 'What the session does, from its start.'
      : `What the session does from ${momentWords(from, nowMs)}.`
  ]
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
