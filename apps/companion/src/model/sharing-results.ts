/**
 * What the person is told, and what the page keeps, once the host's result for one of the four
 * sharing actions is in hand, however it came: from the command that sent the action, from a
 * repeat native code made in the background, or from the person asking the host.
 *
 * These write to the page's desk and to the toast, never to the state of a screen, so they are
 * the same wherever they are called from and still do their work when the screen that sent the
 * action has gone.
 */

import type { GrantCreateResult, GrantTransferResult, RevocationResult } from '@kalareach/protocol'

import { nameWords } from './sharing'
import type { SharingDesk } from './sharing-desk'

/** Says something to the person, as the page's toast does. */
export type Say = (text: string, tone?: 'success' | 'danger' | 'pending') => void

/** How many workers a revocation still waits for. */
export function pendingWorkers(result: RevocationResult): number {
  return result.barrier.workers.filter((worker) => worker.state === 'pending').length
}

/**
 * An invitation was written. With the live view the host kept a screen with it: it is compared
 * with the one the person was shown, and when there is nothing to compare it with the person is
 * told that, and can withdraw the invitation.
 *
 * `shown` is the lines the person was shown; `undefined` when they are not kept any more.
 */
export function invited(
  desk: SharingDesk,
  say: Say,
  made: GrantCreateResult,
  name: string,
  shown: readonly string[] | null | undefined
): void {
  say(`Invitation ready for ${nameWords(name)}. They accept it on their device.`)
  const kept = made.preview.live_screen?.lines ?? null
  if (kept === null) return
  const grantId = made.grant.grant_id
  const sessionId = made.preview.session_id
  if (shown === null || shown === undefined) {
    desk.note({ grantId, sessionId, name, kind: 'unverified', lines: kept })
  } else if (JSON.stringify(kept) !== JSON.stringify(shown)) {
    desk.note({ grantId, sessionId, name, kind: 'changed', lines: kept })
  }
}

/** A share was taken back, or an invitation withdrawn: says how far the session workers have got. */
export function tookBack(
  desk: SharingDesk,
  say: Say,
  result: RevocationResult,
  grantId: string,
  name: string,
  withdrawing: boolean,
  nowMs: number
): void {
  const pending = pendingWorkers(result)
  desk.keepRevocation(grantId, name, nowMs, pending)
  desk.dismissNote(grantId)
  say(
    withdrawing
      ? `Invitation to ${nameWords(name)} withdrawn.`
      : pending === 0
        ? `Revoked ${nameWords(name)}’s access.`
        : `Revoked ${nameWords(name)}’s access. ${String(pending)} session worker${pending === 1 ? ' has' : 's have'} not confirmed yet.`,
    withdrawing || pending === 0 ? 'success' : 'pending'
  )
}

/**
 * A revocation was asked about again, by Check again: the line already kept for it says how far
 * the workers have got, and nothing else about it, neither when it was made nor for whom, is
 * changed by the answer.
 */
export function rechecked(desk: SharingDesk, result: RevocationResult, grantId: string): void {
  desk.checked(grantId, pendingWorkers(result))
}

/**
 * A session's control was handed over. The grant the giving device held was revoked with it, and
 * how far the session workers have got with that is kept like any revocation's, to be checked
 * again by that grant's identity.
 */
export function handedOver(
  desk: SharingDesk,
  say: Say,
  done: GrantTransferResult,
  sourceGrantId: string,
  givingName: string,
  words: string,
  nowMs: number
): void {
  const pending = pendingWorkers(done.revoked)
  desk.keepRevocation(sourceGrantId, givingName, nowMs, pending)
  say(
    pending === 0
      ? words
      : `${words} ${String(pending)} session worker${pending === 1 ? ' has' : 's have'} not confirmed that ${nameWords(givingName)} lost access yet.`,
    pending === 0 ? 'success' : 'pending'
  )
}
