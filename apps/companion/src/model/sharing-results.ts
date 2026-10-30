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
import type { SharingDesk, Waiting } from './sharing-desk'

/** Says something to the person, as the page's toast does. */
export type Say = (text: string, tone?: 'success' | 'danger' | 'pending') => void

/**
 * The session workers a revocation still waits for. The host names the workers that have not
 * confirmed before any that has, and says how many there were in all, so when it cut its list the
 * names are a floor.
 */
export function waitingOn(result: RevocationResult): Waiting {
  const { workers, workers_total: total } = result.barrier
  return {
    sessions: workers.filter((worker) => worker.state === 'pending').map((worker) => worker.session_id),
    cut: Number(total) > workers.length
  }
}

/** How many workers a revocation still waits for. */
export function pendingWorkers(result: RevocationResult): number {
  return waitingOn(result).sessions.length
}

/** "1 session worker has", "3 session workers have", or "at least 3 session workers have". */
export function workersHave(count: number, cut: boolean): string {
  return `${cut ? 'at least ' : ''}${String(count)} session worker${count === 1 ? ' has' : 's have'}`
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
  const waiting = waitingOn(result)
  const done = waiting.sessions.length === 0
  desk.keepRevocation(grantId, name, nowMs, result.authority_revision, waiting)
  desk.dismissNote(grantId)
  const owed = `${workersHave(waiting.sessions.length, waiting.cut)} not confirmed yet.`
  say(
    done
      ? withdrawing
        ? `Invitation to ${nameWords(name)} withdrawn.`
        : `Revoked ${nameWords(name)}’s access.`
      : withdrawing
        ? `The withdrawal of the invitation to ${nameWords(name)} is recorded, and not done: ${owed}`
        : `The revocation for ${nameWords(name)} is recorded, and not done: ${owed}`,
    done ? 'success' : 'pending'
  )
}

/**
 * A revocation was asked about again, by Check again: the line already kept for it says how far
 * the workers have got, and nothing else about it, neither when it was made nor for whom, is
 * changed by the answer.
 */
export function rechecked(desk: SharingDesk, result: RevocationResult, grantId: string): void {
  desk.checked(grantId, waitingOn(result))
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
  const waiting = waitingOn(done.revoked)
  desk.keepRevocation(sourceGrantId, givingName, nowMs, done.revoked.authority_revision, waiting)
  say(
    waiting.sessions.length === 0
      ? words
      : `${words} ${workersHave(waiting.sessions.length, waiting.cut)} not confirmed that ${nameWords(givingName)} lost access yet.`,
    waiting.sessions.length === 0 ? 'success' : 'pending'
  )
}
