/**
 * Queued, sent, applied: what the person's own input is doing.
 *
 * Section 13 asks for these three as different states, and section 9 says where they come from. The
 * first is local: the text is in the composer and nothing has left this device. The second is a
 * request that is with the host. The third needs a receipt, and only a receipt: a network
 * acknowledgement says the bytes arrived, not that the agent took the prompt.
 *
 * The reconnect banner rests on the same rule. It reports what is unresolved; it never reports
 * success because a connection came back.
 */

import type { Receipt } from '@kalareach/protocol'

/** What has happened to one thing the person sent. */
export type InputState = 'queued' | 'sent' | 'applied' | 'refused' | 'rejected' | 'unknown'

/** One submission the interface is tracking. */
export interface Submission {
  /** This device's own identity for the submission, which exists before an action does. */
  readonly localId: string
  /** The action identifier, once the request has been made. */
  readonly actionId: string | null
  /** The text or label the person will recognise. */
  readonly label: string
  /**
   * Exactly what was submitted.
   *
   * Kept until the outcome permits letting it go, because a refusal has to be able to give it
   * back, and the label above is a trimmed thing to show rather than the text itself.
   */
  readonly text: string
  /** Its current state. */
  readonly state: InputState
  /** When it was created. */
  readonly createdAtMs: number
  /** The failure, when it has one. */
  readonly error: { readonly code: string; readonly message: string } | null
}

/**
 * The state a receipt puts a submission in.
 *
 * `received`, `accepted` and `dispatching` are all "with the host and not done". `applied` is the
 * only one that means the effect happened. The rest are outcomes of their own, and `unknown` is
 * the one the interface must never round up: it is the state whose whole point is that nobody
 * knows.
 */
export function stateOfReceipt(receipt: Receipt): InputState {
  switch (receipt.state) {
    case 'received':
    case 'accepted':
    case 'dispatching':
      return 'sent'
    case 'applied':
      return 'applied'
    case 'refused':
      return 'refused'
    case 'rejected':
      return 'rejected'
    case 'unknown':
      return 'unknown'
    default:
      return 'unknown'
  }
}

/** What the interface says about a state. */
export function describeState(state: InputState): string {
  switch (state) {
    case 'queued':
      return 'Queued on this device'
    case 'sent':
      return 'Sent, waiting for the host'
    case 'applied':
      return 'Applied'
    case 'refused':
      return 'Refused by the host'
    case 'rejected':
      return 'Rejected'
    case 'unknown':
      return 'Outcome unknown'
  }
}

/** A submission that has not left this device. */
export function queued(
  localId: string,
  label: string,
  createdAtMs: number,
  text = label
): Submission {
  return { localId, actionId: null, label, text, state: 'queued', createdAtMs, error: null }
}

/** Whether an outcome is one the person can do nothing more about. */
export function isTerminal(state: InputState): boolean {
  return state === 'applied' || state === 'refused' || state === 'rejected'
}

/** Whether an outcome means the submission did not happen and its text should come back. */
export function wasRefused(state: InputState): boolean {
  return state === 'refused' || state === 'rejected'
}

/** Records that the request has been made. */
export function sent(submission: Submission, actionId: string): Submission {
  return { ...submission, actionId, state: 'sent' }
}

/** Records what a receipt said. */
export function settled(submission: Submission, receipt: Receipt): Submission {
  return {
    ...submission,
    actionId: receipt.action_id,
    state: stateOfReceipt(receipt),
    error: receipt.error
      ? { code: String(receipt.error.code), message: String(receipt.error.message) }
      : null
  }
}

/** Records a failure the request itself produced. */
export function failed(
  submission: Submission,
  error: { code: string; message: string }
): Submission {
  // A submission whose outcome the host could not confirm stays unknown: the interface asks what
  // became of it rather than telling the person it failed.
  const state: InputState = error.code === 'OUTCOME_UNKNOWN' ? 'unknown' : 'refused'
  return { ...submission, state, error }
}

/** The submissions that are not finished, which is what the reconnect banner lists. */
export function unresolved(submissions: readonly Submission[]): readonly Submission[] {
  return submissions.filter(
    (submission) =>
      submission.state === 'queued' || submission.state === 'sent' || submission.state === 'unknown'
  )
}

/**
 * What the reconnect banner says.
 *
 * It never says an action succeeded. While anything is unresolved it says so and counts them; when
 * nothing is, it says the connection is back and nothing more. Before anything has answered
 * whether the host is in contact, `connected` is null and it says nothing at all: neither contact
 * nor its loss is known yet.
 */
export function reconnectBanner(
  connected: boolean | null,
  submissions: readonly Submission[]
): { readonly tone: 'warning' | 'accent'; readonly title: string; readonly detail: string } | null {
  if (connected === null) return null
  const pending = unresolved(submissions)
  if (!connected) {
    return {
      tone: 'warning',
      title: 'Not in contact with this host',
      detail:
        pending.length > 0
          ? `${pending.length} ${pending.length === 1 ? 'action has' : 'actions have'} no confirmed outcome. Their processes may still be running.`
          : 'Its processes may still be running. Nothing here says they are not.'
    }
  }
  if (pending.length > 0) {
    return {
      tone: 'accent',
      title: 'Connected again',
      detail: `${pending.length} ${pending.length === 1 ? 'action is' : 'actions are'} still waiting for a receipt. The connection coming back is not an outcome.`
    }
  }
  return null
}
