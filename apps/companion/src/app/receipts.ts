/**
 * Asking the host what became of an action.
 *
 * A request whose answer never came as a receipt, or came as only its identity, is not asked again:
 * section 9 lets the host reconcile it later, and the host keeps what it recorded of it, readable
 * under the same authority. So while the host is reached the interface reads that record for each
 * action it has no outcome for, and takes what it finds as a receipt that arrived.
 *
 * An action can stay without an outcome for as long as the host takes, so the reads slow down: each
 * pass waits twice as long as the one before, up to a ceiling. A person who opens the session, or
 * comes back to the page, is answered at once and starts again at the quick pace; so does an action
 * that has just been sent.
 */

import { useEffect, useRef } from 'react'

import type { Receipt } from '@kalareach/protocol'

import { applyReceipt, type Submission } from '../model/receipts'
import type { OpeningGate } from './agent'
import { readOnCadence } from './cadence'
import { useApp } from './state'

/** How long after the first read of an action's record the next one starts. */
export const RECEIPT_READ_FIRST_MS = 4_000

/** The longest wait between two reads of an action's record. */
export const RECEIPT_READ_LONGEST_MS = 60_000

/** Whether the host may still change what it recorded of a submission's action. */
export function awaitsReceipt(submission: Submission): boolean {
  return (
    submission.actionId !== null &&
    (submission.state === 'sent' || submission.state === 'unknown')
  )
}

/**
 * Reads the record of every action of `sessionId` that has no outcome yet, while the host is
 * reached, and hands `onReceipt` each record that says more than the submission does.
 *
 * A screen with an opening reads under its token, and only while the host says the opening is
 * open: the host decides the read over the session under the standing it holds now, so an opening
 * that is over, refused or being taken up again reads nothing and reads at once when it is open.
 */
export function useReceiptReads({
  sessionId,
  connected,
  submissions,
  onReceipt,
  gate
}: {
  readonly sessionId: string
  readonly connected: boolean | null
  readonly submissions: readonly Submission[]
  readonly onReceipt: (localId: string, receipt: Receipt) => void
  readonly gate?: OpeningGate
}): void {
  const { port, receiptReads } = useApp()
  const owed = submissions.filter(awaitsReceipt)
  // What the next read asks about, as of that read; and what changes whether a read is owed at all.
  const latest = useRef(owed)
  const settle = useRef(onReceipt)
  useEffect(() => {
    latest.current = owed
    settle.current = onReceipt
  })
  const owing = owed.map((each) => `${each.localId}|${each.actionId ?? ''}`).join(',')
  const token = gate === undefined ? undefined : (gate.token ?? undefined)
  const waiting = gate !== undefined && (gate.token === null || !gate.running)
  useEffect(() => {
    if (connected !== true || owing === '' || waiting) return
    // The wait before the next read: the first pace at the start, then twice as long after each.
    let wait = RECEIPT_READ_FIRST_MS
    // False once the view is gone: a pass that is in the middle of its reads makes no more.
    let live = true
    const reads = readOnCadence(
      async () => {
        for (const each of latest.current) {
          // A hidden page reads nothing, and neither does a view that has been left.
          if (!live || document.visibilityState === 'hidden') return
          if (each.actionId === null) continue
          try {
            const record = await port.actionRead(
              { action_id: each.actionId, session_id: sessionId },
              token
            )
            // What the host said is kept as it was read, whatever the submission makes of it: a later
            // prompt quotes the revision the person was shown, and that is the newest one read.
            receiptReads.note(record.receipt)
            // Only a record that says more than the submission does is taken, so that a read of the
            // same answer again changes nothing.
            if (applyReceipt(each, record.receipt) !== each) settle.current(each.localId, record.receipt)
          } catch {
            // The host is not asked twice as fast for failing: the next read is a wait away.
          }
        }
      },
      () => {
        const next = wait
        wait = Math.min(wait * 2, RECEIPT_READ_LONGEST_MS)
        return next
      }
    )
    // A page shown again is read at once by the cadence, and is a person coming back: the quick pace.
    const shown = () => {
      if (document.visibilityState === 'visible') wait = RECEIPT_READ_FIRST_MS
    }
    document.addEventListener('visibilitychange', shown)
    // A refusal that came of a record having moved is answered by reading it again at once.
    const stopAsking = receiptReads.whenAskedAgain(sessionId, () => {
      wait = RECEIPT_READ_FIRST_MS
      reads.now()
    })
    reads.now()
    return () => {
      live = false
      stopAsking()
      document.removeEventListener('visibilitychange', shown)
      reads.stop()
    }
  }, [connected, owing, port, receiptReads, sessionId, token, waiting])
}
