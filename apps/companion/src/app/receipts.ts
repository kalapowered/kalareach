/**
 * Asking the host what became of an action.
 *
 * A request whose answer never came as a receipt, or came as only its identity, is not asked again:
 * section 9 lets the host reconcile it later, and the host keeps what it recorded of it, readable
 * under the same authority. So while the host is reached the interface reads that record on a
 * cadence for each action it has no outcome for, and takes what it finds as a receipt that arrived.
 */

import { useEffect, useRef } from 'react'

import type { Receipt } from '@kalareach/protocol'

import { stateOfReceipt, type Submission } from '../model/receipts'
import { readOnCadence } from './cadence'
import { useApp } from './state'

/** How long after one read of an action's record the next one starts. */
export const RECEIPT_READ_CADENCE_MS = 4_000

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
 */
export function useReceiptReads({
  sessionId,
  connected,
  submissions,
  onReceipt
}: {
  readonly sessionId: string
  readonly connected: boolean | null
  readonly submissions: readonly Submission[]
  readonly onReceipt: (localId: string, receipt: Receipt) => void
}): void {
  const { port } = useApp()
  const owed = submissions.filter(awaitsReceipt)
  // What the next read asks about, as of that read; and what changes whether a read is owed at all.
  const latest = useRef(owed)
  const settle = useRef(onReceipt)
  useEffect(() => {
    latest.current = owed
    settle.current = onReceipt
  })
  const owing = owed.map((each) => `${each.localId}|${each.actionId ?? ''}`).join(',')
  useEffect(() => {
    if (connected !== true || owing === '') return
    const reads = readOnCadence(async () => {
      for (const each of latest.current) {
        if (each.actionId === null) continue
        try {
          const record = await port.actionRead({ action_id: each.actionId, session_id: sessionId })
          if (stateOfReceipt(record.receipt) !== each.state) settle.current(each.localId, record.receipt)
        } catch {
          // The host is not asked twice as fast for failing: the next read is a cadence away.
        }
      }
    }, RECEIPT_READ_CADENCE_MS)
    reads.now()
    return reads.stop
  }, [connected, owing, port, sessionId])
}
