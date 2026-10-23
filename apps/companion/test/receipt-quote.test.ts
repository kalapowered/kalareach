/**
 * The earlier action a later prompt names (KR-REQ-23.24).
 *
 * The host compares a later request with the newest uncertain outcome of the same method for the
 * same session, instance and binding revision, so the page names exactly that one and otherwise
 * names nothing: a quote of an action that does not stand in the prompt's way is refused, and the
 * person is left with no way to send. The render cases in `submissions.test.tsx` show the quote
 * reaching the port from both layouts; these are the choices among several actions that a screen
 * cannot reach in one run.
 */

import type { Receipt } from '@kalareach/protocol'
import { describe, expect, it } from 'vitest'

import { ReceiptReads, supersessionFor } from '../src/model/receipt-reads'
import { queued, type Submission } from '../src/model/receipts'

const INSTANCE = '8a7b6c50-22bb-4c3d-8e4f-000000000201'

/** A prompt whose outcome the page was told nobody knows, sent to `binding` of the agent. */
function unknown(action: string, binding = '1'): Submission {
  return {
    ...queued(`s-${action}`, 'run it', 1),
    actionId: action,
    state: 'unknown',
    sentTo: { applicationInstanceId: INSTANCE, agentBindingRevision: binding }
  }
}

/** The record of an action as the host last said it. */
function record(
  action: string,
  over: Partial<Pick<Receipt, 'method' | 'state' | 'revision' | 'updated_at_ms'>> = {}
): Receipt {
  return {
    action_id: action,
    actor_id: 'owner:local',
    error: null,
    method: 'agent.prompt.submit',
    method_version: 1,
    payload_digest: '0'.repeat(64),
    reason: null,
    revision: '2',
    state: 'unknown',
    updated_at_ms: '100',
    accepted_deadline_ms: null,
    ...over
  }
}

const TO = { applicationInstanceId: INSTANCE, agentBindingRevision: '1' }

describe('the action a later prompt names', () => {
  it('is the prompt to this conversation whose newest read said unknown, with the revision read', () => {
    const reads = new ReceiptReads()
    reads.note(record('a', { revision: '5' }))
    expect(supersessionFor([unknown('a')], reads, TO)).toEqual({ action_id: 'a', revision: '5' })
  })

  it('is the newest of two by the time its record was written, and the later identifier at a tie', () => {
    const reads = new ReceiptReads()
    reads.note(record('a', { updated_at_ms: '100' }))
    reads.note(record('b', { updated_at_ms: '200' }))
    expect(supersessionFor([unknown('a'), unknown('b')], reads, TO)?.action_id).toBe('b')
    reads.note(record('c', { updated_at_ms: '200' }))
    expect(supersessionFor([unknown('a'), unknown('b'), unknown('c')], reads, TO)?.action_id).toBe('c')
  })

  it.each([
    ['a read that said the host still has it', record('a', { state: 'dispatching' })],
    ['a read that said it was applied', record('a', { state: 'applied' })],
    ['an action of another method', record('a', { method: 'agent.prompt.queue' })]
  ])('is none for %s', (_name, read) => {
    const reads = new ReceiptReads()
    reads.note(read)
    expect(supersessionFor([unknown('a')], reads, TO)).toBeNull()
  })

  it('is none for an action nobody read, and for one sent to another conversation', () => {
    const reads = new ReceiptReads()
    expect(supersessionFor([unknown('a')], reads, TO)).toBeNull()
    reads.note(record('a'))
    expect(supersessionFor([unknown('a', '1')], reads, { ...TO, agentBindingRevision: '2' })).toBeNull()
  })

  it('keeps the newest revision read, whatever order the reads arrive in', () => {
    const reads = new ReceiptReads()
    reads.note(record('a', { revision: '9' }))
    reads.note(record('a', { revision: '4' }))
    expect(supersessionFor([unknown('a')], reads, TO)?.revision).toBe('9')
  })
})
