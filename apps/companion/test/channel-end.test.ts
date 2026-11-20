/**
 * How a message to a channel session that confirms nothing is classified, and what its mark
 * takes out of the counts (KR-REQ-12.26).
 *
 * A message is a channel end only on the host's own word that it cannot tell, for a package whose
 * answers are not confirmed, with an action to keep the text under. Once the device's store has
 * the text, the row no longer holds the next message, waits on the host, or is counted.
 */

import { describe, expect, it } from 'vitest'

import {
  awaitsHost,
  endsAsChannelEnd,
  isHandOver,
  isOutOfCounts,
  reconnectBanner,
  unconfirmedReason,
  unresolved,
  type ChannelMark,
  type Submission
} from '../src/model/receipts'

const unknownAnswer = { receipt: null, value: null, action_id: 'action-1', answer_lost: false }

function row(over: Partial<Submission> = {}): Submission {
  return {
    localId: 'l-1',
    actionId: 'action-1',
    label: 'hello',
    text: 'hello',
    state: 'unknown',
    createdAtMs: 1,
    error: null,
    ...over
  }
}

describe('a message is a channel end only on the host’s own word', () => {
  it('C1 is true for an unknown outcome, not lost, of a channel package, with an action', () => {
    expect(endsAsChannelEnd(unknownAnswer, true)).toBe(true)
    // Each other input is not one.
    expect(endsAsChannelEnd(unknownAnswer, false)).toBe(false)
    expect(endsAsChannelEnd({ ...unknownAnswer, answer_lost: true }, true)).toBe(false)
    expect(endsAsChannelEnd({ ...unknownAnswer, answer_lost: undefined }, true)).toBe(false)
    expect(endsAsChannelEnd({ ...unknownAnswer, action_id: null }, true)).toBe(false)
    expect(
      endsAsChannelEnd({ receipt: null, value: { done: true }, action_id: 'action-1', answer_lost: false }, true)
    ).toBe(false)
  })
})

describe('what a mark takes out of the counts', () => {
  const marks: readonly (ChannelMark | undefined)[] = [undefined, 'keeping', 'ended', 'released']

  it('C2 hold, banner and wait skip an ended or released row, and not a row that is still being kept', () => {
    const counted = marks.map((mark) => {
      const submission = row({ channel: mark })
      const submissions = [submission]
      return {
        mark,
        handOver: isHandOver(submission),
        out: isOutOfCounts(submission),
        awaits: awaitsHost(submission),
        reason: unconfirmedReason(submissions) !== null,
        waiting: unresolved(submissions).length,
        banner: reconnectBanner(true, submissions) !== null
      }
    })
    expect(counted).toEqual([
      { mark: undefined, handOver: false, out: false, awaits: true, reason: true, waiting: 1, banner: true },
      { mark: 'keeping', handOver: true, out: false, awaits: true, reason: true, waiting: 1, banner: true },
      { mark: 'ended', handOver: true, out: true, awaits: false, reason: false, waiting: 0, banner: false },
      { mark: 'released', handOver: true, out: true, awaits: false, reason: false, waiting: 0, banner: false }
    ])
  })

  it('C2b counts only the rows still counted when a marked row sits among others', () => {
    const submissions = [
      row({ localId: 'a', channel: 'ended' }),
      row({ localId: 'b' }),
      row({ localId: 'c', state: 'sent' })
    ]
    expect(unresolved(submissions).map((each) => each.localId)).toEqual(['b', 'c'])
    expect(unconfirmedReason(submissions)).toMatch(/^One action has no confirmed outcome yet\./)
  })
})
