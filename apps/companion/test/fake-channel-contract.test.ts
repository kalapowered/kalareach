/**
 * The scripted host's store of channel messages keeps the rules native code keeps, so that a
 * case that runs against it is evidence for the real store (KR-REQ-12.26).
 *
 * Each case here is one of those rules, stated on the scripted store alone: bytes, not UTF-16
 * units; unreadable files that still take their place; a resume that is the same message, by its
 * members and its drafts as a set; and a refusal that lasts as long as it was asked to.
 */

import { describe, expect, it } from 'vitest'

import { FakeChannelMessageStore } from '../src/host/fake-channel-messages'
import { FakeDraftStore } from '../src/host/fake-drafts'
import { failureCode, type ChannelMessageKeep } from '../src/host/port'

const request = (over: Partial<ChannelMessageKeep> = {}): ChannelMessageKeep => ({
  actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000401',
  holdId: null,
  localId: 's-1-test',
  sessionId: '8a7b6c50-22bb-4c3d-8e4f-000000000101',
  applicationInstanceId: null,
  agentBindingRevision: null,
  environmentId: null,
  hostName: 'studio',
  text: 'the message',
  sentAtMs: '1',
  drafts: [],
  ...over
})

function refusal(call: () => unknown): string | null {
  try {
    call()
    return null
  } catch (failure) {
    return failureCode(failure)
  }
}

describe('the scripted store of channel messages keeps the native rules', () => {
  it('counts a message’s text in UTF-8 bytes: 64 KiB is kept, one byte more is refused', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    expect(refusal(() => store.keep(request({ text: 'é'.repeat(32 * 1024) }), drafts))).toBeNull()
    const other = new FakeChannelMessageStore()
    expect(refusal(() => other.keep(request({ text: 'é'.repeat(32 * 1024) + 'a' }), drafts))).toBe('INVALID_ARGUMENT')
    expect(refusal(() => other.keep(request({ text: 'é'.repeat(40_000) }), drafts))).toBe('INVALID_ARGUMENT')
    expect(other.all()).toEqual([])
  })

  it('lets a file that cannot be read take its place against the bound of entries', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    store.lowerLimits({ entries: 2 })
    store.leaveUnreadable('messages', { now: 1 })
    expect(refusal(() => store.keep(request(), drafts))).toBeNull()
    expect(refusal(() => store.keep(request({ actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000402' }), drafts))).toBe(
      'QUOTA_EXCEEDED'
    )
    expect(store.all()).toHaveLength(1)
  })

  it('takes a resume for the same message, and refuses one that differs in any member or draft', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    const a = { id: 'a', expectedRevision: '1' }
    const b = { id: 'b', expectedRevision: '1' }
    expect(refusal(() => store.keep(request({ drafts: [a, b] }), drafts))).toBeNull()
    // The same drafts, as a set: in another order.
    expect(refusal(() => store.keep(request({ drafts: [b, a] }), drafts))).toBeNull()
    const marked = drafts.pendingRemovals().length
    const differs: readonly Partial<ChannelMessageKeep>[] = [
      { text: 'another text' },
      { sessionId: '8a7b6c50-22bb-4c3d-8e4f-000000000102' },
      { applicationInstanceId: '6a7b6c50-22bb-4c3d-8e4f-000000000501' },
      { agentBindingRevision: '7' },
      { drafts: [a] },
      { drafts: [a, { id: 'c', expectedRevision: '1' }] }
    ]
    for (const over of differs) {
      expect(refusal(() => store.keep(request({ drafts: [a, b], ...over }), drafts))).toBe('INVALID_ARGUMENT')
    }
    // A refused resume marks nothing for removal.
    expect(drafts.pendingRemovals()).toHaveLength(marked)
  })

  it('refuses the next keeps asked for and no more', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    store.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' }, 1)
    expect(refusal(() => store.keep(request(), drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(refusal(() => store.keep(request(), drafts))).toBeNull()
    store.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' })
    expect(refusal(() => store.keep(request({ actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000403' }), drafts))).toBe(
      'RESOURCE_UNAVAILABLE'
    )
    expect(refusal(() => store.keep(request({ actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000404' }), drafts))).toBe(
      'RESOURCE_UNAVAILABLE'
    )
  })
})
