/**
 * The scripted host's store of channel messages keeps the rules native code keeps, so that a
 * case that runs against it is evidence for the real store (KR-REQ-12.26).
 *
 * Each case here is one of those rules, stated on the scripted store alone: bytes, not UTF-16
 * units; unreadable files that still take their place; a resume that is the same message, by its
 * members and its drafts as a set; a refusal that lasts as long as it was asked to; the file's own
 * length as the bytes a message takes; and a change of the list of removals that names every draft
 * or none, whoever makes it: a keep, a repair or a set-aside.
 */

import { describe, expect, it } from 'vitest'

import { FakeChannelMessageStore } from '../src/host/fake-channel-messages'
import { FakeDraftStore } from '../src/host/fake-drafts'
import { failureCode, failureMessage, type ChannelMessageKeep, type DraftSaveRequest } from '../src/host/port'

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
    store.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' }, 2)
    expect(refusal(() => store.keep(request(), drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(refusal(() => store.keep(request(), drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(refusal(() => store.keep(request(), drafts))).toBeNull()
  })

  it('refuses the next keep only, by default, and every keep when it is asked to', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    store.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' })
    expect(refusal(() => store.keep(request(), drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(refusal(() => store.keep(request(), drafts))).toBeNull()
    store.refuseKeeps({ code: 'RESOURCE_UNAVAILABLE', message: 'refused' }, Infinity)
    expect(refusal(() => store.keep(request({ actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000405' }), drafts))).toBe(
      'RESOURCE_UNAVAILABLE'
    )
    expect(refusal(() => store.keep(request({ actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000406' }), drafts))).toBe(
      'RESOURCE_UNAVAILABLE'
    )
  })

  it('fails a keep over a list of removals that cannot be read, keeps the entry, and marks nothing for removal', () => {
    for (const state of ['damaged', 'unreadable'] as const) {
      const drafts = new FakeDraftStore()
      const store = new FakeChannelMessageStore()
      store.damageLedger(state)
      const named = { id: 'a', expectedRevision: '1' }
      expect(refusal(() => store.keep(request({ drafts: [named] }), drafts))).toBe('RESOURCE_UNAVAILABLE')
      expect(store.all()).toHaveLength(1)
      expect(drafts.pendingRemovals()).toEqual([])
      // Readable again, the same keep is a resume that finishes the step.
      store.damageLedger('ok')
      expect(refusal(() => store.keep(request({ drafts: [named] }), drafts))).toBeNull()
      expect(drafts.pendingRemovals()).toHaveLength(1)
    }
  })

  it('says a full store and a store that cannot be read in the approved words', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    store.lowerLimits({ entries: 1 })
    expect(refusal(() => store.keep(request(), drafts))).toBeNull()
    const messageOf = (call: () => unknown): string => {
      try {
        call()
        return ''
      } catch (failure) {
        return failureMessage(failure)
      }
    }
    expect(messageOf(() => store.keep(request({ actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000407' }), drafts))).toBe(
      'Channel messages is full. Remove some on the Kept drafts page.'
    )
    store.makeUnavailable()
    expect(messageOf(() => store.list(false))).toBe('This device could not read or write its channel messages.')
  })
})

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const refused = { code: 'RESOURCE_UNAVAILABLE', message: 'This device could not read or write its list of removals. disk full' }

/** A draft in a store, as a person's composer saved it. */
function stored(drafts: FakeDraftStore, text: string): { id: string; expectedRevision: string } {
  const save: DraftSaveRequest = {
    id: null,
    expectedRevision: null,
    sessionId: SESSION,
    applicationInstanceId: null,
    agentBindingRevision: null,
    state: 'open',
    text,
    attachments: []
  }
  const saved = drafts.save(save)
  if (!('draft' in saved)) throw new Error('the draft was not stored')
  return { id: saved.draft.id, expectedRevision: saved.draft.revision }
}

/** The file native code writes for the message of `request` in `channel_messages.rs`, member by member. */
const NATIVE_FILE = [
  '{"version":1,"action_id":"6a7b6c50-22bb-4c3d-8e4f-000000000401","hold_id":null,',
  '"local_id":"s-1","session_id":"8a7b6c50-22bb-4c3d-8e4f-000000000101",',
  '"application_instance_id":"9a7b6c50-22bb-4c3d-8e4f-000000000201",',
  '"agent_binding_revision":"1","environment_id":null,"host_name":"studio",',
  '"text":"é text","sent_at_ms":1001,',
  '"drafts":[{"id":"00000000-0000-4000-8000-000000000001","expectedRevision":"3"}]}'
].join('')

describe('the scripted store counts and changes the list of removals as native code does', () => {
  it('counts the length of the file native code writes, and the sizes of the files it cannot read', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    const message = request({
      localId: 's-1',
      applicationInstanceId: '9a7b6c50-22bb-4c3d-8e4f-000000000201',
      agentBindingRevision: '1',
      text: 'é text',
      sentAtMs: '1001',
      drafts: [{ id: '00000000-0000-4000-8000-000000000001', expectedRevision: '3' }]
    })
    store.keep(message, drafts)
    const length = new TextEncoder().encode(NATIVE_FILE).length
    expect(store.list(false).used).toEqual({ entries: 1, bytes: length })
    store.leaveUnreadable('messages', { now: 1, bytes: 500 })
    expect(store.list(false).used).toEqual({ entries: 2, bytes: length + 500 })
    // The bound on bytes counts the unreadable file's size too: 499 bytes left of a bound, a second message does not fit.
    store.lowerLimits({ bytes: length + 500 })
    const second = request({ ...message, actionId: '6a7b6c50-22bb-4c3d-8e4f-000000000402' })
    expect(refusal(() => store.keep(second, drafts))).toBe('QUOTA_EXCEEDED')
    expect(store.all()).toHaveLength(1)
  })

  it('names every draft of a keep in one change or none, and undoes an entry that no draft of it is named for', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    const a = stored(drafts, 'a')
    const b = stored(drafts, 'b')
    drafts.refuseMarks(refused)
    expect(refusal(() => store.keep(request({ drafts: [a, b] }), drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(store.all()).toEqual([])
    expect(drafts.pendingRemovals()).toEqual([])
    // The refusal was one: the same keep now names both drafts in one change.
    expect(refusal(() => store.keep(request({ drafts: [a, b] }), drafts))).toBeNull()
    expect(drafts.pendingRemovals()).toHaveLength(2)
    // A resume whose change is refused leaves the entry it resumes.
    drafts.refuseMarks(refused)
    expect(refusal(() => store.keep(request({ drafts: [a, b] }), drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(store.all()).toHaveLength(1)
  })

  it('keeps an entry that the list names a draft of, as native code does after a partial change', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    const a = stored(drafts, 'a')
    const b = stored(drafts, 'b')
    drafts.markRemoval(a)
    drafts.refuseMarks(refused)
    expect(refusal(() => store.keep(request({ drafts: [a, b] }), drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(store.all()).toHaveLength(1)
    expect(drafts.pendingRemovals()).toEqual([a])
  })

  it('returns what the entries owe when a repair cannot change the list, keeps the record of the send, and finishes it at the next read', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    const a = stored(drafts, 'a')
    store.createHold({
      holdId: 'h-1',
      localId: 's-1',
      sessionId: SESSION,
      applicationInstanceId: null,
      agentBindingRevision: null,
      environmentId: null,
      hostName: 'studio',
      sentAtMs: '900',
      drafts: [a]
    })
    store.stopAfterEntry()
    expect(refusal(() => store.keep(request({ holdId: 'h-1', drafts: [a] }), drafts))).toBe('RESOURCE_UNAVAILABLE')
    drafts.refuseMarks(refused)
    const read = store.drafts(drafts)
    expect(read.pendingRemovals).toEqual([a])
    expect(drafts.pendingRemovals()).toEqual([])
    expect(store.allHolds()).toHaveLength(1)
    const next = store.drafts(drafts)
    expect(next.pendingRemovals).toEqual([a])
    expect(drafts.pendingRemovals()).toEqual([a])
    expect(store.allHolds()).toEqual([])
  })

  it('returns the owed drafts over a list that cannot be read, names none of them in it, and refuses a mark', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    const a = stored(drafts, 'a')
    const b = stored(drafts, 'b')
    store.keep(request({ drafts: [a] }), drafts)
    store.damageLedger('unreadable')
    const read = store.drafts(drafts)
    expect(read.ledger).toBe('unreadable')
    expect(read.pendingRemovals).toEqual([a])
    expect(refusal(() => store.markRemoval(b, drafts))).toBe('RESOURCE_UNAVAILABLE')
    expect(drafts.pendingRemovals()).toEqual([a])
    store.damageLedger('ok')
    expect(refusal(() => store.markRemoval(b, drafts))).toBeNull()
    expect(drafts.pendingRemovals()).toEqual([a, b])
  })

  it('replaces the list with the one the entries rebuild when a damaged one is set aside, and leaves it when the change is refused', () => {
    const drafts = new FakeDraftStore()
    const store = new FakeChannelMessageStore()
    const a = stored(drafts, 'a')
    const b = stored(drafts, 'b')
    store.keep(request({ drafts: [a] }), drafts)
    drafts.markRemoval(b)
    store.damageLedger('damaged')
    drafts.refuseMarks(refused)
    expect(
      (() => {
        try {
          store.setAside(drafts)
          return null
        } catch (failure) {
          return failureMessage(failure)
        }
      })()
    ).toBe(`This device could not set the list aside. The original list is still in place. ${refused.message}`)
    // Nothing moved: the list is still the damaged one, with what it named.
    expect(store.drafts(drafts).ledger).toBe('damaged')
    expect(drafts.pendingRemovals()).toEqual([a, b])
    const aside = store.setAside(drafts)
    expect(aside).toEqual({ moved: true, confirmed: true })
    expect(store.drafts(drafts).ledger).toBe('ok')
    // The rebuilt list names what an entry names, and the mark of a draft no entry names is gone.
    expect(drafts.pendingRemovals()).toEqual([a])
    expect(refusal(() => store.setAside(drafts))).toBe('INVALID_ARGUMENT')
  })
})
