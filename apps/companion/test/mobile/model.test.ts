/**
 * The mobile models, held to the sentences in the specification that produced them.
 *
 * Every test here names the row it is about. The rules these models exist to keep are rules about
 * what the interface is allowed to claim, and a rule like that is only kept if something fails
 * when it is broken.
 */

import { describe, expect, it } from 'vitest'

import type { AttentionItem, AttentionReadResult } from '@kalareach/protocol'

import { connectionLost, edit, startDraft, type Draft } from '../../src/model/drafts'
import { queued, sent, unresolved, type Submission } from '../../src/model/receipts'
import {
  count,
  describeElapsed,
  detailOf,
  emptyMessage,
  filter,
  inboxNotes,
  MAX_INBOX_PAGES,
  order,
  readWholeInbox
} from '../../src/model/attention'
import {
  ACCESSORY_KEYS,
  NO_LATCH,
  afterKey,
  describeLatch,
  pressModifier,
  rowKey
} from '../../src/mobile/model/accessory'
import {
  MAX_CONTROL_LANE_UPLOAD_LEN,
  admit,
  attributesFor,
  describeBytes
} from '../../src/mobile/model/media'
import { describeMode } from '../../src/mobile/model/gestures'
import {
  EMPTY_DURABLE_STATE,
  onResume,
  persist,
  rebindAll,
  recoveryBanner,
  restore,
  summarise
} from '../../src/mobile/model/lifecycle'
import { DRAFTS_KEY, deviceStore, memoryStore, readRecord, writeRecord } from '../../src/mobile/model/store'
import { commercialSurface, describeAccount, usageFraction } from '../../src/model/account'
import { detectSurface, minimumTarget, showsBackControl, TOUCH_TARGET } from '../../src/mobile/platform'

const NOW = 1_763_000_000_000

function item(over: Partial<AttentionItem> & Pick<AttentionItem, 'rule'>): AttentionItem {
  return {
    key: `${over.rule}|~0123456789abcdef0123456789abcdef`,
    source: 'semantic',
    level: 'notable',
    session_id: '8a7b6c50-22bb-4c3d-8e4f-000000000101',
    summary: 'Something',
    trusted: true,
    routing: 'owner_policy',
    occurrences: '1',
    first_seen_ms: String(NOW),
    last_seen_ms: String(NOW),
    notification: 'delivered',
    awaiting_delivery: false,
    acknowledged: false,
    uncertain: false,
    revision: '1',
    automation: null,
    ...over
  }
}

function inbox(items: AttentionItem[], over: Partial<AttentionReadResult> = {}): AttentionReadResult {
  return {
    items,
    more: false,
    dropped: '0',
    gaps: [],
    quiet_hours: null,
    quiet_now: false,
    quiet_hours_provable: true,
    ...over
  }
}

const INBOX = inbox([
  item({ rule: 'attention.review_ready', last_seen_ms: String(NOW - 1000) }),
  item({
    rule: 'attention.host_contact_lost',
    source: 'receipts',
    session_id: null,
    summary: 'studio',
    first_seen_ms: String(NOW - 2_400_000)
  }),
  item({ rule: 'attention.command_failed', source: 'host_events', last_seen_ms: String(NOW - 500) }),
  item({ rule: 'attention.pending_approval', level: 'urgent', last_seen_ms: String(NOW - 2000) })
])

describe('reading the whole inbox (KR-REQ-13.09)', () => {
  /** An inbox of `total` items, served `size` at a time, oldest first, as the host pages it. */
  function paged(total: number, size: number) {
    const all = Array.from({ length: total }, (_, index) =>
      item({ rule: 'attention.application_notice', key: `k-${String(index).padStart(4, '0')}` })
    )
    const asked: (string | null)[] = []
    const read = (after: string | null): Promise<AttentionReadResult> => {
      asked.push(after)
      const start = after === null ? 0 : all.findIndex((each) => each.key === after) + 1
      return Promise.resolve(
        inbox(all.slice(start, start + size), { more: start + size < total })
      )
    }
    return { read, asked }
  }

  it('follows the pages until the host has no more', async () => {
    const { read, asked } = paged(450, 200)
    const whole = await readWholeInbox(read)
    expect(whole.items).toHaveLength(450)
    expect(whole.more).toBe(false)
    expect(asked).toEqual([null, 'k-0199', 'k-0399'])
  })

  it('stops at its bound and says the host holds more', async () => {
    const { read, asked } = paged(MAX_INBOX_PAGES * 10 + 5, 10)
    const whole = await readWholeInbox(read)
    expect(asked).toHaveLength(MAX_INBOX_PAGES)
    expect(whole.more).toBe(true)
    expect(inboxNotes(whole)).toContain('The host holds more items than this list shows.')
  })

  it('reads again from the start, once, when an item it continued after has gone', async () => {
    let reads = 0
    const whole = await readWholeInbox((after) => {
      reads += 1
      if (after !== null && reads === 2) {
        return Promise.reject({ code: 'DRAFT_CONFLICT', message: 'gone', user_action: 'retry' })
      }
      return Promise.resolve(
        inbox([item({ rule: 'attention.review_ready', key: after === null ? 'a' : 'b' })], {
          more: after === null
        })
      )
    })
    expect(reads).toBe(4)
    expect(whole.items.map((each) => each.key)).toEqual(['a', 'b'])
  })
})

describe('the attention inbox (KR-REQ-13.01, 13.02)', () => {
  it('tells the four kinds apart and puts what is waiting for a person first', () => {
    const rows = order(INBOX, NOW)
    expect(rows.map((row) => row.kind)).toEqual([
      'pending_decision',
      'failed_action',
      'awaiting_review',
      'disconnected'
    ])
    expect(new Set(rows.map((row) => row.label)).size).toBe(4)
    expect(new Set(rows.map((row) => row.tone)).size).toBe(4)
  })

  it('sorts the most recent first within a kind, reading the times as counters', () => {
    const rows = order(
      inbox([
        item({ rule: 'attention.command_failed', key: 'older', last_seen_ms: '9007199254740992' }),
        item({ rule: 'attention.adapter_failed', key: 'newer', last_seen_ms: '9007199254740993' })
      ]),
      NOW
    )
    expect(rows.map((row) => row.item.key)).toEqual(['newer', 'older'])
  })

  it('never turns lost contact into a claim that anything is stuck or failed', () => {
    const lost = detailOf(
      item({ rule: 'attention.host_contact_lost', first_seen_ms: String(NOW - 40 * 60 * 1000) }),
      NOW
    )
    expect(lost).toContain('No contact for 40 minutes')
    expect(lost).toContain('may still be running')
    for (const forbidden of ['stuck', 'hung', 'failed', 'crashed', 'dead', 'stalled']) {
      expect(lost.toLowerCase()).not.toContain(forbidden)
    }
  })

  it('reports elapsed time as elapsed time', () => {
    expect(describeElapsed(1000)).toBe('1 second')
    expect(describeElapsed(90_000)).toBe('1 minute')
    expect(describeElapsed(3 * 3600_000)).toBe('3 hours')
    expect(describeElapsed(50 * 3600_000)).toBe('2 days')
  })

  it('counts a lost host apart from the things a person can act on', () => {
    const counts = count(INBOX)
    expect(counts.disconnected).toBe(1)
    expect(counts.actionable).toBe(2)
  })

  it('offers a decision only on an approval in a session, and none on a host it cannot reach', () => {
    const rows = order(INBOX, NOW)
    expect(rows.find((row) => row.kind === 'disconnected')?.actionable).toBe(false)
    expect(rows.find((row) => row.kind === 'pending_decision')?.actionable).toBe(true)
    const question = order(inbox([item({ rule: 'attention.pending_input' })]), NOW)[0]
    expect(question?.kind).toBe('pending_decision')
    expect(question?.actionable).toBe(false)
  })

  it('reads the kind aloud rather than leaving it to a colour', () => {
    for (const row of order(INBOX, NOW)) {
      expect(row.announcement.startsWith(row.label)).toBe(true)
    }
  })

  it('filters to one kind and says what an empty filter means', () => {
    expect(filter(order(INBOX, NOW), 'failed_action')).toHaveLength(1)
    expect(emptyMessage('disconnected')).toBe('Every host is in contact.')
  })

  it('says a notice a program printed is not a request from the host, and never a decision', () => {
    const [notice] = order(
      inbox([
        item({
          rule: 'attention.application_notice',
          source: 'host_events',
          trusted: false,
          routing: 'lease_holder',
          summary: 'Deploy now?',
          occurrences: '3'
        })
      ]),
      NOW
    )
    expect(notice?.kind).toBe('notice')
    expect(notice?.actionable).toBe(false)
    expect(notice?.detail).toContain('A program in the session printed it.')
    expect(notice?.detail).toContain('It happened 3 times.')
  })

  it('names the rule when the host withheld the item’s own text, and says it withheld it', () => {
    const [withheld] = order(inbox([item({ rule: 'attention.pending_input', summary: null })]), NOW)
    expect(withheld?.title).toBe('A question is waiting for an answer')
    expect(withheld?.detail).toContain('did not share this item’s text')
  })

  it('says what the inbox let go, what it can no longer read, and why it is not holding sounds', () => {
    expect(inboxNotes(INBOX)).toEqual([])
    const notes = inboxNotes(
      inbox([], {
        dropped: '2',
        gaps: [{ source: 'questions', session_id: null, from_sequence: '4', to_sequence: null }],
        quiet_hours: { start_minute: '1320', end_minute: '420', zone: null },
        quiet_hours_provable: false
      })
    )
    expect(notes).toHaveLength(3)
    expect(notes[0]).toContain('let 2 older items go')
    expect(notes[2]).toContain('cannot prove what its clock reads')
  })
})

describe('the accessory row (KR-REQ-13.17)', () => {
  const key = (id: string) => {
    const found = ACCESSORY_KEYS.find((each) => each.id === id)
    if (!found) throw new Error(`no key ${id}`)
    return found
  }
  const NO_LOCKS = { capsLock: false, numLock: false }

  it('names each key as a keyboard names it, never as the bytes a terminal reads', () => {
    expect(ACCESSORY_KEYS.map((each) => each.key ?? each.modifier)).toEqual([
      'Escape',
      'Tab',
      'ctrl',
      'alt',
      'ArrowUp',
      'ArrowDown',
      'ArrowLeft',
      'ArrowRight',
      'Home',
      'End',
      '|',
      '-',
      '/',
      '~'
    ])
    expect(rowKey(key('esc'), NO_LATCH, NO_LOCKS)).toEqual({
      key: 'Escape',
      base: null,
      keypad: null,
      shift: false,
      alt: false,
      control: false,
      caps_lock: false,
      num_lock: false
    })
    // A character of the row is the key that makes it with nothing held.
    expect(rowKey(key('pipe'), NO_LATCH, NO_LOCKS)).toMatchObject({ key: '|', base: '|' })
  })

  it('sends a key with the modifiers the row holds for it and the locks that are on', () => {
    const control = pressModifier(NO_LATCH, 'ctrl')
    expect(rowKey(key('tab'), control, NO_LOCKS)).toMatchObject({ key: 'Tab', control: true, alt: false })
    expect(rowKey(key('up'), pressModifier(control, 'alt'), { capsLock: true, numLock: true })).toMatchObject({
      key: 'ArrowUp',
      control: true,
      alt: true,
      caps_lock: true,
      num_lock: true
    })
    // A modifier latches rather than sends.
    expect(rowKey(key('ctrl'), NO_LATCH, NO_LOCKS)).toBeNull()
  })

  it('latches a modifier for one key, then locks it, then lets it go', () => {
    const once = pressModifier(NO_LATCH, 'ctrl')
    expect(once.ctrl).toBe('once')
    expect(afterKey(once).ctrl).toBe('off')
    const locked = pressModifier(once, 'ctrl')
    expect(locked.ctrl).toBe('locked')
    expect(afterKey(locked).ctrl).toBe('locked')
    expect(pressModifier(locked, 'ctrl').ctrl).toBe('off')
  })

  it('says which of the three states a modifier is in', () => {
    expect(describeLatch(key('ctrl'), NO_LATCH)).toBe('Control, off')
    expect(describeLatch(key('ctrl'), pressModifier(NO_LATCH, 'ctrl'))).toContain('next key')
  })
})

describe('camera, library and file input (KR-REQ-13.17)', () => {
  it('opens the platform pickers through the file input', () => {
    expect(attributesFor('camera')).toEqual({ accept: 'image/*', capture: 'environment', multiple: false })
    expect(attributesFor('library').accept).toContain('image/*')
    expect(attributesFor('files').accept).toBe('*/*')
  })

  it('admits an attachment that fits one control frame', () => {
    const admission = admit({
      name: 'photo.jpg',
      mediaType: 'image/jpeg',
      byteLen: MAX_CONTROL_LANE_UPLOAD_LEN,
      source: 'camera'
    })
    expect(admission.admitted).toBe(true)
  })

  it('refuses a larger one by name, at the bound, rather than failing on the wire', () => {
    const admission = admit({
      name: 'clip.mov',
      mediaType: 'video/quicktime',
      byteLen: 22 * 1024 * 1024,
      source: 'library'
    })
    expect(admission.admitted).toBe(false)
    if (admission.admitted) return
    expect(admission.code).toBe('TOO_LARGE_FOR_LANE')
    expect(admission.reason).toContain('clip.mov')
    expect(admission.reason).toContain('22.0 MB')
    expect(admission.reason).toContain('1020 KB')
  })

  it('describes a size the way a person reads one', () => {
    expect(describeBytes(512)).toBe('512 bytes')
    expect(describeBytes(2048)).toBe('2 KB')
    expect(describeBytes(3 * 1024 * 1024)).toBe('3.0 MB')
  })
})

describe('the raw terminal on a touch screen (KR-REQ-13.18, 13.17)', () => {
  it('says what each state of control does, and why control ended when it did', () => {
    const watching = { number: 0, state: 'watching', ended: null } as const
    const taking = { number: 1, state: 'taking', ended: null } as const
    const controlling = { number: 1, state: 'controlling', ended: null } as const
    expect(describeMode(watching, 'reaches')).toBe(
      'View: drag to move around the session, pinch to make the text larger or smaller.'
    )
    expect(describeMode(taking, 'reaches')).toBe('Asking the session for control…')
    expect(describeMode(controlling, 'reaches')).toBe(
      'Control: your keys and drags go to the program in this terminal.'
    )
    expect(describeMode(controlling, 'unreported')).toBe(
      'Control: your keys go to the program, which is not using the wheel. Look around to scroll.'
    )
    expect(describeMode(controlling, 'unwritable')).toBe(
      'Control: your keys go to the program, which asks for the wheel in a form this view cannot send. Look around to scroll.'
    )
    expect(describeMode(controlling, null)).toBe('Control: your keys go to the program in this terminal.')
    const lost = 'Control ended: another view took it, or the program changed how it reads keys.'
    expect(describeMode({ number: 1, state: 'watching', ended: lost }, 'reaches')).toBe(lost)
  })
})

describe('the durable store (KR-ACC-012)', () => {
  it('keeps a record across a restart', () => {
    const store = memoryStore()
    expect(writeRecord(store, DRAFTS_KEY, [{ draftId: 'd-1' }])).toBe(true)
    expect(readRecord<{ draftId: string }[]>(store, DRAFTS_KEY)).toEqual({
      kind: 'read',
      value: [{ draftId: 'd-1' }]
    })
  })

  it('leaves a record it does not understand where it is, and never replaces it', () => {
    const store = memoryStore()
    store.write(DRAFTS_KEY, JSON.stringify({ version: 99, value: ['keep me'] }))
    expect(readRecord(store, DRAFTS_KEY)).toEqual({ kind: 'unsupported', version: 99 })
    expect(writeRecord(store, DRAFTS_KEY, [])).toBe(false)
    expect(store.read(DRAFTS_KEY)).toContain('keep me')
  })

  it('tells an unreadable record from an absent one', () => {
    const store = memoryStore()
    store.write(DRAFTS_KEY, 'not json at all')
    expect(readRecord(store, DRAFTS_KEY)).toEqual({ kind: 'invalid' })
  })

  it('still runs when the device will not store anything', () => {
    const store = deviceStore(refusingStorage())
    expect(writeRecord(store, DRAFTS_KEY, ['a'])).toBe(true)
    expect(readRecord<string[]>(store, DRAFTS_KEY)).toEqual({ kind: 'read', value: ['a'] })
    expect(store.isDurable(DRAFTS_KEY)).toBe(false)
  })

  it('never answers with what the device held before a write it refused', () => {
    // The device keeps the older value: reading it back would show the person a draft older than
    // the one they typed, which is worse than saying the run has no durability.
    const values = new Map<string, string>([[DRAFTS_KEY, JSON.stringify({ version: 1, value: ['old'] })]])
    const failing = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => {
        if (key === DRAFTS_KEY) throw new Error('quota')
        values.set(key, value)
      },
      removeItem: (key: string) => {
        values.delete(key)
      },
      key: () => null,
      clear: () => undefined,
      length: 0
    } as unknown as Storage
    const store = deviceStore(failing)
    expect(writeRecord(store, DRAFTS_KEY, ['new'])).toBe(true)
    expect(readRecord<string[]>(store, DRAFTS_KEY)).toEqual({ kind: 'read', value: ['new'] })
    expect(store.isDurable(DRAFTS_KEY)).toBe(false)
  })
})

/** A device that refuses every write, which is a private window or a full disk. */
function refusingStorage(): Storage {
  return {
    getItem: () => {
      throw new Error('denied')
    },
    setItem: () => {
      throw new Error('denied')
    },
    removeItem: () => {
      throw new Error('denied')
    },
    key: () => null,
    clear: () => undefined,
    length: 0
  }
}

describe('recovery after suspension, termination and a network change (KR-ACC-012, KR-REQ-13.02)', () => {
  const target = { sessionId: 's-1', applicationInstanceId: 'app-1', agentBindingRevision: '4' }
  const draft: Draft = edit(startDraft('d-1', target, NOW), 'half a sentence', NOW)
  const submission: Submission = sent(queued('local-1', 'run it', NOW), 'action-1')

  it('keeps the draft and drops only the association when contact goes', () => {
    const after = connectionLost(draft)
    expect(after.text).toBe('half a sentence')
    expect(after.revision).toBe(draft.revision)
    expect(after.state).toBe('detached')
    expect(after.attachmentId).toBeNull()
  })

  it('reads back a cold start with the drafts intact and no outcome claimed', () => {
    const store = memoryStore()
    persist(store, { drafts: [draft], submissions: [submission] })
    const restored = restore(store)
    expect(restored.drafts[0]?.text).toBe('half a sentence')
    expect(restored.drafts[0]?.state).toBe('detached')
    expect(restored.submissions[0]?.state).toBe('unknown')
  })

  it('treats a suspension and a network change as a lost connection, not a restart', () => {
    const store = memoryStore()
    const current = { drafts: [draft], submissions: [submission] }
    for (const resumption of ['suspended', 'network_changed'] as const) {
      const after = onResume(resumption, current, store)
      expect(after.drafts[0]?.text).toBe('half a sentence')
      expect(after.drafts[0]?.state).toBe('detached')
      expect(after.submissions[0]?.state).toBe('sent')
    }
  })

  it('rebinds only the same target, conflicts a changed one and orphans a lost session', () => {
    const detached = connectionLost(draft)
    expect(rebindAll([detached], [{ draftId: 'd-1', target, attachmentId: 'at-9' }])[0]).toMatchObject({
      state: 'bound',
      attachmentId: 'at-9'
    })
    expect(
      rebindAll([detached], [
        { draftId: 'd-1', target: { ...target, agentBindingRevision: '5' }, attachmentId: 'at-9' }
      ])[0]
    ).toMatchObject({ state: 'conflicted', attachmentId: null })
    expect(rebindAll([detached], [{ draftId: 'd-1', target: null, attachmentId: 'at-9' }])[0]).toMatchObject({
      state: 'orphaned'
    })
  })

  it('leaves a conflicted or an orphaned draft for the person, whatever the host reports', () => {
    const conflicted = rebindAll(
      [connectionLost(draft)],
      [{ draftId: 'd-1', target: { ...target, agentBindingRevision: '5' }, attachmentId: 'at-9' }]
    )
    const orphaned = rebindAll([connectionLost(draft)], [{ draftId: 'd-1', target: null, attachmentId: 'at-9' }])
    const again = rebindAll([...conflicted, ...orphaned], [
      { draftId: 'd-1', target, attachmentId: 'at-10' }
    ])
    expect(again[0]).toBe(conflicted[0])
    expect(again[1]).toBe(orphaned[0])
  })

  it('never submits anything on the way back', () => {
    const detached = connectionLost(draft)
    const rebound = rebindAll([detached], [{ draftId: 'd-1', target, attachmentId: 'at-9' }])
    expect(rebound[0]?.text).toBe(detached.text)
    expect(unresolved([submission])).toHaveLength(1)
  })

  it('reports what recovered without reporting an action as done', () => {
    const store = memoryStore()
    persist(store, { drafts: [draft], submissions: [submission] })
    const restored = restore(store)
    const summary = summarise(restored)
    expect(summary.kept).toBe(1)
    expect(summary.unresolvedActions).toBe(1)
    const banner = recoveryBanner('restarted', summary)
    expect(banner?.title).toBe('Started again')
    expect(banner?.detail).toContain('no confirmed outcome')
    expect(banner?.detail).toContain('Nothing was sent again.')
    for (const forbidden of ['applied', 'succeeded', 'sent successfully', 'completed']) {
      expect(banner?.detail.toLowerCase()).not.toContain(forbidden)
    }
  })

  it('says nothing when there is nothing to recover', () => {
    expect(recoveryBanner('cold_start', summarise(EMPTY_DURABLE_STATE))).toBeNull()
    // A draft written in this run is a draft, not a consequence of a break.
    expect(recoveryBanner('cold_start', summarise({ drafts: [draft], submissions: [] }))).toBeNull()
  })
})

describe('the commercial surface on a mobile build (KR-REQ-17.32)', () => {
  it('permits signing in and showing usage, and nothing that takes money', () => {
    for (const channel of ['app_store', 'play', 'independent'] as const) {
      expect(commercialSurface(channel)).toEqual({
        signIn: true,
        usage: true,
        checkout: false,
        purchaseCallToAction: false
      })
    }
  })

  it('says plainly that no account is needed for local work', () => {
    const text = describeAccount({ state: 'signed_out', outcome: null })
    expect(text).toContain('work exactly as they do with one')
  })

  it('reads a usage line as a fraction of what is included', () => {
    expect(usageFraction({ label: 'Sessions', used: 5, included: 20, unit: 'sessions' })).toBe(0.25)
    expect(usageFraction({ label: 'Sessions', used: 5, included: null, unit: 'sessions' })).toBeNull()
  })
})

describe('the platform (KR-REQ-13.19)', () => {
  it('reads each platform from what its WebView says it is', () => {
    expect(detectSurface('Mozilla/5.0 (iPhone; CPU iPhone OS 26_5 like Mac OS X)')).toBe('ios')
    expect(detectSurface('Mozilla/5.0 (Linux; Android 16; Pixel 9)')).toBe('android')
    expect(detectSurface('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 5)).toBe('ios')
    expect(detectSurface('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 0)).toBe('desktop')
  })

  it('uses the platform own minimum target', () => {
    expect(TOUCH_TARGET.ios).toBe(44)
    expect(TOUCH_TARGET.android).toBe(48)
    expect(minimumTarget('ios')).toBe(44)
    expect(minimumTarget('android')).toBe(48)
  })

  it('leaves going back to Android, which has its own', () => {
    expect(showsBackControl('android')).toBe(false)
    expect(showsBackControl('ios')).toBe(true)
  })
})
