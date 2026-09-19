/**
 * The mobile models, held to the sentences in the specification that produced them.
 *
 * Every test here names the row it is about. The rules these models exist to keep are rules about
 * what the interface is allowed to claim, and a rule like that is only kept if something fails
 * when it is broken.
 */

import { describe, expect, it } from 'vitest'

import type { AttentionEntry, AttentionInbox } from '../../src/model/pending'
import { connectionLost, edit, startDraft, type Draft } from '../../src/model/drafts'
import { queued, sent, unresolved, type Submission } from '../../src/model/receipts'
import {
  count,
  describeElapsed,
  detailOf,
  emptyMessage,
  filter,
  order
} from '../../src/mobile/model/inbox'
import {
  ACCESSORY_KEYS,
  NO_LATCH,
  afterKey,
  describeLatch,
  pressModifier,
  sequenceFor,
  sequenceForKeyPress
} from '../../src/mobile/model/accessory'
import {
  MAX_CONTROL_LANE_UPLOAD_LEN,
  admit,
  attributesFor,
  describeBytes
} from '../../src/mobile/model/media'
import { routeGesture, consumesGesture } from '../../src/mobile/model/gestures'
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
import { commercialSurface, describeAccount, usageFraction } from '../../src/mobile/model/account'
import { detectSurface, minimumTarget, showsBackControl, TOUCH_TARGET } from '../../src/mobile/platform'

const NOW = 1_763_000_000_000

function entry(over: Partial<AttentionEntry> & Pick<AttentionEntry, 'kind'>): AttentionEntry {
  return {
    attention_id: `a-${over.kind}`,
    title: 'Something',
    detail: 'A detail.',
    host_label: 'studio',
    environment_id: 'e-1',
    session_id: 's-1',
    session_epoch: '1',
    session_display_number: '3',
    application: 'Codex',
    raised_at_ms: NOW,
    ...over
  }
}

const INBOX: AttentionInbox = {
  entries: [
    entry({ kind: 'awaiting_review', raised_at_ms: NOW - 1000 }),
    entry({ kind: 'disconnected', out_of_contact_ms: 2_400_000, session_id: null, session_epoch: null, session_display_number: null, application: null }),
    entry({ kind: 'failed_action', error_code: 'QUOTA_EXCEEDED', raised_at_ms: NOW - 500 }),
    entry({ kind: 'pending_decision', command_preview: 'scripts/release.sh', raised_at_ms: NOW - 2000 })
  ]
}

describe('the attention inbox (KR-REQ-13.01, 13.02)', () => {
  it('tells the four kinds apart and puts what is waiting for a person first', () => {
    const rows = order(INBOX)
    expect(rows.map((row) => row.entry.kind)).toEqual([
      'pending_decision',
      'failed_action',
      'awaiting_review',
      'disconnected'
    ])
    expect(new Set(rows.map((row) => row.label)).size).toBe(4)
    expect(new Set(rows.map((row) => row.tone)).size).toBe(4)
  })

  it('never turns lost contact into a claim that anything is stuck or failed', () => {
    const lost = detailOf(
      entry({ kind: 'disconnected', out_of_contact_ms: 40 * 60 * 1000 })
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

  it('offers no decision on a host it cannot reach', () => {
    const rows = order(INBOX)
    expect(rows.find((row) => row.entry.kind === 'disconnected')?.actionable).toBe(false)
    expect(rows.find((row) => row.entry.kind === 'pending_decision')?.actionable).toBe(true)
  })

  it('reads the kind aloud rather than leaving it to a colour', () => {
    for (const row of order(INBOX)) {
      expect(row.announcement.startsWith(row.label)).toBe(true)
    }
  })

  it('filters to one kind and says what an empty filter means', () => {
    expect(filter(order(INBOX), 'failed_action')).toHaveLength(1)
    expect(emptyMessage('disconnected')).toBe('Every host is in contact.')
  })
})

describe('the accessory row and a hardware keyboard (KR-REQ-13.17)', () => {
  const key = (id: string) => {
    const found = ACCESSORY_KEYS.find((each) => each.id === id)
    if (!found) throw new Error(`no key ${id}`)
    return found
  }

  it('sends the escape and arrow sequences a terminal expects', () => {
    expect(sequenceFor(key('esc'), NO_LATCH)).toBe('\u001b')
    expect(sequenceFor(key('up'), NO_LATCH)).toBe('\u001b[A')
    expect(sequenceFor(key('tab'), NO_LATCH)).toBe('\t')
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

  it('produces the same bytes for a hardware key and for the row', () => {
    expect(sequenceForKeyPress({ key: 'c', ctrlKey: true, altKey: false, metaKey: false, shiftKey: false })).toBe(
      '\u0003'
    )
    expect(sequenceForKeyPress({ key: 'ArrowUp', ctrlKey: false, altKey: false, metaKey: false, shiftKey: false })).toBe(
      sequenceFor(key('up'), NO_LATCH)
    )
  })

  it('leaves a platform chord to the platform', () => {
    expect(
      sequenceForKeyPress({ key: 'c', ctrlKey: false, altKey: false, metaKey: true, shiftKey: false })
    ).toBeNull()
  })

  it('sends nothing rather than an unmodified key when a modifier has no meaning', () => {
    expect(sequenceFor(key('up'), pressModifier(NO_LATCH, 'ctrl'))).toBeNull()
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
  it('gives a one-finger drag to the program while control mode is active', () => {
    const outcome = routeGesture('control', { pointers: 1, deltaX: 0, deltaY: -64, scale: 1 })
    expect(outcome).toEqual({ kind: 'application', lines: 4 })
  })

  it('never pans the view in control mode, however far the finger travels', () => {
    for (const deltaY of [-500, -16, 16, 500]) {
      const outcome = routeGesture('control', { pointers: 1, deltaX: 30, deltaY, scale: 1 })
      expect(outcome.kind).toBe('application')
    }
  })

  it('pans and zooms in view mode', () => {
    expect(routeGesture('view', { pointers: 1, deltaX: 0, deltaY: -32, scale: 1 }).kind).toBe('pan')
    expect(routeGesture('view', { pointers: 2, deltaX: 0, deltaY: 0, scale: 1.4 })).toEqual({
      kind: 'zoom',
      steps: 1
    })
  })

  it('zooms in either mode, because nothing on the wire carries a pinch', () => {
    expect(routeGesture('control', { pointers: 2, deltaX: 0, deltaY: 0, scale: 0.6 })).toEqual({
      kind: 'zoom',
      steps: -1
    })
  })

  it('takes the gesture from the page only where it is used', () => {
    expect(consumesGesture('control', { pointers: 1, deltaX: 0, deltaY: 0, scale: 1 })).toBe(true)
    expect(consumesGesture('view', { pointers: 1, deltaX: 0, deltaY: 0, scale: 1 })).toBe(false)
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
    const text = describeAccount({ kind: 'local_only' })
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
