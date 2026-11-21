/**
 * The feed that puts the host connection's states in order in front of every view: what it applies
 * and what it drops, how it fills a gap, how it starts and how it ends, and what each kind of
 * subscriber is told. It is built here over a scripted source, which answers each read and each
 * request for what was missed only when a test says so.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import { createConnectionFeed, TAIL_MS, type FeedSource } from '../src/host/connection-feed'
import type { ConnectionSince, ConnectionState } from '../src/host/port'

const state = (revision: number, over: Partial<ConnectionState> = {}): ConnectionState => ({
  connected: true,
  environment_id: 'env-a',
  reason: null,
  rights: ['session.view'],
  paired: false,
  replaced: 0,
  revision,
  link: 1,
  host: { kind: 'local' },
  contact: { state: 'in_contact' },
  inbox_epoch: 1,
  others: [],
  ...over
})

const since = (revision: number, states: ConnectionState[], resync = false): ConnectionSince => ({
  revision,
  states,
  resync
})

/** A source that answers only when told to. */
function scripted() {
  let heard: ((state: ConnectionState) => void) | null = null
  let registered = 0
  let stopped = 0
  let completeRegistration: () => void = () => undefined
  let holdRegistration = false
  const reads: { resolve: (state: ConnectionState) => void; reject: (failure: unknown) => void }[] = []
  const asked: {
    after: number
    resolve: (answer: ConnectionSince) => void
    reject: (failure: unknown) => void
  }[] = []
  const document = { visible: true }
  const source: FeedSource = {
    read: () =>
      new Promise((resolve, reject) => {
        reads.push({ resolve, reject })
      }),
    since: (after) =>
      new Promise((resolve, reject) => {
        asked.push({ after, resolve, reject })
      }),
    listen: (listener) => {
      heard = listener
      registered += 1
      const stop = () => {
        stopped += 1
        heard = null
      }
      if (!holdRegistration) return Promise.resolve(stop)
      return new Promise<() => void>((resolve) => {
        completeRegistration = () => {
          resolve(stop)
        }
      })
    },
    visible: () => document.visible
  }
  return {
    source,
    reads,
    asked,
    document,
    tell: (each: ConnectionState) => {
      heard?.(each)
    },
    holdRegistration: () => {
      holdRegistration = true
    },
    completeRegistration: () => {
      completeRegistration()
    },
    registrations: () => registered,
    stops: () => stopped
  }
}

/** Lets every promise that is ready run. */
async function settle(): Promise<void> {
  for (let turn = 0; turn < 8; turn += 1) await Promise.resolve()
}

const revisions = (states: readonly ConnectionState[]): number[] => states.map((each) => each.revision)

afterEach(() => {
  vi.useRealTimers()
})

describe('the feed that orders the connection’s states', () => {
  it('the base read and events heard before it apply once', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    feed.watch((each) => shown.push(each.revision), () => undefined)
    await settle()
    // Two events are heard while the read is out; the read then answers with the first of them.
    script.tell(state(5))
    script.tell(state(6))
    script.reads[0]?.resolve(state(5))
    await settle()
    expect(shown).toEqual([5, 6])
    expect(feed.latest()?.revision).toBe(6)
    expect(feed.appliedThrough()).toBe(6)
    feed.stop()
  })

  it('a duplicate is dropped', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    feed.watch((each) => shown.push(each.revision), () => undefined)
    await settle()
    script.tell(state(1))
    script.tell(state(2))
    script.tell(state(2))
    script.tell(state(1))
    await settle()
    expect(shown).toEqual([1, 2])
    // A duplicate is no gap: nothing is asked for.
    expect(script.asked).toHaveLength(0)
    feed.stop()
  })

  it('a lower revision after a higher is dropped', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: ConnectionState[] = []
    feed.watch((each) => shown.push(each), () => undefined)
    await settle()
    script.tell(state(4))
    script.tell(state(3, { connected: false, reason: 'an older state' }))
    await settle()
    expect(revisions(shown)).toEqual([4])
    expect(feed.latest()?.connected).toBe(true)
    // An older state is no gap either: nothing is asked for.
    expect(script.asked).toHaveLength(0)
    feed.stop()
  })

  it('a gap is filled from the replay in order and the late duplicate is dropped', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    feed.watch((each) => shown.push(each.revision), () => undefined)
    await settle()
    script.tell(state(1))
    // 2 and 3 are missed; 4 arrives and is held while they are asked for.
    script.tell(state(4))
    await settle()
    expect(script.asked.map((each) => each.after)).toEqual([1])
    expect(shown).toEqual([1])
    script.asked[0]?.resolve(since(4, [state(2), state(3), state(4)]))
    await settle()
    expect(shown).toEqual([1, 2, 3, 4])
    // The event of 3 comes late after all.
    script.tell(state(3))
    await settle()
    expect(shown).toEqual([1, 2, 3, 4])
    expect(script.asked).toHaveLength(1)
    feed.stop()
  })

  it('a resync is applied as a new base and flagged', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: { revision: number; resynced: boolean }[] = []
    feed.watch((each, resynced) => shown.push({ revision: each.revision, resynced }), () => undefined)
    await settle()
    script.tell(state(1))
    script.tell(state(900))
    await settle()
    script.asked[0]?.resolve(since(900, [state(900, { connected: false })], true))
    await settle()
    expect(shown).toEqual([
      { revision: 1, resynced: false },
      { revision: 900, resynced: true }
    ])
    expect(feed.latest()?.connected).toBe(false)
    script.tell(state(901))
    await settle()
    expect(shown[2]).toEqual({ revision: 901, resynced: false })
    feed.stop()
  })

  it('a resync that answers after later events advanced the feed is dropped', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: { revision: number; resynced: boolean }[] = []
    feed.watch((each, resynced) => shown.push({ revision: each.revision, resynced }), () => undefined)
    await settle()
    script.tell(state(1))
    // 3 is ahead of the page, so the replay is asked for from 1; 2 and then 4 are heard while it is out.
    script.tell(state(3))
    await settle()
    expect(script.asked.map((each) => each.after)).toEqual([1])
    script.tell(state(2))
    script.tell(state(4, { connected: false, reason: 'the newest state' }))
    await settle()
    expect(shown.map((each) => each.revision)).toEqual([1, 2, 3, 4])
    // Native code answers that the page is too far behind, with the whole state it held when it was
    // asked: that is older than 4, and the page was never behind.
    script.asked[0]?.resolve(since(3, [state(3)], true))
    await settle()
    expect(shown).toEqual([
      { revision: 1, resynced: false },
      { revision: 2, resynced: false },
      { revision: 3, resynced: false },
      { revision: 4, resynced: false }
    ])
    expect(feed.latest()?.revision).toBe(4)
    expect(feed.latest()?.connected).toBe(false)
    expect(feed.appliedThrough()).toBe(4)
    // The next change follows 4, not the older snapshot.
    script.tell(state(5))
    await settle()
    expect(shown.at(-1)).toEqual({ revision: 5, resynced: false })
    feed.stop()
  })

  it('a resync above the events heard meanwhile is applied and flagged', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: { revision: number; resynced: boolean }[] = []
    feed.watch((each, resynced) => shown.push({ revision: each.revision, resynced }), () => undefined)
    await settle()
    script.tell(state(1))
    script.tell(state(3))
    await settle()
    script.tell(state(2))
    await settle()
    // The page is at 3 when native code answers that it was further behind: the whole state is newer.
    script.asked[0]?.resolve(since(900, [state(900)], true))
    await settle()
    expect(shown.at(-1)).toEqual({ revision: 900, resynced: true })
    expect(feed.appliedThrough()).toBe(900)
    feed.stop()
  })

  it('a resync below the cursor is native code starting again when nothing was heard meanwhile', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: { revision: number; resynced: boolean }[] = []
    feed.watch((each, resynced) => shown.push({ revision: each.revision, resynced }), () => undefined)
    await settle()
    script.tell(state(500))
    await settle()
    // The tail asks again; native code has restarted and its revisions begin over.
    feed.catchUp()
    await settle()
    expect(script.asked.map((each) => each.after)).toEqual([500])
    script.asked[0]?.resolve(since(3, [state(3, { reason: 'after the restart' })], true))
    await settle()
    expect(shown.at(-1)).toEqual({ revision: 3, resynced: true })
    expect(feed.appliedThrough()).toBe(3)
    script.tell(state(4))
    await settle()
    expect(shown.at(-1)).toEqual({ revision: 4, resynced: false })
    feed.stop()
  })

  it('a failed fill tells no failure, keeps the state the feed has and is retried', async () => {
    vi.useFakeTimers()
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    const failures: unknown[] = []
    feed.watch(
      (each) => shown.push(each.revision),
      (failure) => failures.push(failure)
    )
    await vi.advanceTimersByTimeAsync(0)
    script.tell(state(1))
    script.tell(state(3))
    await vi.advanceTimersByTimeAsync(0)
    script.asked[0]?.reject(new Error('the replay could not be read'))
    await vi.advanceTimersByTimeAsync(0)
    // The state the views were shown is still the connection's: a request that failed says nothing of it.
    expect(failures).toEqual([])
    expect(shown).toEqual([1])
    expect(feed.latest()?.revision).toBe(1)
    // The next tail asks again, and this time it is answered.
    await vi.advanceTimersByTimeAsync(TAIL_MS)
    expect(script.asked).toHaveLength(2)
    script.asked[1]?.resolve(since(3, [state(2), state(3)]))
    await vi.advanceTimersByTimeAsync(0)
    expect(shown).toEqual([1, 2, 3])
    expect(failures).toEqual([])
    feed.stop()
  })

  it('a base read that fails after an event gave the base tells no failure', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    const failures: unknown[] = []
    feed.watch(
      (each) => shown.push(each.revision),
      (failure) => failures.push(failure)
    )
    await settle()
    // The read is still out when the first event is heard, and the event is the base.
    script.tell(state(7))
    await settle()
    expect(shown).toEqual([7])
    script.reads[0]?.reject(new Error('no state could be read'))
    await settle()
    expect(failures).toEqual([])
    expect(feed.latest()?.revision).toBe(7)
    // The base is not asked for again.
    expect(script.reads).toHaveLength(1)
    feed.stop()
  })

  it('an unbased feed takes the first event as its base and drops a later lower base', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    feed.watch((each) => shown.push(each.revision), () => undefined)
    await settle()
    // The read is still out, and the first event is the base.
    script.tell(state(7))
    await settle()
    expect(shown).toEqual([7])
    script.reads[0]?.resolve(state(5))
    await settle()
    expect(shown).toEqual([7])
    expect(feed.latest()?.revision).toBe(7)
    feed.stop()
  })

  it('a failed base read with no event is retried by the tail', async () => {
    vi.useFakeTimers()
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    const failures: unknown[] = []
    feed.watch(
      (each) => shown.push(each.revision),
      (failure) => failures.push(failure)
    )
    await vi.advanceTimersByTimeAsync(0)
    script.reads[0]?.reject(new Error('no state could be read'))
    await vi.advanceTimersByTimeAsync(0)
    expect(failures).toHaveLength(1)
    expect(shown).toEqual([])
    await vi.advanceTimersByTimeAsync(TAIL_MS)
    expect(script.reads).toHaveLength(2)
    script.reads[1]?.resolve(state(2))
    await vi.advanceTimersByTimeAsync(0)
    expect(shown).toEqual([2])
    feed.stop()
  })

  it('a registration resolves on the first event when the base read fails and the view’s first read starts at once', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    let registered = false
    let rejected = false
    const registration = feed.onChange(() => undefined)
    void registration.then(
      () => {
        registered = true
      },
      () => {
        rejected = true
      }
    )
    await settle()
    script.reads[0]?.reject(new Error('no state could be read'))
    await settle()
    // A failed read does not reject it, and it is not complete before it has a state.
    expect(rejected).toBe(false)
    expect(registered).toBe(false)
    script.tell(state(3))
    await settle()
    expect(registered).toBe(true)
    expect(feed.latest()?.revision).toBe(3)
    feed.stop()
  })

  it('stop during a retry ends it', async () => {
    vi.useFakeTimers()
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    feed.watch((each) => shown.push(each.revision), () => undefined)
    await vi.advanceTimersByTimeAsync(0)
    script.reads[0]?.reject(new Error('no state could be read'))
    await vi.advanceTimersByTimeAsync(TAIL_MS)
    expect(script.reads).toHaveLength(2)
    feed.stop()
    script.reads[1]?.resolve(state(2))
    await vi.advanceTimersByTimeAsync(TAIL_MS * 3)
    expect(shown).toEqual([])
    expect(script.reads).toHaveLength(2)
    expect(script.stops()).toBe(1)
  })

  it('a stop ends a registration that completes late', async () => {
    const script = scripted()
    script.holdRegistration()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    feed.watch((each) => shown.push(each.revision), () => undefined)
    await settle()
    feed.stop()
    script.completeRegistration()
    await settle()
    // The registration that completed after the stop is stopped at once, and nothing is read.
    expect(script.stops()).toBe(1)
    expect(script.reads).toHaveLength(0)
    expect(shown).toEqual([])
  })

  it('two subscribers each see each revision once', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const first: number[] = []
    const second: number[] = []
    feed.watch((each) => first.push(each.revision), () => undefined)
    feed.watch((each) => second.push(each.revision), () => undefined)
    await settle()
    script.tell(state(1))
    script.tell(state(1))
    script.tell(state(2))
    script.reads[0]?.resolve(state(1))
    await settle()
    expect(first).toEqual([1, 2])
    expect(second).toEqual([1, 2])
    expect(script.registrations()).toBe(1)
    feed.stop()
  })

  it('a subscriber attached late gets the latest, then the rest', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const early: number[] = []
    feed.watch((each) => early.push(each.revision), () => undefined)
    await settle()
    script.tell(state(1))
    script.tell(state(2))
    script.tell(state(3))
    const late: number[] = []
    feed.watch((each) => late.push(each.revision), () => undefined)
    expect(late).toEqual([3])
    script.tell(state(4))
    expect(late).toEqual([3, 4])
    expect(early).toEqual([1, 2, 3, 4])
    feed.stop()
  })

  it('calls the trigger only for a changed trigger key', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const triggered: number[] = []
    const watched: number[] = []
    const registration = feed.onChange((each) => triggered.push(each.revision))
    feed.watch((each) => watched.push(each.revision), () => undefined)
    await settle()
    script.tell(state(1))
    await registration
    // None of these moves what a view's reads depend on.
    script.tell(state(2, { others: [{ reference: 'b', name: 'B', contact: { state: 'unknown' }, inbox_epoch: 1 }] }))
    script.tell(state(3, { contact: { state: 'out_of_contact', since_ms: 1, escalates_at_ms: 2 } }))
    script.tell(state(4, { inbox_epoch: 2 }))
    script.tell(state(5, { reason: 'a new reason' }))
    // Each of these does.
    script.tell(state(6, { connected: false, environment_id: null, rights: null }))
    script.tell(state(7, { replaced: 1 }))
    script.tell(state(8, { link: 2 }))
    script.tell(state(9, { host: { kind: 'paired', reference: 'x', name: 'X' } }))
    await settle()
    expect(watched).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9])
    expect(triggered).toEqual([6, 7, 8, 9])
    feed.stop()
  })

  it('an on-connection registration resolves after the base and hears a change the base holds only by the latest state', async () => {
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const triggered: number[] = []
    let completed = false
    const registration = feed.onChange((each) => triggered.push(each.revision))
    void registration.then(() => {
      completed = true
    })
    await settle()
    // The registration is not complete while the feed has no state.
    expect(completed).toBe(false)
    script.reads[0]?.resolve(state(4, { connected: false, environment_id: null, rights: null }))
    await settle()
    expect(completed).toBe(true)
    // The listener is never told of the base: a user that began before the registration completed
    // reads the latest state at that moment.
    expect(triggered).toEqual([])
    expect(feed.latest()).toMatchObject({ revision: 4, connected: false })
    script.tell(state(5))
    await settle()
    expect(triggered).toEqual([5])
    feed.stop()
  })

  it('the tail finds a missed last revision', async () => {
    vi.useFakeTimers()
    const script = scripted()
    const feed = createConnectionFeed(script.source)
    const shown: number[] = []
    feed.watch((each) => shown.push(each.revision), () => undefined)
    await vi.advanceTimersByTimeAsync(0)
    script.tell(state(1))
    // The event of 2 is lost; nothing after it comes. On the interval the tail asks and finds it.
    await vi.advanceTimersByTimeAsync(TAIL_MS)
    expect(script.asked.map((each) => each.after)).toEqual([1])
    script.asked[0]?.resolve(since(2, [state(2)]))
    await vi.advanceTimersByTimeAsync(0)
    expect(shown).toEqual([1, 2])

    // The document was hidden for a while: nothing is asked on the interval, and when it is shown
    // again the feed asks at once.
    script.document.visible = false
    await vi.advanceTimersByTimeAsync(TAIL_MS * 2)
    expect(script.asked).toHaveLength(1)
    script.document.visible = true
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(0)
    expect(script.asked.map((each) => each.after)).toEqual([1, 2])
    script.asked[1]?.resolve(since(3, [state(3)]))
    await vi.advanceTimersByTimeAsync(0)
    expect(shown).toEqual([1, 2, 3])
    feed.stop()
  })
})
