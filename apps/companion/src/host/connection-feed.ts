/**
 * The one ordered feed of the host connection's state, in front of every view that follows it.
 *
 * Native code publishes each accepted change of what the page sees as a whole state with its
 * revision, and answers what a page missed since a revision. A raw event can arrive twice, late or
 * not at all, so a view that took each one as it came could show an older state over a newer one or
 * miss the last change for good. The feed takes what arrives, applies each revision once and in
 * order, and hands the views only that. It is a pure module: the desktop port and the stand-in for
 * native code both build one over their own source, so both keep the same rules.
 *
 * A feed is `unbased` until it has a state, `based` once it has one and `stopped` for good. The first
 * state it hears, from a read or from the first raw event, is its base: a read that answers at or
 * below it afterwards is dropped. In a based feed an event at the next revision is applied, one at
 * or below the last applied is dropped, and one above the next is a gap: the missed states are asked
 * for, one request at a time, applied in order, and the late duplicates are dropped. When the page
 * is further behind than native code keeps, the answer is the whole current state, taken as a new
 * base and flagged, so a view reads again from the start; one that is not above what was heard while
 * it was out is older than the page, and is dropped.
 *
 * Nothing waits on a view to look: while the document is visible the feed asks for what it missed
 * every few seconds, and when the document becomes visible, so a lost last event is found wherever
 * the page is.
 */

import type { ConnectionSince, ConnectionState } from './port'

/** How often the feed asks for what it missed while the document is visible. */
export const TAIL_MS = 5_000

/** What a feed is built over. */
export interface FeedSource {
  /** Reads the current state. */
  readonly read: () => Promise<ConnectionState>
  /** Asks for what the feed missed above `after`. */
  readonly since: (after: number) => Promise<ConnectionSince>
  /**
   * Registers for the raw events, each a whole state. Resolves, with the function that stops it, once
   * the registration is complete: an event published before then is not heard.
   */
  readonly listen: (heard: (state: ConnectionState) => void) => Promise<() => void>
  /** Whether the document is visible, so the tail runs. Defaults to the page's own. */
  readonly visible?: () => boolean
}

/** What a state is a change of, for a view whose reads depend on these members alone. */
export function triggerKey(state: ConnectionState): string {
  return JSON.stringify([
    state.host,
    state.connected,
    state.environment_id,
    state.rights,
    state.paired,
    state.replaced,
    state.link
  ])
}

export interface ConnectionFeed {
  /** Calls `show` with the latest state once there is one, then every revision, each once. */
  readonly watch: (
    show: (state: ConnectionState, resynced: boolean) => void,
    failed: (failure: unknown) => void
  ) => () => void
  /** Calls `listener` for each revision whose trigger key differs from the one before. */
  readonly onChange: (listener: (state: ConnectionState) => void) => Promise<() => void>
  /** The latest state, or null before the feed has one. */
  readonly latest: () => ConnectionState | null
  /** The revision the feed has applied: 0 before it has a state. */
  readonly appliedThrough: () => number
  /** Calls `told` after each state the feed applies, with its revision and whether it was a resync. */
  readonly onApplied: (told: (revision: number, resynced: boolean) => void) => () => void
  /** Asks for what was missed now: a gap fill, or the first state again while there is none. */
  readonly catchUp: () => void
  /** Ends the feed: nothing is told after this, including what a late answer brings. */
  readonly stop: () => void
}

interface Subscriber {
  /** The highest revision handed on, or null before the first. */
  seen: number | null
  /** Takes the first state this subscriber is given. */
  readonly first: (state: ConnectionState) => void
  /** Takes each state after the first. */
  readonly next: (state: ConnectionState, resynced: boolean) => void
  readonly failed: (failure: unknown) => void
}

/** Runs `call`, a refusal before it returns a promise being an answer like any other. */
function attempt<T>(call: () => Promise<T>): Promise<T> {
  try {
    return call()
  } catch (failure) {
    return Promise.reject(failure instanceof Error ? failure : new Error(String(failure)))
  }
}

/** Raises what a view's callback threw where it cannot stop the feed, and is not lost. */
function raise(failure: unknown): void {
  setTimeout(() => {
    throw failure
  }, 0)
}

export function createConnectionFeed(source: FeedSource): ConnectionFeed {
  let stage: 'unbased' | 'based' | 'stopped' = 'unbased'
  let started = false
  let cursor = 0
  let latest: ConnectionState | null = null
  let reading = false
  let filling = false
  let unlisten: (() => void) | null = null
  let timer: ReturnType<typeof setInterval> | null = null
  let looking: (() => void) | null = null
  const buffer = new Map<number, ConnectionState>()
  const subscribers = new Set<Subscriber>()
  const taps = new Set<(revision: number, resynced: boolean) => void>()

  const visible = (): boolean =>
    source.visible === undefined
      ? typeof document === 'undefined' || document.visibilityState !== 'hidden'
      : source.visible()

  const deliver = (subscriber: Subscriber, state: ConnectionState, resynced: boolean): void => {
    try {
      if (subscriber.seen === null) {
        subscriber.seen = state.revision
        subscriber.first(state)
        return
      }
      if (!resynced && state.revision <= subscriber.seen) return
      subscriber.seen = state.revision
      subscriber.next(state, resynced)
    } catch (failure) {
      raise(failure)
    }
  }

  const apply = (state: ConnectionState, resynced: boolean): void => {
    cursor = state.revision
    latest = state
    for (const subscriber of [...subscribers]) deliver(subscriber, state, resynced)
    for (const told of [...taps]) {
      try {
        told(cursor, resynced)
      } catch (failure) {
        raise(failure)
      }
    }
  }

  /** Applies the buffered states that follow the cursor, and drops the ones the cursor passed. */
  const drain = (): void => {
    for (const revision of [...buffer.keys()].sort((a, b) => a - b)) {
      const state = buffer.get(revision)
      if (state === undefined) continue
      if (revision <= cursor) {
        buffer.delete(revision)
        continue
      }
      if (revision !== cursor + 1) return
      buffer.delete(revision)
      apply(state, false)
    }
  }

  const fail = (failure: unknown): void => {
    for (const subscriber of [...subscribers]) {
      try {
        subscriber.failed(failure)
      } catch (raised) {
        raise(raised)
      }
    }
  }

  const fill = (): void => {
    if (filling || stage !== 'based') return
    filling = true
    const from = cursor
    void attempt(() => source.since(from)).then(
      (answer) => {
        filling = false
        if (stage === 'stopped') return
        if (answer.resync) {
          const whole = answer.states[answer.states.length - 1]
          if (whole === undefined) return
          // States heard while the request was out moved the feed on from where it asked, so a whole
          // state that is not above them is older than what the feed holds: the page was never
          // behind, and taking it would show an older state over a newer one. With nothing heard
          // meanwhile, a whole state below the cursor is native code starting its revisions over.
          if (cursor === from || whole.revision > cursor) {
            for (const revision of [...buffer.keys()]) if (revision <= whole.revision) buffer.delete(revision)
            apply(whole, true)
          }
        } else {
          for (const state of answer.states) if (state.revision > cursor) apply(state, false)
        }
        drain()
        if (buffer.size > 0 && cursor > from) fill()
      },
      (failure: unknown) => {
        filling = false
        if (stage === 'stopped') return
        fail(failure)
      }
    )
  }

  const accept = (state: ConnectionState): void => {
    if (stage === 'stopped') return
    if (stage === 'unbased') {
      stage = 'based'
      apply(state, false)
      return
    }
    if (state.revision <= cursor) return
    if (state.revision === cursor + 1) {
      apply(state, false)
      drain()
      if (buffer.size > 0) fill()
      return
    }
    buffer.set(state.revision, state)
    fill()
  }

  const readBase = (): void => {
    if (reading || stage !== 'unbased' || unlisten === null) return
    reading = true
    void attempt(source.read).then(
      (state) => {
        reading = false
        accept(state)
      },
      (failure: unknown) => {
        reading = false
        if (stage === 'stopped') return
        fail(failure)
      }
    )
  }

  const start = (): void => {
    if (started || stage === 'stopped') return
    started = true
    void attempt(() => source.listen(accept)).then(
      (stop) => {
        if (stage === 'stopped') {
          stop()
          return
        }
        unlisten = stop
        readBase()
      },
      (failure: unknown) => {
        started = false
        if (stage === 'stopped') return
        fail(failure)
      }
    )
  }

  const catchUp = (): void => {
    if (stage === 'stopped') return
    if (!started) start()
    else if (stage === 'unbased') readBase()
    else fill()
  }

  const startTail = (): void => {
    if (timer !== null || stage === 'stopped') return
    timer = setInterval(() => {
      if (visible()) catchUp()
    }, TAIL_MS)
    if (typeof document !== 'undefined') {
      const onVisible = (): void => {
        if (visible()) catchUp()
      }
      document.addEventListener('visibilitychange', onVisible)
      looking = () => {
        document.removeEventListener('visibilitychange', onVisible)
      }
    }
  }

  const stopTail = (): void => {
    if (timer !== null) clearInterval(timer)
    timer = null
    looking?.()
    looking = null
  }

  const attach = (subscriber: Subscriber): (() => void) => {
    if (stage === 'stopped') return () => undefined
    subscribers.add(subscriber)
    startTail()
    if (stage === 'based' && latest !== null) deliver(subscriber, latest, false)
    else catchUp()
    return () => {
      subscribers.delete(subscriber)
      if (subscribers.size === 0) stopTail()
    }
  }

  return {
    watch: (show, failed) =>
      attach({
        seen: null,
        first: (state) => {
          show(state, false)
        },
        next: show,
        failed
      }),
    onChange: (listener) =>
      new Promise<() => void>((resolve) => {
        let key = ''
        let off = false
        const detach = (): void => {
          off = true
          detached()
        }
        const detached = attach({
          seen: null,
          first: (state) => {
            key = triggerKey(state)
            resolve(detach)
          },
          next: (state, resynced) => {
            if (off) return
            const now = triggerKey(state)
            if (!resynced && now === key) return
            key = now
            listener(state)
          },
          failed: () => undefined
        })
      }),
    latest: () => latest,
    appliedThrough: () => cursor,
    onApplied: (told) => {
      taps.add(told)
      return () => {
        taps.delete(told)
      }
    },
    catchUp,
    stop: () => {
      if (stage === 'stopped') return
      stage = 'stopped'
      buffer.clear()
      subscribers.clear()
      taps.clear()
      stopTail()
      unlisten?.()
      unlisten = null
    }
  }
}
