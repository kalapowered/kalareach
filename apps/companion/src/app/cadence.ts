/**
 * Reading again while a view is shown.
 *
 * Some of what the host holds changes with no event to say so: the attention inbox, the requests an
 * agent is waiting on, the agent's own history. A view of one reads it again on a cadence while the
 * page is shown, and at once when the page is shown again. It never reads twice at once: the next
 * read starts a cadence after the previous one answered, so a slow host is never asked faster than
 * it answers, and a read asked for while one is on its way runs as soon as that one has answered,
 * so what an action changed is read after the action rather than lost.
 *
 * Something the view can see change, such as output on the screen, asks for a read sooner with
 * `soon()`. Such a wake starts a read now if the last one started a gap ago, and otherwise when the
 * gap has passed, so a stream of output costs at most one read in each gap. It starts a read of its
 * own cadence only: a read that another cadence owns keeps that cadence's own deadline.
 */

/** A view's reads on a cadence. */
export interface Cadence {
  /** Reads now, or as soon as the read on its way has answered. */
  readonly now: () => void
  /**
   * Reads because what the read shows probably changed: now when the last read started at least
   * the wake gap ago, otherwise when that gap has passed; one more read follows a read on its way,
   * under the same gap. Nothing before the first `now()`, and nothing while the page is hidden.
   */
  readonly soon: () => void
  /** Stops reading. A read on its way answers, and no other starts. */
  readonly stop: () => void
}

/** Whether the page is hidden, as a minimised window or a phone app in the background is. */
function hidden(): boolean {
  return typeof document !== 'undefined' && document.visibilityState === 'hidden'
}

/**
 * Reads with `read` every `cadenceMs` while the page is shown, starting at the first `now()`.
 *
 * `read` settles once its read has answered or failed; how it shows either is its own affair. A
 * cadence that is a function is asked how long to wait each time a read has answered, so a caller
 * can read less often the longer nothing changes.
 */
export function readOnCadence(
  read: () => Promise<unknown>,
  cadenceMs: number | (() => number),
  wakeGapMs = 0
): Cadence {
  let running = false
  let owed = false
  let owedSoon = false
  let started = false
  let stopped = false
  let lastStart = Number.NEGATIVE_INFINITY
  let timer: ReturnType<typeof setTimeout> | null = null
  let waking: ReturnType<typeof setTimeout> | null = null

  const clear = () => {
    if (timer !== null) clearTimeout(timer)
    timer = null
    if (waking !== null) clearTimeout(waking)
    waking = null
  }

  function now(): void {
    clear()
    if (stopped) return
    started = true
    if (running) {
      owed = true
      return
    }
    // A hidden page reads nothing; it reads at once when it is shown again.
    if (hidden()) return
    running = true
    lastStart = Date.now()
    void read()
      .catch(() => undefined)
      .finally(() => {
        running = false
        if (stopped) return
        if (owed) {
          owed = false
          owedSoon = false
          now()
          return
        }
        timer = setTimeout(now, typeof cadenceMs === 'function' ? cadenceMs() : cadenceMs)
        if (owedSoon) {
          owedSoon = false
          soon()
        }
      })
  }

  function soon(): void {
    if (stopped || !started) return
    if (running) {
      owedSoon = true
      return
    }
    // A hidden page reads at once when it is shown again; a read already waiting its gap is the one.
    if (hidden() || waking !== null) return
    const wait = lastStart + wakeGapMs - Date.now()
    if (wait <= 0) {
      now()
      return
    }
    waking = setTimeout(() => {
      waking = null
      now()
    }, wait)
  }

  const shown = () => {
    if (started && !hidden()) now()
  }
  if (typeof document !== 'undefined') document.addEventListener('visibilitychange', shown)

  return {
    now,
    soon,
    stop: () => {
      stopped = true
      clear()
      if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', shown)
    }
  }
}
