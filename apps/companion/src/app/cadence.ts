/**
 * Reading again while a view is shown.
 *
 * Some of what the host holds changes with no event to say so: the attention inbox, the requests an
 * agent is waiting on, the agent's own history. A view of one reads it again on a cadence while the
 * page is shown, and at once when the page is shown again. It never reads twice at once: the next
 * read starts a cadence after the previous one answered, so a slow host is never asked faster than
 * it answers, and a read asked for while one is on its way runs as soon as that one has answered,
 * so what an action changed is read after the action rather than lost.
 */

/** A view's reads on a cadence. */
export interface Cadence {
  /** Reads now, or as soon as the read on its way has answered. */
  readonly now: () => void
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
 * `read` settles once its read has answered or failed; how it shows either is its own affair.
 */
export function readOnCadence(read: () => Promise<unknown>, cadenceMs: number): Cadence {
  let running = false
  let owed = false
  let started = false
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | null = null

  const clear = () => {
    if (timer !== null) clearTimeout(timer)
    timer = null
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
    void read()
      .catch(() => undefined)
      .finally(() => {
        running = false
        if (stopped) return
        if (owed) {
          owed = false
          now()
          return
        }
        timer = setTimeout(now, cadenceMs)
      })
  }

  const shown = () => {
    if (started && !hidden()) now()
  }
  if (typeof document !== 'undefined') document.addEventListener('visibilitychange', shown)

  return {
    now,
    stop: () => {
      stopped = true
      clear()
      if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', shown)
    }
  }
}
