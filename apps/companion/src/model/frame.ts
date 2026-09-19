/**
 * Batching semantic updates to one per animation frame.
 *
 * KR-PERF-008 asks for two things at once: updates batched at most once per animation frame, and
 * input that stays responsive while tool output streams and the history is large. Both come from
 * the same decision. A host that publishes forty events in eight milliseconds must not cause forty
 * renders, and the queue that holds them must never be what the keystroke is waiting behind.
 *
 * So an event is folded into a pending batch synchronously, which is cheap, and the batch is
 * published once on the next frame. The keystroke path does not go through here at all: a key is
 * sent as it is typed, and its local echo is a state change of its own.
 */

/** A sink that receives one batch per frame. */
export type Flush<T> = (batch: readonly T[]) => void

/** Schedules work for the next animation frame. */
export type Scheduler = (run: () => void) => void

/** The frame scheduler, or an immediate one where there is no document. */
export const animationFrame: Scheduler = (run) => {
  if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => run())
  else setTimeout(run, 16)
}

/**
 * Collects items and publishes them once per frame.
 *
 * The batch is published even if more arrive while it is being published; those land in the next
 * one. Nothing is dropped and nothing is published twice.
 */
export class FrameBatcher<T> {
  #pending: T[] = []
  #scheduled = false
  #frames = 0
  #flushed = 0

  constructor(
    private readonly flush: Flush<T>,
    private readonly schedule: Scheduler = animationFrame
  ) {}

  /** Adds one item to the pending batch. */
  push(item: T): void {
    this.#pending.push(item)
    this.#schedule()
  }

  /** Adds several items to the pending batch, still as one frame's work. */
  extend(items: readonly T[]): void {
    if (items.length === 0) return
    this.#pending.push(...items)
    this.#schedule()
  }

  /** How many items are waiting for the next frame. */
  get pending(): number {
    return this.#pending.length
  }

  /** How many frames this batcher has published, which is what a benchmark counts. */
  get frames(): number {
    return this.#frames
  }

  /** How many items it has published in total. */
  get published(): number {
    return this.#flushed
  }

  /** Publishes what is pending now, without waiting for a frame. */
  flushNow(): void {
    this.#scheduled = false
    if (this.#pending.length === 0) return
    const batch = this.#pending
    this.#pending = []
    this.#frames += 1
    this.#flushed += batch.length
    this.flush(batch)
  }

  /** Drops what is pending, for a view that is going away. */
  discard(): void {
    this.#pending = []
    this.#scheduled = false
  }

  #schedule(): void {
    if (this.#scheduled) return
    this.#scheduled = true
    this.schedule(() => {
      this.flushNow()
    })
  }
}
