/**
 * The physics behind the one gesture in this application.
 *
 * Settings open over a live session as a sheet, and a sheet is the only thing here a person drags.
 * Everything else is a transition of 120 to 200 ms, which CSS does better than JavaScript because
 * it runs off the main thread.
 *
 * A dragged surface has to do four things a transition cannot. It tracks the pointer one to one,
 * including the offset from where it was grabbed. It resists past its own edge instead of stopping
 * dead. It decides from the velocity at release, not the distance, so a flick dismisses. And it can
 * be caught and reversed at any instant, which means the animation must always start from the value
 * that is on screen rather than from where the last animation thought it was.
 *
 * A critically damped spring gives all four: it has no overshoot to look wrong on a sheet, it takes
 * the release velocity as its initial condition, and retargeting it mid-flight is just a new target
 * with the current position and velocity.
 */

/** Whether the person asked for less motion. */
export function prefersReducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
}

/** A spring's shape, in the two numbers a designer can reason about. */
export interface Spring {
  /** 1 is critically damped: it settles without overshooting. Below 1 it bounces. */
  readonly damping: number
  /** Roughly how long it takes to reach the target, in seconds. */
  readonly response: number
}

/** The default for a surface: no overshoot, and quick. */
export const SHEET_SPRING: Spring = { damping: 1, response: 0.35 }

/**
 * Projects where a flick would come to rest.
 *
 * This is the same exponential decay a scroll view uses, so a flick in this application lands where
 * a flick anywhere else on the platform would.
 */
export function projectEndpoint(
  position: number,
  velocity: number,
  decelerationRate = 0.998
): number {
  return position + (velocity / 1000) * (decelerationRate / (1 - decelerationRate))
}

/**
 * How far a drag past a boundary actually moves.
 *
 * Real things slow before they stop. A hard stop reads as the interface having frozen; increasing
 * resistance reads as "you have reached the end", which is what it means.
 */
export function rubberband(overshoot: number, dimension: number, constant = 0.55): number {
  if (dimension <= 0) return 0
  return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot))
}

/** What a running spring is doing. */
export interface SpringState {
  value: number
  velocity: number
}

/**
 * Advances a critically damped spring by one step.
 *
 * The closed form is used rather than an integrator, so a long frame does not make the motion
 * overshoot or explode: a dropped frame produces the position the spring would have been at, not
 * a numerically larger one.
 */
export function stepSpring(
  state: SpringState,
  target: number,
  spring: Spring,
  deltaSeconds: number
): SpringState {
  if (deltaSeconds <= 0) return state
  // Response is the time to settle; the natural frequency that produces it for a critically damped
  // spring is about 2 pi over the response.
  const omega = (2 * Math.PI) / Math.max(spring.response, 0.01)
  const zeta = Math.max(0.05, spring.damping)
  const offset = state.value - target

  if (zeta >= 1) {
    const decay = Math.exp(-omega * deltaSeconds)
    const c1 = offset
    const c2 = state.velocity + omega * offset
    return {
      value: target + (c1 + c2 * deltaSeconds) * decay,
      velocity: (state.velocity - c2 * omega * deltaSeconds) * decay
    }
  }

  const damped = omega * Math.sqrt(1 - zeta * zeta)
  const decay = Math.exp(-zeta * omega * deltaSeconds)
  const cosine = Math.cos(damped * deltaSeconds)
  const sine = Math.sin(damped * deltaSeconds)
  const c2 = (state.velocity + zeta * omega * offset) / damped
  const value = target + decay * (offset * cosine + c2 * sine)
  const velocity =
    decay *
    (state.velocity * cosine -
      (offset * omega * omega + zeta * omega * state.velocity) * (sine / damped))
  return { value, velocity }
}

/** When a spring is close enough to be done. */
export function settled(state: SpringState, target: number): boolean {
  return Math.abs(state.value - target) < 0.5 && Math.abs(state.velocity) < 20
}

/** A handle on a running animation. */
export interface Animation {
  /** Retargets from wherever the value is now, keeping the velocity it has. */
  retarget(target: number): void
  /** The value on screen at this instant. */
  readonly value: number
  /** Stops it where it is. */
  stop(): void
}

/**
 * Runs a spring toward a target, calling back with each frame's value.
 *
 * `onDone` fires only when the spring settles, never when it is stopped or retargeted, so a caller
 * can use it to decide that a sheet is now closed.
 */
export function animateSpring(options: {
  from: number
  velocity: number
  to: number
  spring?: Spring
  onFrame: (value: number) => void
  onDone?: () => void
  now?: () => number
  schedule?: (run: (time: number) => void) => number
  cancel?: (handle: number) => void
}): Animation {
  const spring = options.spring ?? SHEET_SPRING
  const schedule =
    options.schedule ??
    ((run: (time: number) => void) =>
      typeof requestAnimationFrame === 'function'
        ? requestAnimationFrame(run)
        : (setTimeout(() => {
            run(Date.now())
          }, 16)))
  const cancel =
    options.cancel ??
    ((handle: number) => {
      if (typeof cancelAnimationFrame === 'function') cancelAnimationFrame(handle)
      else clearTimeout(handle)
    })

  let state: SpringState = { value: options.from, velocity: options.velocity }
  let target = options.to
  let last = options.now?.() ?? null
  let handle: number | null = null
  let running = true

  const frame = (time: number) => {
    if (!running) return
    const previous = last ?? time
    last = time
    // A tab that was hidden produces one enormous delta. Clamping it keeps the motion continuous
    // instead of teleporting the surface.
    const delta = Math.min(0.064, Math.max(0, (time - previous) / 1000))
    state = stepSpring(state, target, spring, delta)
    if (settled(state, target)) {
      state = { value: target, velocity: 0 }
      running = false
      options.onFrame(state.value)
      options.onDone?.()
      return
    }
    options.onFrame(state.value)
    handle = schedule(frame)
  }

  handle = schedule(frame)

  return {
    retarget(next: number) {
      // From the presentation value, with the velocity it already has. Restarting from the logical
      // value is what makes a reversed gesture jump.
      target = next
      if (!running) {
        running = true
        last = null
        handle = schedule(frame)
      }
    },
    get value() {
      return state.value
    },
    stop() {
      running = false
      if (handle !== null) cancel(handle)
      handle = null
    }
  }
}

/** A short history of pointer positions, which is where a release velocity comes from. */
export class VelocityTracker {
  #samples: { position: number; time: number }[] = []

  /** Records one pointer position. */
  add(position: number, time: number): void {
    this.#samples.push({ position, time })
    // Only the last 100 ms matter: a velocity averaged over a whole drag is not the velocity the
    // finger had when it left.
    const cutoff = time - 100
    while (this.#samples.length > 2 && (this.#samples[0]?.time ?? 0) < cutoff) {
      this.#samples.shift()
    }
  }

  /** Pixels per second at the moment of release. */
  velocity(): number {
    const first = this.#samples[0]
    const last = this.#samples[this.#samples.length - 1]
    if (!first || !last || last.time === first.time) return 0
    return ((last.position - first.position) / (last.time - first.time)) * 1000
  }

  /** Forgets everything, for the next gesture. */
  reset(): void {
    this.#samples = []
  }
}

/** How far a pointer must travel before a drag is a drag rather than a tap. */
export const DRAG_THRESHOLD = 10

/**
 * Whether a released drag should dismiss.
 *
 * Distance alone makes a quick flick fail; velocity alone makes a slow, deliberate drag fail. The
 * projected resting point uses both, which is what a person means by either gesture.
 */
export function shouldDismiss(offset: number, velocity: number, height: number): boolean {
  if (velocity < -80) return false
  return projectEndpoint(offset, velocity) > height / 2
}
