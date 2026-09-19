/**
 * Touch on a raw terminal, and who owns it.
 *
 * The desktop view routes the wheel: in control mode it belongs to the program inside the
 * terminal, and a pan control that took it would make a pager or an editor unusable. A finger is
 * the same question in a different shape, and it gets the same answer.
 *
 * In control mode a one-finger drag is the program's scroll, exactly as the wheel is, and the
 * view's own pan does not exist. Zoom is the one thing a finger can do that no program has a
 * meaning for: nothing on the wire carries a pinch, so a pinch cannot be taken from anyone. In
 * view mode the person is reading the projection rather than driving the program, so the view owns
 * every gesture.
 */

import { WHEEL_ROW_PIXELS, type ViewMode, type WheelOutcome } from '../../terminal/modes'

/** One touch gesture, in the terms both modes understand. */
export interface TouchGesture {
  /** How many fingers are down. */
  readonly pointers: number
  /** How far the gesture has moved since it began. */
  readonly deltaX: number
  readonly deltaY: number
  /** The pinch factor, where 1 is unchanged. Only meaningful with two fingers. */
  readonly scale: number
}

/** How much a pinch must change before it is a zoom rather than an unsteady two-finger drag. */
export const PINCH_THRESHOLD = 0.08

/**
 * Decides what a touch gesture does.
 *
 * A one-finger drag in control mode produces the same outcome a wheel would, in the same units, so
 * the program receives one kind of scroll however the person produced it.
 */
export function routeGesture(mode: ViewMode, gesture: TouchGesture): WheelOutcome {
  const pinching = gesture.pointers >= 2 && Math.abs(gesture.scale - 1) >= PINCH_THRESHOLD
  if (pinching) {
    return { kind: 'zoom', steps: gesture.scale > 1 ? 1 : -1 }
  }
  if (mode === 'control') {
    // Down the screen is backwards through the program's output, which is a negative line count,
    // the same sign the wheel produces for the same movement.
    return { kind: 'application', lines: Math.trunc(-gesture.deltaY / WHEEL_ROW_PIXELS) }
  }
  return {
    kind: 'pan',
    rows: Math.trunc(-gesture.deltaY / WHEEL_ROW_PIXELS),
    columns: Math.trunc(-gesture.deltaX / WHEEL_ROW_PIXELS)
  }
}

/**
 * Whether the view should stop the browser handling this gesture itself.
 *
 * The answer is yes for every gesture the view or the program uses, because the alternative is the
 * page scrolling under the person's finger while the program also scrolls. It is no for a gesture
 * neither of them uses, so a person can still scroll the screen the terminal sits on.
 */
export function consumesGesture(mode: ViewMode, gesture: TouchGesture): boolean {
  if (gesture.pointers >= 2) return true
  return mode === 'control' || Math.abs(gesture.deltaY) > 0 || Math.abs(gesture.deltaX) > 0
}

/** What the mode switch says it does, which is the same sentence on both platforms. */
export function describeMode(mode: ViewMode): string {
  return mode === 'control'
    ? 'Control: your touches go to the program in this terminal.'
    : 'View: your touches pan and zoom this projection.'
}
