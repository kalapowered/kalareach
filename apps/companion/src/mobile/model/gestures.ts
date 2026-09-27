/**
 * Touch on a raw terminal, and who owns it.
 *
 * The desktop view routes the wheel: in control mode it belongs to the program inside the
 * terminal, and a pan control that took it would make a pager or an editor unusable. A finger is
 * the same question in a different shape, and it gets the same answer.
 *
 * In control mode a one-finger drag is the program's wheel, exactly as the wheel is: the view turns
 * it once for each row the finger crosses, at the session's cell under the finger. Zoom is the one
 * thing a finger can do that no program has a meaning for: nothing on the wire carries a pinch, so a
 * pinch cannot be taken from anyone. In view mode the person is reading the screen rather than
 * driving the program, so the view owns every gesture: a one-finger drag moves the window across
 * the session, up into its history and down its live screen, and a pinch makes the text larger or
 * smaller.
 */

import type { TerminalControl, TerminalWheel } from '../../host/port'
import { ASKING, type ViewMode } from '../../terminal/modes'

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

/**
 * Whether the view should stop the browser handling this gesture itself.
 *
 * The answer is yes for every gesture the program owns, which is every gesture in control mode, and
 * for every gesture the view owns: a pinch in either mode, and any movement in view mode, which moves
 * the view's window, so the page never scrolls under a finger that is moving it. It is no for a
 * touch in view mode that has not moved, which neither of them uses.
 */
export function consumesGesture(mode: ViewMode, gesture: TouchGesture): boolean {
  if (gesture.pointers >= 2) return true
  return mode === 'control' || Math.abs(gesture.deltaY) > 0 || Math.abs(gesture.deltaX) > 0
}

/**
 * What the view says of control: what view mode does, or why control last ended; that it asks the
 * session for control; or what reaches the program while it controls it, which the program's
 * `wheel` decides for a drag.
 */
export function describeMode(control: TerminalControl, wheel: TerminalWheel | null): string {
  switch (control.state) {
    case 'watching':
      return control.ended ?? 'View: drag to move around the session, pinch to make the text larger or smaller.'
    case 'taking':
      return ASKING
    case 'controlling':
      switch (wheel) {
        case null:
          return 'Control: your keys go to the program in this terminal.'
        case 'reaches':
          return 'Control: your keys and drags go to the program in this terminal.'
        case 'unreported':
          return 'Control: your keys go to the program, which is not using the wheel. Look around to scroll.'
        case 'unwritable':
          return 'Control: your keys go to the program, which asks for the wheel in a form this view cannot send. Look around to scroll.'
      }
  }
}
