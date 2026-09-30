/**
 * Touch on a raw terminal, and what the view says of who owns it.
 *
 * The browser's own panning and zooming are off inside the terminal (`touch-action: none`), so the
 * view is given every gesture in both modes and decides what each means; this says so to the person.
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
import { ASKING } from '../../terminal/modes'

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
