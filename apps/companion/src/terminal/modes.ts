/**
 * Control mode and view mode, and which of them owns the wheel.
 *
 * A raw terminal view has one input and two possible owners. In control mode the application inside
 * the terminal owns the pointer: a wheel event is the application's scroll, and a control of the
 * view's that consumed it would make `less` and `vim` unusable. In view mode the person is reading
 * the screen rather than driving the program, so the view owns the wheel, and zooms with it. The
 * window stays on the live screen, so nothing pans.
 *
 * The switch is explicit in both directions. Nothing here infers a mode from how fast a wheel
 * turned or whether a modifier was held.
 *
 * The raw views on the desktop and the phone also share what they say: how the host presents a
 * view, directly or as a viewport, and why, from the view's own attachment; where its palette came
 * from; the words for attaching, waiting and a window smaller than the session; and what a screen
 * warns of.
 */

import type {
  AttachmentSummary,
  PaletteState,
  PresentationReason,
  TerminalPresentationMode
} from '@kalareach/protocol'

import type { TerminalScreen } from '../host/port'

/** Who owns the pointer. */
export type ViewMode = 'control' | 'view'

/** What a wheel event turns into. */
export type WheelOutcome =
  /** Forwarded to the application as its own scroll. */
  | { readonly kind: 'application'; readonly lines: number }
  /** Used by the view to zoom. */
  | { readonly kind: 'zoom'; readonly steps: number }
  /** Taken by the view and used for nothing: the window stays on the live screen. */
  | { readonly kind: 'none' }

/** One wheel event, in the terms both modes understand. */
export interface Wheel {
  readonly deltaX: number
  readonly deltaY: number
  /** True when the platform reports this as a zoom gesture rather than a scroll. */
  readonly zoomGesture: boolean
}

/** How many pixels of wheel make one row. */
export const WHEEL_ROW_PIXELS = 16

/**
 * Decides what one wheel event does.
 *
 * In control mode the answer is always the application's, including when a modifier is held: a
 * modifier is a thing the application may itself interpret, and the view taking it would be the
 * same theft in a different shape.
 */
export function routeWheel(mode: ViewMode, wheel: Wheel): WheelOutcome {
  if (mode === 'control') {
    return { kind: 'application', lines: Math.trunc(wheel.deltaY / WHEEL_ROW_PIXELS) }
  }
  if (wheel.zoomGesture) {
    return { kind: 'zoom', steps: -Math.sign(wheel.deltaY) }
  }
  return { kind: 'none' }
}

/** The zoom steps this view offers, as multiples of the base cell size. */
export const ZOOM_STEPS = [0.75, 0.875, 1, 1.125, 1.25, 1.5, 1.75, 2] as const

/** The index of the unscaled step. */
export const ZOOM_DEFAULT_INDEX = 2

/** Moves the zoom by some steps, staying inside the range. */
export function zoomBy(index: number, steps: number): number {
  return Math.max(0, Math.min(ZOOM_STEPS.length - 1, index + steps))
}

/** What the palette's source is called, in words. */
export function describeProvenance(source: PaletteState['source']): string {
  switch (source) {
    case 'profile_default':
      return "the profile's default"
    case 'client_preference':
      return "the creating terminal's colours"
    case 'light_preset':
      return 'the light preset'
    case 'dark_preset':
      return 'the dark preset'
    case 'explicit_change':
      return 'changed after the session began'
    default:
      return 'not recorded'
  }
}

/** What a view says while it attaches to its session, before the host has answered. */
export const ATTACHING = 'Attaching to this session…'

/** What a view says when it has no complete screen to draw and has waited for one. */
export const WAITING = "Waiting for the session's screen…"

/** How long a view with a frame to keep waits before it says it is waiting. */
export const SLOW_MS = 250

/**
 * What a view says when the host drew it a window smaller than the session, or null when the
 * window holds the whole of it. The window starts at the live screen's top left.
 */
export function clipping(screen: TerminalScreen): string | null {
  const columns = Number(screen.dimensions.columns)
  const rows = Number(screen.dimensions.rows)
  if (screen.window.columns >= columns && screen.window.rows >= rows) return null
  return `Showing the top-left ${screen.window.columns}×${screen.window.rows} of the session's ${columns}×${rows}.`
}

/** Something a screen is missing, with the words a view shows for it. */
export interface ScreenWarning {
  /** Which warning it is, as the view's markup names it. */
  readonly id: 'substituted-count' | 'rows-truncated' | 'screen-degraded'
  readonly words: string
}

/**
 * What a screen warns of, in the order both views show it: cells native code could not place and
 * left blank, lines the session cut short, and a screen the session shortened.
 */
export function warningsOf(screen: TerminalScreen): readonly ScreenWarning[] {
  const warnings: ScreenWarning[] = []
  if (screen.replaced > 0) {
    warnings.push({ id: 'substituted-count', words: `${screen.replaced} left blank` })
  }
  if (screen.lines.some((line) => line.truncated)) {
    warnings.push({ id: 'rows-truncated', words: 'Rows cut short' })
  }
  if (screen.degraded) warnings.push({ id: 'screen-degraded', words: 'Shortened by the session' })
  return warnings
}

/**
 * Why the host shows an attachment a viewport of the session rather than its live output, in the
 * host's own words: each reason with the sentence the protocol gives it for a person.
 */
export const PRESENTATION_REASONS: Readonly<Record<PresentationReason, string>> = {
  no_terminal_profile:
    "its client declared no terminal profile, so what the session's output would do on its terminal is not known",
  unqualified_terminal_profile:
    'the terminal profile its client declared is not one this build has qualified',
  size_mismatch: "its size is not the session's",
  history_window: 'its window is above the live screen',
  stream_not_carryable:
    "the session's output is no longer something a terminal can be handed as it is",
  restoration_incomplete:
    'the screen it was last given could not carry everything the application addresses',
  awaiting_parser_boundary:
    "forwarding waits for the session's output to reach the end of a sequence"
}

/** How the host presents one view, and the sentence the view says it with. */
export interface Presentation {
  /** What the host said: the live output directly, a viewport, or nothing for this view. */
  readonly state: TerminalPresentationMode | 'unreported'
  /** The host's reason for a viewport, or null when it gave none. */
  readonly reason: PresentationReason | null
  readonly sentence: string
}

/**
 * How the host presents one view, from its own attachment's summary.
 *
 * A viewport is given with the host's reason in the host's words. A viewport with no reason, which
 * is how a worker built before reasons reports every viewport, says that no reason was reported
 * and is never taken for a direct presentation. A direct presentation has no reason.
 */
export function presentationOf(own: AttachmentSummary): Presentation {
  if (own.presentation === null) {
    return {
      state: 'unreported',
      reason: null,
      sentence: 'The host reports no presentation for this view.'
    }
  }
  if (own.presentation === 'direct') {
    return { state: 'direct', reason: null, sentence: "This view is shown the session's output directly." }
  }
  const reason = own.presentation_reason ?? null
  return reason === null
    ? {
        state: 'viewport',
        reason: null,
        sentence: 'This view is shown a viewport. The host reported no reason for it.'
      }
    : {
        state: 'viewport',
        reason,
        sentence: `This view is shown a viewport because ${PRESENTATION_REASONS[reason]}.`
      }
}
