/**
 * Control mode and view mode, and which of them owns the wheel.
 *
 * A raw terminal view has one input and two possible owners. In control mode the application inside
 * the terminal owns the pointer: a wheel event is the application's scroll, and a pan control that
 * consumed it would make `less` and `vim` unusable. In view mode the person is looking around the
 * projection rather than driving the program, so the view owns pan and zoom.
 *
 * The switch is explicit in both directions. Nothing here infers a mode from how fast a wheel
 * turned or whether a modifier was held.
 */

/** Who owns the pointer. */
export type ViewMode = 'control' | 'view'

/** What a wheel event turns into. */
export type WheelOutcome =
  /** Forwarded to the application as its own scroll. */
  | { readonly kind: 'application'; readonly lines: number }
  /** Used by the view to pan the projection. */
  | { readonly kind: 'pan'; readonly rows: number; readonly columns: number }
  /** Used by the view to zoom. */
  | { readonly kind: 'zoom'; readonly steps: number }

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
  return {
    kind: 'pan',
    rows: Math.trunc(wheel.deltaY / WHEEL_ROW_PIXELS),
    columns: Math.trunc(wheel.deltaX / WHEEL_ROW_PIXELS)
  }
}

/** The zoom steps this view offers, as multiples of the base cell size. */
export const ZOOM_STEPS = [0.75, 0.875, 1, 1.125, 1.25, 1.5, 1.75, 2] as const

/** The index of the unscaled step. */
export const ZOOM_DEFAULT_INDEX = 2

/** Moves the zoom by some steps, staying inside the range. */
export function zoomBy(index: number, steps: number): number {
  return Math.max(0, Math.min(ZOOM_STEPS.length - 1, index + steps))
}

/**
 * What a view releases when it stops being the raw view.
 *
 * Switching to the rich view gives up this view's own geometry claim and nothing else: another
 * view's claim, and the session's own dimensions, are not this view's to release.
 */
export interface GeometryClaim {
  readonly attachmentId: string
  readonly columns: number
  readonly rows: number
}

/**
 * The attachment a raw terminal view is, named from its session.
 *
 * The desktop's raw view and the phone's name their own attachment the same way, and each reads
 * the summary with this name from the session's snapshot, never another attachment's. A host that
 * reports no attachment of this name reports no presentation for the view.
 */
export function terminalAttachment(sessionId: string): string {
  return `att-${sessionId}`
}

/** The request that releases one view's geometry claim. */
export function releaseGeometry(claim: GeometryClaim): {
  readonly attachment_id: string
  readonly geometry: null
} {
  return { attachment_id: claim.attachmentId, geometry: null }
}

/** What the palette's provenance is called, in words. */
export function describeProvenance(provenance: string): string {
  switch (provenance) {
    case 'client_probe':
      return 'Probed from the terminal that created this session'
    case 'client_preset':
      return 'A light or dark preset this client sent'
    case 'session_create':
      return 'Chosen when the session was created'
    case 'host_default':
      return "The host's own default palette"
    default:
      return 'Not recorded'
  }
}
