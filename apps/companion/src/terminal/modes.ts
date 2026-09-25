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
 *
 * The raw views on the desktop and the phone also share what the host says about each of them:
 * the attachment a view is, and how the host presents it, directly or as a viewport, and why.
 */

import type {
  AttachmentSummary,
  PresentationReason,
  TerminalPresentationMode
} from '@kalareach/protocol'

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
  /**
   * What the host said: the live output directly, a viewport, nothing for this view, or no answer
   * that could be read.
   */
  readonly state: TerminalPresentationMode | 'unreported' | 'unread'
  /** The host's reason for a viewport, or null when it gave none. */
  readonly reason: PresentationReason | null
  readonly sentence: string
}

/**
 * How the host presents one view, from the attachments of the session's snapshot.
 *
 * Only the summary with the view's own attachment identity is read, never another attachment's. A
 * viewport is given with the host's reason in the host's words. A viewport with no reason, which
 * is how a worker built before reasons reports every viewport, says that no reason was reported
 * and is never taken for a direct presentation. A direct presentation has no reason.
 */
export function presentationOf(
  attachments: readonly AttachmentSummary[],
  attachmentId: string
): Presentation {
  const own = attachments.find((summary) => summary.attachment_id === attachmentId)
  if (!own || own.presentation === null) {
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

/** What a view says when the snapshot that would say how it is presented could not be read. */
export function unreadPresentation(failure: string): Presentation {
  return {
    state: 'unread',
    reason: null,
    sentence: `How the host presents this view could not be read: ${failure}`
  }
}

