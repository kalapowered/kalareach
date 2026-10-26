/**
 * What the launch surface draws of a read, and the words for it.
 *
 * The worker answers whether a launch could be made at the root editor now, how the asking
 * connection stands to the session's input, the shell's name and the commands the host offers. The
 * page draws buttons only where the answer is verified and the asking link holds the input; the
 * rest of the table is words, and a stock shell's is the command to type.
 *
 * A button is advice drawn from a read. The press quotes the prompt generation and the buffer
 * revision of the newest read, and the session refuses a quote of a prompt that has moved before
 * anything is typed, so a button that is lit a moment too long does no harm.
 */

import type { LaunchShell, ShellLaunchSurfaceResult } from '@kalareach/protocol'

import type { LaunchSurfaceReading } from '../host/port'

/** The commands the host offers to start. */
export type LaunchOffers = ShellLaunchSurfaceResult['offers']

/** One command the host offers. */
export type LaunchOffer = LaunchOffers[number]

/** Why the editor is not verified. */
export type LaunchUnverifiedReason = Extract<
  ShellLaunchSurfaceResult['editor'],
  { readonly state: 'unverified' }
>['reason']

/** What the page draws of a read. */
export type LaunchDrawing =
  /** The host does not serve the read. */
  | { readonly kind: 'not_served' }
  /** The editor is a stock shell's, which the host cannot see: the command to type, for each offer. */
  | {
      readonly kind: 'instructions'
      readonly shell: LaunchShell | null
      readonly offers: LaunchOffers
    }
  /** The connection holds no right to type: it can look and not start. */
  | { readonly kind: 'cannot_start' }
  /** Nobody holds the input and no fence stands: the person takes control of the terminal first. */
  | { readonly kind: 'take_control' }
  /** The editor is not verified, for a reason the person is told in words. */
  | { readonly kind: 'unverified'; readonly reason: LaunchUnverifiedReason }
  /** The editor is verified and this link does not hold the input: the buttons are not usable. */
  | {
      readonly kind: 'not_held_here'
      readonly input: 'held_elsewhere' | 'free' | 'withheld'
      readonly offers: LaunchOffers
    }
  /** The editor is verified at a prompt and this link holds the input: the buttons are usable. */
  | {
      readonly kind: 'live'
      readonly offers: LaunchOffers
      readonly promptGeneration: string
      readonly bufferRevision: string
    }

/**
 * What to draw of `reading` for a connection that does or does not hold the right to type.
 *
 * A read that is not served is one line whoever asks, and so is a stock shell's instruction and a
 * reason the editor is not verified. A connection without the right to type is told it can look and
 * not start wherever buttons or the first step towards them would be drawn.
 */
export function drawing(reading: LaunchSurfaceReading, mayType: boolean): LaunchDrawing {
  if (reading.state === 'not_served') return { kind: 'not_served' }
  const { editor, input, shell, offers } = reading.surface
  if (editor.state === 'unverified') {
    if (editor.reason === 'stock_shell') return { kind: 'instructions', shell, offers }
    if (editor.reason === 'no_fence' && input === 'free') {
      return mayType ? { kind: 'take_control' } : { kind: 'cannot_start' }
    }
    return { kind: 'unverified', reason: editor.reason }
  }
  if (!mayType) return { kind: 'cannot_start' }
  if (input === 'held_here') {
    return {
      kind: 'live',
      offers,
      promptGeneration: editor.prompt_generation,
      bufferRevision: editor.buffer_revision
    }
  }
  return { kind: 'not_held_here', input, offers }
}

/** What the page says of each reason the editor is not verified. */
export const UNVERIFIED_WORDS: Readonly<Record<LaunchUnverifiedReason, string>> = {
  closing: 'This session is closing.',
  not_a_shell: 'This session runs a command, not a shell, so nothing can be started in it.',
  stock_shell: 'This is a stock shell, so nothing can be typed into it for you.',
  profile_forbids: 'This session was set up so that nothing is started in it from here.',
  not_shown: 'This device cannot see the terminal.',
  starting: 'The shell is still starting.',
  integration_lost: 'The shell has lost its link with KalaReach, so nothing can be started in it.',
  not_at_prompt: 'The terminal is not at a prompt: something is running in it.',
  not_primary_prompt: 'The shell is waiting for more of a command, not at a fresh prompt.',
  launch_in_progress: 'Something is being started here.',
  no_fence: 'The prompt has not been checked yet.',
  buffer_not_empty: 'There is text on the prompt.',
  reader_pending: 'The shell is in the middle of an editing step.',
  changed_since_fence: 'The prompt changed since it was last checked.'
}

/**
 * What the page says of a launch the session refused or could not confirm.
 *
 * A prompt that moved, and an editor that could not hold the launch, installed nothing. An editor
 * that could not say is not "nothing was typed": the command may be on the prompt.
 */
export function pressRefusal(code: string | null, words: string): string {
  switch (code) {
    case 'DRAFT_CONFLICT':
      return 'The prompt changed before the launch was installed. Nothing was typed.'
    case 'EDITOR_BUSY':
      return 'The terminal was busy, so the launch was not installed. Nothing was typed.'
    case 'LEASE_LOST':
      return 'This view does not hold the terminal any more. Nothing was typed.'
    case 'OUTCOME_UNKNOWN':
      return 'The terminal could not confirm whether the launch was installed. Look at the prompt before trying again.'
    default:
      return words
  }
}
