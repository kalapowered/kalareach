/**
 * The launch surface: what a person can start at a session's prompt, and why a button is not lit.
 *
 * A button is lit only where the worker has verified an empty prompt and the link it was read on
 * holds the session's input, which is a raw terminal view's own link once the person has taken
 * control. Anywhere else the surface is words: the command to type at a stock shell, that this
 * device can look and not start, that the terminal has to be taken first, or why the prompt is not
 * one a launch could be installed at.
 *
 * Every press quotes the prompt generation and the buffer revision of the newest read. A button
 * drawn at one prompt stays disabled after the prompt moved until the person has looked at it. It
 * is disabled while a press waits, and after one has settled until a read that started after it has
 * landed: a read already on its way says nothing of what the press found. The session refuses a
 * quote that has gone stale before anything is typed, so a button lit a moment too long does no
 * harm.
 */

import { useState, type ReactNode } from 'react'

import type { LaunchShell, ShellLaunchResult } from '@kalareach/protocol'

import { useApp } from '../app/state'
import type { LaunchSurfaceReads } from '../app/launch-surface'
import { Button, CommitButton } from '../components/ui'
import { failureCode, failureWords, type LaunchPress } from '../host/port'
import { commandLine } from '../model/command-line'
import {
  drawing,
  pressRefusal,
  UNVERIFIED_WORDS,
  type LaunchOffer,
  type LaunchOffers
} from '../model/launch'

/** The words of a command as the person would type it, for the shell the session runs. */
function typed(offer: LaunchOffer, shell: LaunchShell | null): string {
  if ('quoted_command' in offer.command) return offer.command.quoted_command
  // The host does not know this shell's quoting, so the command's words are shown as they are.
  return shell === null
    ? offer.command.arguments.join(' ')
    : commandLine(offer.command.arguments, shell)
}

/** The launch surface of one session, as the link it was read on shows it. */
export function LaunchSurface({
  reads,
  mayType,
  connected,
  press
}: {
  /** What has been read of it. */
  readonly reads: LaunchSurfaceReads
  /** Whether the connection holds the right to type. */
  readonly mayType: boolean
  readonly connected: boolean
  /**
   * Presses a launch on the link the surface was read on, or null where there is none to press on:
   * the link then never holds the input, and no button is lit.
   */
  readonly press: ((press: LaunchPress) => Promise<ShellLaunchResult>) | null
}): ReactNode {
  const { say } = useApp()
  const { reading, unread, number, newest, again } = reads
  const [drawnAt, setDrawnAt] = useState<string | null>(null)
  // Whether a press waits for the session's answer.
  const [pressing, setPressing] = useState(false)
  // The last press that settled: the newest read started by then, which no read numbered no higher
  // is taken to say anything of, and whether the session refused it.
  const [settled, setSettled] = useState<{ readonly after: number; readonly refused: boolean } | null>(
    null
  )
  const [shown, setShown] = useState<string | null>(null)

  const drawn = reading === null ? null : drawing(reading, mayType)
  const generation = drawn?.kind === 'live' ? drawn.promptGeneration : null
  // The prompt the buttons were drawn at is the one a live surface first showed, and it ends with
  // the buttons.
  if (generation === null && drawnAt !== null) setDrawnAt(null)
  else if (generation !== null && drawnAt === null) setDrawnAt(generation)
  // Whether the newest answer was read after the last press settled.
  const readSince = settled === null || number > settled.after

  if (reading === null || drawn === null) {
    return unread === null ? null : (
      <p className="small faint" data-testid="launch-unread">
        The launch surface could not be read: {unread}
      </p>
    )
  }

  switch (drawn.kind) {
    case 'not_served':
      return (
        <p className="small faint" data-testid="launch-not-served">
          Starting something here is not available on this host.
        </p>
      )
    case 'cannot_start':
      return (
        <p className="small faint" data-testid="launch-cannot-start">
          This device can look but not start.
        </p>
      )
    case 'take_control':
      return (
        <p className="small faint" data-testid="launch-take-control">
          Take control of the terminal to start something here.
        </p>
      )
    case 'unverified':
      return (
        <p className="small faint" data-testid="launch-unverified" data-reason={drawn.reason}>
          {UNVERIFIED_WORDS[drawn.reason]}
        </p>
      )
    case 'instructions': {
      const offers: LaunchOffers = drawn.offers
      const chosen = offers.find((offer) => offer.plugin_id === shown) ?? null
      return (
        <section className="launch-surface" data-testid="launch-instructions">
          <p className="eyebrow">Start something here</p>
          <div className="row wrap">
            {offers.map((offer) => (
              <Button
                key={offer.plugin_id}
                data-offer={offer.plugin_id}
                data-wraps
                aria-pressed={shown === offer.plugin_id}
                onClick={() => {
                  setShown(offer.plugin_id)
                }}
              >
                {/* One piece of text, so that a label that has to wrap wraps as a line does. */}
                <span>{offer.label}</span>
              </Button>
            ))}
          </div>
          <p className="small faint" data-testid="launch-instruction">
            {chosen === null ? (
              'This is a stock shell, so nothing is typed into it for you. Choose one to see what to type.'
            ) : (
              <>
                Type this at the prompt: <code>{typed(chosen, drawn.shell)}</code>
              </>
            )}
          </p>
        </section>
      )
    }
    case 'not_held_here':
    case 'live': {
      const live = drawn.kind === 'live'
      const stale = live && drawnAt !== null && drawnAt !== drawn.promptGeneration
      const lit = live && press !== null && connected && !stale && !pressing && readSince
      const why = !connected
        ? 'Not in contact with this host, so nothing can be started on it.'
        : drawn.kind === 'not_held_here'
          ? drawn.input === 'held_elsewhere'
            ? "Another connection holds this terminal's input."
            : 'Take control of the terminal to start something here.'
          : press === null
            ? 'Start something from the terminal view, which holds the input.'
            : stale
              ? 'The prompt changed since these were drawn. Nothing will be typed into it.'
              : settled?.refused === true && !readSince
                ? 'The last launch was refused. Reading the prompt again.'
                : null
      return (
        <section
          className="launch-surface"
          data-testid="launch-surface"
          data-stale={stale}
          aria-busy={pressing}
        >
          <p className="eyebrow">Start something here</p>
          <div className="row wrap">
            {drawn.offers.map((offer) => (
              <CommitButton
                key={offer.plugin_id}
                data-offer={offer.plugin_id}
                data-wraps
                disabled={!lit}
                title={why ?? typed(offer, null)}
                onCommit={() => {
                  if (!lit || press === null || drawn.kind !== 'live') return
                  setPressing(true)
                  press({
                    command: offer.command,
                    expected_prompt_generation: drawn.promptGeneration,
                    expected_buffer_revision: drawn.bufferRevision
                  }).then(
                    () => {
                      setPressing(false)
                      setSettled({ after: newest(), refused: false })
                      say(`${offer.label} started.`, 'success')
                      again()
                    },
                    (failure: unknown) => {
                      setPressing(false)
                      setSettled({ after: newest(), refused: true })
                      say(pressRefusal(failureCode(failure), failureWords(failure)), 'danger')
                      again()
                    }
                  )
                }}
              >
                {/* One piece of text, so that a label that has to wrap wraps as a line does. */}
                <span>{offer.label}</span>
              </CommitButton>
            ))}
          </div>
          {why === null ? (
            <p className="small faint">
              The prompt is empty and verified. A launch installs the command; it never pastes one.
            </p>
          ) : (
            <p className="small warning-text" data-testid="launch-stale">
              {why}
              {stale && connected ? (
                <Button
                  data-testid="launch-refresh"
                  onClick={() => {
                    setDrawnAt(drawn.kind === 'live' ? drawn.promptGeneration : null)
                  }}
                >
                  I have looked at the prompt
                </Button>
              ) : null}
            </p>
          )}
        </section>
      )
    }
  }
}
