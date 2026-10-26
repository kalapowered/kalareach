/**
 * What the test host says of a session's launch surface, and how it takes a launch.
 *
 * The answers are the ones a real worker gave: they were recorded from a worker whose reader a test
 * scripted, one for each state a companion can meet, and a check on the worker fails when the worker
 * says something else (`fixtures/shell-launch`). The host changes only what a person's screen would
 * not take from the worker's answer as given: the session it names, and the prompt generation and
 * buffer revision of a verified editor, which move as the test moves the prompt.
 *
 * A launch is taken as the worker takes it: only from a view that holds the session's input, and
 * only when the prompt generation and the buffer revision it quotes are the ones the prompt has now.
 * A quote that has gone stale installs nothing.
 */

import type { LaunchShell, ShellLaunchResult, ShellLaunchSurfaceResult } from '@kalareach/protocol'

import recorded from '../../../../fixtures/shell-launch/answers.json'
import type { LaunchPress, LaunchSurfaceReading } from './port'

/** The states a worker was recorded in. */
export type RecordedLaunchState = keyof typeof recorded

/**
 * What the host answers: the state a view's own link would read, following what the view does; one
 * of the recorded states, whatever the view does; or that the host does not serve the read.
 */
export type LaunchScenario = 'follow' | 'not_served' | RecordedLaunchState

/** One launch the host installed. */
export interface InstalledLaunch {
  readonly sessionId: string
  readonly command: LaunchPress['command']
  /** The prompt generation the launch was installed at. */
  readonly promptGeneration: string
}

/** Refuses as the host does: with a protocol code and words. */
type Refuse = (code: string, message: string) => never

/** The test host's launch surface. */
export class ScriptedLaunching {
  /** What the host answers now. */
  scenario: LaunchScenario = 'follow'
  /** The launches the host installed, oldest first. */
  readonly installed: InstalledLaunch[] = []
  /** What the host refuses every launch with, when a test says so: the reader's other answers. */
  refusal: { readonly code: string; readonly message: string } | null = null
  /** The generation of the prompt the reader is at. */
  generation = 7
  /** The revision of its buffer. */
  revision = 12
  /** False once a launch left the prompt for a program, until the prompt comes back. */
  private atPrompt = true

  constructor(private readonly refuse: Refuse) {}

  /** The reader draws a new prompt. */
  changePromptGeneration(): void {
    this.generation += 1
    this.atPrompt = true
  }

  /**
   * What a link reads of `sessionId`'s launch surface. `controls` is whether the link is a view
   * that holds the session's input, which only such a link reads as held here. `stockShell` is the
   * shell a stock shell session runs, or null for a managed session.
   */
  read(
    sessionId: string,
    controls: boolean,
    stockShell: LaunchShell | null
  ): LaunchSurfaceReading {
    if (this.scenario === 'not_served') return { state: 'not_served' }
    const state: RecordedLaunchState =
      this.scenario !== 'follow'
        ? this.scenario
        : stockShell !== null
          ? 'stock_shell'
          : !this.atPrompt
            ? 'not_at_prompt'
            : controls
              ? 'verified_held_here'
              : 'free_no_fence'
    const surface = structuredClone(recorded[state]) as unknown as ShellLaunchSurfaceResult
    const moved: ShellLaunchSurfaceResult = {
      ...surface,
      session_id: sessionId,
      shell: state === 'stock_shell' && stockShell !== null ? stockShell : surface.shell,
      editor:
        surface.editor.state === 'verified'
          ? {
              ...surface.editor,
              prompt_generation: String(this.generation),
              buffer_revision: String(this.revision)
            }
          : surface.editor
    }
    return { state: 'served', surface: moved }
  }

  /**
   * Takes a launch pressed on a view. Refused as the worker refuses it: `LEASE_LOST` from a view
   * that does not hold the input, `DRAFT_CONFLICT` for a quote the prompt has moved past.
   */
  press(sessionId: string, controls: boolean, press: LaunchPress): ShellLaunchResult {
    if (!controls) this.refuse('LEASE_LOST', 'This view does not control the program.')
    if (this.refusal !== null) this.refuse(this.refusal.code, this.refusal.message)
    if (
      !this.atPrompt ||
      press.expected_prompt_generation !== String(this.generation) ||
      press.expected_buffer_revision !== String(this.revision)
    ) {
      this.refuse('DRAFT_CONFLICT', 'The prompt moved on before the launch was installed.')
    }
    this.installed.push({
      sessionId,
      command: press.command,
      promptGeneration: String(this.generation)
    })
    this.atPrompt = false
    return {
      fence_id: '00000000-0000-4000-8000-0000000000ff',
      prompt_generation: String(this.generation),
      buffer_revision: String(this.revision + 1)
    }
  }
}
