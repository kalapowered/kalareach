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

import type {
  LaunchShell,
  NamedLaunch,
  ShellLaunchCommandsRemoveParams,
  ShellLaunchCommandsRemoveResult,
  ShellLaunchCommandsSaveParams,
  ShellLaunchCommandsSaveResult,
  ShellLaunchResult,
  ShellLaunchSurfaceResult
} from '@kalareach/protocol'

import recorded from '../../../../fixtures/shell-launch/answers.json'
import type { LaunchCommandsReading, LaunchPress, LaunchSurfaceReading } from './port'

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

/** One save or remove the host was asked for. */
export type LaunchCommandWrite =
  | ({ readonly kind: 'save' } & ShellLaunchCommandsSaveParams)
  | ({ readonly kind: 'remove' } & ShellLaunchCommandsRemoveParams)

/**
 * What the test host says of the saved launch commands: a list in the order the commands were first
 * saved, and a revision that moves with every change that lands. A save or a remove is taken as the
 * host takes it: against the revision it names, and a request against an old one changes nothing and
 * is answered with the list as it stands. The host's own character rules are the page's to foresee;
 * a test that needs the host to refuse what the page let through says so with `refuseNext`.
 */
export class ScriptedLaunchCommands {
  /** What the host answers to a read of the list. */
  scenario: 'serve' | 'not_served' | 'unreadable' = 'serve'
  /** The commands the host holds, oldest first. */
  commands: NamedLaunch[] = []
  /** How many reads of the list the page has made. */
  reads = 0
  /** Every save and remove the host was asked for, in order. */
  readonly writes: LaunchCommandWrite[] = []
  /** The revision of the list: a decimal number that moves each time the list changes. */
  private revision = 1_000_000
  /** What the host refuses the next write with, when a test says so. */
  private refusal: { readonly code: string; readonly message: string } | null = null

  constructor(private readonly refuse: Refuse) {}

  /** The revision now, as the protocol writes it. */
  get current(): string {
    return String(this.revision)
  }

  /** The list changes somewhere else, as `kr launch` or the host's own screen changes it. */
  changeElsewhere(commands: readonly NamedLaunch[]): void {
    this.commands = commands.map((command) => structuredClone(command))
    this.revision += 7
  }

  /** The host refuses the next write with this code and these words, whatever it asks. */
  refuseNext(code: string, message: string): void {
    this.refusal = { code, message }
  }

  /** What a read of the list comes to, for a connection that may or may not read it. */
  read(mayRead: boolean): LaunchCommandsReading {
    this.reads += 1
    if (!mayRead) return { state: 'refused' }
    if (this.scenario === 'not_served') return { state: 'not_served' }
    if (this.scenario === 'unreadable') {
      this.refuse('STORAGE_UNAVAILABLE', 'The saved launch commands could not be read.')
    }
    return {
      state: 'served',
      list: { revision: this.current, commands: structuredClone(this.commands) }
    }
  }

  private refused(): void {
    const refusal = this.refusal
    this.refusal = null
    if (refusal !== null) this.refuse(refusal.code, refusal.message)
  }

  /** Takes a save. */
  save(params: ShellLaunchCommandsSaveParams): ShellLaunchCommandsSaveResult {
    this.writes.push({ kind: 'save', ...structuredClone(params) })
    this.refused()
    const command = { ...params.command, label: params.command.label.trim() }
    if (params.expected_revision !== this.current) {
      return {
        applied: false,
        changed: false,
        replaced: false,
        revision: this.current,
        commands: structuredClone(this.commands)
      }
    }
    const at = this.commands.findIndex(
      (held) => held.label.toLowerCase() === command.label.toLowerCase()
    )
    const same =
      at >= 0 && JSON.stringify(this.commands[at]) === JSON.stringify(command)
    if (!same) {
      if (at >= 0) this.commands[at] = command
      else this.commands.push(command)
      this.revision += 1
    }
    return {
      applied: true,
      changed: !same,
      replaced: at >= 0,
      revision: this.current,
      commands: structuredClone(this.commands)
    }
  }

  /** Takes a remove. */
  remove(params: ShellLaunchCommandsRemoveParams): ShellLaunchCommandsRemoveResult {
    this.writes.push({ kind: 'remove', ...structuredClone(params) })
    this.refused()
    if (params.expected_revision !== this.current) {
      return {
        applied: false,
        removed: false,
        revision: this.current,
        commands: structuredClone(this.commands)
      }
    }
    const at = this.commands.findIndex(
      (held) => held.label.toLowerCase() === params.label.toLowerCase()
    )
    if (at >= 0) {
      this.commands.splice(at, 1)
      this.revision += 1
    }
    return {
      applied: true,
      removed: at >= 0,
      revision: this.current,
      commands: structuredClone(this.commands)
    }
  }
}
