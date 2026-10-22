/**
 * The shapes this application reads from methods whose wire types are not published.
 *
 * The launch surface has no published parameter and result type, so the desktop port refuses it and
 * the interface is built against the shape the specification describes. Every field below has a sentence in the specification behind
 * it. Nothing here invents a concept the product does not have.
 */

/** One installed launch profile, or a command the person named. */
export interface LaunchProfile {
  readonly profile_id: string
  readonly label: string
  /** The executable as it resolves in this environment, or null when it is not installed. */
  readonly executable: string | null
  readonly version: string | null
  /** True when the person added this rather than the host detecting it. */
  readonly user_defined: boolean
  /** The argument vector the launch installs. */
  readonly arguments: readonly string[]
}

/**
 * The shell a session runs, as far as how it reads a command: the three families whose quoting
 * differs are POSIX shells (`sh`, `zsh`, `bash`), Fish and PowerShell.
 */
export type ShellKind = 'sh' | 'zsh' | 'bash' | 'fish' | 'powershell'

/** What the launch surface reads before it draws a button. */
export interface LaunchSurface {
  /** The shell the session runs, which decides how a command is written for the person to type. */
  readonly shell_kind: ShellKind
  /** True only when the host verified the prompt is empty. */
  readonly prompt_is_empty: boolean
  /** The generation a launch must name. A launch at another generation is refused. */
  readonly prompt_generation: string
  /** The buffer revision a launch must name. */
  readonly buffer_revision: string
  readonly profiles: readonly LaunchProfile[]
}
