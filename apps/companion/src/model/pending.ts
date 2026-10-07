/**
 * The shapes this application reads from methods whose wire types are not published.
 *
 * The launch surface and what a privacy generation left behind have no published parameter and
 * result type, so the desktop port refuses both and the interface for each is built against the
 * shape the specification describes. Every field below has a sentence in the specification behind
 * it. Nothing here invents a concept the product does not have.
 */

/** One artefact a privacy generation left behind. */
export interface RetainedArtefact {
  readonly object_id: string
  readonly kind: 'archive' | 'notification' | 'viewer_copy'
  readonly description: string
  readonly location: string
  readonly byte_len: number
  readonly created_at_ms: number
  /** True when this copy is held by someone else and deletion cannot reach it. */
  readonly held_by_other_party: boolean
}

/** What `storage.status` answers with, for the privacy screen. */
export interface RetainedArtefacts {
  readonly privacy_mode: boolean
  readonly privacy_generation: string
  readonly artefacts: readonly RetainedArtefact[]
}

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

/** What the launch surface reads before it draws a button. */
export interface LaunchSurface {
  /** True only when the host verified the prompt is empty. */
  readonly prompt_is_empty: boolean
  /** The generation a launch must name. A launch at another generation is refused. */
  readonly prompt_generation: string
  /** The buffer revision a launch must name. */
  readonly buffer_revision: string
  readonly profiles: readonly LaunchProfile[]
}
