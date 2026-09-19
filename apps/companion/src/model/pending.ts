/**
 * The shapes this application reads from methods whose wire types are not published yet.
 *
 * `attention.read`, `changeset.read`, `grant.list`, `plugin.list` and `catalogue.list` are in the
 * method registry and their parameter and result types land with the host work that implements
 * them. The interface for each is built here and now, against the shape the specification
 * describes, so that adopting the generated type later is a rename rather than a rewrite.
 *
 * Every field below has a sentence in the specification behind it. Nothing here invents a concept
 * the product does not have.
 */

/**
 * What an attention entry is asking for.
 *
 * Section 13 names four and the inbox must distinguish them. "Disconnected" is the one that must
 * never be shown as a failure: a host that cannot be contacted says nothing about what its
 * processes are doing.
 */
export type AttentionKind = 'pending_decision' | 'failed_action' | 'awaiting_review' | 'disconnected'

/** One entry in the attention inbox. */
export interface AttentionEntry {
  readonly attention_id: string
  readonly kind: AttentionKind
  readonly title: string
  readonly detail: string
  readonly host_label: string
  readonly environment_id: string
  readonly session_id: string | null
  readonly session_display_number: string | null
  readonly application: string | null
  readonly raised_at_ms: number
  /** The approval this entry refers to, for a pending decision. */
  readonly approval_request_id?: string
  /** The command a pending decision would run, shown before it is allowed. */
  readonly command_preview?: string
  /** The protocol error code of a failed action. */
  readonly error_code?: string
  /** How long contact has been lost, for a disconnected host. */
  readonly out_of_contact_ms?: number
}

/** What `attention.read` answers with. */
export interface AttentionInbox {
  readonly entries: readonly AttentionEntry[]
}

/** One file in a change set. */
export interface ChangedFile {
  readonly path: string
  readonly added: number
  readonly removed: number
  readonly hunks: readonly {
    readonly header: string
    readonly lines: readonly { readonly kind: 'add' | 'remove' | 'context'; readonly text: string }[]
  }[]
}

/** One immutable change set. */
export interface ChangeSet {
  readonly changeset_id: string
  readonly title: string
  readonly session_id: string
  readonly captured_at_ms: number
  readonly reviewed: boolean
  readonly files: readonly ChangedFile[]
}

/** What `changeset.read` answers with. */
export interface ChangeSets {
  readonly changesets: readonly ChangeSet[]
}

/** One installed package. */
export interface InstalledPackage {
  readonly package_id: string
  readonly name: string
  readonly publisher: string
  readonly version: string
  readonly enabled: boolean
  readonly pinned_generation: string | null
  readonly capabilities: readonly string[]
}

/** One catalogue entry, whether or not it is installed. */
export interface CatalogueEntry {
  readonly package_id: string
  readonly name: string
  readonly publisher: string
  readonly summary: string
  readonly version: string
  readonly repository_id: string
  readonly installed: boolean
  /** True when the payload is not cached and the host is offline. */
  readonly payload_available_offline: boolean
}

/** One enrolled repository. */
export interface Repository {
  readonly repository_id: string
  readonly label: string
  readonly kind: 'official' | 'vendor' | 'community' | 'local' | 'mirror'
  readonly publisher: string
  readonly origin: string
  readonly generation: string
  readonly synced_at_ms: number
  readonly automatic_matching: boolean
  readonly pinned: boolean
  readonly metadata_expired: boolean
}

/** What `plugin.list` and `catalogue.list` answer with together. */
export interface PackageViews {
  readonly installed: readonly InstalledPackage[]
  readonly catalogue: readonly CatalogueEntry[]
  readonly repositories: readonly Repository[]
  /** True when the whole catalogue index is held locally, which is what makes search offline. */
  readonly index_complete: boolean
}

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

/** One issued grant. */
export interface IssuedGrant {
  readonly grant_id: string
  readonly role: 'viewer' | 'reviewer' | 'controller' | 'owner'
  readonly recipient: string
  readonly rights: readonly string[]
  readonly expires_at_ms: number
}

/** What `grant.list` answers with. */
export interface IssuedGrants {
  readonly grants: readonly IssuedGrant[]
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

/** The six agent profiles the specification names, in the order it names them. */
export const INSTALLED_PROFILE_IDS = [
  'codex',
  'claude-code',
  'opencode',
  'gemini',
  'kimi',
  'qoder'
] as const
