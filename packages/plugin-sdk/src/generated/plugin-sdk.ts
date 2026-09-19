/* eslint-disable */
/**
 * Generated from schema/kalareach-plugin-sdk.schema.json. Do not edit.
 *
 * Rust is canonical: change the types in crates/kr-plugin-sdk, run
 * `cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen`, then `pnpm -C packages/plugin-sdk generate`.
 */

/**
 * The user-facing reason something is unavailable. One line, no control or bidirectional characters.
 */
export type DisabledReason = string
/**
 * A SHA-256 digest as 64 lower-case hexadecimal characters.
 */
export type PayloadDigest = string
/**
 * Current evidence for a versioned capability. Never permission.
 */
export type CapabilityRevision = string
/**
 * A plugin identifier from its manifest.
 */
export type PluginId = string
/**
 * The publisher that signs and maintains a package. Immutable for the package's life.
 */
export type PublisherId = string
/**
 * An exact semantic version, such as 1.4.0 or 2.0.0-rc.1.
 */
export type PackageVersion = string
/**
 * What makes a capability record stale.
 */
export type InvalidationTrigger =
  | 'binary_changed'
  | 'binding_changed'
  | 'schema_changed'
  | 'os_permission_changed'
  | 'desktop_generation_changed'
  | 'profile_changed'
/**
 * A short display name. One line, no control or bidirectional characters.
 */
export type Label = string
/**
 * How a package recognises the distribution an application was installed from.
 */
export type DistributionMatch =
  | {
      /**
       * The package name.
       */
      package: string
      registry: 'npm'
    }
  | {
      /**
       * The project name.
       */
      project: string
      registry: 'py_pi'
    }
  | {
      /**
       * The formula or cask name.
       */
      formula: string
      registry: 'homebrew'
    }
  | {
      /**
       * The crate name.
       */
      crate_name: string
      registry: 'cargo'
    }
  | {
      /**
       * The module path.
       */
      module: string
      registry: 'go_module'
    }
  | {
      /**
       * The package name.
       */
      package: string
      registry: 'deb'
    }
  | {
      /**
       * The bundle identifier.
       */
      bundle_id: string
      registry: 'mac_bundle'
    }
  | {
      /**
       * The package identifier.
       */
      package_id: string
      registry: 'windows_package'
    }
  | {
      /**
       * The image reference.
       */
      image: string
      registry: 'container_image'
    }
/**
 * A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected.
 */
export type VersionRange = string
/**
 * A processor architecture a package supports.
 */
export type Architecture = 'x86_64' | 'aarch64'
/**
 * One segment of a [`FieldPath`].
 */
export type FieldSegment =
  | {
      /**
       * The member name.
       */
      name: string
      type: 'member'
    }
  | {
      /**
       * The zero-based index.
       */
      index: number
      type: 'index'
    }
/**
 * The package summary. One line, no control or bidirectional characters.
 */
export type Summary = string
/**
 * The inner predicate.
 */
export type Predicate1 =
  | {
      op: 'always'
    }
  | {
      op: 'never'
    }
  | {
      op: 'not'
      term: Predicate1
    }
  | {
      op: 'all'
      /**
       * The terms.
       */
      terms: Predicate[]
    }
  | {
      op: 'any'
      /**
       * The terms.
       */
      terms: Predicate[]
    }
  | {
      /**
       * The capability.
       */
      capability:
        | 'metadata.match'
        | 'presentation.declarative'
        | 'broker.semantic_events'
        | 'terminal.stream'
        | 'terminal.transcript_tail'
        | 'terminal.input'
        | 'filesystem.read'
        | 'network.outbound'
        | 'process.observe'
        | 'upstream.action'
        | 'approval.decode'
        | 'approval.respond'
        | 'native_bridge.install'
      op: 'capability'
      /**
       * The state it must be in.
       */
      state:
        | 'qualified_available'
        | 'version_qualified'
        | 'missing_installation'
        | 'permission_required'
        | 'incompatible'
        | 'temporarily_unavailable'
        | 'not_tested'
    }
  | {
      op: 'grant'
      /**
       * The right.
       */
      right:
        | 'session.view'
        | 'terminal.input'
        | 'terminal.geometry'
        | 'terminal.geometry.transfer'
        | 'terminal.palette'
        | 'agent.prompt'
        | 'agent.cancel'
        | 'agent.approval.respond'
        | 'question.respond'
        | 'files.read'
        | 'files.upload'
        | 'files.apply_diff'
        | 'project.create'
        | 'workspace.manage'
        | 'changeset.create'
        | 'session.create'
        | 'session.rename'
        | 'session.close'
        | 'session.share'
        | 'automation.manage'
        | 'host.manage'
        | 'voice.use'
    }
  | {
      op: 'binding'
      /**
       * The state.
       */
      state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
    }
  | {
      /**
       * The node.
       */
      node_id: string
      op: 'node_present'
    }
  | {
      /**
       * The fact.
       */
      flag:
        | 'pending_approval'
        | 'draft_not_empty'
        | 'compact_layout'
        | 'transfer_in_progress'
        | 'holds_input_lease'
      op: 'flag'
    }
/**
 * One term of a visibility predicate.
 */
export type Predicate =
  | {
      op: 'always'
    }
  | {
      op: 'never'
    }
  | {
      op: 'not'
      term: Predicate1
    }
  | {
      op: 'all'
      /**
       * The terms.
       */
      terms: Predicate[]
    }
  | {
      op: 'any'
      /**
       * The terms.
       */
      terms: Predicate[]
    }
  | {
      /**
       * The capability.
       */
      capability:
        | 'metadata.match'
        | 'presentation.declarative'
        | 'broker.semantic_events'
        | 'terminal.stream'
        | 'terminal.transcript_tail'
        | 'terminal.input'
        | 'filesystem.read'
        | 'network.outbound'
        | 'process.observe'
        | 'upstream.action'
        | 'approval.decode'
        | 'approval.respond'
        | 'native_bridge.install'
      op: 'capability'
      /**
       * The state it must be in.
       */
      state:
        | 'qualified_available'
        | 'version_qualified'
        | 'missing_installation'
        | 'permission_required'
        | 'incompatible'
        | 'temporarily_unavailable'
        | 'not_tested'
    }
  | {
      op: 'grant'
      /**
       * The right.
       */
      right:
        | 'session.view'
        | 'terminal.input'
        | 'terminal.geometry'
        | 'terminal.geometry.transfer'
        | 'terminal.palette'
        | 'agent.prompt'
        | 'agent.cancel'
        | 'agent.approval.respond'
        | 'question.respond'
        | 'files.read'
        | 'files.upload'
        | 'files.apply_diff'
        | 'project.create'
        | 'workspace.manage'
        | 'changeset.create'
        | 'session.create'
        | 'session.rename'
        | 'session.close'
        | 'session.share'
        | 'automation.manage'
        | 'host.manage'
        | 'voice.use'
    }
  | {
      op: 'binding'
      /**
       * The state.
       */
      state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
    }
  | {
      /**
       * The node.
       */
      node_id: string
      op: 'node_present'
    }
  | {
      /**
       * The fact.
       */
      flag:
        | 'pending_approval'
        | 'draft_not_empty'
        | 'compact_layout'
        | 'transfer_in_progress'
        | 'holds_input_lease'
      op: 'flag'
    }
/**
 * One piece of a terminal text template.
 */
export type TextSegment =
  | {
      /**
       * The text.
       */
      text: string
      type: 'literal'
    }
  | {
      /**
       * The parameter supplying the value.
       */
      parameter: string
      type: 'parameter'
    }
/**
 * One edit a native bridge installation makes.
 *
 * A recipe lists exact files, configuration edits, hashes, version requirements and the
 * operations that remove them again. Unrelated settings are preserved: the recipe names what it
 * adds, so removal can name the same thing.
 */
export type BridgeStep =
  | {
      /**
       * The path under the application's documented plugin directory.
       */
      destination: string
      /**
       * The digest of the installed bytes.
       */
      digest: string
      /**
       * The file inside the package.
       */
      source: string
      type: 'install_file'
    }
  | {
      /**
       * The configuration file under the application's documented directory.
       */
      file: string
      /**
       * The key path, as dotted members.
       */
      key: string
      type: 'add_configuration_key'
      /**
       * The value written, as JSON text.
       */
      value: string
    }
/**
 * One edit a native bridge removal undoes.
 *
 * Removal has its own vocabulary because it is not installation run backwards. Deleting a file the
 * recipe installed is safe; deleting a file it edited is not. Each step names exactly what it
 * undoes, so unrelated settings survive.
 */
export type BridgeRemoval =
  | {
      /**
       * The path under the application's documented plugin directory.
       */
      destination: string
      /**
       * The digest the recipe installed.
       */
      digest: string
      type: 'remove_file'
    }
  | {
      /**
       * The configuration file under the application's documented directory.
       */
      file: string
      /**
       * The key path, as dotted members.
       */
      key: string
      type: 'remove_configuration_key'
    }
/**
 * The stable identifier of one control.
 */
export type ControlId = string
/**
 * The stable identifier of one document node.
 */
export type NodeId = string
/**
 * The state of the binding a control belongs to.
 */
export type BindingState =
  'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
/**
 * How the broker reaches the upstream.
 *
 * The broker owns the handle. A connector names the kind and its bounded parameters; the
 * executable, launch, upstream identity and environment come from the binding the host made, so
 * a package cannot substitute an arbitrary URL, process or path.
 */
export type BrokerTransport =
  'stdio' | 'private_socket' | 'loopback_http' | 'web_socket' | 'server_sent_events' | 'byte_stream'
/**
 * What a host currently knows about one capability on one subject.
 *
 * Runtime states distinguish the reasons something does not work, because "unavailable" alone
 * sends a person to the wrong fix.
 */
export type CapabilityState =
  | 'qualified_available'
  | 'version_qualified'
  | 'missing_installation'
  | 'permission_required'
  | 'incompatible'
  | 'temporarily_unavailable'
  | 'not_tested'
/**
 * What an action does. The broker validates the prepared effect against this class.
 */
export type EffectClass =
  | 'observe'
  | 'upstream.prompt'
  | 'upstream.cancel'
  | 'upstream.attachment'
  | 'approval.decode'
  | 'approval.respond'
  | 'terminal.input'
/**
 * Where a capability record came from.
 */
export type EvidenceSource = 'host_probe' | 'live_binding' | 'signed_record' | 'package_declaration'
/**
 * A stable code for one kind of finding.
 *
 * Codes are part of the contract: a publisher's build, a catalogue pipeline and a host all
 * report the same code for the same defect, so a fixture can assert on it and a person can look
 * it up.
 */
export type FindingCode =
  | 'directory_unreadable'
  | 'manifest_missing'
  | 'manifest_unreadable'
  | 'manifest_version_unsupported'
  | 'unsafe_path'
  | 'not_a_regular_file'
  | 'case_colliding_path'
  | 'duplicate_path'
  | 'undeclared_file'
  | 'missing_payload'
  | 'size_mismatch'
  | 'digest_mismatch'
  | 'package_too_large'
  | 'too_many_files'
  | 'unbounded_version_range'
  | 'version_range_excludes_host'
  | 'no_match_rules'
  | 'no_platforms'
  | 'duplicate_action_id'
  | 'action_not_registered'
  | 'effect_without_capability'
  | 'duplicate_capability'
  | 'bridge_without_capability'
  | 'attachment_without_capability'
  | 'predicate_invalid'
  | 'parameter_schema_invalid'
  | 'document_too_large'
  | 'voice_projection_unknown'
  | 'connector_table_invalid'
  | 'connector_method_unrouted'
  | 'connector_payload_missing'
  | 'connector_undeclared'
  | 'connector_plugin_mismatch'
  | 'unknown_effect_class'
  | 'unknown_capability'
  | 'name_not_utf8'
  | 'duplicate_member'
  | 'payload_role_invalid'
  | 'implementation_mismatch'
  | 'implementation_unsatisfied'
  | 'bridge_recipe_invalid'
  | 'duplicate_element_id'
  | 'control_parameters_widen'
  | 'qualification_invalid'
/**
 * How messages are separated on the wire.
 */
export type Framing =
  | {
      /**
       * Maximum bytes in one line.
       */
      max_message_bytes: string
      type: 'line_delimited_json'
    }
  | {
      /**
       * The header that carries the length.
       */
      length_header: string
      /**
       * Maximum bytes in one body.
       */
      max_message_bytes: string
      type: 'content_length'
    }
  | {
      /**
       * Maximum bytes in one body.
       */
      max_message_bytes: string
      /**
       * Width of the length prefix in bytes.
       */
      prefix_bytes: number
      type: 'length_prefixed'
    }
  | {
      /**
       * Maximum bytes in one event.
       */
      max_message_bytes: string
      type: 'server_sent_events'
    }
/**
 * What a native method does to the upstream.
 */
export type MethodClass = 'observation' | 'mutation' | 'credential' | 'unsupported'
/**
 * An operating system a package supports.
 */
export type OperatingSystem = 'linux' | 'mac_os' | 'windows'
/**
 * A relative POSIX path inside the package, in ASCII letters, digits, '.', '-' and '_'. At most 8 segments. A '..' or '.' segment, a segment of only dots, a trailing dot, a Windows device name, a case-folded collision with another path and a path that shadows another's directory are all rejected by the host; a pattern cannot express them.
 */
export type PackagePath = string
/**
 * What one payload in a package is.
 */
export type PayloadRole =
  'connector' | 'presentation' | 'component' | 'asset' | 'native_bridge' | 'skill' | 'fixture'
/**
 * One capability a package may request. The vocabulary is closed.
 */
export type PluginCapability =
  | 'metadata.match'
  | 'presentation.declarative'
  | 'broker.semantic_events'
  | 'terminal.stream'
  | 'terminal.transcript_tail'
  | 'terminal.input'
  | 'filesystem.read'
  | 'network.outbound'
  | 'process.observe'
  | 'upstream.action'
  | 'approval.decode'
  | 'approval.respond'
  | 'native_bridge.install'
/**
 * A fact about the current presentation that a control can depend on.
 */
export type PresentationFlag =
  | 'pending_approval'
  | 'draft_not_empty'
  | 'compact_layout'
  | 'transfer_in_progress'
  | 'holds_input_lease'
/**
 * Why a package stops receiving new bindings.
 */
export type RevocationReason = 'withdrawn' | 'vulnerable' | 'key_compromise' | 'superseded'
/**
 * How prominently a client presents a control.
 *
 * Priority is semantic, not visual: it says how important the action is, and each client decides
 * what that looks like on its own platform.
 */
export type SemanticPriority = 'primary' | 'secondary' | 'overflow' | 'destructive'
/**
 * An icon from the standard set every client ships.
 */
export type StandardIcon =
  | 'play'
  | 'stop'
  | 'pause'
  | 'check'
  | 'cross'
  | 'retry'
  | 'open'
  | 'copy'
  | 'attachment'
  | 'file'
  | 'folder'
  | 'diff'
  | 'terminal'
  | 'tool'
  | 'warning'
  | 'info'
  | 'error'
  | 'settings'
  | 'search'
  | 'person'
  | 'question'
  | 'send'

/**
 * Generated from the Rust types in crates/kr-plugin-sdk. Rust is canonical: edit the Rust types and regenerate. Every property below names one root document; $defs holds the referenced types.
 */
export interface KalaReachPluginSDK {
  action_invocation?: ActionInvocation
  capability_evidence?: CapabilityEvidence
  catalogue_index?: CatalogueIndex
  connector_manifest?: ConnectorManifest
  document_node?: DocumentNode
  index_entry?: IndexEntry
  instance_limits?: InstanceLimits
  plugin_identity?: PluginIdentity
  plugin_manifest?: PluginManifest
  presentation_manifest?: PresentationManifest
  publisher_record?: PublisherRecord
  repository_budgets?: RepositoryBudgets
  unsupported_node?: UnsupportedNode
  validation_report?: Report
  visibility_predicate?: Predicate
  /**
   * Every closed vocabulary in the package contract. This is a vocabulary rather than a document: it exists so each enumeration has one named type.
   */
  vocabulary?: {
    architecture?: Architecture
    binding_state?: BindingState
    broker_transport?: BrokerTransport
    capability_state?: CapabilityState
    effect_class?: EffectClass
    evidence_source?: EvidenceSource
    finding_code?: FindingCode
    framing?: Framing
    invalidation_trigger?: InvalidationTrigger
    method_class?: MethodClass
    operating_system?: OperatingSystem
    package_path?: PackagePath
    package_version?: PackageVersion
    payload_digest?: PayloadDigest
    payload_role?: PayloadRole
    plugin_capability?: PluginCapability
    presentation_flag?: PresentationFlag
    revocation_reason?: RevocationReason
    semantic_priority?: SemanticPriority
    standard_icon?: StandardIcon
    version_range?: VersionRange
  }
}
/**
 * An action invocation the host has not yet checked.
 *
 * The host rechecks the effect class, the parameters and the grant on every invocation, so a
 * control that was visible when it was rendered cannot dispatch after the state it depended on
 * changed.
 */
export interface ActionInvocation {
  /**
   * The action being invoked.
   */
  action_id: string
  /**
   * The supplied parameter values, keyed by parameter name.
   */
  arguments: ActionArgument[]
}
/**
 * One supplied parameter value.
 */
export interface ActionArgument {
  /**
   * The parameter name.
   */
  name: string
  /**
   * The supplied value.
   */
  value:
    | {
        /**
         * The text.
         */
        text: string
        type: 'text'
      }
    | {
        type: 'integer'
        /**
         * The number.
         */
        value: number
      }
    | {
        type: 'boolean'
        /**
         * The decision.
         */
        value: boolean
      }
    | {
        /**
         * The chosen identifier.
         */
        choice_id: string
        type: 'choice'
      }
    | {
        /**
         * The opaque handle.
         */
        handle: string
        type: 'attachment_handle'
      }
    | {
        /**
         * The node identifier.
         */
        node_id: string
        type: 'node_ref'
      }
}
/**
 * One capability evidence record.
 */
export interface CapabilityEvidence {
  /**
   * The versioned capability this record is about.
   */
  capability_id: string
  /**
   * The capability version.
   */
  capability_version: string
  /**
   * The user-facing reason, required whenever the state is not usable.
   */
  disabled_reason: DisabledReason | null
  identity: SubjectIdentity
  /**
   * What makes it stale.
   */
  invalidated_by: InvalidationTrigger[]
  /**
   * When the record was gathered.
   */
  observed_at: string
  /**
   * Current evidence for a versioned capability. Never permission.
   */
  revision: string
  /**
   * Where the record came from.
   */
  source: 'host_probe' | 'live_binding' | 'signed_record' | 'package_declaration'
  /**
   * The current state.
   */
  state:
    | 'qualified_available'
    | 'version_qualified'
    | 'missing_installation'
    | 'permission_required'
    | 'incompatible'
    | 'temporarily_unavailable'
    | 'not_tested'
  subject: EvidenceSubject
}
/**
 * The exact identity the evidence was gathered against.
 */
export interface SubjectIdentity {
  /**
   * The digest of the tested binary, where the subject is a binary.
   */
  binary_digest: PayloadDigest | null
  /**
   * The binding the evidence was gathered through, where a live binding gathered it.
   *
   * An installed upgrade does not invalidate an old running process's correctly pinned
   * identity, which is only expressible if the record names the binding rather than the
   * package.
   */
  binding_revision: CapabilityRevision | null
  /**
   * The digest of that package's manifest.
   */
  package_digest: PayloadDigest | null
  /**
   * The package the evidence is about, where it is about one.
   */
  plugin_id: PluginId | null
  /**
   * The digest of the signed qualification profile the evidence came from, where one did.
   */
  profile_digest: PayloadDigest | null
  /**
   * The publisher whose signed record supplied the evidence, where one did.
   */
  publisher_id: PublisherId | null
  /**
   * The version of the tested schema or protocol, where the subject is one.
   */
  schema_version: PackageVersion | null
}
/**
 * What the record is about.
 */
export interface EvidenceSubject {
  /**
   * The application the evidence is about, where it is about one.
   */
  application: Label | null
  /**
   * The desktop session generation the evidence is bound to, where it is bound to one.
   */
  desktop_generation: Label | null
  /**
   * The environment the evidence was gathered in.
   */
  environment_id: string
  /**
   * The terminal profile the evidence is about, where it is about one.
   */
  terminal: Label | null
}
/**
 * The complete signed metadata snapshot.
 */
export interface CatalogueIndex {
  /**
   * The entries, ordered by publisher, plugin name and version.
   */
  entries: IndexEntry[]
  /**
   * The generation this snapshot is.
   *
   * A generation is what a host pins. Index activation is atomic after metadata verification,
   * so a host is always on one whole generation and never on a mixture of two.
   */
  generation: string
  /**
   * The index format version.
   */
  index_version: number
  /**
   * When the snapshot was built.
   */
  produced_at: string
  /**
   * The publishers whose packages appear in it.
   */
  publishers: PublisherRecord[]
}
/**
 * One entry in the catalogue index.
 */
export interface IndexEntry {
  /**
   * What it asks to be permitted.
   */
  capabilities: CapabilityRequest[]
  /**
   * The one-line description offline search reads.
   */
  description: string
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  display_name: string
  /**
   * Whether the package ships a Wasm component.
   */
  has_component: boolean
  /**
   * A SHA-256 digest as 64 lower-case hexadecimal characters.
   */
  manifest_digest: string
  /**
   * The exact length of the manifest.
   *
   * The manifest does not declare itself, so its length is here. A host checks a declared size
   * before it downloads, and the manifest is the first thing it downloads.
   */
  manifest_size_bytes: string
  /**
   * The applications the package recognises.
   */
  match_rules: MatchRule[]
  /**
   * Every payload, by hash and exact size.
   */
  payloads: PayloadRef[]
  /**
   * The platforms it supports.
   */
  platforms: PlatformSupport[]
  /**
   * A plugin identifier from its manifest.
   */
  plugin_id: string
  /**
   * The plugin name under that publisher.
   */
  plugin_name: string
  /**
   * The publisher that signs and maintains a package. Immutable for the package's life.
   */
  publisher_id: string
  /**
   * What the publisher qualified this release against.
   */
  qualification: QualificationResult[]
  /**
   * The revocation record, where this release has one.
   */
  revocation: RevocationRecord | null
  /**
   * A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected.
   */
  sdk_range: string
  source: SourcePin
  /**
   * The sum of every payload size and the manifest's own length.
   */
  total_size_bytes: string
  /**
   * An exact semantic version, such as 1.4.0 or 2.0.0-rc.1.
   */
  version: string
  /**
   * A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected.
   */
  wit_range: string
}
/**
 * A capability a package asks for, with the reason a reviewer and a user read.
 */
export interface CapabilityRequest {
  /**
   * The requested capability.
   */
  capability:
    | 'metadata.match'
    | 'presentation.declarative'
    | 'broker.semantic_events'
    | 'terminal.stream'
    | 'terminal.transcript_tail'
    | 'terminal.input'
    | 'filesystem.read'
    | 'network.outbound'
    | 'process.observe'
    | 'upstream.action'
    | 'approval.decode'
    | 'approval.respond'
    | 'native_bridge.install'
  /**
   * Why the package needs it. Shown in the installation grant.
   */
  reason: string
}
/**
 * One declarative match rule.
 */
export interface MatchRule {
  /**
   * How certain the rule is.
   */
  confidence: 'exact' | 'inferred'
  /**
   * The distribution the application was installed from, where the rule names one.
   */
  distribution: DistributionMatch | null
  executable: ExecutableMatch
  /**
   * The rule identifier, unique inside the package.
   */
  id: string
}
/**
 * How the executable is recognised.
 */
export interface ExecutableMatch {
  /**
   * The executable's file stem.
   */
  file_stem: string
  /**
   * Whole path segments the executable's directory must end with.
   */
  path_suffix: string[]
  /**
   * The versions the rule covers, where the host can read a version.
   */
  version_range: VersionRange | null
}
/**
 * One payload, named by its path, its digest and its exact length.
 *
 * The declared size is checked before download and the actual size and digest during processing,
 * so a payload cannot expand past what the manifest declared.
 *
 * `plugin.json` is not listed here. It is the document doing the declaring, so its own digest
 * belongs in the catalogue index entry that points at it, not inside itself.
 */
export interface PayloadRef {
  /**
   * A SHA-256 digest as 64 lower-case hexadecimal characters.
   */
  digest: string
  /**
   * Where it lives in the package.
   */
  path: string
  /**
   * What the payload is.
   */
  role: 'connector' | 'presentation' | 'component' | 'asset' | 'native_bridge' | 'skill' | 'fixture'
  /**
   * Its exact length in bytes.
   */
  size_bytes: string
}
/**
 * One operating system and the architectures a package supports on it.
 */
export interface PlatformSupport {
  /**
   * The architectures supported on it.
   */
  architectures: Architecture[]
  /**
   * The operating system.
   */
  os: 'linux' | 'mac_os' | 'windows'
}
/**
 * One compatibility result the catalogue carries about a package.
 *
 * Section 25 stores compatibility results beside the manifests and hashes. Section 11 ships that
 * qualification data as signed, immutable catalogue artefacts, separately from host binaries, so
 * updating it cannot create new primitive effects, raise a grant or turn an old live binding into
 * a different version.
 *
 * A result says how a version behaved where it was tested. It is not permission, and it is not a
 * live binding: a host still probes, still checks its grant and still rechecks the capability
 * revision on every action.
 */
export interface QualificationResult {
  /**
   * The versioned capability the result is about.
   */
  capability_id: string
  /**
   * An exact semantic version, such as 1.4.0 or 2.0.0-rc.1.
   */
  capability_version: string
  /**
   * A SHA-256 digest as 64 lower-case hexadecimal characters.
   */
  profile_digest: string
  /**
   * Where the result came from.
   */
  source: 'host_probe' | 'live_binding' | 'signed_record' | 'package_declaration'
  /**
   * What the result is.
   *
   * A catalogue result can report that a version was qualified or that it is incompatible. It
   * cannot report that a capability is available on a host it has never seen.
   */
  state:
    | 'qualified_available'
    | 'version_qualified'
    | 'missing_installation'
    | 'permission_required'
    | 'incompatible'
    | 'temporarily_unavailable'
    | 'not_tested'
  /**
   * What a person reads about it.
   */
  statement: string
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  subject: string
}
/**
 * A revocation record.
 *
 * A revoked package stops new bindings. An active binding receives a warning and follows the
 * administrator's explicit disable policy; it does not change under a live request.
 */
export interface RevocationRecord {
  /**
   * Why it was revoked.
   */
  reason: 'withdrawn' | 'vulnerable' | 'key_compromise' | 'superseded'
  /**
   * When the revocation was published.
   */
  revoked_at: string
  /**
   * What a person reads about it.
   */
  statement: string
}
/**
 * Where the source came from.
 */
export interface SourcePin {
  /**
   * Where the source lives.
   */
  repository: string
  /**
   * The exact revision the package was built from.
   */
  revision: string
}
/**
 * A publisher record.
 *
 * Publishers are named in the index so a person can see who signed a package before installing
 * it, and so a delegation can be scoped to one publisher's path.
 */
export interface PublisherRecord {
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  display_name: string
  /**
   * Whether this publisher ships with KalaReach.
   */
  first_party: boolean
  /**
   * Where the publisher's own source and contact details live.
   */
  homepage: string
  /**
   * The publisher that signs and maintains a package. Immutable for the package's life.
   */
  id: string
}
/**
 * The connector manifest.
 */
export interface ConnectorManifest {
  /**
   * How messages are separated.
   */
  framing:
    | {
        /**
         * Maximum bytes in one line.
         */
        max_message_bytes: string
        type: 'line_delimited_json'
      }
    | {
        /**
         * The header that carries the length.
         */
        length_header: string
        /**
         * Maximum bytes in one body.
         */
        max_message_bytes: string
        type: 'content_length'
      }
    | {
        /**
         * Maximum bytes in one body.
         */
        max_message_bytes: string
        /**
         * Width of the length prefix in bytes.
         */
        prefix_bytes: number
        type: 'length_prefixed'
      }
    | {
        /**
         * Maximum bytes in one event.
         */
        max_message_bytes: string
        type: 'server_sent_events'
      }
  /**
   * The manifest format version.
   */
  manifest_version: number
  method_path: FieldPath
  /**
   * What each method does.
   */
  methods: MethodClassification[]
  /**
   * A plugin identifier from its manifest.
   */
  plugin_id: string
  protocol: ProtocolPin
  /**
   * What the publisher says about the qualification behind this table.
   */
  qualification_note: Summary | null
  request_id_path: FieldPath1
  /**
   * How a response is matched to its request.
   */
  response_correlation:
    | {
        id_path: FieldPath2
        type: 'matching_id'
      }
    | {
        type: 'ordered'
      }
  /**
   * The routes.
   */
  routes: Route[]
  /**
   * How the broker reaches the upstream.
   */
  transport:
    | 'stdio'
    | 'private_socket'
    | 'loopback_http'
    | 'web_socket'
    | 'server_sent_events'
    | 'byte_stream'
  /**
   * Whether the connector has a tested volatile forwarding mode.
   *
   * Without one it is not a resilient managed gateway: on receipt-storage failure its
   * unchanged terminal integration is the supported path, and the manifest says so rather than
   * letting a reader assume otherwise.
   */
  volatile_forwarding: boolean
}
/**
 * Where a message names its method.
 */
export interface FieldPath {
  /**
   * The path segments, from the root of the message.
   */
  segments: FieldSegment[]
}
/**
 * One entry in the method classification table.
 */
export interface MethodClassification {
  /**
   * What it does.
   */
  class: 'observation' | 'mutation' | 'credential' | 'unsupported'
  /**
   * What the publisher qualified this classification against.
   */
  evidence: string
  /**
   * The method.
   */
  method: string
}
/**
 * The upstream protocol this table is qualified against.
 */
export interface ProtocolPin {
  /**
   * The protocol name as the vendor publishes it.
   */
  name: string
  /**
   * A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected.
   */
  qualified_range: string
  /**
   * An exact semantic version, such as 1.4.0 or 2.0.0-rc.1.
   */
  tested_version: string
}
/**
 * Where a request carries its identifier.
 */
export interface FieldPath1 {
  /**
   * The path segments, from the root of the message.
   */
  segments: FieldSegment[]
}
/**
 * Where the identifier is in a response.
 */
export interface FieldPath2 {
  /**
   * The path segments, from the root of the message.
   */
  segments: FieldSegment[]
}
/**
 * One route from a native method to the stream that carries it.
 */
export interface Route {
  /**
   * The direction the method travels.
   */
  direction: 'upstream_to_host' | 'host_to_upstream' | 'bidirectional'
  /**
   * The method as the table names it.
   */
  method: string
  /**
   * The method name exactly as it appears on the wire.
   */
  wire_name: string
}
/**
 * One document node.
 */
export interface DocumentNode {
  /**
   * What the node is.
   */
  body:
    | {
        /**
         * A short display name. One line, no control or bidirectional characters.
         */
        author: string
        kind: 'message'
        /**
         * The package summary. One line, no control or bidirectional characters.
         */
        text: string
      }
    | {
        kind: 'markdown'
        /**
         * The Markdown source, rendered by the client's own renderer.
         */
        source: string
      }
    | {
        kind: 'tool'
        /**
         * A short display name. One line, no control or bidirectional characters.
         */
        name: string
        /**
         * Its outcome.
         */
        outcome: 'running' | 'succeeded' | 'failed' | 'cancelled'
        /**
         * The package summary. One line, no control or bidirectional characters.
         */
        summary: string
      }
    | {
        /**
         * The files.
         */
        files: DiffFile[]
        kind: 'diff'
      }
    | {
        kind: 'progress'
        /**
         * A short display name. One line, no control or bidirectional characters.
         */
        label: string
        /**
         * How far along it is.
         */
        state:
          | {
              /**
               * Completed units.
               */
              completed: string
              kind: 'determinate'
              /**
               * Total units.
               */
              total: string
            }
          | {
              kind: 'indeterminate'
            }
          | {
              kind: 'complete'
            }
          | {
              kind: 'failed'
            }
      }
    | {
        fields: ParameterSchema
        kind: 'form'
        submit: Control
        /**
         * A short display name. One line, no control or bidirectional characters.
         */
        title: string
      }
    | {
        /**
         * The attachment.
         */
        attachment_id: string
        kind: 'attachment'
        /**
         * A short display name. One line, no control or bidirectional characters.
         */
        name: string
        /**
         * Its size in bytes.
         */
        size_bytes: string
      }
    | {
        /**
         * The ledger resource.
         */
        approval_request_id: string
        kind: 'approval_ref'
      }
    | {
        kind: 'terminal_ref'
        /**
         * The session whose terminal this is.
         */
        session_id: string
      }
    | {
        control: Control1
        kind: 'action_button'
      }
    | {
        /**
         * The controls.
         */
        controls: Control2[]
        kind: 'action_group'
        /**
         * A short display name. One line, no control or bidirectional characters.
         */
        label: string
      }
    | {
        /**
         * The controls.
         */
        controls: Control2[]
        kind: 'command_palette'
      }
    | {
        contribute: Control3
        kind: 'attachment_entry'
        /**
         * A short display name. One line, no control or bidirectional characters.
         */
        label: string
      }
  /**
   * The stable identifier.
   */
  id: string
  /**
   * The revision of this node.
   */
  revision: string
}
/**
 * One entry in a diff node.
 */
export interface DiffFile {
  /**
   * Lines added.
   */
  added: number
  /**
   * The path as the upstream reported it.
   */
  path: string
  /**
   * Lines removed.
   */
  removed: number
}
/**
 * The fields.
 */
export interface ParameterSchema {
  /**
   * The parameters, in the order a client presents them.
   */
  parameters: ParameterDeclaration[]
}
/**
 * One parameter of an action.
 */
export interface ParameterDeclaration {
  /**
   * What it accepts.
   */
  kind:
    | {
        /**
         * Maximum length in characters.
         */
        max_length: number
        /**
         * Whether the client offers a multi-line field.
         */
        multiline: boolean
        type: 'text'
      }
    | {
        /**
         * Highest accepted value.
         */
        maximum: number
        /**
         * Lowest accepted value.
         */
        minimum: number
        type: 'integer'
      }
    | {
        type: 'boolean'
      }
    | {
        /**
         * The choices, each a stable identifier and its label.
         */
        choices: ParameterChoice[]
        type: 'choice'
      }
    | {
        type: 'attachment_handle'
      }
    | {
        type: 'node_ref'
      }
  /**
   * The label a person reads.
   */
  label: string
  /**
   * The parameter name.
   */
  name: string
  /**
   * Whether the action can be invoked without it.
   */
  required: boolean
}
/**
 * One choice in a [`ParameterKind::Choice`] parameter.
 */
export interface ParameterChoice {
  /**
   * The stable identifier submitted with the action.
   */
  id: string
  /**
   * The label a person reads.
   */
  label: string
}
/**
 * The control that submits the completed form.
 *
 * Submission is an action invocation like any other, so it carries a control rather than
 * a bare action name: the same label, icon, accessible description, priority, visibility
 * and disabled reason every other way of invoking an action carries.
 */
export interface Control {
  /**
   * The description a screen reader announces.
   */
  accessible_description: string
  /**
   * The registered action this control invokes.
   */
  action_id: string
  /**
   * The reason shown while the control is disabled.
   */
  disabled_reason: DisabledReason | null
  /**
   * When the control is present but not usable.
   */
  enabled_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
  /**
   * The standard icon.
   */
  icon:
    | 'play'
    | 'stop'
    | 'pause'
    | 'check'
    | 'cross'
    | 'retry'
    | 'open'
    | 'copy'
    | 'attachment'
    | 'file'
    | 'folder'
    | 'diff'
    | 'terminal'
    | 'tool'
    | 'warning'
    | 'info'
    | 'error'
    | 'settings'
    | 'search'
    | 'person'
    | 'question'
    | 'send'
  /**
   * The stable identifier.
   */
  id: string
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  label: string
  parameters: ParameterSchema1
  /**
   * How prominently a client presents it.
   */
  priority: 'primary' | 'secondary' | 'overflow' | 'destructive'
  /**
   * The revision of this control.
   */
  revision: string
  /**
   * One term of a visibility predicate.
   */
  visible_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
}
/**
 * The parameters this control supplies.
 *
 * A control may narrow its action's parameters but never widen them. The host checks the
 * invocation against the action's own schema regardless.
 */
export interface ParameterSchema1 {
  /**
   * The parameters, in the order a client presents them.
   */
  parameters: ParameterDeclaration[]
}
/**
 * The control.
 */
export interface Control1 {
  /**
   * The description a screen reader announces.
   */
  accessible_description: string
  /**
   * The registered action this control invokes.
   */
  action_id: string
  /**
   * The reason shown while the control is disabled.
   */
  disabled_reason: DisabledReason | null
  /**
   * When the control is present but not usable.
   */
  enabled_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
  /**
   * The standard icon.
   */
  icon:
    | 'play'
    | 'stop'
    | 'pause'
    | 'check'
    | 'cross'
    | 'retry'
    | 'open'
    | 'copy'
    | 'attachment'
    | 'file'
    | 'folder'
    | 'diff'
    | 'terminal'
    | 'tool'
    | 'warning'
    | 'info'
    | 'error'
    | 'settings'
    | 'search'
    | 'person'
    | 'question'
    | 'send'
  /**
   * The stable identifier.
   */
  id: string
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  label: string
  parameters: ParameterSchema1
  /**
   * How prominently a client presents it.
   */
  priority: 'primary' | 'secondary' | 'overflow' | 'destructive'
  /**
   * The revision of this control.
   */
  revision: string
  /**
   * One term of a visibility predicate.
   */
  visible_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
}
/**
 * One declarative control.
 */
export interface Control2 {
  /**
   * The description a screen reader announces.
   */
  accessible_description: string
  /**
   * The registered action this control invokes.
   */
  action_id: string
  /**
   * The reason shown while the control is disabled.
   */
  disabled_reason: DisabledReason | null
  /**
   * When the control is present but not usable.
   */
  enabled_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
  /**
   * The standard icon.
   */
  icon:
    | 'play'
    | 'stop'
    | 'pause'
    | 'check'
    | 'cross'
    | 'retry'
    | 'open'
    | 'copy'
    | 'attachment'
    | 'file'
    | 'folder'
    | 'diff'
    | 'terminal'
    | 'tool'
    | 'warning'
    | 'info'
    | 'error'
    | 'settings'
    | 'search'
    | 'person'
    | 'question'
    | 'send'
  /**
   * The stable identifier.
   */
  id: string
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  label: string
  parameters: ParameterSchema1
  /**
   * How prominently a client presents it.
   */
  priority: 'primary' | 'secondary' | 'overflow' | 'destructive'
  /**
   * The revision of this control.
   */
  revision: string
  /**
   * One term of a visibility predicate.
   */
  visible_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
}
/**
 * One declarative control.
 */
export interface Control3 {
  /**
   * The description a screen reader announces.
   */
  accessible_description: string
  /**
   * The registered action this control invokes.
   */
  action_id: string
  /**
   * The reason shown while the control is disabled.
   */
  disabled_reason: DisabledReason | null
  /**
   * When the control is present but not usable.
   */
  enabled_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
  /**
   * The standard icon.
   */
  icon:
    | 'play'
    | 'stop'
    | 'pause'
    | 'check'
    | 'cross'
    | 'retry'
    | 'open'
    | 'copy'
    | 'attachment'
    | 'file'
    | 'folder'
    | 'diff'
    | 'terminal'
    | 'tool'
    | 'warning'
    | 'info'
    | 'error'
    | 'settings'
    | 'search'
    | 'person'
    | 'question'
    | 'send'
  /**
   * The stable identifier.
   */
  id: string
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  label: string
  parameters: ParameterSchema1
  /**
   * How prominently a client presents it.
   */
  priority: 'primary' | 'secondary' | 'overflow' | 'destructive'
  /**
   * The revision of this control.
   */
  revision: string
  /**
   * One term of a visibility predicate.
   */
  visible_when:
    | {
        op: 'always'
      }
    | {
        op: 'never'
      }
    | {
        op: 'not'
        term: Predicate1
      }
    | {
        op: 'all'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        op: 'any'
        /**
         * The terms.
         */
        terms: Predicate[]
      }
    | {
        /**
         * The capability.
         */
        capability:
          | 'metadata.match'
          | 'presentation.declarative'
          | 'broker.semantic_events'
          | 'terminal.stream'
          | 'terminal.transcript_tail'
          | 'terminal.input'
          | 'filesystem.read'
          | 'network.outbound'
          | 'process.observe'
          | 'upstream.action'
          | 'approval.decode'
          | 'approval.respond'
          | 'native_bridge.install'
        op: 'capability'
        /**
         * The state it must be in.
         */
        state:
          | 'qualified_available'
          | 'version_qualified'
          | 'missing_installation'
          | 'permission_required'
          | 'incompatible'
          | 'temporarily_unavailable'
          | 'not_tested'
      }
    | {
        op: 'grant'
        /**
         * The right.
         */
        right:
          | 'session.view'
          | 'terminal.input'
          | 'terminal.geometry'
          | 'terminal.geometry.transfer'
          | 'terminal.palette'
          | 'agent.prompt'
          | 'agent.cancel'
          | 'agent.approval.respond'
          | 'question.respond'
          | 'files.read'
          | 'files.upload'
          | 'files.apply_diff'
          | 'project.create'
          | 'workspace.manage'
          | 'changeset.create'
          | 'session.create'
          | 'session.rename'
          | 'session.close'
          | 'session.share'
          | 'automation.manage'
          | 'host.manage'
          | 'voice.use'
      }
    | {
        op: 'binding'
        /**
         * The state.
         */
        state: 'bound' | 'upstream_busy' | 'awaiting_person' | 'disabled' | 'native_only_volatile'
      }
    | {
        /**
         * The node.
         */
        node_id: string
        op: 'node_present'
      }
    | {
        /**
         * The fact.
         */
        flag:
          | 'pending_approval'
          | 'draft_not_empty'
          | 'compact_layout'
          | 'transfer_in_progress'
          | 'holds_input_lease'
        op: 'flag'
      }
}
/**
 * The complete set of execution limits one component instance runs under.
 */
export interface InstanceLimits {
  /**
   * The window the fault count is measured over.
   */
  fault_window_ms: string
  /**
   * Faults within `fault_window_ms` that disable the binding.
   */
  faults_before_disable: number
  /**
   * Deadline in milliseconds for `decode-request` and `encode-response`.
   */
  interpretation_deadline_ms: string
  /**
   * Linear memory in bytes.
   */
  memory_bytes: string
  /**
   * Deadline in milliseconds for `observe` and `prepare-action`.
   */
  observation_deadline_ms: string
  /**
   * Size in bytes of the bounded observation queue.
   */
  observation_queue_bytes: string
  /**
   * Maximum bytes one call may return.
   */
  output_bytes_per_call: string
  /**
   * Deadline in milliseconds for `snapshot`.
   */
  snapshot_deadline_ms: string
}
/**
 * The identity of one executable plugin package, as a host records it.
 */
export interface PluginIdentity {
  /**
   * A SHA-256 digest as 64 lower-case hexadecimal characters.
   */
  package_hash: string
  /**
   * A plugin identifier from its manifest.
   */
  plugin_id: string
  /**
   * The catalogue generation the package was resolved against.
   */
  repository_generation: string
  /**
   * An exact semantic version, such as 1.4.0 or 2.0.0-rc.1.
   */
  version: string
}
/**
 * The `plugin.json` manifest.
 */
export interface PluginManifest {
  /**
   * The actions a control may invoke.
   */
  actions: ActionDeclaration[]
  /**
   * How the package contributes attachments, where it does.
   */
  attachments: AttachmentContribution | null
  /**
   * What the package asks to be permitted.
   */
  capabilities: CapabilityRequest[]
  /**
   * The one-line catalogue description.
   */
  description: string
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  display_name: string
  /**
   * The manifest format version.
   */
  manifest_version: number
  /**
   * The applications this package recognises.
   */
  match_rules: MatchRule[]
  /**
   * The native bridge recipe, where the package installs one.
   */
  native_bridge: NativeBridge | null
  /**
   * Every byte the package consists of.
   */
  payloads: PayloadRef[]
  /**
   * The platforms it supports.
   */
  platforms: PlatformSupport[]
  /**
   * The plugin name under that publisher. Immutable for the package's life.
   */
  plugin_name: string
  /**
   * The publisher that signs and maintains a package. Immutable for the package's life.
   */
  publisher_id: string
  /**
   * A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected.
   */
  sdk_range: string
  source: SourcePin1
  /**
   * An exact semantic version, such as 1.4.0 or 2.0.0-rc.1.
   */
  version: string
  /**
   * A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected.
   */
  wit_range: string
}
/**
 * An action registered in the package manifest.
 *
 * Registration is what makes an action invocable. A control may name only a registered action,
 * so the effect class the broker enforces is always the one the publisher declared.
 */
export interface ActionDeclaration {
  /**
   * Whether the host asks the person to confirm before dispatch.
   */
  confirmation_required: boolean
  /**
   * Why the action exists, shown in the installation grant beside its effect class.
   */
  description: string
  /**
   * What the action does.
   */
  effect:
    | 'observe'
    | 'upstream.prompt'
    | 'upstream.cancel'
    | 'upstream.attachment'
    | 'approval.decode'
    | 'approval.respond'
    | 'terminal.input'
  /**
   * The action identifier a control names.
   */
  id: string
  /**
   * How it becomes an effect.
   */
  implementation:
    | {
        type: 'presentation'
      }
    | {
        type: 'component'
      }
    | {
        /**
         * Which declared parameter supplies each field of the request.
         */
        bindings: ParameterBinding[]
        /**
         * The method, as the connector table names it.
         */
        method: string
        type: 'upstream_method'
      }
    | {
        type: 'upstream_cancel'
      }
    | {
        /**
         * The template.
         */
        template: TextSegment[]
        type: 'terminal_text'
      }
  /**
   * The label a person reads.
   */
  label: string
  parameters: ParameterSchema2
}
/**
 * One declared parameter bound to a field of an upstream request.
 */
export interface ParameterBinding {
  field: FieldPath3
  /**
   * The declared parameter supplying the value.
   */
  parameter: string
}
/**
 * Where the value goes in the upstream request.
 */
export interface FieldPath3 {
  /**
   * The path segments, from the root of the message.
   */
  segments: FieldSegment[]
}
/**
 * The parameters it accepts.
 */
export interface ParameterSchema2 {
  /**
   * The parameters, in the order a client presents them.
   */
  parameters: ParameterDeclaration[]
}
/**
 * How a package contributes attachments to an upstream draft.
 *
 * Transfer, draft insertion, submission and upstream acceptance stay separate. The package
 * declares what it accepts and where anything leaves the host; it never receives the bytes.
 */
export interface AttachmentContribution {
  /**
   * The MIME types the upstream accepts, as exact types or `type/*` families.
   */
  accepted_media_types: string[]
  /**
   * The external service the bytes are uploaded to, where one is involved.
   *
   * A destination outside the host is disclosed before anything is submitted, because an
   * upload that leaves the machine is not made private by encrypted KalaReach routing.
   */
  external_destination: Label | null
  /**
   * How the attachment reaches the draft.
   */
  insertion: 'native_composer' | 'upstream_upload' | 'terminal_draft_path'
  /**
   * Maximum bytes per attachment the bound upstream execution accepts.
   */
  max_bytes: string
  /**
   * Maximum attachments per draft.
   */
  max_count: number
}
/**
 * A native bridge installation recipe.
 *
 * Bridge code runs under the application's own permissions, outside Wasmtime. The installation
 * grant states that, which is why the recipe names its steps rather than running a script.
 */
export interface NativeBridge {
  /**
   * A short display name. One line, no control or bidirectional characters.
   */
  application: string
  /**
   * A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected.
   */
  application_range: string
  /**
   * The package summary. One line, no control or bidirectional characters.
   */
  grant_statement: string
  /**
   * What installation does.
   */
  install: BridgeStep[]
  /**
   * What removal undoes, in the order it is applied.
   *
   * Every install step has a removal step. A recipe that installs something it cannot remove is
   * a recipe that leaves the application changed after the package is gone.
   */
  remove: BridgeRemoval[]
}
/**
 * Where the source came from.
 */
export interface SourcePin1 {
  /**
   * Where the source lives.
   */
  repository: string
  /**
   * The exact revision the package was built from.
   */
  revision: string
}
/**
 * The presentation manifest of one package.
 */
export interface PresentationManifest {
  /**
   * The revision this document as a whole is at.
   *
   * A delta names this revision as its base, so a client knows whether it can apply the delta
   * or must ask for a fresh snapshot.
   */
  base_revision: string
  /**
   * The manifest format version.
   */
  manifest_version: number
  /**
   * The document nodes, in presentation order.
   */
  nodes: DocumentNode[]
  voice: VoiceProjection
}
/**
 * The bounded projection a voice client receives.
 */
export interface VoiceProjection {
  /**
   * The controls voice offers as choices.
   */
  choice_controls: ControlId[]
  /**
   * The nodes voice refers to without reading out.
   */
  detail_nodes: NodeId[]
  /**
   * The nodes whose status voice announces.
   */
  status_nodes: NodeId[]
}
/**
 * The budgets a host sets when it enrols a repository.
 */
export interface RepositoryBudgets {
  /**
   * Whether every referenced payload is fetched rather than only what is installed.
   */
  full_offline_mirror: boolean
  /**
   * Maximum bytes of catalogue metadata.
   */
  metadata_bytes: string
  /**
   * Maximum number of index entries.
   */
  metadata_entries: string
  /**
   * Maximum bytes of cached payloads.
   */
  payload_cache_bytes: string
}
/**
 * A node whose kind this build does not know.
 *
 * A client renders it as an unsupported-content block. It carries no body and therefore no
 * action: a newer package cannot reach a hidden action through a node an older client cannot
 * read.
 */
export interface UnsupportedNode {
  /**
   * The stable identifier of one document node.
   */
  id: string
  /**
   * The kind the document claimed, for the unsupported-content block to name.
   */
  kind: string
  /**
   * The revision of the node that could not be read.
   */
  revision: string
}
/**
 * Everything validation found.
 */
export interface Report {
  /**
   * The findings, in the order they were produced.
   */
  findings: Finding[]
}
/**
 * One thing wrong with a package.
 */
export interface Finding {
  /**
   * What kind of thing it is.
   */
  code:
    | 'directory_unreadable'
    | 'manifest_missing'
    | 'manifest_unreadable'
    | 'manifest_version_unsupported'
    | 'unsafe_path'
    | 'not_a_regular_file'
    | 'case_colliding_path'
    | 'duplicate_path'
    | 'undeclared_file'
    | 'missing_payload'
    | 'size_mismatch'
    | 'digest_mismatch'
    | 'package_too_large'
    | 'too_many_files'
    | 'unbounded_version_range'
    | 'version_range_excludes_host'
    | 'no_match_rules'
    | 'no_platforms'
    | 'duplicate_action_id'
    | 'action_not_registered'
    | 'effect_without_capability'
    | 'duplicate_capability'
    | 'bridge_without_capability'
    | 'attachment_without_capability'
    | 'predicate_invalid'
    | 'parameter_schema_invalid'
    | 'document_too_large'
    | 'voice_projection_unknown'
    | 'connector_table_invalid'
    | 'connector_method_unrouted'
    | 'connector_payload_missing'
    | 'connector_undeclared'
    | 'connector_plugin_mismatch'
    | 'unknown_effect_class'
    | 'unknown_capability'
    | 'name_not_utf8'
    | 'duplicate_member'
    | 'payload_role_invalid'
    | 'implementation_mismatch'
    | 'implementation_unsatisfied'
    | 'bridge_recipe_invalid'
    | 'duplicate_element_id'
    | 'control_parameters_widen'
    | 'qualification_invalid'
  /**
   * What exactly is wrong.
   */
  detail: string
  /**
   * Where in the package it is, where it is in one place.
   */
  path?: string | null
}
