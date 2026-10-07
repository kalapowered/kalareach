//! Every store the host keeps, as the code declares it, and every other name the host keeps under
//! the state root.
//!
//! A version is the constant its crate writes, never a number typed here. What a store keeps is
//! declared by hand, next to the crate that writes it: a type the protocol generates a schema for
//! by that schema, and a type private to a crate by its definition in the source.

use kr_protocol::update::{Recording, ReleaseStore, StoreScope};

use super::{Claim, Kept, Named, Store, protocol};

fn version(number: i64) -> u32 {
    u32::try_from(number).expect("a version is a small number")
}

fn sqlite_table(table: &str) -> Recording {
    Recording::SqliteTable {
        table: table.to_owned(),
    }
}

fn member(name: &str, absent: u32) -> Recording {
    Recording::JsonMember {
        member: name.to_owned(),
        absent,
    }
}

fn entry(
    store: &str,
    scope: StoreScope,
    path: &str,
    recording: Recording,
    version: u32,
    migrates_from: u32,
) -> ReleaseStore {
    ReleaseStore {
        store: store.to_owned(),
        scope,
        path: path.to_owned(),
        recording,
        version,
        migrates_from,
    }
}

/// Every store, in the order of their names.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn table() -> Vec<Store> {
    use kr_protocol::{
        action, archive, attention, automation, changeset, grant, hostinfo, invitation, machine,
        mailbox, pairing, project, push, session, sharing, skill, transfer, voice,
    };

    let mut stores = vec![
        // The store of releases itself.
        Store {
            entry: entry(
                "install-record",
                StoreScope::Install,
                "install.json",
                member("format", 0),
                kr_cli::update::RECORD_FORMAT,
                kr_cli::update::RECORD_FORMAT,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Source(
                "crates/kr-cli/src/update/mod.rs",
                &[
                    "Record",
                    "Transaction",
                    "TransactionState",
                    "Restart",
                    "Start",
                ],
            )],
        },
        // The startup files an install wrote an entry to, which a removal works from.
        Store {
            entry: entry(
                "shell-entries",
                StoreScope::StateRoot,
                "shell-entries.json",
                member("version", 0),
                kr_shell_integration::host::startup::ENTRY_RECORD_VERSION,
                0,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Source(
                "crates/kr-shell-integration/src/host/startup.rs",
                &["Recorded", "RecordedEntry"],
            )],
        },
        // The environment's own state directory.
        Store {
            entry: entry(
                "registry",
                StoreScope::Environment,
                "registry.sqlite",
                sqlite_table("schema_version"),
                version(kr_controller::registry::SCHEMA_VERSION),
                version(kr_controller::registry::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<session::SessionCreateParams>("SessionCreateParams"),
                protocol::<session::ClosureRecord>("ClosureRecord"),
                protocol::<hostinfo::configuration::ConfigurationDocument>("ConfigurationDocument"),
                protocol::<grant::Grant>("Grant"),
                protocol::<sharing::InvitationPreview>("InvitationPreview"),
                protocol::<sharing::GrantCreateResult>("GrantCreateResult"),
                protocol::<sharing::RevocationResult>("RevocationResult"),
                protocol::<sharing::DeviceKeysCompleteResult>("DeviceKeysCompleteResult"),
                protocol::<sharing::DevicePreviewKeyUpdateResult>("DevicePreviewKeyUpdateResult"),
                protocol::<machine::MachineStepResult>("MachineStepResult"),
                protocol::<voice::VoiceGrantResult>("VoiceGrantResult"),
                protocol::<voice::VoiceDelegateResult>("VoiceDelegateResult"),
                protocol::<invitation::PairingSecurityEvent>("PairingSecurityEvent"),
                protocol::<pairing::OwnerConfirmationRequest>("OwnerConfirmationRequest"),
                protocol::<pairing::OwnerConfirmationProof>("OwnerConfirmationProof"),
                Kept::Source(
                    "crates/kr-controller/src/grants/durable.rs",
                    &[
                        "StoredPolicy",
                        "StoredFeed",
                        "StoredEnrolment",
                        "StoredBinding",
                        "StoredLeaseRecord",
                        "StoredRevocation",
                    ],
                ),
                Kept::Source(
                    "crates/kr-controller/src/net/invitations.rs",
                    &["StoredCommitment"],
                ),
                Kept::Source(
                    "crates/kr-controller/src/net/devices.rs",
                    &["KeyDeclaration"],
                ),
            ],
        },
        Store {
            entry: entry(
                "attention",
                StoreScope::Environment,
                "attention.sqlite3",
                sqlite_table("attention_schema"),
                version(kr_attention::store::SCHEMA_VERSION),
                version(kr_attention::store::OLDEST_SCHEMA_VERSION),
            ),
            owned: vec![Claim {
                name: "attention-time.cbor",
                children: &[],
            }],
            kept: vec![
                protocol::<attention::AttentionAcknowledgeResult>("AttentionAcknowledgeResult"),
                protocol::<attention::AttentionQuietHoursResult>("AttentionQuietHoursResult"),
                protocol::<attention::ReviewAcknowledgeResult>("ReviewAcknowledgeResult"),
                protocol::<attention::VisitAcknowledgeResult>("VisitAcknowledgeResult"),
                protocol::<action::HostTimeState>("HostTimeState"),
            ],
        },
        Store {
            entry: entry(
                "backup",
                StoreScope::Environment,
                "backup.sqlite",
                sqlite_table("schema_version"),
                version(kr_controller::backup::store::SCHEMA_VERSION),
                version(kr_controller::backup::store::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: vec![protocol::<archive::ArchiveDescriptor>("ArchiveDescriptor")],
        },
        Store {
            entry: entry(
                "delivery",
                StoreScope::Environment,
                "delivery.sqlite3",
                sqlite_table("delivery_schema"),
                version(kr_delivery::journal::SCHEMA_VERSION),
                version(kr_delivery::journal::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<push::PushDeliveryRequest>("PushDeliveryRequest"),
                protocol::<mailbox::SealedEnvelope>("SealedEnvelope"),
                Kept::Source(
                    "crates/kr-delivery/src/producer.rs",
                    &["Production", "Notice"],
                ),
                Kept::Source("crates/kr-delivery/src/preview.rs", &["PreviewBody"]),
            ],
        },
        Store {
            entry: entry(
                "descriptions",
                StoreScope::Environment,
                "descriptions.sqlite3",
                sqlite_table("describe_schema"),
                version(kr_describe::store::SCHEMA_VERSION),
                version(kr_describe::store::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: Vec::new(),
        },
        Store {
            entry: entry(
                "privacy",
                StoreScope::Environment,
                "privacy.sqlite3",
                sqlite_table("privacy_schema"),
                version(kr_controller::privacy::SCHEMA_VERSION),
                version(kr_controller::privacy::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: Vec::new(),
        },
        Store {
            entry: entry(
                "workflows",
                StoreScope::Environment,
                "workflows.db",
                Recording::SqliteUserVersion,
                kr_automation::store::WORKFLOW_SCHEMA_VERSION,
                kr_automation::store::WORKFLOW_OLDEST_SCHEMA_VERSION,
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<automation::WorkflowDefinition>("WorkflowDefinition"),
                protocol::<automation::NodeOutput>("NodeOutput"),
                protocol::<automation::WorkflowInstallResult>("WorkflowInstallResult"),
                protocol::<automation::WorkflowEnableResult>("WorkflowEnableResult"),
                protocol::<automation::WorkflowPauseResult>("WorkflowPauseResult"),
                protocol::<automation::WorkflowRunResult>("WorkflowRunResult"),
                protocol::<automation::ShellCommandParams>("ShellCommandParams"),
                protocol::<automation::RunTestsParams>("RunTestsParams"),
                protocol::<automation::RequestReviewParams>("RequestReviewParams"),
                protocol::<automation::AttentionNoticeParams>("AttentionNoticeParams"),
                protocol::<session::SessionCreateParams>("SessionCreateParams"),
                Kept::Source("crates/kr-automation/src/store.rs", &["StoredEvent"]),
            ],
        },
        Store {
            entry: entry(
                "catalogue",
                StoreScope::Environment,
                "catalogue/catalogue.sqlite3",
                Recording::SqliteUserVersion,
                version(kr_plugin_catalogue::db::SCHEMA_VERSION),
                version(kr_plugin_catalogue::db::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<hostinfo::configuration::EnrolmentBudgets>("EnrolmentBudgets"),
                protocol::<kr_plugin_sdk::capability::CapabilityRequest>("CapabilityRequest"),
                Kept::Source(
                    "crates/kr-plugin-catalogue/src/trust.rs",
                    &["MetadataVersions"],
                ),
                Kept::Words(
                    "capability names",
                    kr_plugin_sdk::capability::PluginCapability::ALL
                        .iter()
                        .map(|capability| capability.as_str().to_owned())
                        .collect(),
                ),
            ],
        },
        Store {
            entry: entry(
                "changesets",
                StoreScope::Environment,
                "changesets/changesets.sqlite",
                sqlite_table("schema_version"),
                version(kr_changeset::store::SCHEMA_VERSION),
                version(kr_changeset::store::OLDEST_SCHEMA_VERSION),
            ),
            owned: vec![Claim {
                name: "changesets",
                children: &["objects", "materialisations", "staging"],
            }],
            kept: vec![
                protocol::<changeset::ChangeSetVersionRecord>("ChangeSetVersionRecord"),
                protocol::<changeset::MaterialisationRecord>("MaterialisationRecord"),
                protocol::<changeset::MaterialisationResult>("MaterialisationResult"),
                protocol::<changeset::CapturedPath>("CapturedPath"),
                protocol::<changeset::Exclusion>("Exclusion"),
                Kept::Source(
                    "crates/kr-changeset/src/version.rs",
                    &["Manifest", "DeletedPath"],
                ),
            ],
        },
        Store {
            entry: entry(
                "projects",
                StoreScope::Environment,
                "projects/projects.sqlite",
                sqlite_table("schema_version"),
                version(kr_project::store::SCHEMA_VERSION),
                version(kr_project::store::OLDEST_SCHEMA_VERSION),
            ),
            owned: vec![Claim {
                name: "projects",
                children: &["git-profile"],
            }],
            kept: vec![
                protocol::<project::ProjectInitResult>("ProjectInitResult"),
                protocol::<project::ProjectCloneResult>("ProjectCloneResult"),
                protocol::<project::ProjectAdoptResult>("ProjectAdoptResult"),
                protocol::<project::ProjectOperationCancelResult>("ProjectOperationCancelResult"),
                protocol::<project::WorkspaceCreateResult>("WorkspaceCreateResult"),
                protocol::<project::WorkspaceRemoveResult>("WorkspaceRemoveResult"),
                protocol::<project::ProjectLocationAuthoriseResult>(
                    "ProjectLocationAuthoriseResult",
                ),
                protocol::<project::ProjectLocationWithdrawResult>("ProjectLocationWithdrawResult"),
                protocol::<project::ProjectLocationAttachResult>("ProjectLocationAttachResult"),
                protocol::<project::ProjectSummary>("ProjectSummary"),
                protocol::<project::OperationRecord>("OperationRecord"),
                Kept::Source("crates/kr-project/src/service.rs", &["CreationAnswer"]),
                Kept::Words(
                    "stored text of the project store",
                    kr_project::store::vocabularies(),
                ),
            ],
        },
        Store {
            entry: entry(
                "transfers",
                StoreScope::Environment,
                "transfers/transfers.sqlite",
                sqlite_table("schema_version"),
                version(kr_transfer::store::SCHEMA_VERSION),
                version(kr_transfer::store::OLDEST_SCHEMA_VERSION),
            ),
            owned: vec![Claim {
                name: "transfers",
                children: &["*"],
            }],
            kept: vec![
                protocol::<transfer::UploadBeginResult>("UploadBeginResult"),
                protocol::<transfer::UploadChunkResult>("UploadChunkResult"),
                protocol::<transfer::UploadFinishResult>("UploadFinishResult"),
                protocol::<transfer::UploadCancelResult>("UploadCancelResult"),
                protocol::<transfer::DraftCreateResult>("DraftCreateResult"),
                protocol::<transfer::DraftUpdateResult>("DraftUpdateResult"),
                protocol::<transfer::AgentDraftAddAttachmentResult>(
                    "AgentDraftAddAttachmentResult",
                ),
                protocol::<transfer::AttachmentPreview>("AttachmentPreview"),
            ],
        },
        Store {
            entry: entry(
                "environments",
                StoreScope::Environment,
                "environments.json",
                member("version", 0),
                kr_controller::bridge::store::RECORD_VERSION,
                0,
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<kr_protocol::identity::EnvironmentEnrolment>("EnvironmentEnrolment"),
                Kept::Source(
                    "crates/kr-controller/src/bridge/store.rs",
                    &[
                        "Record",
                        "Observation",
                        "ScopedChannel",
                        "EnrolmentInstance",
                    ],
                ),
            ],
        },
        Store {
            entry: entry(
                "machine-group",
                StoreScope::Environment,
                "machine-group",
                member("version", 0),
                kr_controller::machine::RECORD_VERSION,
                0,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Source(
                "crates/kr-controller/src/machine.rs",
                &["MachineGroup", "Change", "Step"],
            )],
        },
        Store {
            entry: entry(
                "terminal-preference",
                StoreScope::Environment,
                "terminal.json",
                member(
                    kr_shell_integration::host::terminal::PREFERENCE_VERSION_KEY,
                    0,
                ),
                u32::try_from(kr_shell_integration::host::terminal::PREFERENCE_VERSION)
                    .expect("a small number"),
                0,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Words(
                "the preference document",
                vec![
                    kr_shell_integration::host::terminal::PREFERENCE_KEY.to_owned(),
                    kr_shell_integration::host::terminal::PREFERENCE_VERSION_KEY.to_owned(),
                ],
            )],
        },
        Store {
            entry: entry(
                "controller-service",
                StoreScope::Environment,
                "controller-service.json",
                member("version", 0),
                kr_cli::service_manager::RECORD_VERSION,
                kr_cli::service_manager::RECORD_VERSION,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Source(
                "crates/kr-cli/src/service_manager.rs",
                &["Record", "Manager"],
            )],
        },
        Store {
            entry: entry(
                "native-bridges",
                StoreScope::Environment,
                "native-bridges/*.json",
                member("version", 0),
                kr_controller::catalogue::native_bridge::JOURNAL_VERSION,
                kr_controller::catalogue::native_bridge::JOURNAL_VERSION,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Source(
                "crates/kr-controller/src/catalogue/native_bridge/journal.rs",
                &[
                    "Journal",
                    "State",
                    "Release",
                    "Change",
                    "Publication",
                    "Kept",
                ],
            )],
        },
        Store {
            entry: entry(
                "agent-tools",
                StoreScope::Environment,
                "agent-tools/*.json",
                member("version", 0),
                kr_controller::agent_tools::INSTALLATION_RECORD_VERSION,
                0,
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<skill::ChangeManifest>("ChangeManifest"),
                Kept::Source(
                    "crates/kr-controller/src/agent_tools.rs",
                    &["InstallationRecord"],
                ),
            ],
        },
        Store {
            entry: entry(
                "agent-tool-actions",
                StoreScope::Environment,
                "agent-tools/actions/*.json",
                member("version", 0),
                kr_controller::agent_tools::ACTION_RECORD_VERSION,
                0,
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<skill::AgentToolsInstallResult>("AgentToolsInstallResult"),
                Kept::Source("crates/kr-controller/src/agent_tools.rs", &["ActionRecord"]),
            ],
        },
        // The configuration document, wherever the environment keeps it.
        Store {
            entry: entry(
                "configuration",
                StoreScope::Configuration,
                "config.json",
                member("version", 1),
                u32::try_from(hostinfo::configuration::VERSION).expect("a small number"),
                u32::try_from(hostinfo::configuration::VERSION).expect("a small number"),
            ),
            owned: Vec::new(),
            kept: vec![protocol::<hostinfo::configuration::ConfigurationDocument>(
                "ConfigurationDocument",
            )],
        },
    ];
    stores.sort_by(|left, right| left.entry.store.cmp(&right.entry.store));
    stores
}

/// Everything else the host keeps under the state root, each with the reason it has no version.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn named() -> Vec<Named> {
    let leaf = |scope, name, reason| Named {
        scope,
        name,
        children: &[],
        opaque: false,
        databases: false,
        reason,
    };
    let content = |scope, name, reason| Named {
        scope,
        name,
        children: &[],
        opaque: true,
        databases: false,
        reason,
    };
    vec![
        leaf(
            StoreScope::StateRoot,
            "environment-id",
            "written once, as text, and never changed: a build reads no other form",
        ),
        content(
            StoreScope::StateRoot,
            "environments",
            "the state directories of the environments, each of which is named under its own scope",
        ),
        content(
            StoreScope::StateRoot,
            "kept-answers",
            "answers a person gave that the host has not taken, kept on this device by the client; not host state, so not a store of the host's (an unreadable one is reported by name)",
        ),
        leaf(
            StoreScope::StateRoot,
            "machine-merge-plan",
            "the client's merge plan, kept on this device; not host state (an unreadable one is reported by name and moved aside by the person)",
        ),
        leaf(
            StoreScope::StateRoot,
            "machine-merge-plan.lock",
            "the lock on the merge plan; empty",
        ),
        content(
            StoreScope::StateRoot,
            "entry-locks",
            "the locks that keep two writers of one startup file apart; empty files",
        ),
        content(
            StoreScope::StateRoot,
            "host",
            "the store of releases on a platform whose default state root holds it; its record is the store install-record, and roots/<digest>.root is a frozen form (two paths separated by a NUL byte) that a change replaces with a file of another name",
        ),
        content(
            StoreScope::StateRoot,
            "run",
            "the runtime root on a platform whose default state root holds it; nothing in it outlives a boot",
        ),
        leaf(
            StoreScope::StateRoot,
            ".*.tmp",
            "a temporary file an interrupted write left; nothing reads it",
        ),
        leaf(
            StoreScope::Environment,
            "environment",
            "the environment's identity, written once as text and never changed",
        ),
        leaf(
            StoreScope::Environment,
            "controller-identity",
            "a marker that the controller's keys were made, which names the kind of key store; read as absent when it cannot be read",
        ),
        leaf(
            StoreScope::Environment,
            "controller.lock",
            "the daemon's singleton lock, which holds its process number as text",
        ),
        leaf(
            StoreScope::Environment,
            "controller.log",
            "the daemon's log, as text",
        ),
        leaf(
            StoreScope::Environment,
            "boot",
            "the boot the environment last ran in; a record that does not decode is read as none and written again, which costs one pass over sessions of an earlier boot",
        ),
        leaf(
            StoreScope::Environment,
            "capabilities",
            "the capability revision, a number as text; an environment whose record cannot be read keeps revision zero",
        ),
        leaf(
            StoreScope::Environment,
            "login-session",
            "written only on Windows, which keeps no store of releases; a record that does not decode is an error that names it",
        ),
        leaf(
            StoreScope::Environment,
            ".config.lock",
            "the lock on the configuration document; empty",
        ),
        leaf(
            StoreScope::Environment,
            "controller-service.lock",
            "the lock on the service definition; empty",
        ),
        leaf(
            StoreScope::Environment,
            "power.json",
            "a document the sleep setting used to live in; nothing reads it",
        ),
        leaf(
            StoreScope::Environment,
            ".*.tmp",
            "a temporary file an interrupted write left; nothing reads it",
        ),
        leaf(
            StoreScope::Environment,
            ".machine-group.*",
            "a temporary file an interrupted step left; nothing reads it",
        ),
        leaf(
            StoreScope::Environment,
            "*.partial",
            "a temporary file an interrupted write left; nothing reads it",
        ),
        content(
            StoreScope::Environment,
            "backup",
            "the backup service's staging area: objects in the archive's own formats",
        ),
        content(
            StoreScope::Environment,
            "catalogue",
            "the plugin catalogue's repositories: TUF metadata and package payloads in the formats TUF and the package format fix, and each repository's trust checkpoint under datastore/ in TUF's metadata form; the catalogue's database is the store of that name",
        ),
        content(
            StoreScope::Environment,
            "models",
            "the description model's files and their markers, downloaded content that a marker compared whole with the one expected says is complete",
        ),
        content(
            StoreScope::Environment,
            "terminfo",
            "terminal descriptions compiled from the build's own, written again when absent",
        ),
        content(
            StoreScope::Environment,
            "secrets",
            "the secret store's fallback files, one per name, in the secret store's own format",
        ),
        content(
            StoreScope::Environment,
            "jobs",
            "per-session launch definitions and their diagnostics, named by session and read by the daemon that started them",
        ),
        content(
            StoreScope::Environment,
            "workers",
            "one working directory per worker",
        ),
        content(
            StoreScope::Environment,
            "spool",
            "output history, a bounded spool the archive's own rule reads",
        ),
        Named {
            scope: StoreScope::Environment,
            name: "sessions",
            children: &[],
            opaque: true,
            databases: true,
            reason: "the per-session journals, which keep the archive's own rule (kr host import-journals)",
        },
        content(
            StoreScope::Environment,
            "plugin-cache",
            "compiled plugin components, a cache written again when absent",
        ),
        content(
            StoreScope::Environment,
            "services",
            "plugin service directories",
        ),
    ]
}
