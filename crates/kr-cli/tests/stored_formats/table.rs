//! Every store the host keeps, as the code declares it, and every other name the host keeps under
//! the state root.
//!
//! A version is the constant its crate writes, never a number typed here. What a store keeps is
//! declared by hand, next to the crate that writes it: a type the protocol generates a schema for
//! by that schema, and a type private to a crate by its definition in the source.

use kr_protocol::update::{Recording, ReleaseStore, StoreScope};

use super::{Claim, Kept, Known, KnownIs, Named, Store, Writers, known_protocol, protocol};

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

fn cbor_member(name: &str, absent: u32) -> Recording {
    Recording::CborMember {
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

/// The types a store keeps that the table does not declare yet, each with the store that keeps it and a
/// digest of what it is today. Each store declares its own at its next raise, and deletes its lines.
#[must_use]
pub fn known() -> Vec<Known> {
    use kr_protocol::{
        account, attention, automation, delivery, describe, error, identity, pairing, privacy,
        push, sharing, skill, update,
    };

    let source = |store, name, file, pinned| Known {
        store,
        name,
        is: KnownIs::Source(file),
        pinned,
    };

    let words = |store, name, words: Vec<String>, pinned| Known {
        store,
        name,
        is: KnownIs::Words(words),
        pinned,
    };
    let literal = |words: &[&str]| {
        words
            .iter()
            .map(|word| (*word).to_owned())
            .collect::<Vec<_>>()
    };
    vec![
        // The update record: the release names, and the update channel's root metadata, which the
        // `tough` crate defines and its locked version stands for.
        source(
            "install-record",
            "ReleaseName",
            "crates/kr-protocol/src/update.rs",
            "91bbc30b10d91732394bbfe480fef5bbf3139f8cb0d927090a3f5a374904fe08",
        ),
        Known {
            store: "install-record",
            name: "Root",
            is: KnownIs::Crate("tough"),
            pinned: "f5b947cf662ef8fdff16acb09d75cac6c569657f033d5d3f0327621e8daa8c14",
        },
        Known {
            store: "install-record",
            name: "Signed",
            is: KnownIs::Crate("tough"),
            pinned: "f5b947cf662ef8fdff16acb09d75cac6c569657f033d5d3f0327621e8daa8c14",
        },
        // The installed agent tools record.
        known_protocol::<skill::ChangeOperation>(
            "agent-tools",
            "ChangeOperation",
            "985268b0d22fb13c1fc2ad1decd42d7fed267550734783dc22a1018fc236166a",
        ),
        // The workflow journal.
        known_protocol::<automation::WorkflowRunStatus>(
            "workflows",
            "WorkflowRunStatus",
            "7840b23fa2bfbd1d3167e89020a9502fda0b13ce1ffd075765332b0ba5886756",
        ),
        // What the registry keeps inside its tables and the answers it keeps for a retried call.
        known_protocol::<pairing::DevicePublicKeys>(
            "registry",
            "DevicePublicKeys",
            "a4a908abbd01f0e01b9e41265b30c82b901bf23271b5156c97c5bf06007da604",
        ),
        known_protocol::<error::ErrorCode>(
            "registry",
            "ErrorCode",
            "1adf42bfb02be22cdba273eadccfff60f55bf8bac135c476a56678a211e3f353",
        ),
        known_protocol::<pairing::ClientBundle>(
            "registry",
            "ClientBundle",
            "5a5f7a11c4a723dbed6a2036b3e178a043479b1fba2bf832f8a72e8549754b68",
        ),
        known_protocol::<pairing::ProposedGrant>(
            "registry",
            "ProposedGrant",
            "9f9b7667a7d609186639a05a23abeea6c869c9329759eca726b7e2c464a5b9cf",
        ),
        known_protocol::<account::PolicyAuthorityLink>(
            "registry",
            "PolicyAuthorityLink",
            "d9aab1ca1f34156f2a5541e55f6bbef63516ea7073ac3ca2f44cc250a20fdc19",
        ),
        known_protocol::<sharing::OfflineValidityPolicy>(
            "registry",
            "OfflineValidityPolicy",
            "2de9e423e33e137cf44fce90d9474ebeff021e6fcb25eb1c85f55ed13a581c04",
        ),
        known_protocol::<pairing::RevocationRequest>(
            "registry",
            "RevocationRequest",
            "9c4f06edcd64ab8b33dc62ae19587459c4ac85394fbf981eb50284d686d0eeef",
        ),
        known_protocol::<describe::SessionRenameResult>(
            "registry",
            "SessionRenameResult",
            "8647db2b73068c496d6d6fc3a923e0bf3b2838d05c6926b0052c937115003c2b",
        ),
        known_protocol::<delivery::DeliveryDestinationSecretSetResult>(
            "registry",
            "DeliveryDestinationSecretSetResult",
            "7e42aec33f5a7268d9be57d2d354b4cc851e08a130d89430d98104be3c2c4c53",
        ),
        known_protocol::<identity::EnvironmentEnrolResult>(
            "registry",
            "EnvironmentEnrolResult",
            "3eb4302c748c84b5bcab7b7574a679c467c724731e5ca050220b3e4e7c7cb8ea",
        ),
        known_protocol::<identity::EnvironmentForgetResult>(
            "registry",
            "EnvironmentForgetResult",
            "e272573f7b9fc996da5193d518004c36cb03bf95545ce1eac3579b89c1d586ed",
        ),
        known_protocol::<identity::EnvironmentRefreshResult>(
            "registry",
            "EnvironmentRefreshResult",
            "64d30dbbfe9ee9d78404d2a2f004b683c8d46675a209606032c8341dbad54468",
        ),
        known_protocol::<update::HostUpdateHandoverResult>(
            "registry",
            "HostUpdateHandoverResult",
            "b216ad57793ff4fb71dd5829f786381e2498baac9c3b9193b20dae2100949e0e",
        ),
        known_protocol::<privacy::PrivacyReport>(
            "registry",
            "PrivacyReport",
            "dadfdbb0172fc9bd6a888204d9f6902bb6c3c2b62e9f1746f27c65413b46f070",
        ),
        known_protocol::<describe::DescriptionSetup>(
            "registry",
            "DescriptionSetup",
            "8ba498cbe7eb06a54b8574f4228f984cc1639567863034b35b7f8a4176e26f72",
        ),
        // The delivery journal: what a notice holds, and the words it matches stored text against.
        source(
            "delivery",
            "Audience",
            "crates/kr-delivery/src/producer.rs",
            "5e41c0cda7e2b49990ef41184e0013514dd1742cde3f951e1cd616ea07ac53cc",
        ),
        source(
            "delivery",
            "EventKey",
            "crates/kr-delivery/src/journal.rs",
            "3d28f50a04cc36f772c63a50afa83056c2da969d66b3322e61b2625376b058f6",
        ),
        source(
            "delivery",
            "EventSource",
            "crates/kr-delivery/src/journal.rs",
            "9d7ca85f394721ecbea1c7a09f08ffb90a68306181435b9ea570c418e9e7c06e",
        ),
        source(
            "delivery",
            "ContentLine",
            "crates/kr-delivery/src/external.rs",
            "18bd4f8548e3dc51740d1a715185a4c5ac710f8d2277a6b381ca2db85d17fa0f",
        ),
        known_protocol::<push::PushAlert>(
            "delivery",
            "PushAlert",
            "bbc5b37ad31b754786dddec762e2119addf7419446d390380f60ca7ab1eae9b4",
        ),
        known_protocol::<push::PushUrgency>(
            "delivery",
            "PushUrgency",
            "e299a0789eb8e4f4c26d886628cc8d967bfdb5bee1f82f3ef89e3c95d6a36bd0",
        ),
        words(
            "delivery",
            "push suppression reasons",
            literal(&["burst", "sustained"]),
            "de82eba869b9dbf098a23a0a921d19ed77c21cbc7d4d563d1ca93d0085cc52a8",
        ),
        words(
            "delivery",
            "event sources",
            kr_delivery::journal::EventSource::ALL
                .iter()
                .map(|source| source.as_str().to_owned())
                .collect(),
            "e59eb540e3a179fa14b6a3c0c3e55665967ad3a9d4a4be710fb096e3adf97ab2",
        ),
        words(
            "delivery",
            "delivery states",
            kr_delivery::journal::DeliveryState::ALL
                .iter()
                .map(|state| state.as_str().to_owned())
                .collect(),
            "e12dd6b5cb95d82e6e30bc54b206ad3fea8f00076b827fe76a64a5e7338d21b7",
        ),
        words(
            "delivery",
            "destination kinds",
            kr_delivery::destination::DestinationKind::ALL
                .iter()
                .map(|kind| kind.as_str().to_owned())
                .collect(),
            "3123a85b676f90000801236159af1bbc579cb2d26f772618f5a946dae158c050",
        ),
        words(
            "delivery",
            "next actions",
            kr_delivery::push::NextAction::ALL
                .iter()
                .map(|next| next.as_str().to_owned())
                .collect(),
            "dc39b51d2095b584734fb1a33503909b1bace98db1606d43d273163b64b52305",
        ),
        // The attention store: the words it matches stored text against.
        words(
            "attention",
            "process start sources",
            literal(&[
                "linux_proc_stat",
                "macos_proc_bsd_info",
                "windows_process_creation_time",
                "windows_process_start_seconds",
            ]),
            "15d202f8f72fe6e3a3183e0454462e53a19ae06445785daa887695fb7b361cc9",
        ),
        words(
            "attention",
            "review subject kinds",
            literal(&["turn", "change_set"]),
            "b34a38aa076f20a913ec857d821cfb6f4ff9a75f9e2c3cc462faaf30cabab7de",
        ),
        words(
            "attention",
            "text kinds",
            literal(&["host", "record"]),
            "db5e9656329786e081f32a0daf648491c53b7d87bed7d8a49ec5437e68b1ae0b",
        ),
        words(
            "attention",
            "automation subject kinds",
            literal(&["workflow", "chain"]),
            "b166c0fbd1c39270bdf0c9397d28df767d53363579008941ac96c9bc461c1f91",
        ),
        words(
            "attention",
            "rules",
            attention::AttentionRule::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            "519c73683ee26b59fd65693a407c92add1673c029b372a0f55d6ab5d779ffcca",
        ),
        words(
            "attention",
            "levels",
            attention::AttentionLevel::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            "a94a1c95f39f0a6395f5eaf7256efe68c942f806129f494c7d0b6bb3c87c03fd",
        ),
        words(
            "attention",
            "routings",
            attention::AttentionRouting::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            "b48e4399501817c47f5b4c88c6b07705a7dd39c94f91be5bf0b193e495514bef",
        ),
        words(
            "attention",
            "notification states",
            attention::NotificationState::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            "09ebe720c0e2dd869bf8de29a9da7d3baf6c8e6cdf1bb4949a77808cdfc95855",
        ),
        words(
            "attention",
            "sources",
            attention::AttentionSource::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            "791ebfa23cf9f7cc8a70383a61166c41b573460ea570d2178bc3a333f387ee25",
        ),
        words(
            "attention",
            "semantic change kinds",
            attention::SemanticChangeKind::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            "61c6654c47ba6b0a774eb233be4c99d8aeec089608bc720e6deb1fd33a17eb9c",
        ),
        // The environment's presence record.
        known_protocol::<identity::EnvironmentPresence>(
            "environments",
            "EnvironmentPresence",
            "a07b031cd0381ebcd6a05d6bd312db6de6af43e1bfc92cbb9f85562523a7a3fa",
        ),
        // The startup files an install wrote an entry to.
        source(
            "shell-entries",
            "ShellKind",
            "crates/kr-shell-integration/src/contract/qualification.rs",
            "f26c63cc6c6c50b9cc71b44e302a694c66a91fd6159d7b18e45b518a1409b4bd",
        ),
        // A merge's recorded steps.
        known_protocol::<error::ErrorCode>(
            "machine-merge-plan",
            "ErrorCode",
            "1adf42bfb02be22cdba273eadccfff60f55bf8bac135c476a56678a211e3f353",
        ),
    ]
}

/// The type of the answer the registry keeps for each method that has it kept, by the type's name:
/// the method's answer, as `kr_controller::service::RETAINED_AUTHORITY_ANSWERS` and
/// `RETAINED_MACHINE_ANSWERS` name the methods.
#[must_use]
pub fn retained_answers() -> Vec<(kr_protocol::method::Method, &'static str)> {
    use kr_protocol::method::Method;

    vec![
        (Method::GrantCreate, "GrantCreateResult"),
        (Method::GrantRevoke, "RevocationResult"),
        (Method::DeviceRevoke, "RevocationResult"),
        (
            Method::DevicePreviewKeyUpdate,
            "DevicePreviewKeyUpdateResult",
        ),
        (
            Method::DeliveryDestinationSecretSet,
            "DeliveryDestinationSecretSetResult",
        ),
        (Method::PrivacySet, "PrivacyReport"),
        (Method::SessionRename, "SessionRenameResult"),
        (Method::DescriptionConfigure, "DescriptionSetup"),
        (Method::DescriptionDownload, "DescriptionSetup"),
        (Method::EnvironmentEnrol, "EnvironmentEnrolResult"),
        (Method::EnvironmentForget, "EnvironmentForgetResult"),
        (Method::EnvironmentRefresh, "EnvironmentRefreshResult"),
        (Method::HostUpdateHandover, "HostUpdateHandoverResult"),
        (Method::MachineJoin, "MachineStepResult"),
        (Method::MachineMerge, "MachineStepResult"),
        (Method::MachineSplit, "MachineStepResult"),
    ]
}

/// Every store, in the order of their names.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn table() -> Vec<Store> {
    use kr_controller::registry::LaunchPhase;
    use kr_protocol::{
        action, archive, attention, automation, catalogue, changeset, grant, hostinfo, invitation,
        machine, mailbox, pairing, project, push, session, sharing, skill, transfer, voice,
    };

    let mut stores = vec![
        // The store of releases itself.
        Store {
            writers: Writers::Update,
            entry: entry(
                "install-record",
                StoreScope::Install,
                "install.json",
                member("format", 0),
                kr_cli::update::RECORD_FORMAT,
                kr_cli::update::OLDEST_RECORD_FORMAT,
            ),
            owned: Vec::new(),
            kept: vec![
                Kept::Source(
                    "crates/kr-cli/src/update/mod.rs",
                    &[
                        "Record",
                        "Transaction",
                        "Abandoned",
                        "TransactionState",
                        "Restart",
                        "Start",
                    ],
                ),
                protocol::<kr_protocol::update::PathVariable>("PathVariable"),
            ],
        },
        // The startup files an install wrote an entry to, which a removal works from.
        Store {
            writers: Writers::Barred(&kr_shell_integration::host::startup::ENTRY_WRITTEN),
            entry: entry(
                kr_shell_integration::host::startup::ENTRY_WRITTEN.store,
                StoreScope::StateRoot,
                "shell-entries.json",
                member("version", 0),
                kr_shell_integration::host::startup::ENTRY_WRITTEN.version,
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
            writers: Writers::Daemon,
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
                Kept::Words(
                    "methods a recorded pairing action names",
                    kr_controller::service::net::invitations::RECORDED_METHODS
                        .iter()
                        .map(|method| method.as_str().to_owned())
                        .collect(),
                ),
                Kept::Words(
                    "launch phases",
                    LaunchPhase::ALL
                        .iter()
                        .map(|phase| phase.as_str().to_owned())
                        .collect(),
                ),
            ],
        },
        Store {
            writers: Writers::Daemon,
            entry: entry(
                "attention",
                StoreScope::Environment,
                "attention.sqlite3",
                sqlite_table("attention_schema"),
                version(kr_attention::store::SCHEMA_VERSION),
                version(kr_attention::store::OLDEST_SCHEMA_VERSION),
            ),
            // An earlier build kept the host's clock record in `attention-time.cbor`, a
            // `HostTimeState`. A daemon now takes it into the registry once, when it starts, and
            // removes it. That file and that type leave this entry when the code that takes it in
            // does.
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
                protocol::<automation::NodeStatus>("NodeStatus"),
                protocol::<automation::ShellCommandParams>("ShellCommandParams"),
                protocol::<automation::RunTestsParams>("RunTestsParams"),
                protocol::<automation::RequestReviewParams>("RequestReviewParams"),
                protocol::<automation::AttentionNoticeParams>("AttentionNoticeParams"),
                protocol::<session::SessionCreateParams>("SessionCreateParams"),
                Kept::Source(
                    "crates/kr-automation/src/store.rs",
                    &["StoredEvent", "JournalEventKind", "EventChain"],
                ),
            ],
        },
        Store {
            writers: Writers::Daemon,
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
                protocol::<catalogue::CatalogueAddResult>("CatalogueAddResult"),
                protocol::<catalogue::CatalogueSyncResult>("CatalogueSyncResult"),
                protocol::<catalogue::CataloguePinResult>("CataloguePinResult"),
                protocol::<catalogue::CatalogueRemoveResult>("CatalogueRemoveResult"),
                protocol::<catalogue::PluginInstallResult>("PluginInstallResult"),
                protocol::<catalogue::PluginRemoveResult>("PluginRemoveResult"),
                protocol::<catalogue::PluginPinResult>("PluginPinResult"),
                protocol::<catalogue::PluginEnableResult>("PluginEnableResult"),
                protocol::<catalogue::PluginGrantResult>("PluginGrantResult"),
                protocol::<kr_protocol::error::ProtocolError>("ProtocolError"),
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
            writers: Writers::Barred(&kr_shell_integration::host::terminal::PREFERENCE_WRITTEN),
            entry: entry(
                kr_shell_integration::host::terminal::PREFERENCE_WRITTEN.store,
                StoreScope::Environment,
                "terminal.json",
                member(
                    kr_shell_integration::host::terminal::PREFERENCE_VERSION_KEY,
                    0,
                ),
                kr_shell_integration::host::terminal::PREFERENCE_WRITTEN.version,
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
            writers: Writers::Barred(&kr_cli::service_manager::WRITTEN),
            entry: entry(
                kr_cli::service_manager::WRITTEN.store,
                StoreScope::Environment,
                "controller-service.json",
                member("version", 0),
                kr_cli::service_manager::WRITTEN.version,
                kr_cli::service_manager::RECORD_VERSION,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Source(
                "crates/kr-cli/src/service_manager.rs",
                &["Record", "Manager"],
            )],
        },
        Store {
            writers: Writers::Daemon,
            entry: entry(
                "native-bridges",
                StoreScope::Environment,
                "native-bridges/*.json",
                member("version", 0),
                kr_controller::catalogue::native_bridge::JOURNAL_VERSION,
                kr_controller::catalogue::native_bridge::JOURNAL_VERSION,
            ),
            owned: Vec::new(),
            kept: vec![
                Kept::Source(
                    "crates/kr-controller/src/catalogue/native_bridge/journal.rs",
                    &[
                        "Journal",
                        "State",
                        "Release",
                        "RecordedFacts",
                        "Removal",
                        "Change",
                        "Staging",
                        "Publication",
                        "Kept",
                    ],
                ),
                Kept::Source(
                    "crates/kr-controller/src/catalogue/native_bridge/tree.rs",
                    &["Identity"],
                ),
                Kept::Source("crates/kr-worker/src/broker/bridge.rs", &["BridgeSurface"]),
            ],
        },
        Store {
            writers: Writers::Daemon,
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
            writers: Writers::Daemon,
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
                protocol::<skill::AgentToolsRemoveResult>("AgentToolsRemoveResult"),
                Kept::Source("crates/kr-controller/src/agent_tools.rs", &["ActionRecord"]),
            ],
        },
        // The records the client keeps on this device, in the user's state root.
        Store {
            writers: Writers::Barred(&kr_client::answers::WRITTEN),
            entry: entry(
                kr_client::answers::WRITTEN.store,
                StoreScope::StateRoot,
                "kept-answers/*.answer",
                cbor_member("version", 0),
                kr_client::answers::WRITTEN.version,
                0,
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<kr_protocol::envelope::ActionTarget>("ActionTarget"),
                protocol::<kr_protocol::question::QuestionAnswer>("QuestionAnswer"),
                Kept::Source("crates/kr-client/src/answers.rs", &["AnswerDraft"]),
            ],
        },
        Store {
            writers: Writers::Barred(&kr_cli::machine::WRITTEN),
            entry: entry(
                kr_cli::machine::WRITTEN.store,
                StoreScope::StateRoot,
                "machine-merge-plan",
                cbor_member("version", 0),
                kr_cli::machine::WRITTEN.version,
                0,
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<kr_protocol::machine::MachineGroup>("MachineGroup"),
                protocol::<kr_protocol::machine::MachineExpected>("MachineExpected"),
                protocol::<kr_protocol::envelope::MutationRequest>("MutationRequest"),
                protocol::<kr_protocol::identity::EnvironmentEnrolment>("EnvironmentEnrolment"),
                Kept::Source(
                    "crates/kr-cli/src/machine.rs",
                    &["Plan", "PlannedStep", "StepState", "Why", "Reach"],
                ),
            ],
        },
        // The configuration document, wherever the environment keeps it. A document with no
        // `version` member is read as the version its reader writes, and the lock counts it as
        // version 1, which every release that reads this document reads.
        Store {
            writers: Writers::Barred(&kr_cli::doctor::configuration::WRITTEN),
            entry: entry(
                kr_cli::doctor::configuration::WRITTEN.store,
                StoreScope::Configuration,
                "config.json",
                member("version", 1),
                kr_cli::doctor::configuration::WRITTEN.version,
                u32::try_from(hostinfo::configuration::OLDEST_VERSION).expect("a small number"),
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
        Named {
            scope: StoreScope::StateRoot,
            name: "kept-answers",
            children: &["answers.lock"],
            opaque: false,
            databases: false,
            reason: "the lock a write of a kept answer holds from reading the answer it replaces until the new one is in place; empty",
        },
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
            "the store of releases on a platform whose default state root holds it; its record is the store install-record, and roots/<digest>.root, roots/<digest>.registered (a command's roots) and roots/<digest>.document (an environment and a path, separated by a NUL byte) are frozen forms (two values separated by a NUL byte) that a change replaces with a file of another name",
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
            StoreScope::StateRoot,
            ".shell-entries.json.kalareach-lock",
            "the lock `kr shell install` and `kr shell remove` hold on the record of the startup files they changed; empty",
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
            "terminal.lock",
            "the lock on the saved terminal preference; empty",
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
            "per-session launch definitions and their diagnostics, named by session and read by every daemon's sweep, so a name does not change",
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
