//! Every store the host keeps, as the code declares it, and every other name the host keeps under
//! the state root.
//!
//! A version is the constant its crate writes, never a number typed here. What a store keeps is
//! declared by hand, next to the crate that writes it: a type the protocol generates a schema for
//! by that schema, and a type private to a crate by its definition in the source.

use kr_protocol::update::{Recording, ReleaseStore, StoreScope};

use super::{
    Claim, Kept, Known, KnownIs, Levels, Named, Store, Writers, known_protocol, protocol,
    protocol_at_base,
};

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
        reads_through: None,
    }
}

/// A store entry that reads through `version` above the one it writes.
trait ReadsThrough {
    fn reading_through(self, version: u32) -> Self;
}

impl ReadsThrough for ReleaseStore {
    fn reading_through(mut self, version: u32) -> Self {
        self.reads_through = Some(version);
        self
    }
}

/// The types a store keeps that the table does not declare yet, each with the store that keeps it and a
/// digest of what it is today. Each store declares its own at its next raise, and deletes its lines.
#[must_use]
pub fn known() -> Vec<Known> {
    use kr_protocol::{
        account, attention, automation, delivery, error, host_account, identity, pairing, push,
        sharing, skill,
    };

    let source = |store, name, file, pinned| Known {
        store,
        name,
        is: KnownIs::Source(file),
        pinned,
    };

    // Words the code matches stored text against, and the enums that name them where there are
    // some: the digest holds each enum's definition, so a variant added to one moves it.
    let words_of = |store, name, words: Vec<String>, anchor, enums, pinned| Known {
        store,
        name,
        is: KnownIs::Words(words, anchor, enums),
        pinned,
    };
    // A set whose words are taken from the code itself (an `ALL` and `as_str`) has nothing to anchor
    // and no enum to hold beside it: the words are the enum's. Every set typed in the table says
    // which file writes its words and which enum it stands for, with `&[]` where it has none.
    let words = |store, name, words: Vec<String>, anchor: Option<&'static str>, pinned| {
        assert!(
            anchor.is_none(),
            "{name}: a set with an anchor names its enum: use words_of"
        );
        words_of(store, name, words, anchor, &[], pinned)
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
        known_protocol::<push::DevicePushRegisterResult>(
            "registry",
            "DevicePushRegisterResult",
            "e9aaf057c87c511242039f5fde45cea281a56cb916155865a10b0886c91b16e8",
        ),
        known_protocol::<delivery::DeliveryDestinationConfigureResult>(
            "registry",
            "DeliveryDestinationConfigureResult",
            "481a136e9e840abc8d93a11972f41ad975655e3d98deb982819a8113c3f4f1b7",
        ),
        known_protocol::<delivery::DeliveryDestinationRemoveResult>(
            "registry",
            "DeliveryDestinationRemoveResult",
            "16a90c0562fa5ae4906d61e674153bf59c316d30abc54ec5ecc79b08e019c443",
        ),
        known_protocol::<host_account::AccountSignInStarted>(
            "registry",
            "AccountSignInStarted",
            "4c582a489bd5ec4347e20b6f0015386ef7ffc4912739e649b28d88b2cc4bc382",
        ),
        known_protocol::<host_account::AccountSignedOut>(
            "registry",
            "AccountSignedOut",
            "1c02b8aa44a0f9f364e09cf7cfcb8c9dad9ac89a63d9294a4bd7a4c019f97442",
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
        words_of(
            "delivery",
            "push suppression reasons",
            literal(&["burst", "sustained"]),
            Some("crates/kr-delivery/src/journal.rs"),
            &[("crates/kr-protocol/src/push.rs", "PushSuppressionReason")],
            "a8bd4c6fd3dd8adbfd67f642f2122ec7c209d1e9bc4a7dff39b40cb492236ec1",
        ),
        words(
            "delivery",
            "event sources",
            kr_delivery::journal::EventSource::ALL
                .iter()
                .map(|source| source.as_str().to_owned())
                .collect(),
            None,
            "e59eb540e3a179fa14b6a3c0c3e55665967ad3a9d4a4be710fb096e3adf97ab2",
        ),
        words(
            "delivery",
            "delivery states",
            kr_delivery::journal::DeliveryState::ALL
                .iter()
                .map(|state| state.as_str().to_owned())
                .collect(),
            None,
            "e12dd6b5cb95d82e6e30bc54b206ad3fea8f00076b827fe76a64a5e7338d21b7",
        ),
        words(
            "delivery",
            "destination kinds",
            kr_delivery::destination::DestinationKind::ALL
                .iter()
                .map(|kind| kind.as_str().to_owned())
                .collect(),
            None,
            "3123a85b676f90000801236159af1bbc579cb2d26f772618f5a946dae158c050",
        ),
        words(
            "delivery",
            "next actions",
            kr_delivery::push::NextAction::ALL
                .iter()
                .map(|next| next.as_str().to_owned())
                .collect(),
            None,
            "dc39b51d2095b584734fb1a33503909b1bace98db1606d43d273163b64b52305",
        ),
        // The attention store: the words it matches stored text against.
        words_of(
            "attention",
            "process start sources",
            literal(&[
                "linux_proc_stat",
                "macos_proc_bsd_info",
                "windows_process_creation_time",
                "windows_process_start_seconds",
            ]),
            Some("crates/kr-attention/src/store.rs"),
            &[("crates/kr-protocol/src/identity.rs", "ProcessStartSource")],
            "efd94e47ea16145263aeb3fb022c89efda99adbf99f17495bc06cb3dab7e0138",
        ),
        words_of(
            "attention",
            "review subject kinds",
            literal(&["turn", "change_set"]),
            Some("crates/kr-attention/src/store.rs"),
            &[("crates/kr-protocol/src/attention.rs", "ReviewSubject")],
            "caadb9f56cfaf54422e1e9b605c0a25be659299f99c01eb892864eb51e477297",
        ),
        words_of(
            "attention",
            "text kinds",
            literal(&["host", "record"]),
            Some("crates/kr-attention/src/store.rs"),
            &[("crates/kr-attention/src/engine.rs", "Text")],
            "dfc35cf97fb6509566f2c0684824f8cd2a51698f272a510457848a25fbf8ac29",
        ),
        words_of(
            "attention",
            "automation subject kinds",
            literal(&["workflow", "chain"]),
            Some("crates/kr-attention/src/store.rs"),
            &[(
                "crates/kr-protocol/src/attention.rs",
                "AttentionAutomationSubject",
            )],
            "50677eeec032dc58f7ab6e46310dac288493220e0e449c4e3b7f128a9d45a624",
        ),
        words(
            "attention",
            "levels",
            attention::AttentionLevel::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            None,
            "a94a1c95f39f0a6395f5eaf7256efe68c942f806129f494c7d0b6bb3c87c03fd",
        ),
        words(
            "attention",
            "routings",
            attention::AttentionRouting::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            None,
            "b48e4399501817c47f5b4c88c6b07705a7dd39c94f91be5bf0b193e495514bef",
        ),
        words(
            "attention",
            "notification states",
            attention::NotificationState::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            None,
            "09ebe720c0e2dd869bf8de29a9da7d3baf6c8e6cdf1bb4949a77808cdfc95855",
        ),
        words(
            "attention",
            "semantic change kinds",
            attention::SemanticChangeKind::ALL
                .iter()
                .map(|word| word.as_str().to_owned())
                .collect(),
            None,
            "61c6654c47ba6b0a774eb233be4c99d8aeec089608bc720e6deb1fd33a17eb9c",
        ),
        words_of(
            "attention",
            "origin words",
            literal(&["environment"]),
            Some("crates/kr-attention/src/store.rs"),
            &[("crates/kr-attention/src/event.rs", "Origin")],
            "e799e9f01ab42d78a4fd7dcc2d4611e41cfbd1900a5e2c0b620ae7490bfb955c",
        ),
        // The registry's columns of words, and the consumed reasons it stores by their protocol
        // names.
        words_of(
            "registry",
            "process start sources",
            literal(&[
                "linux_proc_stat",
                "macos_proc_bsd_info",
                "windows_process_creation_time",
                "windows_process_start_seconds",
            ]),
            Some("crates/kr-controller/src/registry.rs"),
            &[("crates/kr-protocol/src/identity.rs", "ProcessStartSource")],
            "8d0462fea698cd5062e47b8c5d9d0257dd829ac52bca210fad6dbb814ee278b6",
        ),
        words_of(
            "registry",
            "invitation states",
            literal(&["open", "locked", "committed", "consumed"]),
            Some("crates/kr-controller/src/net/invitations.rs"),
            &[("crates/kr-pairing/src/platform.rs", "InvitationState")],
            "30c62bdf8453f6dd1a294b8d52ae7a5e149d0ba6d979fb221f339747b8244326",
        ),
        words_of(
            "registry",
            "host owner kinds",
            literal(&["migrated", "first_owner"]),
            Some("crates/kr-controller/src/net/invitations.rs"),
            &[("crates/kr-controller/src/net/invitations.rs", "HostOwner")],
            "12da03792d3c200ec87495bc1ff96a236c5b43a55aeab9f011e38dc7983fd563",
        ),
        known_protocol::<pairing::PairingConsumedReason>(
            "registry",
            "PairingConsumedReason",
            "8e47614af034efad7f29d0c65b13daad3f150bbe2d59cda4034dfe69dbfad33c",
        ),
        words_of(
            "catalogue",
            "repository kinds",
            literal(&["official", "vendor", "community", "local", "mirror"]),
            Some("crates/kr-plugin-catalogue/src/db.rs"),
            &[(
                "crates/kr-plugin-catalogue/src/repository.rs",
                "RepositoryKind",
            )],
            "79096143ddb5237b2adb39514d7c187c29edb14840a5af10d20ed199a733c75a",
        ),
        words_of(
            "transfers",
            "snapshot states",
            literal(&["reserving", "open", "failed", "expired", "released"]),
            Some("crates/kr-transfer/src/store.rs"),
            &[("crates/kr-transfer/src/store.rs", "SnapshotState")],
            "49e5f3b705b933016657462dba3bf9a0971954b08a67e97fd03f28385b0517af",
        ),
        // The delivery journal's queued external message: the document and the words in it.
        source(
            "delivery",
            "StoredMessage",
            "crates/kr-controller/src/push/client.rs",
            "c8bfa256400551e27e55fae73643fb75e1b0950986ba66af56ee12dea9094b97",
        ),
        source(
            "delivery",
            "StoredInterval",
            "crates/kr-controller/src/push/client.rs",
            "14747dd6a7c6ca6f67e5d2a1d29b6f41750cba354750ec6b57ecefc7b7a16fdf",
        ),
        words_of(
            "delivery",
            "queued message keys",
            literal(&[
                "alert",
                "body",
                "delivery_id",
                "interval",
                "from_ms",
                "to_ms",
                "resources",
                "withheld",
            ]),
            Some("crates/kr-delivery/src/producer.rs"),
            // The keys of a document, not the words of an enum: `StoredMessage` and
            // `StoredInterval` above pin the document's shape.
            &[],
            "c8b1404c75a2d5a04b7d230e6ed9ec6725d7d4512fd5471f6a93760f8622a6f2",
        ),
        words_of(
            "delivery",
            "withheld reasons",
            literal(&[
                "outside_history_scope",
                "resource_not_granted",
                "no_production_time",
            ]),
            Some("crates/kr-delivery/src/external.rs"),
            &[("crates/kr-delivery/src/external.rs", "Withheld")],
            "1320677d9b402b374f5bff99e3252ee3dac5d7033c0b4400661b59d7fc002be4",
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

/// The known types that no source item holds: a type a store keeps in a column of words, and the
/// document that is the root of a stored value. A known line for one is not stale for want of a
/// holder.
#[must_use]
pub fn kept_without_a_holder() -> Vec<&'static str> {
    vec!["PairingConsumedReason", "StoredMessage"]
}

/// The type of the answer the registry keeps for each method that has it kept, by the type's name:
/// the method's answer, as `kr_controller::service::RETAINED_AUTHORITY_ANSWERS` and
/// `RETAINED_MACHINE_ANSWERS` name the methods.
#[must_use]
pub fn retained_answers() -> Vec<(kr_protocol::method::Method, &'static str)> {
    use kr_protocol::method::Method;

    vec![
        (Method::GrantCreate, "GrantCreateResult"),
        (Method::GrantRedeem, "GrantRedeemResult"),
        (Method::GrantRevoke, "RevocationResult"),
        (Method::GrantTransfer, "GrantTransferResult"),
        (Method::DeviceRevoke, "RevocationResult"),
        (
            Method::DevicePreviewKeyUpdate,
            "DevicePreviewKeyUpdateResult",
        ),
        (
            Method::DeliveryDestinationConfigure,
            "DeliveryDestinationConfigureResult",
        ),
        (
            Method::DeliveryDestinationRemove,
            "DeliveryDestinationRemoveResult",
        ),
        (
            Method::DeliveryDestinationSecretSet,
            "DeliveryDestinationSecretSetResult",
        ),
        (Method::DevicePushRegister, "DevicePushRegisterResult"),
        (Method::OrganisationEnrol, "OrganisationEnrolResult"),
        (
            Method::OrganisationExclusiveSet,
            "OrganisationExclusiveSetResult",
        ),
        (Method::OrganisationWithdraw, "RevocationResult"),
        (Method::PrivacySet, "PrivacyReport"),
        (Method::AccountSignIn, "AccountSignInStarted"),
        (Method::AccountSignOut, "AccountSignedOut"),
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
        action, archive, attention, automation, catalogue, changeset, delivery, describe, desktop,
        grant, hostinfo, identity, invitation, machine, mailbox, organisation, pairing, privacy,
        project, push, session, sharing, skill, transfer, voice,
    };

    let mut stores = vec![
        // The store of releases itself.
        Store {
            levels: None,
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
            levels: None,
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
            levels: None,
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
                protocol_at_base::<hostinfo::configuration::ConfigurationDocument>(
                    "ConfigurationDocument",
                    hostinfo::configuration::LEVELLED,
                ),
                protocol::<grant::Grant>("Grant"),
                protocol::<sharing::InvitationPreview>("InvitationPreview"),
                protocol::<sharing::GrantCreateResult>("GrantCreateResult"),
                protocol::<sharing::RevocationResult>("RevocationResult"),
                protocol::<sharing::GrantRedeemResult>("GrantRedeemResult"),
                protocol::<sharing::GrantTransferResult>("GrantTransferResult"),
                protocol::<sharing::DeviceKeysCompleteResult>("DeviceKeysCompleteResult"),
                protocol::<sharing::DevicePreviewKeyUpdateResult>("DevicePreviewKeyUpdateResult"),
                protocol::<machine::MachineStepResult>("MachineStepResult"),
                protocol::<voice::VoiceGrantResult>("VoiceGrantResult"),
                protocol::<voice::VoiceDelegateResult>("VoiceDelegateResult"),
                protocol::<voice::VoiceStartResult>("VoiceStartResult"),
                protocol::<voice::VoiceStopResult>("VoiceStopResult"),
                // What the registry keeps for an action it claimed, beside the claim. Each is the
                // answer a repeat of that action is given.
                protocol::<organisation::OrganisationEnrolResult>("OrganisationEnrolResult"),
                protocol::<organisation::OrganisationExclusiveSetResult>(
                    "OrganisationExclusiveSetResult",
                ),
                protocol::<organisation::OrganisationChangeMarker>("OrganisationChangeMarker"),
                protocol::<describe::SessionRenameResult>("SessionRenameResult"),
                protocol::<describe::DescriptionSetup>("DescriptionSetup"),
                protocol::<delivery::DeliveryDestinationSecretSetResult>(
                    "DeliveryDestinationSecretSetResult",
                ),
                protocol::<identity::EnvironmentEnrolResult>("EnvironmentEnrolResult"),
                protocol::<identity::EnvironmentForgetResult>("EnvironmentForgetResult"),
                protocol::<identity::EnvironmentRefreshResult>("EnvironmentRefreshResult"),
                protocol::<kr_protocol::update::HostUpdateHandoverResult>(
                    "HostUpdateHandoverResult",
                ),
                protocol::<privacy::PrivacyReport>("PrivacyReport"),
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
                        "StoredRemoval",
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
            levels: None,
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
                // The `source` of the cursors, the gaps, the items and the omitted ranges, and
                // the `record_source` of the items, the changes and the pending inputs, hold one
                // of these, and the store refuses a row that holds another.
                Kept::Words(
                    "attention sources",
                    attention::AttentionSource::ALL
                        .iter()
                        .map(|source| source.as_str().to_owned())
                        .collect(),
                ),
                // The `rule` of every item holds one of these, and the store refuses a row that
                // holds another.
                Kept::Words(
                    "attention rules",
                    attention::AttentionRule::ALL
                        .iter()
                        .map(|rule| rule.as_str().to_owned())
                        .collect(),
                ),
            ],
        },
        Store {
            levels: None,
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
            levels: None,
            writers: Writers::Daemon,
            entry: entry(
                "delivery",
                StoreScope::Environment,
                "delivery.sqlite3",
                sqlite_table("delivery_schema"),
                version(kr_delivery::journal::SCHEMA_VERSION),
                version(kr_delivery::journal::OLDEST_SCHEMA_VERSION),
            )
            .reading_through(version(kr_delivery::journal::READS_THROUGH)),
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
            levels: None,
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
            levels: None,
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
            levels: None,
            writers: Writers::Daemon,
            entry: entry(
                "mailbox-replay",
                StoreScope::Environment,
                "mailbox-replay.sqlite3",
                sqlite_table("mailbox_replay_schema"),
                version(kr_controller::mailbox_reader::record::SCHEMA_VERSION),
                version(kr_controller::mailbox_reader::record::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: Vec::new(),
        },
        Store {
            levels: None,
            writers: Writers::Daemon,
            entry: entry(
                "capability-answers",
                StoreScope::Environment,
                "capability-answers.sqlite3",
                sqlite_table("capability_answers_schema"),
                version(kr_controller::capability_answers::SCHEMA_VERSION),
                version(kr_controller::capability_answers::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            // The answer a repeat of a request for the disclosed checks is given, kept for 30 days.
            kept: vec![protocol::<desktop::CapabilityChecks>("CapabilityChecks")],
        },
        Store {
            levels: None,
            writers: Writers::Daemon,
            entry: entry(
                "relay-leases",
                StoreScope::Environment,
                "relay-leases.sqlite3",
                sqlite_table("relay_lease_schema"),
                version(kr_controller::relay_leases::record::SCHEMA_VERSION),
                version(kr_controller::relay_leases::record::OLDEST_SCHEMA_VERSION),
            ),
            owned: Vec::new(),
            kept: vec![Kept::Words(
                "the reasons an ending is stored with",
                kr_controller::relay_leases::record::REASONS
                    .iter()
                    .map(|reason| (*reason).to_owned())
                    .collect(),
            )],
        },
        Store {
            levels: None,
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
            levels: None,
            writers: Writers::Daemon,
            entry: entry(
                "workflow-resources",
                StoreScope::Environment,
                "workflow-resources.db",
                Recording::SqliteUserVersion,
                kr_automation::resources::RESOURCES_SCHEMA_VERSION,
                kr_automation::resources::RESOURCES_OLDEST_SCHEMA_VERSION,
            ),
            owned: Vec::new(),
            kept: vec![
                protocol::<automation::WorkflowActionKind>("WorkflowActionKind"),
                protocol::<identity::ProcessStartIdentity>("ProcessStartIdentity"),
                protocol::<identity::BootIdentity>("BootIdentity"),
            ],
        },
        Store {
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: None,
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
        // The policies the owner applied for the organisations the host is enrolled in. An earlier
        // release does not name this store, and the registry, which it reads, holds none of it.
        Store {
            levels: None,
            writers: Writers::Daemon,
            entry: entry(
                kr_controller::grants::applied::STORE_NAME,
                StoreScope::Environment,
                "organisation-policy.json",
                member("version", 0),
                kr_controller::grants::applied::RECORD_VERSION,
                kr_controller::grants::applied::RECORD_VERSION,
            ),
            owned: Vec::new(),
            kept: vec![Kept::Source(
                "crates/kr-controller/src/grants/applied.rs",
                &["Record", "StoredAppliedPolicy"],
            )],
        },
        Store {
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: None,
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
            levels: Some(Levels {
                release: hostinfo::configuration::THIS_RELEASE,
                document: kr_protocol::schema::schema_for::<
                    hostinfo::configuration::ConfigurationDocument,
                >(),
            }),
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
            kept: vec![protocol_at_base::<
                hostinfo::configuration::ConfigurationDocument,
            >(
                "ConfigurationDocument", hostinfo::configuration::LEVELLED
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
            "the store of releases on a platform whose default state root holds it; its record is the store install-record, and roots/<digest>.root, roots/<digest>.registered (a command's roots) and roots/<digest>.document (an environment and a path, separated by a NUL byte) are frozen forms (two values separated by a NUL byte) that a change replaces with a file of another name; installer is one line naming the package manager that put the releases there, a file of its own so that the record is as an earlier release wrote it",
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
        Named {
            scope: StoreScope::Environment,
            name: "workflow-scratch",
            children: &[],
            opaque: true,
            databases: true,
            reason: "the directories a workflow's commands run in, one for each node and removed when its row in the resource ledger is released unless the removal refuses the tree, which then stays and is named in the daemon's log; what a command writes there is its own",
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
