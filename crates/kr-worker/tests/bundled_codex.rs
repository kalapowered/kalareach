//! The Codex package the plugins repository publishes, read by the worker as an installation hands
//! it over.
//!
//! The package under `fixtures/plugins/released/kalareach/codex/0.3.0/` is a byte copy of every file
//! of the release. These cases read it through the package check the host runs, pin its identity,
//! and show what the worker makes of it: a table the gateway interprets, a reading that names the
//! thread, the turn and the cleared request, the four decisions the package's answer action
//! labels, and a rich table that lists exactly the operations the package declares.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.30 | the released table compiles for the executable its build record names, and classifies every method of the pinned schema |
//! | KR-REQ-11.33 | the released table answers the two approvals Codex asks as responses, offers the four decisions the package's action labels, and trusts a binding that holds the two approval grants |
//! | KR-REQ-12.06 | the released table says where the thread, the turn and the cleared request are named |
//! | KR-REQ-12.12 | the released table's rich table lists prompt, steer and cancel and no queue, each with a template the package check accepted |
//!
//! Not claimed: Windows, where no gateway runs.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::validate::validate_package_directory;
use kr_protocol::gateway::RichOperation;
use kr_protocol::scalars::Digest256;
use kr_worker::broker::connectors::{
    ConnectorSource, InstalledConnector, QualifiedExecutable, fixture,
};

/// The directory of the copied package.
fn package_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/released/kalareach/codex/0.3.0")
}

fn digest_of(path: &Path) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(
        &std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    ))
}

/// The digest the build record names for the executable the tables are compiled for.
fn executable() -> Digest256 {
    Digest256::from_bytes([3; 32])
}

/// What an installation hands the worker for the package: every capability it asks for, and the
/// build a signed record names.
fn source() -> ConnectorSource {
    ConnectorSource {
        package_digest: digest_of(&package_dir().join("plugin.json")),
        package_dir: package_dir(),
        bridge: None,
        granted: [
            PluginCapability::MetadataMatch,
            PluginCapability::DeclarativePresentation,
            PluginCapability::BrokerSemanticEvents,
            PluginCapability::UpstreamAction,
            PluginCapability::CommandIntegrationLaunch,
            PluginCapability::ApprovalDecode,
            PluginCapability::ApprovalRespond,
        ]
        .into_iter()
        .collect(),
        qualified: vec![QualifiedExecutable {
            digest: executable(),
            version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
        }],
    }
}

/// The package is the one the plugins repository publishes: its manifest has the identity this
/// suite pins, and every other file is the bytes the manifest names, which the package check
/// refuses a copy of otherwise. Where the plugins repository is checked out (`KR_PLUGINS_CHECKOUT`,
/// or beside this checkout), each file is also compared with the repository's.
#[test]
fn the_copy_is_the_package_the_plugins_repository_publishes() {
    let hash: String = kr_cbor::sha256(&std::fs::read(package_dir().join("plugin.json")).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hash, "a37d8d7eaf63f8502ae2da2e57a39784a01a159426060aca53a48647d30b928f",
        "the package hash an owner confirms at installation"
    );
    let checked = validate_package_directory(&package_dir());
    assert!(
        checked.report.is_valid(),
        "the package check refuses the copy: {:?}",
        checked.report.findings
    );
    // Where the plugins repository is checked out: `KR_PLUGINS_CHECKOUT` names it, and a checkout
    // beside this one is found without it.
    let checkouts: Vec<PathBuf> = std::env::var_os("KR_PLUGINS_CHECKOUT")
        .map(PathBuf::from)
        .into_iter()
        .chain(std::iter::once(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../kalareach-plugins"),
        ))
        .collect();
    for checkout in checkouts {
        let repository = checkout.join("plugins/kalareach/codex");
        if !repository.join("plugin.json").is_file() {
            continue;
        }
        // The checkout may be at another release; only a checkout of this one is compared.
        let same_release = std::fs::read(repository.join("plugin.json"))
            .is_ok_and(|bytes| bytes == std::fs::read(package_dir().join("plugin.json")).unwrap());
        if !same_release {
            continue;
        }
        for file in [
            "plugin.json",
            "connector.json",
            "presentation.json",
            "README.md",
            "fixtures/conformance.json",
            "fixtures/frames.json",
        ] {
            assert_eq!(
                std::fs::read(repository.join(file)).expect("the repository's file"),
                std::fs::read(package_dir().join(file)).expect("the copy's file"),
                "{file} differs from the plugins repository's"
            );
        }
    }
}

/// KR-REQ-11.30, KR-REQ-11.33 and KR-REQ-12.12: the worker compiles the released table, and what
/// it compiles is what the package declares.
#[test]
fn the_released_table_compiles_to_what_the_package_declares() {
    let connector = InstalledConnector::read(source()).expect("the worker reads the package");
    let tables = connector
        .native_tables(&executable())
        .expect("the table compiles for the executable a record names");

    // Every stable method of the pinned schema is classified, so no frame of a session suspends
    // rich mutations for being unlisted.
    assert!(
        tables.table.entries.len() >= 195,
        "{} methods are classified",
        tables.table.entries.len()
    );

    // The two approvals the package answers are answered in the member the table names, and
    // nothing else is.
    let answered: Vec<&str> = tables
        .table
        .entries
        .iter()
        .filter(|entry| entry.approval_option_field.is_present())
        .map(|entry| entry.method.as_str())
        .collect();
    assert_eq!(
        answered,
        [
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval"
        ]
    );
    let answers = tables
        .reading
        .answers
        .as_ref()
        .expect("a decision response");
    assert_eq!(answers.result_member, "decision");
    assert_eq!(
        answers
            .offered
            .iter()
            .map(|decision| (decision.option_id.as_str(), decision.label.as_str()))
            .collect::<Vec<_>>(),
        [
            ("accept", "Allow once"),
            ("accept-for-session", "Allow for the session"),
            ("decline", "Decline"),
            ("decline-and-stop", "Decline and stop"),
        ]
    );
    assert_eq!(
        answers.values.get("accept-for-session").map(String::as_str),
        Some("acceptForSession"),
        "each decision is the value Codex reads"
    );
    assert_eq!(
        answers.values.get("decline-and-stop").map(String::as_str),
        Some("cancel")
    );

    // The places the stream names the thread, the turn and the cleared request.
    let reading = &tables.reading;
    let selecting: Vec<&str> = reading
        .selections
        .keys()
        .map(|method| method.as_str())
        .collect();
    assert_eq!(selecting, ["thread/fork", "thread/resume", "thread/start"]);
    let leaving: Vec<&str> = reading
        .leaves
        .keys()
        .map(|method| method.as_str())
        .collect();
    assert_eq!(
        leaving,
        [
            "thread/archived",
            "thread/closed",
            "thread/deleted",
            "thread/unsubscribe"
        ]
    );
    assert!(reading.turn_started.is_some() && reading.turn_ended.is_some());
    assert!(reading.request_resolved.is_some());

    // The rich table lists prompt, steer and cancel, and no queue.
    let operations: Vec<RichOperation> = tables
        .rich
        .entries
        .iter()
        .filter_map(|entry| entry.operation.as_ref().copied())
        .collect();
    assert_eq!(operations.len(), 3, "{operations:?}");
    for wanted in [
        RichOperation::PromptSubmit,
        RichOperation::TurnSteer,
        RichOperation::TurnCancel,
    ] {
        assert!(operations.contains(&wanted), "{wanted} is declared");
    }
    assert!(!operations.contains(&RichOperation::PromptQueue));
    assert_eq!(
        reading.operations[&RichOperation::TurnCancel]
            .method
            .as_str(),
        "turn/interrupt"
    );
}
