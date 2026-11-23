//! A daemon over a registry one schema version ahead of the one it writes, and over the
//! configuration document that registry accepted at the next version.
//!
//! A later release writes the next registry version and records the document it accepted at version 4 of
//! the document. This build reads both as found when the document holds nothing it lacks. When the
//! document holds a ceiling this build lacks, the daemon refuses to start: the copy decides the
//! restrictions in force from the first request, and read as no copy it would lift the rights
//! ceiling, the enrolment budgets, the description budgets and the disable policy the owner
//! accepted. The golden documents are in `fixtures/configuration/`.

use std::path::PathBuf;
use std::sync::Arc;

use kr_controller::error::ControllerError;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, NoTerminal, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::hostinfo::configuration::{self, DocumentState};
use kr_protocol::ids::BuildId;
use rusqlite::Connection;
use serde_json::Value;

/// A supervisor that starts nothing. These cases create no sessions.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/configuration")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The golden file with one member of `ceilings` replaced.
fn with_ceiling(name: &str, member: &str, value: &Value) -> String {
    let mut document: Value = serde_json::from_str(&fixture(name)).expect("a JSON document");
    document["ceilings"][member] = value.clone();
    serde_json::to_string_pretty(&document).expect("a document")
}

async fn start(temp: &kr_ipc::testing::TempHost) -> kr_controller::error::Result<Arc<Controller>> {
    kr_controller::testing::taken_over(|| {
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let secrets = environment.secrets_dir();
        // The daemon's start is a large future; on the heap it does not count against the test
        // thread's stack.
        Box::pin(Controller::start(ControllerSetup {
            paths: environment,
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(NoWorkers),
            worker_program: temp.root().join("kr-worker"),
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(NoTerminal),
        }))
    })
    .await
}

/// A registry the daemon made, stopped.
async fn a_stopped_environment() -> kr_ipc::testing::TempHost {
    let temp = kr_ipc::testing::TempHost::create();
    drop(start(&temp).await.expect("the daemon starts"));
    temp
}

fn document_path(temp: &kr_ipc::testing::TempHost) -> PathBuf {
    kr_worker::config::document_path(&temp.environment())
}

fn write_the_document(temp: &kr_ipc::testing::TempHost, text: &str) {
    kr_ipc::paths::write_owner_only_file(&document_path(temp), text.as_bytes())
        .expect("writes the document");
}

/// The schema version above the one this build writes, which it reads as found.
const NEXT_REGISTRY_VERSION: i64 = kr_controller::registry::READS_THROUGH_SCHEMA_VERSION;

/// What a later release leaves in the registry: its schema version, and the document it accepted.
fn as_a_later_release_left_it(
    temp: &kr_ipc::testing::TempHost,
    schema_version: i64,
    accepted: Option<&str>,
) {
    let connection = Connection::open(temp.environment().registry_database()).expect("opens");
    connection
        .execute("UPDATE schema_version SET version = ?1", [schema_version])
        .expect("the version moves");
    connection
        .execute(
            "UPDATE environment SET accepted_revision = 3, accepted_document = ?1",
            [accepted],
        )
        .expect("the record is replaced");
}

/// The schema version, the accepted document and the generation the registry records.
fn recorded(temp: &kr_ipc::testing::TempHost) -> (i64, Option<String>, i64) {
    let connection = Connection::open(temp.environment().registry_database()).expect("opens");
    let version = connection
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .expect("a version");
    let (document, generation) = connection
        .query_row(
            "SELECT accepted_document, generation FROM environment",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the environment row");
    (version, document, generation)
}

/// KR-REQ-26.13, KR-REQ-26.10: a daemon starts over a registry one schema version ahead of the one
/// it writes and over a copy of the document it accepted at the next version of the document, when
/// the copy holds nothing this build lacks. It reads both as found: the registry still records the
/// version it recorded, the copy is the copy it was, and the start, which finds the document on
/// disk to be the document it accepted, accepts nothing again. The first question about what is in
/// force puts the document through acceptance, which records it at the version this build writes,
/// in a registry that still records the version it had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_starts_over_the_next_registry_version_and_the_document_it_accepted() {
    let temp = a_stopped_environment().await;
    let golden = fixture("version-5.json");
    as_a_later_release_left_it(&temp, NEXT_REGISTRY_VERSION, Some(&golden));
    write_the_document(&temp, &golden);
    let before = recorded(&temp);
    Connection::open(temp.environment().registry_database())
        .expect("opens")
        .execute_batch(
            "CREATE TABLE acceptance_writes (n INTEGER);
             CREATE TRIGGER count_acceptance AFTER UPDATE OF accepted_document ON environment
             BEGIN INSERT INTO acceptance_writes VALUES (1); END;",
        )
        .expect("a trigger that counts");

    let controller = start(&temp).await.expect("the daemon starts");

    // Read before anything asks the daemon what is in force: every such question puts the document
    // through acceptance again and records it, as it is read, at the version this build writes. The
    // generation moves at every start; the version and the accepted copy do not.
    let after = recorded(&temp);
    assert_eq!(
        (after.0, &after.1),
        (before.0, &before.1),
        "the version and the accepted copy are as they were found"
    );
    assert!(after.2 > before.2, "and the start advanced the generation");
    let acceptance_writes = || -> i64 {
        Connection::open(temp.environment().registry_database())
            .expect("opens")
            .query_row("SELECT COUNT(*) FROM acceptance_writes", [], |row| {
                row.get(0)
            })
            .expect("the count")
    };
    assert_eq!(
        acceptance_writes(),
        0,
        "the start accepted a document it had accepted"
    );

    let effective = controller.effective_configuration().await;
    assert_eq!(effective.status.state, DocumentState::Loaded);
    drop(controller);
    let as_this_build_reads_it = configuration::load(Some(golden.as_bytes()))
        .document
        .expect("this build reads the document");
    assert_eq!(as_this_build_reads_it.version, configuration::VERSION);
    let accepted = recorded(&temp);
    assert_eq!(
        accepted.0, NEXT_REGISTRY_VERSION,
        "no acceptance writes the registry's version"
    );
    assert_eq!(acceptance_writes(), 1, "the question accepted the document");
    assert_eq!(
        accepted.1.as_deref(),
        Some(configuration::contents(&as_this_build_reads_it).as_str()),
        "and recorded it as this build reads it, at the version this build writes"
    );
    assert_eq!(
        std::fs::read_to_string(document_path(&temp)).expect("the document"),
        golden,
        "the file is the owner's"
    );
}

/// KR-REQ-26.13, KR-REQ-26.10: a daemon starts over the copy of the document that the release
/// before this one accepted, which records it at version 3 with the level it states, and over the
/// same document on disk. The registry's version is the one it has; the daemon reads the copy
/// through the document reader, so a copy that reader refuses would stop the start. The first
/// question about what is in force accepts the document and records it at the version this build
/// writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_starts_over_the_document_the_release_before_it_accepted_at_version_3() {
    let temp = a_stopped_environment().await;
    let saved = fixture("version-3.json");
    assert!(
        saved.contains("\"version\": 3") && saved.contains("\"level\": 1"),
        "the saved copy is a version-3 document that states its level"
    );
    let registry_version = recorded(&temp).0;
    as_a_later_release_left_it(&temp, registry_version, Some(&saved));
    write_the_document(&temp, &saved);

    let controller = start(&temp)
        .await
        .expect("the daemon starts over a saved version-3 copy of the accepted document");
    let effective = controller.effective_configuration().await;
    assert_eq!(
        effective.status.state,
        DocumentState::Loaded,
        "{:?}",
        effective.status
    );
    drop(controller);
    let as_this_build_reads_it = configuration::load(Some(saved.as_bytes()))
        .document
        .expect("this build reads the document");
    assert_eq!(as_this_build_reads_it.version, configuration::VERSION);
    let accepted = recorded(&temp);
    assert_eq!(
        accepted.0, registry_version,
        "the registry's version is as it was"
    );
    assert_eq!(
        accepted.1.as_deref(),
        Some(configuration::contents(&as_this_build_reads_it).as_str()),
        "the copy is recorded as this build reads it, at the version this build writes"
    );
    assert_eq!(
        std::fs::read_to_string(document_path(&temp)).expect("the document"),
        saved,
        "the file is the owner's"
    );
}

/// KR-REQ-22.10: a daemon that starts with no document on disk over a copy of the one it accepted,
/// which holds the owner's description budgets, keeps the budgets the copy holds, as it keeps the
/// session number and the other ceilings: a file that is gone is not a document that lifts them.
/// The report says that the host is still enforcing the number, and names no document as its source.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_with_no_document_keeps_the_description_budgets_its_accepted_copy_holds() {
    let temp = a_stopped_environment().await;
    let accepted = fixture("version-4-description-budgets.json");
    as_a_later_release_left_it(&temp, recorded(&temp).0, Some(&accepted));
    assert!(
        !document_path(&temp).exists(),
        "the owner's file is not there"
    );

    let controller = start(&temp)
        .await
        .expect("the daemon starts over a copy it can read");
    let report = controller.effective_configuration().await;
    assert_eq!(report.status.state, DocumentState::Absent);
    let ceiling = report
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "description_budgets.process_memory_bytes")
        .expect("the report has the ceiling");
    assert_eq!(
        ceiling.value.clone().render(),
        (2_u64 << 30).to_string(),
        "the ceiling the copy holds is in force, not the 4 GiB default"
    );
    // The report says why that number is in force, and names no document: none decided it.
    let why = match &ceiling.narrowed_by.0 {
        Some(sentence) => sentence.clone().render(),
        None => panic!("the report does not say that the host still enforces the copy's number"),
    };
    assert!(
        why.starts_with("this host is still enforcing"),
        "the report says the number is the one this host last accepted: {why}"
    );
    assert_eq!(
        ceiling.origin.0, None,
        "no document is in front of the report, so the row names no path"
    );
    drop(controller);
}

/// KR-REQ-26.13, KR-REQ-26.10: a daemon refuses to start over a copy of the accepted document that
/// it cannot read, whatever the form of the ceiling it lacks, and changes nothing: not the
/// registry's version, not the copy, not the generation, and not the document on disk, which is
/// itself one this build reads. Absent is none, and the control starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_refuses_to_start_over_an_accepted_copy_it_cannot_read() {
    let temp = a_stopped_environment().await;
    let readable = fixture("version-5.json");
    let empty = Value::Object(serde_json::Map::new());
    let mut copies: Vec<(String, String)> = Vec::new();
    {
        let (name, member) = ("version-4-limits.json", "limits");
        let forms = [
            (format!("{member} set"), fixture(name)),
            (
                format!("{member} null"),
                with_ceiling(name, member, &Value::Null),
            ),
            (
                format!("{member} empty"),
                with_ceiling(name, member, &empty),
            ),
        ];
        // At the version this build writes and at the one it reads through.
        for (what, copy) in forms {
            copies.push((format!("{what} at version 4"), copy.clone()));
            copies.push((
                format!("{what} at version 5"),
                copy.replace("\"version\": 4", "\"version\": 5"),
            ));
        }
    }
    copies.push(("not a document".to_owned(), "not json".to_owned()));
    copies.push((
        "a version this build does not know".to_owned(),
        readable.replace("\"version\": 5", "\"version\": 6"),
    ));

    for (what, copy) in copies {
        as_a_later_release_left_it(&temp, NEXT_REGISTRY_VERSION, Some(&copy));
        write_the_document(&temp, &readable);
        let before = recorded(&temp);
        let refused = start(&temp)
            .await
            .err()
            .unwrap_or_else(|| panic!("{what}: the daemon started over a copy it cannot read"));
        assert!(
            matches!(
                &refused,
                ControllerError::RegistryUnavailable { detail }
                    if detail.contains(&temp.environment_id().to_string())
            ),
            "{what}: the refusal names the environment: {refused}"
        );
        assert_eq!(recorded(&temp), before, "{what}: nothing was changed");
        assert_eq!(
            std::fs::read_to_string(document_path(&temp)).expect("the document"),
            readable,
            "{what}: the file is the owner's"
        );
    }

    // The control: with no copy there is nothing to read, and the daemon accepts the document.
    as_a_later_release_left_it(&temp, NEXT_REGISTRY_VERSION, None);
    write_the_document(&temp, &readable);
    let controller = start(&temp)
        .await
        .expect("a registry with no copy of an accepted document starts");
    drop(controller);
    assert_eq!(
        recorded(&temp).0,
        NEXT_REGISTRY_VERSION,
        "the version stays as it was found"
    );
}
