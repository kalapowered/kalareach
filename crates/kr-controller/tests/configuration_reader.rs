//! A daemon over a registry one schema version ahead of the one it writes, and over the
//! configuration document that registry accepted at the next version.
//!
//! A later release writes registry version 16 and records the document it accepted at version 4 of
//! the document. This build reads both as found when the document holds nothing it lacks. When the
//! document holds a ceiling this build lacks, the daemon refuses to start: the copy decides the
//! restrictions in force from the first request, and read as no copy it would lift the rights
//! ceiling, the enrolment budgets and the disable policy the owner accepted. The golden documents
//! are in `fixtures/configuration/`.

use std::path::PathBuf;
use std::sync::Arc;

use kr_controller::error::ControllerError;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, NoTerminal, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::hostinfo::configuration::DocumentState;
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
/// version it recorded, the copy is the copy it was, and the daemon, which finds the document on
/// disk to be the document it accepted, accepts nothing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_starts_over_the_next_registry_version_and_the_document_it_accepted() {
    let temp = a_stopped_environment().await;
    let golden = fixture("version-4.json");
    as_a_later_release_left_it(&temp, 16, Some(&golden));
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
    let effective = controller.effective_configuration().await;
    assert_eq!(effective.status.state, DocumentState::Loaded);
    drop(controller);

    assert_eq!(
        recorded(&temp),
        before,
        "nothing the registry records moved"
    );
    let writes: i64 = Connection::open(temp.environment().registry_database())
        .expect("opens")
        .query_row("SELECT COUNT(*) FROM acceptance_writes", [], |row| {
            row.get(0)
        })
        .expect("the count");
    assert_eq!(writes, 0, "the start accepted a document it had accepted");
    assert_eq!(
        std::fs::read_to_string(document_path(&temp)).expect("the document"),
        golden,
        "the file is the owner's"
    );
}

/// KR-REQ-26.13, KR-REQ-26.10: a daemon refuses to start over a copy of the accepted document that
/// it cannot read, whatever the form of the ceiling it lacks, and changes nothing: not the
/// registry's version, not the copy, not the generation, and not the document on disk, which is
/// itself one this build reads. Absent is none, and the control starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_refuses_to_start_over_an_accepted_copy_it_cannot_read() {
    let temp = a_stopped_environment().await;
    let readable = fixture("version-4.json");
    let empty = Value::Object(serde_json::Map::new());
    let mut copies: Vec<(String, String)> = Vec::new();
    for (name, member) in [
        ("version-4-limits.json", "limits"),
        ("version-4-description-budgets.json", "description_budgets"),
    ] {
        copies.push((format!("{member} set"), fixture(name)));
        copies.push((
            format!("{member} null"),
            with_ceiling(name, member, &Value::Null),
        ));
        copies.push((
            format!("{member} empty"),
            with_ceiling(name, member, &empty),
        ));
    }
    copies.push(("not a document".to_owned(), "not json".to_owned()));
    copies.push((
        "a version this build does not know".to_owned(),
        readable.replace("\"version\": 4", "\"version\": 5"),
    ));

    for (what, copy) in copies {
        as_a_later_release_left_it(&temp, 16, Some(&copy));
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
    as_a_later_release_left_it(&temp, 16, None);
    write_the_document(&temp, &readable);
    let controller = start(&temp)
        .await
        .expect("a registry with no copy of an accepted document starts");
    drop(controller);
    assert_eq!(recorded(&temp).0, 16, "the version stays as it was found");
}

/// KR-REQ-26.10: the registry one version past the one this build reads through is refused, as an
/// unreadable one is, and nothing in it changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_refuses_a_registry_past_the_version_it_reads_through() {
    let temp = a_stopped_environment().await;
    let golden = fixture("version-4.json");
    as_a_later_release_left_it(&temp, 17, Some(&golden));
    let before = recorded(&temp);
    let refused = start(&temp)
        .await
        .err()
        .expect("the daemon refuses a registry it cannot read");
    assert!(
        matches!(
            &refused,
            ControllerError::RegistryUnavailable { detail } if detail.contains("schema version 17")
        ),
        "{refused}"
    );
    assert_eq!(recorded(&temp), before);
}
