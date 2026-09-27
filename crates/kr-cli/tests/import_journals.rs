//! `kr host import-journals`, run the way a person runs it: the real `kr`, copied to the internal
//! disk, against an environment tree of the test's own with no daemon running.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.30 | a journal older than this build's migrations is imported once, under the environment's singleton lock, and refused while something holds that lock |

#![cfg(unix)]

use std::process::{Command, Output, Stdio};

use kr_protocol::ids::SessionId;
use serde_json::Value;

mod support;

/// Runs `kr` on plain pipes with `temp`'s directories, from the root directory.
fn run_kr(temp: &kr_ipc::testing::TempHost, line: &[&str]) -> Output {
    Command::new(support::kr())
        .args(line)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.root())
        .env("KR_RUNTIME_DIR", temp.paths().runtime_root())
        .env("KR_STATE_DIR", temp.paths().state_root())
        .current_dir("/")
        .stdin(Stdio::null())
        .output()
        .expect("kr runs")
}

/// Writes the journal the first build of this schema wrote, version 1 with one receipt.
fn write_version_one_journal(path: &std::path::Path) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    let connection = rusqlite::Connection::open(path).expect("creates the fixture");
    connection
        .execute_batch(
            "CREATE TABLE schema_version (version INTEGER NOT NULL);
             CREATE TABLE receipts (
                 actor_id             TEXT    NOT NULL,
                 action_id            BLOB    NOT NULL,
                 method               TEXT    NOT NULL,
                 method_version       INTEGER NOT NULL,
                 revision             INTEGER NOT NULL,
                 state                TEXT    NOT NULL,
                 reason               TEXT,
                 payload_digest       BLOB    NOT NULL,
                 accepted_deadline_ms INTEGER,
                 error_code           TEXT,
                 error_message        TEXT,
                 created_at_ms        INTEGER NOT NULL,
                 updated_at_ms        INTEGER NOT NULL,
                 PRIMARY KEY (actor_id, action_id)
             );
             CREATE INDEX receipts_created_at ON receipts (created_at_ms);
             INSERT INTO schema_version (version) VALUES (1);",
        )
        .expect("the version 1 schema");
    connection
        .execute(
            "INSERT INTO receipts (
                 actor_id, action_id, method, method_version, revision, state,
                 payload_digest, accepted_deadline_ms, created_at_ms, updated_at_ms
             ) VALUES ('test:import', ?1, 'session.close', 1, 1, 'rejected', ?2, 10000, 1000, 1000)",
            rusqlite::params![[3_u8; 16].as_slice(), [3_u8; 32].as_slice()],
        )
        .expect("the earlier build's receipt");
}

/// Reads the one document `kr` printed.
fn document(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "kr printed no JSON ({error}): {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn a_version_one_journal_is_imported_once_while_the_environment_is_stopped() {
    let temp = kr_ipc::testing::TempHost::create();
    let paths = temp.environment();
    // The registry the environment's daemon kept, which records no worker for this session.
    drop(
        kr_controller::registry::Registry::open(paths.registry_database(), temp.environment_id())
            .expect("the registry"),
    );
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let journal = paths.journal_database(session_id);
    write_version_one_journal(&journal);

    let first = run_kr(&temp, &["host", "import-journals", "--json"]);
    assert!(
        first.status.success(),
        "the import succeeds: {}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first = document(&first);
    assert_eq!(first["ok"], Value::Bool(true), "{first}");
    let reported = &first["journals"][0];
    assert_eq!(reported["session_id"], session_id.to_string(), "{first}");
    assert_eq!(reported["outcome"], "imported", "{first}");
    assert_eq!(reported["from_version"], 1, "{first}");
    assert_eq!(
        reported["to_version"],
        kr_worker::persistence::migration::CURRENT,
        "{first}"
    );
    assert_eq!(reported["receipts"], 1, "{first}");
    assert_eq!(
        kr_worker::journal::Journal::recorded_schema_version(&journal).expect("reads the version"),
        kr_worker::persistence::migration::CURRENT
    );

    let second = document(&run_kr(&temp, &["host", "import-journals", "--json"]));
    assert_eq!(
        second["journals"][0]["outcome"], "untouched",
        "a second run finds nothing to import: {second}"
    );
}

#[test]
fn the_import_is_refused_while_something_holds_the_environment() {
    // The singleton lock is what a running daemon holds. A command that took the files from
    // under a daemon, or from under another import, would be a second writer, so it is refused
    // and the journal is left exactly where it was.
    let temp = kr_ipc::testing::TempHost::create();
    let paths = temp.environment();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let journal = paths.journal_database(session_id);
    write_version_one_journal(&journal);
    let held = kr_controller::singleton::SingletonLock::acquire(
        &paths.singleton_lock(),
        temp.environment_id(),
    )
    .expect("the test holds the environment, as a running daemon does");

    let refused = run_kr(&temp, &["host", "import-journals"]);
    assert!(!refused.status.success(), "the import is refused");
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(said.contains("daemon"), "the refusal says why: {said}");
    assert_eq!(
        kr_worker::journal::Journal::recorded_schema_version(&journal).expect("reads the version"),
        1,
        "nothing was imported"
    );
    drop(held);
}
