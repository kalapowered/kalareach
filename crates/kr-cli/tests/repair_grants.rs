//! `kr host repair-grants`, run the way a person runs it: the real `kr`, against an environment
//! tree of the test's own with no daemon running.

#![cfg(unix)]

use std::process::{Command, Output, Stdio};

use kr_controller::grants::{GrantDirectory, GrantRecord};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};

mod support;

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

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn id(byte: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([byte; 16]))
}

fn key(byte: u8) -> String {
    format!("X'{}'", format!("{byte:02x}").repeat(16))
}

/// A registry with grant 0x41 whose record does not decode, and its readable child 0x42.
fn damaged_registry(temp: &kr_ipc::testing::TempHost) -> std::path::PathBuf {
    let path = temp.environment().registry_database();
    drop(
        kr_controller::registry::Registry::open(&path, temp.environment_id())
            .expect("the registry"),
    );
    let directory = GrantDirectory::open(&path).expect("the grants tables");
    for (byte, parent) in [(0x41_u8, None), (0x42, Some(0x41_u8))] {
        directory
            .issue(
                &GrantRecord {
                    grant: Grant {
                        grant_id: id(byte),
                        parent_grant_id: Nullable(parent.map(id)),
                        issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
                        recipient_device_id: DeviceId::new(Uuid::from_bytes([0xe0; 16])),
                        authority_revision: AuthorityRevision::new(1),
                        environment_selector: EnvironmentSelector::Any,
                        session_selector: SessionSelector::Any,
                        actions: [ActionRight::SessionView].into_iter().collect(),
                        history: HistoryScope {
                            lower_bound_ms: Nullable::some(TimestampMs::new(1)),
                            include_live_screen: false,
                            named_questions: CanonicalSet::new(),
                            named_approvals: CanonicalSet::new(),
                        },
                        expiry: GrantExpiry::Never,
                        organisation: Nullable::null(),
                    },
                    session_id: None,
                    issued_at_ms: 1_000,
                    activated_at_ms: Some(1_000),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("written");
    }
    drop(directory);
    rusqlite::Connection::open(&path)
        .expect("opens")
        .execute_batch(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(0x41)
        ))
        .expect("the record no longer decodes");
    path
}

fn grants_rows(path: &std::path::Path) -> i64 {
    rusqlite::Connection::open(path)
        .expect("opens")
        .query_row("SELECT COUNT(*) FROM grants", [], |row| row.get(0))
        .expect("counts")
}

const NOTHING: &str = "Every grants row can be read and every live grant traces to a root. There is \
                       nothing to repair.\n";

/// A registry that holds nothing to repair says so, with and without `--apply`, and makes no copy.
#[test]
fn a_sound_registry_has_nothing_to_repair() {
    let temp = kr_ipc::testing::TempHost::create();
    drop(
        kr_controller::registry::Registry::open(
            temp.environment().registry_database(),
            temp.environment_id(),
        )
        .expect("the registry"),
    );
    drop(GrantDirectory::open(temp.environment().registry_database()).expect("tables"));
    for line in [
        &["host", "repair-grants"][..],
        &["host", "repair-grants", "--apply"],
    ] {
        let output = run_kr(&temp, line);
        assert!(output.status.success(), "{}", said(&output));
        assert_eq!(said(&output), NOTHING);
    }
}

/// The preview names each damaged row by place, class and key and each live grant it would
/// withdraw, and changes nothing; the repair then removes the row, withdraws the grant, reports the
/// copy, and the undo puts the registry back.
#[test]
fn the_preview_the_repair_and_the_undo_say_what_they_do() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = damaged_registry(&temp);
    let preview = run_kr(&temp, &["host", "repair-grants"]);
    assert!(preview.status.success(), "{}", said(&preview));
    assert_eq!(
        said(&preview),
        format!(
            "Grants rows that cannot be read: 1.\n  row 1: its record does not decode; key {}\n\
             Live grants that would be withdrawn: 1.\n  grant {}\n\
             Nothing is changed. Run with --apply to change it.\n",
            id(0x41),
            id(0x42)
        )
    );
    assert_eq!(grants_rows(&path), 2, "the preview changes nothing");

    let applied = run_kr(&temp, &["host", "repair-grants", "--apply"]);
    assert!(applied.status.success(), "{}", said(&applied));
    let text = said(&applied);
    let copy = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("Copy of the registry before the repair: "))
        .and_then(|line| line.strip_suffix('.'))
        .unwrap_or_else(|| panic!("the copy is named first: {text}"))
        .to_owned();
    let folder = std::path::Path::new(&copy)
        .parent()
        .expect("a folder")
        .display()
        .to_string();
    assert_eq!(
        text,
        format!(
            "Copy of the registry before the repair: {copy}.\n\
             Removed 1 grants rows that cannot be read:\n  row 1: its record does not decode; key {}\n\
             Withdrew 1 live grants:\n  grant {}\n\
             One fence is owed; the host pays it when it starts.\n\
             To undo: kr host repair-grants --undo {copy} --apply. Everything written to the \
             registry after this copy was made is lost with it.\n\
             The copy stays until you remove it: remove the folder {folder} yourself when you no \
             longer need it.\n",
            id(0x41),
            id(0x42)
        )
    );
    assert_eq!(grants_rows(&path), 1, "the damaged row is removed");
    assert_eq!(
        grants_rows(std::path::Path::new(&copy)),
        2,
        "the copy holds both rows"
    );
    let held: i64 = rusqlite::Connection::open(&path)
        .expect("opens")
        .query_row("SELECT COUNT(*) FROM fence_debt", [], |row| row.get(0))
        .expect("counts");
    assert_eq!(held, 1, "one fence is owed");

    let undo = run_kr(&temp, &["host", "repair-grants", "--undo", &copy]);
    assert!(undo.status.success(), "{}", said(&undo));
    assert_eq!(
        said(&undo),
        format!(
            "Putting this copy back withdraws nothing and revokes nothing: it makes the registry \
             what the copy held.\nGrants that the repair withdrew and that become live again: 1.\n\
             \x20 grant {}\nEverything written to the registry after the copy was made is lost. \
             Nothing is changed. Run with --apply to change it.\n",
            id(0x42)
        )
    );
    assert_eq!(grants_rows(&path), 1, "the undo preview changes nothing");
    let undone = run_kr(
        &temp,
        &["host", "repair-grants", "--undo", &copy, "--apply"],
    );
    assert!(undone.status.success(), "{}", said(&undone));
    assert_eq!(
        said(&undone),
        "The registry is back to what the copy held. Every change made after the copy is gone \
         with it, and the grants the repair withdrew are live again.\n"
    );
    assert_eq!(grants_rows(&path), 2, "the registry is what the copy held");
}

/// Another holder of the environment's lock stops the repair, which says so and changes nothing.
#[test]
fn the_repair_refuses_while_another_holder_has_the_environment_lock() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = damaged_registry(&temp);
    let _held = kr_controller::singleton::SingletonLock::hold(
        &temp.environment().singleton_lock(),
        temp.environment_id(),
    )
    .expect("the lock is taken");
    let output = run_kr(&temp, &["host", "repair-grants", "--apply"]);
    assert!(!output.status.success());
    assert!(
        said(&output).contains(
            "Another process holds this host's environment: the host, an update, an import or \
             another repair. Stop it, then run this command again. Nothing is changed."
        ),
        "{}",
        said(&output)
    );
    assert_eq!(grants_rows(&path), 2);
}

/// A registry of another schema is refused by its version, and nothing is changed.
#[test]
fn the_repair_refuses_a_registry_of_another_schema() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = damaged_registry(&temp);
    rusqlite::Connection::open(&path)
        .expect("opens")
        .execute_batch("UPDATE schema_version SET version = 14;")
        .expect("another schema");
    let output = run_kr(&temp, &["host", "repair-grants", "--apply"]);
    assert!(!output.status.success());
    assert!(
        said(&output).contains(&format!(
            "This registry was written by another build (schema version 14; this build reads {}). \
             Start the host once, or use that build. Nothing is changed.",
            kr_controller::registry::SCHEMA_VERSION
        )),
        "{}",
        said(&output)
    );
    assert_eq!(grants_rows(&path), 2);
}

/// The one document of a run that succeeded.
fn document_of(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", said(output));
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("one document, not {error}: {}", said(output)))
}

/// `--json` states what the lines state, in one document for each run: the rows by place, cause
/// and key, the grants, the copy, the fence, and the undo's grants.
#[test]
fn the_json_form_states_what_the_lines_state() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = damaged_registry(&temp);
    let preview = document_of(&run_kr(&temp, &["--json", "host", "repair-grants"]));
    assert_eq!(
        preview,
        serde_json::json!({
            "ok": true,
            "applied": false,
            "nothing_to_repair": false,
            "unreadable_rows": [
                {"place": 1, "cause": "its record does not decode", "key": id(0x41).to_string()}
            ],
            "grants_to_withdraw": [id(0x42).to_string()],
        })
    );
    assert_eq!(grants_rows(&path), 2, "the preview changes nothing");

    let applied = document_of(&run_kr(
        &temp,
        &["host", "repair-grants", "--apply", "--json"],
    ));
    let copy = applied["copy"]
        .as_str()
        .expect("the copy is named")
        .to_owned();
    let folder = std::path::Path::new(&copy)
        .parent()
        .expect("a folder")
        .display()
        .to_string();
    assert_eq!(
        applied,
        serde_json::json!({
            "ok": true,
            "applied": true,
            "nothing_to_repair": false,
            "copy": copy,
            "folder": folder,
            "removed_rows": [
                {"place": 1, "cause": "its record does not decode", "key": id(0x41).to_string()}
            ],
            "withdrawn_grants": [id(0x42).to_string()],
            "fence_owed": true,
        })
    );
    assert_eq!(grants_rows(&path), 1, "the damaged row is removed");

    let undo = document_of(&run_kr(
        &temp,
        &["--json", "host", "repair-grants", "--undo", &copy],
    ));
    assert_eq!(
        undo,
        serde_json::json!({
            "ok": true,
            "applied": false,
            "grants_live_again": [id(0x42).to_string()],
        })
    );
    let undone = document_of(&run_kr(
        &temp,
        &[
            "--json",
            "host",
            "repair-grants",
            "--undo",
            &copy,
            "--apply",
        ],
    ));
    assert_eq!(undone, serde_json::json!({"ok": true, "applied": true}));
    assert_eq!(grants_rows(&path), 2, "the registry is what the copy held");
}

/// A registry with nothing to repair gives the document that says so, with and without `--apply`.
#[test]
fn the_json_form_of_a_sound_registry_says_there_is_nothing_to_repair() {
    let temp = kr_ipc::testing::TempHost::create();
    drop(
        kr_controller::registry::Registry::open(
            temp.environment().registry_database(),
            temp.environment_id(),
        )
        .expect("the registry"),
    );
    drop(GrantDirectory::open(temp.environment().registry_database()).expect("tables"));
    for line in [
        &["--json", "host", "repair-grants"][..],
        &["--json", "host", "repair-grants", "--apply"],
    ] {
        assert_eq!(
            document_of(&run_kr(&temp, line)),
            serde_json::json!({
                "ok": true,
                "applied": false,
                "nothing_to_repair": true,
                "unreadable_rows": [],
                "grants_to_withdraw": [],
            })
        );
    }
}

/// A refusal under `--json` is the one failure document the command line gives, and nothing is
/// changed.
#[test]
fn the_json_form_of_a_refusal_is_one_failure_document() {
    let temp = kr_ipc::testing::TempHost::create();
    let path = damaged_registry(&temp);
    rusqlite::Connection::open(&path)
        .expect("opens")
        .execute_batch("UPDATE schema_version SET version = 14;")
        .expect("another schema");
    let output = run_kr(&temp, &["--json", "host", "repair-grants", "--apply"]);
    assert!(!output.status.success());
    let failure: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("one document, not {error}: {}", said(&output)));
    assert_eq!(failure["ok"], serde_json::json!(false), "{failure}");
    assert!(
        failure.to_string().contains("Nothing is changed."),
        "the document says nothing was changed: {failure}"
    );
    assert_eq!(grants_rows(&path), 2);
}
