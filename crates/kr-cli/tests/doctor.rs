//! `kr doctor`, run as the command a person types.
//!
//! What these establish, with the real binary on a real environment tree. KR-REQ-01.23: the
//! command documents the two things it can do beyond reporting, and the flag that used to be
//! reserved for a repair now says what it prints. KR-REQ-26.13 and 26.16: `kr host power` writes
//! the one versioned configuration document through the validated edit, at a new revision, and a
//! document this build must not rewrite is refused with nothing written. KR-REQ-26.44: the bundle
//! is refused without a host rather than written half-empty, and `--include-content` without
//! `--bundle` is a usage error rather than a silent no-op.
//!
//! Every binary is launched from the copy on the internal disk, and every run is given a tree of
//! its own through the two documented environment overrides, so nothing here reads or writes the
//! configuration of the person running the tests.

mod support;

use std::process::Command;

use kr_protocol::desktop::SleepInhibitionSetting;
use kr_protocol::hostinfo::configuration::{self, ConfigurationDocument, DocumentState};
use support::kr;

/// A tree of this test's own, and the command that runs against it.
struct Installation {
    tree: kr_ipc::testing::TempHost,
}

impl Installation {
    fn create() -> Self {
        Self {
            tree: kr_ipc::testing::TempHost::create(),
        }
    }

    /// Runs `kr` with the arguments given, against this tree and nothing else.
    fn run(&self, arguments: &[&str]) -> std::process::Output {
        Command::new(kr())
            .args(arguments)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.tree.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.tree.paths().state_root(),
            )
            // The binaries live on the internal disk and the command runs there too, so nothing a
            // launched process opens is on the volume this workspace lives on.
            .current_dir(support::command_binaries())
            .output()
            .expect("the command runs")
    }

    fn environment(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.tree.environment()
    }
}

/// KR-REQ-01.23: the command says what each of its flags does, and none of them is reserved.
#[test]
fn the_command_documents_what_it_prints_and_what_it_writes() {
    let installation = Installation::create();
    let output = installation.run(&["doctor", "--help"]);
    assert!(output.status.success(), "the help is printed");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        !help.to_lowercase().contains("reserved"),
        "nothing here is reserved for a later version: {help}"
    );
    assert!(
        help.contains("--verbose") && help.contains("including the checks that passed"),
        "{help}"
    );
    assert!(
        help.contains("--bundle") && help.contains("redacted errors"),
        "{help}"
    );
    assert!(
        help.contains("--include-content") && help.contains("before it writes"),
        "{help}"
    );
}

/// KR-REQ-26.44: the content-bearing export is only ever an addition to a bundle.
#[test]
fn asking_for_content_without_a_bundle_is_a_usage_error() {
    let installation = Installation::create();
    let output = installation.run(&["doctor", "--include-content"]);
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("--bundle"),
        "it says what is missing: {message}"
    );
}

/// KR-REQ-01.23: with no host to ask, the command says so and writes no bundle.
#[test]
fn with_no_host_the_command_reports_and_writes_nothing() {
    let installation = Installation::create();
    let bundle = installation.tree.root().join("support.tar");
    let output = installation.run(&["doctor", "--bundle", bundle.to_str().expect("a path")]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "the exit status a host that cannot be reached carries"
    );
    assert!(
        !bundle.exists(),
        "and a bundle is never written from a host that was not asked"
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("no KalaReach host is running"),
        "{message}"
    );
}

/// KR-REQ-26.13, KR-REQ-26.16: `kr host power` writes the one document, at a new revision.
#[test]
fn the_power_setting_is_written_into_the_one_configuration_document() {
    let installation = Installation::create();
    let environment = installation.environment();
    assert!(
        !kr_cli::doctor::configuration::document_path(&environment).exists(),
        "nothing is written until the owner chooses"
    );

    // The daemon is asked what the setting is doing afterwards, and there is none here, so the
    // command reports that. The write happens first and is what this is about.
    let output = installation.run(&["host", "power", "--set", "mains_only"]);
    assert_eq!(output.status.code(), Some(3), "no host answered");

    let loaded = kr_cli::doctor::configuration::load(&environment);
    assert_eq!(loaded.status.state, DocumentState::Loaded);
    assert_eq!(loaded.revision(), 1, "one validated edit, one revision");
    assert_eq!(
        loaded
            .preferences()
            .and_then(|set| set.sleep_inhibition.0)
            .expect("the chosen setting"),
        SleepInhibitionSetting::MainsOnly
    );
    assert!(
        !environment
            .state_dir()
            .join(configuration::SUPERSEDED_FILE_NAME)
            .exists(),
        "and the document the setting used to live in is not written again"
    );

    // A second choice is a second revision of the same document, not a second document.
    installation.run(&["host", "power", "--set", "off"]);
    let loaded = kr_cli::doctor::configuration::load(&environment);
    assert_eq!(loaded.revision(), 2);
    assert_eq!(
        loaded
            .preferences()
            .and_then(|set| set.sleep_inhibition.0)
            .expect("the chosen setting"),
        SleepInhibitionSetting::Off
    );
}

/// KR-REQ-26.13: a document from a later build is refused, not rewritten.
#[test]
fn a_document_this_build_does_not_know_is_left_exactly_as_it_was() {
    let installation = Installation::create();
    let environment = installation.environment();
    let path = kr_cli::doctor::configuration::document_path(&environment);
    let later = configuration::contents(&ConfigurationDocument {
        version: 99,
        ..ConfigurationDocument::empty()
    });
    kr_ipc::paths::write_owner_only_file(&path, later.as_bytes()).expect("writes it");

    let output = installation.run(&["host", "power", "--set", "battery_too"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a refused edit is a usage failure, not a host failure"
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("version 99"), "{message}");
    assert_eq!(
        std::fs::read_to_string(&path).expect("still there"),
        later,
        "byte for byte as the owner left it"
    );
}
