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

/// Every path under `root`, with each file's content, so a test can say that nothing was added,
/// removed or changed there.
fn every_path_under(root: &std::path::Path) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
    let mut found = Vec::new();
    let mut waiting = vec![root.to_path_buf()];
    while let Some(directory) = waiting.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                waiting.push(path.clone());
                found.push((path, None));
            } else {
                let content = std::fs::read(&path).ok();
                found.push((path, content));
            }
        }
    }
    found.sort();
    found
}

/// KR-REQ-07.04: `kr new --attach` registers the creating terminal and its size before a shell
/// exists, and a create whose terminal cannot take part in that exchange goes no further. Run with
/// no terminal at all, the command fails with the terminal failure's own code and exit status
/// rather than the missing host's: it stopped before it asked for a session, so none was created
/// and no shell was started.
#[cfg(unix)]
#[test]
fn an_attach_create_with_no_terminal_to_register_asks_for_no_session() {
    use std::os::unix::process::CommandExt as _;

    let installation = Installation::create();
    let before = every_path_under(installation.tree.root());
    let mut command = Command::new(kr());
    command
        .args(["--json", "new", "--attach"])
        .stdin(std::process::Stdio::null())
        .env(
            kr_ipc::paths::RUNTIME_DIR_VARIABLE,
            installation.tree.paths().runtime_root(),
        )
        .env(
            kr_ipc::paths::STATE_DIR_VARIABLE,
            installation.tree.paths().state_root(),
        )
        .current_dir(support::command_binaries());
    // A session of its own and so no controlling terminal: the command can open none, neither
    // through its standard input nor through `/dev/tty`.
    #[expect(
        unsafe_code,
        reason = "starting a process in a session of its own has no safe form in the standard \
                  library"
    )]
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().expect("the command runs");

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("a JSON failure report");
    assert_eq!(report["ok"], serde_json::json!(false));
    assert_eq!(
        report["code"],
        serde_json::json!("TERMINAL_PROBE_FAILED"),
        "the terminal exchange failed, and the host was never asked: {report}"
    );
    assert_eq!(output.status.code(), Some(6));
    assert!(
        every_path_under(installation.tree.root()) == before,
        "nothing was created"
    );
}

/// KR-REQ-07.13: with no control daemon set up, `kr new` fails with `HOST_NOT_CONFIGURED` and the
/// action that sets one up. On the way it changes nothing in the home and host trees it is given,
/// where a service definition or a lingering setting would be written: no path is added or removed
/// and no file's content changes. It runs none of the service-manager, lingering or privilege
/// tools found through its `PATH` either; each of those is replaced there by one that records
/// being run.
#[test]
fn creating_with_no_host_says_what_to_set_up_and_installs_nothing() {
    let installation = Installation::create();
    let home = installation.tree.root().join("home");
    std::fs::create_dir_all(&home).expect("a home of this test's own");
    let calls = installation.tree.root().join("tool-calls");
    let tools = installation.tree.root().join("tools");
    std::fs::create_dir_all(&tools).expect("a directory for the recording tools");
    #[cfg(unix)]
    for tool in [
        "systemctl",
        "loginctl",
        "launchctl",
        "sudo",
        "doas",
        "pkexec",
        "runuser",
    ] {
        use std::os::unix::fs::PermissionsExt as _;

        let path = tools.join(tool);
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho \"{tool} $*\" >> '{}'\n", calls.display()),
        )
        .expect("writes a recording tool");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("makes it runnable");
    }
    let path = format!("{}:/usr/bin:/bin", tools.display());
    // The recording tools record: one run through the same `PATH` is found, and then forgotten.
    #[cfg(unix)]
    {
        Command::new("/bin/sh")
            .args(["-c", "loginctl enable-linger"])
            .env("PATH", &path)
            .status()
            .expect("runs a recording tool");
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap_or_default(),
            "loginctl enable-linger\n"
        );
        std::fs::remove_file(&calls).expect("forgets the check");
    }
    let before = every_path_under(installation.tree.root());

    let output = Command::new(kr())
        .args(["--json", "new", "--invisible"])
        .env_clear()
        .env("PATH", &path)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            kr_ipc::paths::RUNTIME_DIR_VARIABLE,
            installation.tree.paths().runtime_root(),
        )
        .env(
            kr_ipc::paths::STATE_DIR_VARIABLE,
            installation.tree.paths().state_root(),
        )
        .current_dir(support::command_binaries())
        .output()
        .expect("the command runs");

    assert_ne!(output.status.code(), Some(0), "nothing was created");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("a JSON failure report");
    assert_eq!(report["ok"], serde_json::json!(false));
    assert_eq!(report["code"], serde_json::json!("HOST_NOT_CONFIGURED"));
    let message = report["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("start the control daemon"),
        "the failure names the setup it needs: {message}"
    );
    assert!(
        !calls.exists(),
        "no service manager, lingering or privilege tool was run: {}",
        std::fs::read_to_string(&calls).unwrap_or_default()
    );
    assert!(
        every_path_under(installation.tree.root()) == before,
        "no service definition, no lingering setting and no runtime file was written, removed or \
         changed in the home and host trees this command was given"
    );
}
