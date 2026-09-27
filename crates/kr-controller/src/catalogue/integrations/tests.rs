//! The entries a session gets, from admitted packages read by a worker's rules.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::admission::AdmittedPackage;
use kr_protocol::ids::PluginId;
use kr_worker::broker::catalogue::testing::admitted;
use kr_worker::broker::connectors::fixture;

use super::*;

/// A directory of the test's own, removed when it is dropped.
struct Store(PathBuf);

impl Store {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("kr-integrations-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a store directory");
        Self(root)
    }

    /// One package of `shape`, as an admission hands it over, with what `installed` makes of its
    /// installation.
    fn admitted(
        &self,
        shape: &fixture::Shape,
        installed: impl FnOnce(&mut kr_worker::broker::connectors::ConnectorSource),
    ) -> AdmittedPackage {
        let mut source = fixture::package(&self.0, &self.0.join("kr-hook"), shape)
            .expect("the package is written");
        installed(&mut source);
        admitted(&source)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn plugin(name: &str) -> PluginId {
    PluginId::new(format!("kalareach/{name}")).expect("a plugin identifier")
}

fn enabled(names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|name| format!("kalareach/{name}"))
        .collect()
}

/// KR-REQ-12.07: one entry for each connector whose integration applies, with the command and the
/// flags its verified manifest declares, on where the configuration names its package and off
/// where it does not.
#[test]
fn each_integration_that_applies_gives_an_entry_on_or_off_by_the_configuration() {
    let store = Store::new("entries");
    let packages = vec![
        store.admitted(&fixture::Shape::claude_code(), |_| {}),
        store.admitted(&fixture::Shape::gemini_cli(&[]), |_| {}),
        store.admitted(&fixture::Shape::qoder_cli(), |_| {}),
    ];
    let reading = Integrations::new().read(&packages);
    let entries = entries(&reading, &enabled(&["claude-code", "qoder-cli"]));
    let summary: Vec<(PluginId, &str, usize, bool)> = entries
        .iter()
        .map(|entry| {
            (
                entry.plugin_id.clone(),
                entry.command.as_str(),
                entry.flags.len(),
                entry.enabled,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (plugin("claude-code"), "claude", 2, true),
            (plugin("gemini-cli"), "gemini", 0, false),
            (plugin("qoder-cli"), "qodercli", 2, true),
        ]
    );
    assert_eq!(
        entries[0].flags,
        fixture::FLAGS.map(str::to_owned),
        "the flags are the verified manifest's"
    );
    assert_eq!(entries[2].flags, fixture::qoder_flags());
}

/// KR-REQ-12.07: an integration whose grant the installation does not hold gives no entry, whatever
/// the configuration names; nor does a package that declares none, nor two packages that integrate
/// one command.
#[test]
fn an_integration_that_does_not_apply_gives_no_entry() {
    let store = Store::new("none");
    let ungranted = store.admitted(&fixture::Shape::gemini_cli(&[]), |source| {
        source
            .granted
            .remove(&PluginCapability::CommandIntegrationLaunch);
    });
    let undeclared = store.admitted(
        &fixture::Shape {
            plugin_name: "silent",
            integration: None,
            ..fixture::Shape::claude_code()
        },
        |_| {},
    );
    let qoder = store.admitted(&fixture::Shape::qoder_cli(), |_| {});
    let another = store.admitted(
        &fixture::Shape {
            plugin_name: "another-qoder",
            ..fixture::Shape::qoder_cli()
        },
        |_| {},
    );
    let reading = Integrations::new().read(&[ungranted, undeclared, qoder, another]);
    assert!(
        reading
            .packages
            .iter()
            .filter(|(_, read)| read.is_ok())
            .count()
            == 2,
        "the two that integrate no command are read: {:?}",
        reading
            .packages
            .iter()
            .map(|(package, read)| (package.plugin_id.clone(), read.as_ref().err().cloned()))
            .collect::<Vec<_>>()
    );
    assert!(
        entries(
            &reading,
            &enabled(&["gemini-cli", "silent", "qoder-cli", "another-qoder"])
        )
        .is_empty()
    );
}

/// A package is checked once by its hash: a reading after its copy lost a file still reads it, as
/// the verified files a hash names never change.
#[test]
fn a_package_is_checked_once_by_its_hash() {
    let store = Store::new("once");
    let package = store.admitted(&fixture::Shape::gemini_cli(&[]), |_| {});
    let integrations = Integrations::new();
    assert_eq!(
        entries(&integrations.read(std::slice::from_ref(&package)), &[]).len(),
        1
    );
    std::fs::remove_file(Path::new(&package.package_dir).join("presentation.json"))
        .expect("a file of the copy goes");
    assert_eq!(
        entries(&integrations.read(std::slice::from_ref(&package)), &[]).len(),
        1,
        "the check this reader kept"
    );
    assert!(
        entries(&Integrations::new().read(&[package]), &[]).is_empty(),
        "a reader that never checked it refuses the copy"
    );
}

/// A host whose worker can launch through an integration.
fn able(search_path: Vec<PathBuf>) -> Host {
    Host {
        search_path,
        backends: true,
        launcher: true,
    }
}

/// Writes an executable that is not a script, `name` in `directory`, and returns its path.
fn executable(directory: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(directory).expect("a directory");
    let path = directory.join(name);
    std::fs::write(&path, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).expect("an executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("runnable");
    }
    path
}

/// KR-REQ-07.45: the doctor reports what a session created now gets of each integration and why:
/// on and off by the configuration, not granted, not installed and left out of the admissions;
/// the mode an invocation runs in; and the executable the search path names first, with the
/// version the signed record gives its digest.
#[test]
fn the_doctor_reports_each_integration_and_its_resolution() {
    let store = Store::new("report");
    let bin = store.0.join("bin");
    let claude = executable(&bin, "claude");
    let digest = crate::catalogue::native_bridge::read_executable(&claude).expect("a digest");
    let packages = vec![
        store.admitted(&fixture::Shape::claude_code(), |source| {
            source.qualified = vec![kr_worker::broker::connectors::QualifiedExecutable {
                digest,
                version: "2.1.278".to_owned(),
            }];
        }),
        store.admitted(&fixture::Shape::gemini_cli(&[]), |_| {}),
        store.admitted(&fixture::Shape::qoder_cli(), |source| {
            source
                .granted
                .remove(&PluginCapability::CommandIntegrationLaunch);
        }),
    ];
    let reading = Integrations::new().read(&packages);
    let left = LeftOut {
        plugin_id: plugin("left"),
        reason: kr_protocol::catalogue::PluginLeftOutReason::Disabled,
        detail: "kalareach/left at 00 is installed and disabled".to_owned(),
    };
    let reports = report(
        Some(&reading),
        std::slice::from_ref(&left),
        &enabled(&["claude-code", "qoder-cli", "left", "missing"]),
        &able(vec![store.0.join("empty"), bin]),
    );
    let states: Vec<(String, CommandIntegrationState, IntegrationMode)> = reports
        .iter()
        .map(|report| (report.plugin_id.clone(), report.state, report.mode))
        .collect();
    assert_eq!(
        states,
        [
            (
                "kalareach/claude-code".to_owned(),
                CommandIntegrationState::On,
                IntegrationMode::NativeBridge
            ),
            (
                "kalareach/gemini-cli".to_owned(),
                CommandIntegrationState::Off,
                IntegrationMode::NativeTerminal
            ),
            (
                "kalareach/left".to_owned(),
                CommandIntegrationState::NotAdmitted,
                IntegrationMode::NativeTerminal
            ),
            (
                "kalareach/missing".to_owned(),
                CommandIntegrationState::NotInstalled,
                IntegrationMode::NativeTerminal
            ),
            (
                "kalareach/qoder-cli".to_owned(),
                CommandIntegrationState::NotGranted,
                IntegrationMode::NativeTerminal
            ),
        ]
    );
    let on = &reports[0];
    assert_eq!(on.command.0.as_deref(), Some("claude"));
    assert_eq!(on.flags, fixture::FLAGS.map(str::to_owned));
    assert_eq!(on.version.0.as_deref(), Some("0.3.0"));
    assert_eq!(on.executable.0, Some(claude.display().to_string()));
    assert_eq!(on.executable_version.0.as_deref(), Some("2.1.278"));
    assert!(on.unavailable.0.is_none());
    let gemini = &reports[1];
    assert_eq!(gemini.variables.len(), 1, "{:?}", gemini.variables);
    assert!(
        gemini.executable.0.is_none(),
        "gemini is on none of the directories"
    );
    assert_eq!(reports[2].reason.0.as_deref(), Some(left.detail.as_str()));
    assert_eq!(
        reports[4].flags,
        fixture::qoder_flags(),
        "a release not granted says what it declares"
    );
}

/// KR-REQ-07.45: an integration the configuration turns on is reported as one a session created
/// now cannot launch through where the platform establishes no backend or no launcher is
/// installed, and its command then runs as typed.
#[test]
fn an_integration_on_where_no_backend_can_be_established_is_unavailable() {
    let store = Store::new("unavailable");
    let reading =
        Integrations::new().read(&[store.admitted(&fixture::Shape::claude_code(), |_| {})]);
    for (host, why) in [
        (
            Host {
                backends: false,
                ..able(Vec::new())
            },
            CommandIntegrationUnavailable::Platform,
        ),
        (
            Host {
                launcher: false,
                ..able(Vec::new())
            },
            CommandIntegrationUnavailable::NoLauncher,
        ),
    ] {
        let reports = report(Some(&reading), &[], &enabled(&["claude-code"]), &host);
        assert_eq!(reports[0].state, CommandIntegrationState::On);
        assert_eq!(reports[0].unavailable.0, Some(why));
        assert_eq!(reports[0].mode, IntegrationMode::NativeTerminal);
        assert_eq!(
            check(&reports, &enabled(&["claude-code"])).status,
            DoctorStatus::Warning
        );
    }
}

/// KR-REQ-07.45: two packages that integrate one command are each reported as a conflict, with
/// the command and why.
#[test]
fn two_packages_integrating_one_command_are_reported_as_a_conflict() {
    let store = Store::new("conflict");
    let reading = Integrations::new().read(&[
        store.admitted(&fixture::Shape::qoder_cli(), |_| {}),
        store.admitted(
            &fixture::Shape {
                plugin_name: "another-qoder",
                ..fixture::Shape::qoder_cli()
            },
            |_| {},
        ),
    ]);
    let reports = report(Some(&reading), &[], &[], &able(Vec::new()));
    assert_eq!(reports.len(), 2);
    for reported in &reports {
        assert_eq!(reported.state, CommandIntegrationState::Conflict);
        assert_eq!(reported.command.0.as_deref(), Some("qodercli"));
        assert!(reported.reason.0.is_some());
    }
}

/// KR-REQ-07.45: the check is not applicable with no integration anywhere, passes while every
/// integration the configuration turns on can be used, and warns when one cannot.
#[test]
fn the_check_warns_only_for_an_integration_turned_on_that_cannot_be_used() {
    assert_eq!(check(&[], &[]).status, DoctorStatus::NotApplicable);
    let store = Store::new("check");
    let reading =
        Integrations::new().read(&[store.admitted(&fixture::Shape::gemini_cli(&[]), |_| {})]);
    let off = report(Some(&reading), &[], &[], &able(Vec::new()));
    assert_eq!(check(&off, &[]).status, DoctorStatus::Ok);
    let on = report(
        Some(&reading),
        &[],
        &enabled(&["gemini-cli"]),
        &able(Vec::new()),
    );
    assert_eq!(
        check(&on, &enabled(&["gemini-cli"])).status,
        DoctorStatus::Ok
    );
    let missing = report(
        Some(&reading),
        &[],
        &enabled(&["claude-code"]),
        &able(Vec::new()),
    );
    assert_eq!(
        check(&missing, &enabled(&["claude-code"])).status,
        DoctorStatus::Warning
    );
}
