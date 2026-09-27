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
            ..fixture::Shape::gemini_cli(&[])
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
    let claude = executable(&bin, &format!("claude{}", std::env::consts::EXE_SUFFIX));
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

/// KR-REQ-12.07: an integration that is off carries no flags in a session's entry: nothing is added
/// under it, and a launch specification is not made larger by what it cannot use.
#[test]
fn an_integration_turned_off_carries_no_flags() {
    let store = Store::new("off");
    let reading = Integrations::new().read(&[store.admitted(&fixture::Shape::qoder_cli(), |_| {})]);
    let entries = entries(&reading, &[]);
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].enabled);
    assert!(entries[0].flags.is_empty(), "{:?}", entries[0].flags);
}

/// Sixteen flags of the most bytes a flag may have.
fn largest_flags() -> Vec<String> {
    (0..kr_plugin_sdk::integration::MAX_FLAGS)
        .map(|index| {
            format!(
                "--{index}{}",
                "x".repeat(kr_plugin_sdk::integration::MAX_FLAG_BYTES - 4)
            )
        })
        .collect()
}

/// A launch specification whose create request carries `entries`.
fn specification(entries: Vec<CommandIntegration>) -> kr_protocol::worker::WorkerLaunchSpec {
    use kr_protocol::scalars::{U64, Uuid};
    let environment_id = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([2; 16]));
    kr_protocol::worker::WorkerLaunchSpec {
        session_id: kr_protocol::ids::SessionId::new(Uuid::from_bytes([1; 16])),
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id,
        display_number: kr_protocol::session::DisplayNumber::new(1),
        create: kr_protocol::session::SessionCreateParams {
            environment_id,
            presentation: kr_protocol::session::Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile {
                command_integrations: entries,
                ..kr_protocol::session::LaunchProfile::default()
            },
            terminal: Nullable::null(),
        },
        shell_package: Nullable::null(),
        controller_public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([3; 32]),
        controller_generation: kr_protocol::ids::ControllerGeneration::new(1),
        release: "0".to_owned(),
        plugins: kr_protocol::admission::AdmissionsHeader {
            frame: kr_protocol::admission::FrameId {
                generation: kr_protocol::ids::ControllerGeneration::new(1),
                revision: U64::new(1),
                round: U64::new(1),
            },
            parts: 1,
        },
    }
}

/// Whether a launch specification fits the one control frame it travels in.
fn fits(specification: &kr_protocol::worker::WorkerLaunchSpec) -> bool {
    kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control)
        .encode_message(&kr_protocol::envelope::ControlFrame::LaunchSpec(Box::new(
            specification.clone(),
        )))
        .is_ok()
}

/// KR-REQ-12.07: a session whose command integrations one control frame cannot carry is launched
/// without the largest of them, which are named, rather than not launched at all; one that fits
/// loses nothing.
#[test]
fn a_launch_specification_leaves_out_the_integrations_a_frame_cannot_carry() {
    let entry = |command: &str, flags: Vec<String>| CommandIntegration {
        plugin_id: plugin(command),
        command: command.to_owned(),
        flags,
        enabled: true,
    };
    let mut entries: Vec<CommandIntegration> = (0..20)
        .map(|index| entry(&format!("big{index}"), largest_flags()))
        .collect();
    entries.push(entry("small", vec!["--small".to_owned()]));
    let mut specification = specification(entries);
    assert!(
        !fits(&specification),
        "the test's entries are too large for a frame"
    );
    let omitted = fit_launch_specification(&mut specification);
    assert!(fits(&specification), "what is left fits");
    assert!(!omitted.is_empty());
    let left = &specification.create.launch_profile.command_integrations;
    assert!(
        left.iter().any(|entry| entry.command == "small"),
        "the largest go first"
    );
    assert_eq!(left.len() + omitted.len(), 21, "nothing else goes");

    let mut small = crate::catalogue::integrations::tests::specification(vec![entry(
        "small",
        vec!["--small".to_owned()],
    )]);
    assert!(fit_launch_specification(&mut small).is_empty());
    assert_eq!(small.create.launch_profile.command_integrations.len(), 1);
}

/// The names of the packages a budget test writes, which a shape names for good.
const BIG: [(&str, &str); 5] = [
    ("big-a", "biga"),
    ("big-b", "bigb"),
    ("big-c", "bigc"),
    ("big-d", "bigd"),
    ("big-e", "bige"),
];

/// KR-REQ-07.45: the doctor's reports carry flags up to their budget; a report past it carries none
/// and says why, so the doctor's answer fits the frame it travels in.
#[test]
fn the_doctor_reports_flags_within_their_budget() {
    let store = Store::new("budget");
    let flags = largest_flags();
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let packages: Vec<AdmittedPackage> = BIG
        .iter()
        .map(|(plugin_name, command)| {
            store.admitted(
                &fixture::Shape {
                    plugin_name,
                    display_name: "A large integration",
                    executable: command,
                    directory: &[],
                    integration: Some(fixture::declaration(command, &flags, &[])),
                    native_bridge: false,
                    component: false,
                },
                |_| {},
            )
        })
        .collect();
    let reading = Integrations::new().read(&packages);
    let reports = report(Some(&reading), &[], &[], &able(Vec::new()));
    assert_eq!(reports.len(), BIG.len());
    let carried: usize = reports
        .iter()
        .flat_map(|report| report.flags.iter().map(String::len))
        .sum();
    assert!(
        carried <= MAX_REPORTED_FLAG_BYTES,
        "{carried} bytes of flags in the reports"
    );
    let trimmed: Vec<&CommandIntegrationReport> = reports
        .iter()
        .filter(|report| report.flags.is_empty())
        .collect();
    assert!(!trimmed.is_empty(), "some report is past the budget");
    for report in trimmed {
        assert!(
            report
                .reason
                .0
                .as_deref()
                .is_some_and(|reason| reason.contains("flags")),
            "{:?}",
            report.reason
        );
    }
}

/// KR-REQ-07.45: where the admissions in force could not be read, each package the configuration
/// names is reported as unknown, never as not installed, and the check warns.
#[test]
fn a_failed_admissions_read_reports_the_configured_packages_as_unknown() {
    let reports = report(None, &[], &enabled(&["claude-code"]), &able(Vec::new()));
    let states: Vec<CommandIntegrationState> = reports.iter().map(|report| report.state).collect();
    assert_eq!(states, [CommandIntegrationState::Unknown]);
    assert_eq!(
        check(&reports, &enabled(&["claude-code"])).status,
        DoctorStatus::Warning
    );
}

/// KR-REQ-07.45: the search takes each directory in its order and, in each, the platform's
/// extensions in theirs, as a shell finds a command.
#[test]
fn the_search_takes_the_extensions_in_their_order() {
    let store = Store::new("extensions");
    let first = store.0.join("first");
    let second = store.0.join("second");
    let exe = executable(&second, "claude.exe");
    let _cmd = executable(&second, "claude.cmd");
    let extensions: Vec<String> = [".com", ".exe", ".bat", ".cmd"]
        .iter()
        .map(|extension| (*extension).to_owned())
        .collect();
    assert_eq!(
        resolve_with("claude", &[first, second.clone()], &extensions),
        Some(exe)
    );
    let reversed: Vec<String> = extensions.iter().rev().cloned().collect();
    assert_eq!(
        resolve_with("claude", std::slice::from_ref(&second), &reversed),
        Some(second.join("claude.cmd"))
    );
}

/// KR-REQ-07.45: a file this account cannot execute is passed over for the next candidate, and a
/// launcher it cannot execute is no launcher.
#[cfg(unix)]
#[test]
fn a_candidate_this_account_cannot_execute_is_passed_over() {
    use std::os::unix::fs::PermissionsExt as _;
    let store = Store::new("unrunnable");
    let first = store.0.join("first");
    let second = store.0.join("second");
    let locked = executable(&first, "claude");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o601)).expect("its mode");
    let runnable = executable(&second, "claude");
    assert_eq!(
        resolve_with("claude", &[first, second], &[String::new()]),
        Some(runnable)
    );
}
