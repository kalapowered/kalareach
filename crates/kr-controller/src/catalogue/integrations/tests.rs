//! The entries a session gets, from admitted packages read by a worker's rules.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::admission::AdmittedPackage;
use kr_protocol::ids::{PluginId, SessionId};
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
    let entries = fill(&reading, &enabled(&["claude-code", "qoder-cli"])).entries;
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
        fill(
            &reading,
            &enabled(&["gemini-cli", "silent", "qoder-cli", "another-qoder"])
        )
        .entries
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
        fill(&integrations.read(std::slice::from_ref(&package)), &[])
            .entries
            .len(),
        1
    );
    std::fs::remove_file(Path::new(&package.package_dir).join("presentation.json"))
        .expect("a file of the copy goes");
    assert_eq!(
        fill(&integrations.read(std::slice::from_ref(&package)), &[])
            .entries
            .len(),
        1,
        "the check this reader kept"
    );
    assert!(
        fill(&Integrations::new().read(&[package]), &[])
            .entries
            .is_empty(),
        "a reader that never checked it refuses the copy"
    );
}

/// A host whose worker can launch through an integration.
fn able(search_path: Vec<PathBuf>) -> Host {
    Host {
        search_path,
        backends: true,
        backends_failure: None,
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
    )
    .reports;
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
        let reported = report(Some(&reading), &[], &enabled(&["claude-code"]), &host);
        let reports = &reported.reports;
        assert_eq!(reports[0].state, CommandIntegrationState::On);
        assert_eq!(reports[0].unavailable.0, Some(why));
        assert_eq!(reports[0].mode, IntegrationMode::NativeTerminal);
        assert_eq!(
            check(&reported, &enabled(&["claude-code"])).status,
            DoctorStatus::Warning
        );
    }
}

/// KR-REQ-07.45: a platform that says why its command backends do not run has the reason in the
/// doctor's check, beside the count of integrations a new session cannot use. Control: the same
/// host with no reason says no reason.
#[test]
fn a_platform_that_says_why_its_backends_do_not_run_has_the_reason_in_the_check() {
    let store = Store::new("reason");
    let reading =
        Integrations::new().read(&[store.admitted(&fixture::Shape::claude_code(), |_| {})]);
    let because =
        "the kernel's record of when a process started cannot be believed on this machine";
    let host = Host {
        backends: false,
        backends_failure: Some(because),
        ..able(Vec::new())
    };
    let reported = report(Some(&reading), &[], &enabled(&["claude-code"]), &host);
    let shown = check(&reported, &enabled(&["claude-code"]));
    assert!(
        shown.detail().contains(because),
        "the reason is in the check: {}",
        shown.detail()
    );
    // Nowhere else: where the backends run, or where no integration is on, the reason is not
    // stated whatever the host carries.
    for (elsewhere, enabled_names) in [
        (
            Host {
                backends: true,
                ..host.clone()
            },
            enabled(&["claude-code"]),
        ),
        (host.clone(), enabled(&[])),
    ] {
        let reported = report(Some(&reading), &[], &enabled_names, &elsewhere);
        let shown = check(&reported, &enabled_names);
        assert!(
            !shown.detail().contains(because),
            "no reason where it does not apply: {}",
            shown.detail()
        );
    }
    let silent = Host {
        backends_failure: None,
        ..host
    };
    let reported = report(Some(&reading), &[], &enabled(&["claude-code"]), &silent);
    let shown = check(&reported, &enabled(&["claude-code"]));
    assert!(!shown.detail().contains("do not run here"));
}

/// KR-REQ-07.45: where this platform's command backends run, which the daemon asks the worker for,
/// an integration that is on and has a launcher beside the worker is reported as one a session
/// created now can launch through, and is not reported as unavailable for the platform.
#[test]
fn a_platform_whose_command_backends_run_reports_an_integration_with_a_launcher_available() {
    let store = Store::new("runs");
    let reading =
        Integrations::new().read(&[store.admitted(&fixture::Shape::claude_code(), |_| {})]);
    let host = Host {
        search_path: Vec::new(),
        backends: kr_worker::broker::process::ManagedProcess::runs_command_backends(),
        backends_failure: kr_worker::broker::process::ManagedProcess::command_backends_failure(),
        launcher: true,
    };
    let reported = report(Some(&reading), &[], &enabled(&["claude-code"]), &host);
    assert_eq!(reported.reports[0].state, CommandIntegrationState::On);
    assert_eq!(
        reported.reports[0].unavailable.0, None,
        "a platform whose backends run is not the reason this integration is unavailable"
    );
    // Control: a platform whose backends do not run is.
    let without = Host {
        backends: false,
        ..host
    };
    let reported = report(Some(&reading), &[], &enabled(&["claude-code"]), &without);
    assert_eq!(
        reported.reports[0].unavailable.0,
        Some(CommandIntegrationUnavailable::Platform)
    );
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
    let reports = report(Some(&reading), &[], &[], &able(Vec::new())).reports;
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
    assert_eq!(
        check(&Reported::default(), &[]).status,
        DoctorStatus::NotApplicable
    );
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
    let entries = fill(&reading, &[]).entries;
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
        privacy: kr_protocol::worker::PrivacyLaunch {
            generation: U64::ZERO,
            enabled: false,
        },
        environment_origin: kr_protocol::worker::EnvironmentOrigin::CreatorSnapshot,
        environment_additions: Vec::new(),
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
/// without the largest of them, which are returned, rather than not launched at all; the last one
/// left out was needed to fit, and a specification that fits loses nothing.
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
    let left = &specification.create.launch_profile.command_integrations;
    assert!(
        left.iter().any(|entry| entry.command == "small"),
        "the largest go first"
    );
    assert_eq!(left.len() + omitted.len(), 21, "nothing else goes");
    let mut again = specification.clone();
    again
        .create
        .launch_profile
        .command_integrations
        .push(omitted.last().expect("one is left out").clone());
    assert!(!fits(&again), "the last one left out did not fit");

    let mut small = crate::catalogue::integrations::tests::specification(vec![entry(
        "small",
        vec!["--small".to_owned()],
    )]);
    assert!(fit_launch_specification(&mut small).is_empty());
    assert_eq!(small.create.launch_profile.command_integrations.len(), 1);
}

/// `text` for the life of the test process, as a package shape names it.
fn lasting(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

/// `count` packages named `<prefix>-<index>`, each integrating its own command with `flags`.
fn many(store: &Store, prefix: &str, count: usize, flags: &[String]) -> Vec<AdmittedPackage> {
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    (0..count)
        .map(|index| {
            let command = lasting(format!("{prefix}{index:03}"));
            store.admitted(
                &fixture::Shape {
                    plugin_name: lasting(format!("{prefix}-{index:03}")),
                    display_name: "A test integration",
                    executable: command,
                    directory: &[],
                    integration: Some(fixture::declaration(command, &flags, &[])),
                    native_bridge: false,
                    component: false,
                },
                |_| {},
            )
        })
        .collect()
}

/// The packages [`many`] writes, as the configuration names them.
fn many_named(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("kalareach/{prefix}-{index:03}"))
        .collect()
}

/// The bytes of flags a session's entries carry together.
fn flag_bytes(entries: &[CommandIntegration]) -> usize {
    entries
        .iter()
        .flat_map(|entry| entry.flags.iter().map(String::len))
        .sum()
}

/// KR-REQ-12.07: a session's entries carry the flags of the integrations the configuration turns on
/// up to one session's bound; past it the largest are left out and named, and the rest are carried
/// whole.
#[test]
fn a_session_carries_the_flags_of_its_integrations_within_a_bound() {
    let store = Store::new("session-flags");
    let reading = Integrations::new().read(&many(&store, "big", 21, &largest_flags()));
    let fill = fill(&reading, &many_named("big", 21));
    assert!(
        flag_bytes(&fill.entries) <= kr_protocol::session::MAX_COMMAND_INTEGRATION_FLAG_BYTES,
        "{} bytes of flags",
        flag_bytes(&fill.entries)
    );
    assert_eq!(
        fill.omitted.len(),
        17,
        "four integrations with the most flags a package may declare fit"
    );
    assert_eq!(fill.entries.len() + fill.omitted.len(), 21);
    for entry in &fill.entries {
        assert!(entry.enabled);
        assert_eq!(entry.flags.len(), 16, "an entry is carried whole");
        assert!(!fill.omitted.contains(&entry.plugin_id));
    }
}

/// KR-REQ-12.07: a session carries at most its number of entries: every integration the
/// configuration turns on, then as many that are off as there is room for.
#[test]
fn a_session_carries_at_most_its_number_of_entries() {
    let store = Store::new("session-entries");
    let count = kr_protocol::session::MAX_COMMAND_INTEGRATION_ENTRIES + 2;
    let reading = Integrations::new().read(&many(&store, "small", count, &["--small".to_owned()]));
    let enabled = many_named("small", count).split_off(count - 3);
    let fill = fill(&reading, &enabled);
    assert_eq!(
        fill.entries.len(),
        kr_protocol::session::MAX_COMMAND_INTEGRATION_ENTRIES
    );
    assert!(fill.omitted.is_empty(), "an entry that is off adds nothing");
    for named in &enabled {
        assert!(
            fill.entries
                .iter()
                .any(|entry| entry.enabled && entry.plugin_id.as_str() == named),
            "{named} is carried"
        );
    }
    assert!(
        fill.entries
            .windows(2)
            .all(|pair| pair[0].command < pair[1].command),
        "in command order"
    );
}

/// KR-REQ-12.07: one note names every integration a launch left out, however many there are.
#[test]
fn one_note_names_every_integration_a_launch_leaves_out() {
    let session_id = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]));
    assert!(omission_note(session_id, &[]).is_none());
    let omitted: Vec<PluginId> = (0..17)
        .map(|index| plugin(&format!("big-{index:03}")))
        .collect();
    let note = omission_note(session_id, &omitted).expect("a note");
    assert!(note.contains(&session_id.to_string()), "{note}");
    for plugin_id in &omitted {
        assert!(note.contains(plugin_id.as_str()), "{plugin_id} in {note}");
    }
}

/// KR-REQ-07.45: the doctor reports an integration a session created now would be launched without
/// as one it cannot launch through, and the check warns.
#[test]
fn the_doctor_marks_an_integration_a_session_is_launched_without() {
    let store = Store::new("too-large");
    let reading = Integrations::new().read(&many(&store, "big", 5, &largest_flags()));
    let enabled = many_named("big", 5);
    let left_out = fill(&reading, &enabled).omitted;
    assert_eq!(left_out.len(), 1);
    let reported = report(Some(&reading), &[], &enabled, &able(Vec::new()));
    assert_eq!(reported.reports.len(), 5);
    for report in &reported.reports {
        assert_eq!(report.state, CommandIntegrationState::On);
        assert_eq!(
            report.unavailable.0 == Some(CommandIntegrationUnavailable::TooLarge),
            left_out
                .iter()
                .any(|plugin_id| plugin_id.as_str() == report.plugin_id),
            "{}",
            report.plugin_id
        );
    }
    assert_eq!(check(&reported, &enabled).status, DoctorStatus::Warning);
}

/// The bytes `value` takes encoded as it travels.
fn encoded(value: &impl serde::Serialize) -> usize {
    kr_cbor::encoded_len(&kr_cbor::to_canonical_value(value).expect("a value"))
}

/// KR-REQ-07.45: the doctor's reports are carried whole within the bytes one answer gives them, in
/// either of its forms; the rest are left out and counted, and the check says so.
#[test]
fn the_doctor_carries_whole_reports_within_its_bytes() {
    let store = Store::new("report-bytes");
    let reading = Integrations::new().read(&many(&store, "big", 8, &largest_flags()));
    let reported = report(Some(&reading), &[], &[], &able(Vec::new()));
    assert_eq!(
        reported.reports.len(),
        5,
        "five of the largest declarations fit, and a sixth would not"
    );
    assert_eq!(reported.omitted, 3);
    let carried: usize = reported
        .reports
        .iter()
        .map(|report| encoded(report).max(encoded(&report.withheld_form())))
        .sum();
    assert!(carried <= MAX_REPORT_BYTES, "{carried} bytes");
    for report in &reported.reports {
        assert_eq!(report.flags.len(), 16, "a report is carried whole");
    }
    let check = check(&reported, &[]);
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(
        check.detail().contains(&reported.omitted.to_string()),
        "{}",
        check.detail()
    );
}

/// KR-REQ-07.45: the doctor carries at most its number of reports, the packages the configuration
/// names first, in package order, and counts the rest.
#[test]
fn the_doctor_carries_at_most_its_number_of_reports_configured_first() {
    let store = Store::new("report-count");
    let count = MAX_REPORTS + 4;
    let reading = Integrations::new().read(&many(&store, "small", count, &["--small".to_owned()]));
    let enabled = many_named("small", count).split_off(count - 3);
    let reported = report(Some(&reading), &[], &enabled, &able(Vec::new()));
    assert_eq!(reported.reports.len(), MAX_REPORTS);
    assert_eq!(reported.omitted, 4);
    for named in &enabled {
        assert!(
            reported
                .reports
                .iter()
                .any(|report| &report.plugin_id == named),
            "{named} is carried"
        );
    }
    assert!(
        reported
            .reports
            .windows(2)
            .all(|pair| pair[0].plugin_id < pair[1].plugin_id),
        "in package order"
    );
}

/// KR-REQ-07.45: the doctor's answer fits the one response frame it travels in, in the owner's form
/// and in the withheld one, with its reports filling their budget and its catalogue check carrying
/// the sixteen notes it keeps, each naming as many packages as long as a configuration can turn on,
/// and room left over for the rest of its checks.
#[test]
fn the_doctor_answer_fits_one_response_frame() {
    use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
    use kr_protocol::hostinfo::export::ForExport as _;

    let store = Store::new("answer");
    let mut packages = many(&store, "big", 8, &largest_flags());
    packages.extend(many(&store, "small", MAX_REPORTS, &["--small".to_owned()]));
    let reading = Integrations::new().read(&packages);
    let enabled = many_named("big", 8);
    let reported = report(Some(&reading), &[], &enabled, &able(Vec::new()));
    let carried: usize = reported
        .reports
        .iter()
        .map(|report| encoded(report).max(encoded(&report.withheld_form())))
        .sum();
    assert!(
        carried >= MAX_REPORT_BYTES * 3 / 4,
        "{carried} bytes of reports fill most of their budget"
    );
    let longest: Vec<PluginId> = (0
        ..kr_protocol::hostinfo::configuration::MAX_COMMAND_INTEGRATIONS)
        .map(|index| {
            PluginId::new(format!("{}/{index:0>64}", "p".repeat(64))).expect("an identifier")
        })
        .collect();
    let notes: Vec<String> = (0..16u8)
        .map(|index| {
            omission_note(
                SessionId::new(kr_protocol::scalars::Uuid::from_bytes([index; 16])),
                &longest,
            )
            .expect("a note")
        })
        .collect();
    let catalogue = crate::config::catalogue::check(
        Some(&crate::catalogue::evidence::Evidence {
            repositories: Vec::new(),
            warnings: notes,
        }),
        kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
    );
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    environment.create().expect("the environment's directories");
    let effective = crate::config::effective(
        &crate::config::Accepted::in_force(
            crate::config::open(&environment),
            crate::config::HardLimits::default(),
        ),
        crate::config::HardLimits::default(),
        kr_protocol::identity::WorkerProfile::HeadlessUser,
    );
    let checks = vec![catalogue, check(&reported, &enabled)];
    let result = kr_protocol::hostinfo::HostDoctorResult::new(checks, effective)
        .with_command_integrations(reported.reports);
    let answer = |value: ParamsValue| {
        ControlFrame::Response(Response {
            request_id: kr_protocol::ids::RequestId::new(u64::MAX),
            outcome: Outcome::Ok(value),
        })
    };
    let codec = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control);
    // The daemon's other checks are sentences of a line or two each: a quarter of the frame is
    // many times what they take.
    let room = kr_protocol::limits::MAX_CONTROL_FRAME_LEN / 4;
    for (form, value) in [
        (
            "the owner's",
            ParamsValue::from_typed(&result).expect("the owner's form"),
        ),
        (
            "the withheld",
            ParamsValue::from_typed(result.for_export().get()).expect("the withheld form"),
        ),
    ] {
        let framed = codec
            .encode_message(&answer(value))
            .unwrap_or_else(|error| panic!("{form} answer fits: {error:?}"));
        assert!(
            framed.len() + room <= kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
            "{form} answer takes {} bytes",
            framed.len()
        );
    }
}

/// KR-REQ-07.45: where the admissions in force could not be read, each package the configuration
/// names is reported as unknown, never as not installed, and the check warns.
#[test]
fn a_failed_admissions_read_reports_the_configured_packages_as_unknown() {
    let reported = report(None, &[], &enabled(&["claude-code"]), &able(Vec::new()));
    let states: Vec<CommandIntegrationState> =
        reported.reports.iter().map(|report| report.state).collect();
    assert_eq!(states, [CommandIntegrationState::Unknown]);
    assert_eq!(
        check(&reported, &enabled(&["claude-code"])).status,
        DoctorStatus::Warning
    );
    assert_eq!(unread_check().status, DoctorStatus::Warning);
}

/// KR-REQ-07.45: admissions read and empty say a configured package is not installed, which
/// admissions not read cannot say.
#[test]
fn an_empty_reading_is_not_an_unread_one() {
    let reading = Integrations::new().read(&[]);
    let read = report(
        Some(&reading),
        &[],
        &enabled(&["claude-code"]),
        &able(Vec::new()),
    );
    assert_eq!(read.reports[0].state, CommandIntegrationState::NotInstalled);
    let unread = report(None, &[], &enabled(&["claude-code"]), &able(Vec::new()));
    assert_eq!(unread.reports[0].state, CommandIntegrationState::Unknown);
    assert_eq!(
        check(&report(Some(&reading), &[], &[], &able(Vec::new())), &[]).status,
        DoctorStatus::NotApplicable,
        "nothing admitted and nothing named"
    );
}

/// KR-REQ-07.45: the search takes each directory in its order and, in each, the platform's
/// extensions in theirs, as a shell finds a command: a match in an earlier directory wins over an
/// earlier extension in a later one.
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
        resolve_with("claude", &[first.clone(), second.clone()], &extensions),
        Some(exe)
    );
    let reversed: Vec<String> = extensions.iter().rev().cloned().collect();
    assert_eq!(
        resolve_with("claude", std::slice::from_ref(&second), &reversed),
        Some(second.join("claude.cmd"))
    );
    let bat = executable(&first, "claude.bat");
    assert_eq!(
        resolve_with("claude", &[first, second], &extensions),
        Some(bat),
        "the earlier directory wins"
    );
}

/// KR-REQ-07.45: a file this account cannot execute is passed over for the next candidate. The
/// launcher is held to the same rule, `kr_worker::broker::commands::runnable`, which the worker's
/// own tests cover.
#[cfg(unix)]
#[test]
fn a_candidate_this_account_cannot_execute_is_passed_over() {
    use std::os::unix::fs::PermissionsExt as _;
    let store = Store::new("unrunnable");
    let first = store.0.join("first");
    let second = store.0.join("second");
    let locked = executable(&first, "claude");
    // The superuser may execute a file any execute bit allows, so only a file with none is closed
    // to it; an ordinary account is given one only another account may execute.
    let closed = if rustix::process::geteuid().is_root() {
        0o600
    } else {
        0o601
    };
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(closed)).expect("its mode");
    let runnable = executable(&second, "claude");
    assert_eq!(
        resolve_with("claude", &[first, second], &[String::new()]),
        Some(runnable)
    );
}
