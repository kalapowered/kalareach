//! What the command prints, what it writes and what it refuses to write.

use kr_protocol::hostinfo::configuration::{
    ConfigurationDocument, DocumentState, ValueEffect, ValueSource,
};
use kr_protocol::hostinfo::{
    ComposedBundle, DoctorCheck, DoctorStatus, EffectiveConfiguration, EffectiveValue,
    HostDoctorResult,
};
use kr_protocol::scalars::{Nullable, TimestampMs};

use kr_protocol::hostinfo::export::{ContentClass, Declared, Sentence};

use super::content::Approved;
use super::*;

fn checks() -> Vec<DoctorCheck> {
    vec![
        DoctorCheck::new(
            "runtime-directory",
            "The runtime directory is owner-only",
            DoctorStatus::Ok,
            Sentence::new()
                .stated("created with owner-only permissions and verified on every open: ")
                .withheld(ContentClass::Path, "/tmp/kalareach/ab12cd34"),
            None,
        ),
        DoctorCheck::new(
            "workers",
            "Every published descriptor answered its challenge",
            DoctorStatus::Warning,
            Sentence::new()
                .number(1)
                .stated(" verified, ")
                .number(1)
                .stated(" quarantined"),
            Some("A quarantined descriptor is never used."),
        ),
        DoctorCheck::new(
            "catalogue",
            "Catalogue metadata and its capability evidence",
            DoctorStatus::NotApplicable,
            Sentence::new().stated("no catalogue is synchronised on this host"),
            None,
        ),
    ]
}

fn configured() -> EffectiveConfiguration {
    let mut effective = EffectiveConfiguration::unread();
    effective.document = "/tmp/kalareach/config.json".to_owned();
    effective.values = vec![EffectiveValue::new(
        "sleep_inhibition",
        "whether this host keeps itself awake for work it has admitted",
        &Declared::term("mains_only"),
        ValueSource::HostConfiguration,
        Nullable::some("/tmp/kalareach/config.json".to_owned()),
        Nullable::null(),
        ValueEffect::Immediately,
    )];
    effective.locations = vec![kr_protocol::hostinfo::ReportedLocation {
        what: "document".to_owned(),
        documented: kr_protocol::hostinfo::export::Stated::new(
            "beside this environment's own state",
        ),
    }];
    // What a command is actually handed: the host answers the owner's own control path with the
    // paths it resolved, and the export allowlist stands between those and a support bundle.
    effective
}

pub(in crate::doctor) fn result() -> HostDoctorResult {
    HostDoctorResult::new(checks(), configured())
}

/// The lines as a person reads them.
fn text(lines: &[Line]) -> String {
    lines.iter().map(Line::text).collect::<Vec<_>>().join("\n")
}

/// KR-REQ-01.23: the default output shows evidence for what did not pass, and nothing else.
#[test]
fn the_default_output_shows_evidence_only_where_a_check_did_not_pass() {
    let text = text(&doctor_lines(&result(), false));
    assert!(
        text.contains("The runtime directory is owner-only"),
        "{text}"
    );
    assert!(
        !text.contains("/tmp/kalareach/ab12cd34"),
        "a passing check's evidence is not printed by default: {text}"
    );
    assert!(
        text.contains("1 verified, 1 quarantined"),
        "a warning's evidence is: {text}"
    );
    assert!(
        text.contains("A quarantined descriptor is never used."),
        "and its remedy with it: {text}"
    );
    assert!(
        text.contains("no catalogue is synchronised on this host"),
        "and so is the reason a check does not apply: {text}"
    );
}

/// KR-REQ-01.23: `--verbose` shows every check's evidence, including the ones that passed.
#[test]
fn verbose_shows_every_checks_evidence() {
    let text = text(&doctor_lines(&result(), true));
    for evidence in [
        "[path withheld, 23 bytes]",
        "1 verified, 1 quarantined",
        "no catalogue is synchronised on this host",
    ] {
        assert!(text.contains(evidence), "{evidence} is missing: {text}");
    }
}

/// Two command integrations as the host reports them: Claude Code's on and resolved on the
/// daemon's search path, and Gemini CLI's on and unable to launch here.
fn integrated() -> HostDoctorResult {
    use kr_protocol::hostinfo::{
        CommandIntegrationReport, CommandIntegrationState, CommandIntegrationUnavailable,
    };
    result().with_command_integrations(vec![
        CommandIntegrationReport {
            plugin_id: "kalareach/claude-code".to_owned(),
            version: Nullable::some("0.4.0".to_owned()),
            command: Nullable::some("claude".to_owned()),
            flags: vec![
                "--dangerously-load-development-channels".to_owned(),
                "plugin:kalareach-channels@skills-dir".to_owned(),
            ],
            variables: Vec::new(),
            state: CommandIntegrationState::On,
            unavailable: Nullable::null(),
            mode: kr_protocol::broker::IntegrationMode::NativeBridge,
            executable: Nullable::some("/Users/someone/.local/bin/claude".to_owned()),
            executable_version: Nullable::some("2.1.278".to_owned()),
            reason: Nullable::null(),
        },
        CommandIntegrationReport {
            plugin_id: "kalareach/gemini-cli".to_owned(),
            version: Nullable::some("0.4.0".to_owned()),
            command: Nullable::some("gemini".to_owned()),
            flags: Vec::new(),
            variables: vec![kr_protocol::session::EnvironmentVariable {
                name: "GEMINI_CLI_NO_RELAUNCH".to_owned(),
                value: "true".to_owned(),
            }],
            state: CommandIntegrationState::On,
            unavailable: Nullable::some(CommandIntegrationUnavailable::NoLauncher),
            mode: kr_protocol::broker::IntegrationMode::NativeTerminal,
            executable: Nullable::null(),
            executable_version: Nullable::null(),
            reason: Nullable::null(),
        },
    ])
}

/// KR-REQ-07.45: the doctor shows each command integration: the resolved executable, the flags as
/// the elements they are, the variables, the version and the mode, and why a new session cannot
/// launch through one where it cannot; the document form carries them all.
#[test]
fn the_doctor_shows_each_command_integration() {
    let text = text(&doctor_lines(&integrated(), false));
    for shown in [
        "claude (kalareach/claude-code 0.4.0): on, native_bridge",
        r#""--dangerously-load-development-channels" "plugin:kalareach-channels@skills-dir""#,
        "/Users/someone/.local/bin/claude",
        "2.1.278",
        "gemini (kalareach/gemini-cli 0.4.0): on, native_terminal",
        r#"GEMINI_CLI_NO_RELAUNCH="true""#,
        "no_launcher",
    ] {
        assert!(text.contains(shown), "{shown} is missing: {text}");
    }
    let document = doctor(&integrated()).json();
    let reported = document["command_integrations"]
        .as_array()
        .expect("the integrations are in the document");
    assert_eq!(reported.len(), 2);
    assert_eq!(
        reported[0]["flags"][1],
        "plugin:kalareach-channels@skills-dir"
    );
    assert_eq!(reported[1]["unavailable"], "no_launcher");
}

/// KR-REQ-01.23: the summary counts every verdict.
#[test]
fn the_summary_counts_each_verdict() {
    let lines = doctor_lines(&result(), false);
    let last = lines.last().expect("a summary line").text();
    assert_eq!(
        last,
        "3 checks: 1 passed, 1 with something worth knowing, 0 failed, 1 not applicable"
    );
}

/// KR-REQ-26.13, KR-REQ-01.23: each configurable default is shown with its value and its source,
/// and the owner is shown where their own files are.
#[test]
fn the_configurable_defaults_are_shown_with_their_value_and_source() {
    let lines = configurable_lines(&configured())
        .iter()
        .map(|line| line.text().to_owned())
        .collect::<Vec<_>>();
    // The document is one of this host's own locations, which the owner asked for and is told
    // whole, spelled as every path is.
    let document = kr_client::shown::spelled(std::path::Path::new("/tmp/kalareach/config.json"));
    assert!(
        lines[0].contains(&document),
        "the owner is told which document this is: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("beside this environment's own state")),
        "and the rule this platform follows: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line
            .contains("sleep_inhibition = mains_only from host_configuration")
            && line.contains("applies immediately")),
        "{lines:?}"
    );
}

/// KR-REQ-23.25, KR-REQ-26.44: planted text in the diagnostics shows only where the person asked
/// `kr doctor` for it, this host's own locations, where each value came from and each value by its
/// class, and where the host's own export text is said through its door: a check's words and the
/// configuration's own sentences.
#[test]
fn planted_text_in_the_diagnostics_shows_only_where_it_was_asked_for() {
    use crate::output::planted::{only_asked_lines, only_asked_or_host_text, planted};
    use crate::shown::marker::MARKER;

    let door = |text: &dyn Fn() -> String| text().matches(MARKER).count();
    let mut shown = std::collections::BTreeSet::new();
    let mut integrations = std::collections::BTreeSet::new();
    for result in planted::<HostDoctorResult>() {
        integrations.extend(only_asked_or_host_text(
            "kr doctor",
            &doctor(&result),
            &[
                "checks[].id",
                "checks[].title",
                "checks[].detail",
                "checks[].remedy",
            ],
        ));
        // A command integration's lines show only what was asked for; what the host adds about
        // its state is said as its class and its length.
        for report in &result.command_integrations {
            only_asked_lines("kr doctor", &integration_lines(report, "", ""));
        }
        // A check's lines are the host's words, through the door and nowhere else.
        let said: usize = check_lines(&result, true)
            .iter()
            .map(|line| line.as_str().matches(MARKER).count())
            .sum();
        let words: usize = result
            .checks
            .iter()
            .map(|check| {
                door(&|| check.stated_title().as_str().to_owned())
                    + door(&|| check.stated_detail().as_str().to_owned())
                    + check
                        .stated_remedy()
                        .map_or(0, |remedy| door(&|| remedy.as_str().to_owned()))
            })
            .sum();
        assert_eq!(said, words, "a check's lines say only its own words");

        let configuration = &result.configuration;
        shown.extend(only_asked_or_host_text(
            "kr doctor",
            &configuration_report(configuration),
            &[
                "status.detail",
                "not_in_force",
                "fence_outstanding",
                "locations[].documented",
                "precedence[]",
                "overrides[].why",
                "values[].about",
                "ceilings[].configured",
                "ceilings[].value",
                "ceilings[].narrowed_by",
            ],
        ));
        // The configuration's lines: asked content, and the host's sentences each line prints.
        let unasked: usize = configurable_lines(configuration)
            .iter()
            .map(|line| line.unasked(MARKER))
            .sum();
        let sentences = door(&|| configuration.status.detail.as_str().to_owned())
            + configuration
                .locations
                .iter()
                .map(|location| door(&|| location.documented.as_str().to_owned()))
                .sum::<usize>()
            + configuration
                .ceilings
                .iter()
                .map(|ceiling| {
                    door(&|| ceiling.value.as_str().to_owned())
                        + ceiling
                            .narrowed_by
                            .as_ref()
                            .map_or(0, |why| door(&|| why.as_str().to_owned()))
                })
                .sum::<usize>();
        assert_eq!(
            unasked, sentences,
            "the configuration's lines say nothing unasked but the host's own sentences"
        );
    }
    for asked in [
        "document",
        "runtime_directory",
        "state_directory",
        "stale_documents[]",
        "values[].origin",
        "values[].value",
        "ceilings[].origin",
    ] {
        assert!(shown.contains(asked), "{asked} shows what was asked for");
    }
    // KR-REQ-07.45: what the doctor is asked to show of each command integration.
    for asked in [
        "command_integrations[].plugin_id",
        "command_integrations[].version",
        "command_integrations[].command",
        "command_integrations[].flags[]",
        "command_integrations[].variables[].name",
        "command_integrations[].variables[].value",
        "command_integrations[].executable",
        "command_integrations[].executable_version",
    ] {
        assert!(
            integrations.contains(asked),
            "{asked} shows what was asked for"
        );
    }
    assert!(!integrations.contains("command_integrations[].reason"));
}

/// Section 26: each effective value is shown; one made of names the owner wrote down, the packages
/// whose command integration a new session applies, whole, and a path or a word by its class.
#[test]
fn each_effective_value_is_shown_by_what_it_is_made_of() {
    let said = |declared: &Declared| {
        let value = EffectiveValue::new(
            "command_integrations",
            "the installed packages whose command integration a new session applies",
            declared,
            ValueSource::HostConfiguration,
            Nullable::null(),
            Nullable::null(),
            ValueEffect::NewSessionsOnly,
        );
        crate::output::Document::new()
            .with("value", value_said(&value))
            .json()["value"]
            .clone()
    };
    assert_eq!(
        said(&Declared::names([
            "kalareach/claude-code",
            "kalareach/gemini-cli"
        ])),
        "kalareach/claude-code, kalareach/gemini-cli"
    );
    assert_eq!(said(&Declared::term("mains_only")), "mains_only");
}

/// The marker this file plants in every text-bearing field of a reply.
///
/// Spelled so that no identifier, no wire word and no enumeration accepts it: a field that takes
/// it is a field arbitrary text fits in, which is the set these tests are about.
const PLANTED: &str = "opensesame marker!! 42";

/// One `host.info` reply, as a daemon answers it.
fn host_info(build: &str) -> kr_protocol::hostinfo::HostInfoResult {
    kr_protocol::hostinfo::HostInfoResult {
        build_id: kr_protocol::ids::BuildId::new(build).expect("a build identifier"),
        protocol_version: kr_protocol::hello::ProtocolVersion { major: 1, minor: 4 },
        environment_id: kr_protocol::ids::EnvironmentId::new(
            kr_protocol::scalars::Uuid::from_bytes([3; 16]),
        ),
        generation: kr_protocol::ids::ControllerGeneration::new(1),
        boot_identity: kr_protocol::identity::BootIdentity {
            source: kr_protocol::identity::BootIdentitySource::BootTime,
            value: kr_protocol::scalars::Bytes::new(Vec::new()),
        },
        started_at_ms: TimestampMs::new(1_700_000_000_000),
        live_sessions: kr_protocol::scalars::U64::new(0),
        session_limit: kr_protocol::scalars::U64::new(8),
        default_worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        power: kr_protocol::desktop::SleepInhibitionState {
            // Populated so that the walk below has somewhere to plant: a field left null offers
            // no leaf to replace, and a reply a daemon sends carries both of these.
            holder: Nullable::some("com.apple.powerd".to_owned()),
            withheld_reason: Nullable::some("no session has verified work".to_owned()),
            ..kr_protocol::desktop::SleepInhibitionState::off(
                kr_protocol::desktop::InhibitionMechanism::None,
                kr_protocol::desktop::PowerSource::Unknown,
            )
        },
        machine: None,
    }
}

/// Returns the reply with every string leaf that can hold [`PLANTED`] holding it.
///
/// Each leaf is replaced in turn and kept only when the whole document still parses back, so what
/// comes back is the set of fields a daemon on the other end of the socket could put anything in.
/// Nothing here consults the type's field list, so a field added tomorrow is covered on the day it
/// is added.
fn planted(reply: &kr_protocol::hostinfo::HostInfoResult) -> (serde_json::Value, Vec<String>) {
    fn leaves(value: &serde_json::Value, at: &mut Vec<Vec<String>>, path: Vec<String>) {
        match value {
            serde_json::Value::String(_) => at.push(path),
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    let mut next = path.clone();
                    next.push(index.to_string());
                    leaves(item, at, next);
                }
            }
            serde_json::Value::Object(fields) => {
                for (name, field) in fields {
                    let mut next = path.clone();
                    next.push(name.clone());
                    leaves(field, at, next);
                }
            }
            _ => {}
        }
    }

    fn at<'a>(
        value: &'a mut serde_json::Value,
        path: &[String],
    ) -> Option<&'a mut serde_json::Value> {
        let mut cursor = value;
        for step in path {
            cursor = match cursor {
                serde_json::Value::Array(items) => items.get_mut(step.parse::<usize>().ok()?)?,
                serde_json::Value::Object(fields) => fields.get_mut(step)?,
                _ => return None,
            };
        }
        Some(cursor)
    }

    let mut document = serde_json::to_value(reply).expect("the reply serialises");
    let mut paths = Vec::new();
    leaves(&document, &mut paths, Vec::new());
    let mut held = Vec::new();
    for path in paths {
        let mut attempt = document.clone();
        let Some(leaf) = at(&mut attempt, &path) else {
            continue;
        };
        *leaf = serde_json::Value::String(PLANTED.to_owned());
        if serde_json::from_value::<kr_protocol::hostinfo::HostInfoResult>(attempt.clone()).is_ok()
        {
            document = attempt;
            held.push(path.join("."));
        }
    }
    held.sort();
    (document, held)
}

/// KR-REQ-26.44: the software versions a bundle carries are built by the producer under test.
///
/// The rows in a bundle's `software` are composed here, out of a reply this command parsed, so
/// this walks the producer rather than a fixture of finished rows: a marker is planted in every
/// text-bearing field of the reply, the reply is read back the way the command reads one, and the
/// rows it yields are serialised. A producer that repeated something the daemon said would show
/// the marker whatever the row's type promised.
#[test]
fn the_software_versions_are_built_from_a_reply_without_repeating_it() {
    let (document, held) = planted(&host_info("kr-controller/0.1.0"));
    // Named rather than counted, so a field that stops taking the marker is a failure here
    // instead of a quiet loss of reach.
    assert_eq!(
        held,
        vec!["build_id", "power.holder", "power.withheld_reason"],
        "the marker reached these fields of the reply"
    );
    let reply: kr_protocol::hostinfo::HostInfoResult =
        serde_json::from_value(document).expect("a reply parses");
    let rows = software(&reply);
    let written = serde_json::to_string(&rows).expect("the rows serialise");
    assert!(!written.contains(PLANTED), "{written}");

    // And the diagnostic a bundle exists for: the build that is running, named in full because it
    // is a build identity and not because it arrived in the field for one.
    let named = software(&host_info("kr-controller/0.1.0"));
    let version = serde_json::to_string(&named).expect("the rows serialise");
    assert!(version.contains("kr-controller/0.1.0"), "{version}");
    for (arrived, measured) in [
        ("kr-controller 0.1.0 opensesame", 30),
        ("kr-controller/sk-live-opensesame", 32),
        ("kr-controller/0.1.0+sk-live-opensesame", 38),
    ] {
        let rows = software(&host_info(arrived));
        let version = serde_json::to_string(&rows).expect("the rows serialise");
        assert!(!version.contains("opensesame"), "{arrived}: {version}");
        assert!(
            version.contains(&format!("[name withheld, {measured} bytes]")),
            "{arrived}: {version}"
        );
    }
}

/// KR-REQ-26.44: a bundle carries versions, capabilities, checks and nothing content-bearing.
#[test]
fn a_bundle_carries_the_diagnostics_and_no_content_unless_it_was_selected() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("support.tar");
    let bundle = ComposedBundle::new(
        TimestampMs::new(1_700_000_000_000),
        vec![kr_protocol::hostinfo::SoftwareComponent {
            component: kr_protocol::hostinfo::export::Stated::new("kr"),
            version: kr_protocol::hostinfo::export::Sentence::new().stated("0.1.0"),
        }],
        Vec::new(),
        result(),
        vec![kr_protocol::hostinfo::RedactedError::new(
            "relay",
            "dial failed for https://operator:hunter2@relay.example.com",
        )],
    );
    assert!(!bundle.content().is_present(), "nothing was selected");
    bundle::write(&path, &bundle, None).expect("writes the bundle");

    let bytes = std::fs::read(&path).expect("reads it back");
    let names = entry_names(&bytes);
    assert_eq!(names, vec![bundle::MANIFEST, bundle::REPORT]);
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("hunter2"),
        "the error was redacted on the way in"
    );
    assert!(
        text.contains("\"component\": \"relay\""),
        "and still says which part of this host was talking: {text}"
    );
    assert!(
        text.contains("message withheld"),
        "with the library's own sentence as its class and its length: {text}"
    );
    assert!(
        !text.contains("\"content\": {"),
        "and carries no content-bearing export: {text}"
    );
}

/// KR-REQ-26.44: the content-bearing export exists only when the person selected it, and names
/// what it holds.
#[test]
fn a_selected_content_export_is_named_and_listed_in_the_manifest() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("support.tar");
    let entry = bundle::Content::new(
        bundle::SESSIONS_ENTRY,
        kr_protocol::hostinfo::export::Sentence::new()
            .stated("every live and closed session with its shell command line"),
        br#"{"sessions": []}"#.to_vec(),
    );
    assert!(
        entry.describe().as_str().contains("shell command line"),
        "the command prints what it will contain before writing"
    );
    // A rendering of the entry names it and counts its bytes, and never holds them: they are the
    // content the person selected to send.
    assert_eq!(
        format!("{entry:?}"),
        "Content { entry: \"content/sessions.json\", describes: \"every live and closed session \
         with its shell command line\", bytes: 16 }"
    );
    let bundle = ComposedBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        result(),
        Vec::new(),
    );
    let content = Approved::for_test(entry);
    bundle::write(&path, &bundle, Some(&content)).expect("writes the bundle");

    let bytes = std::fs::read(&path).expect("reads it back");
    assert_eq!(
        entry_names(&bytes),
        vec![
            bundle::MANIFEST.to_owned(),
            bundle::REPORT.to_owned(),
            "content/sessions.json".to_owned()
        ]
    );
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("every live and closed session"), "{text}");
}

/// KR-REQ-26.44: a bundle written to a bare file name lands in the directory the command ran in.
///
/// Run as the command runs it: a separate process, in a directory of its own, given the name and
/// nothing else. A bare name has no parent for the atomic replacement to write its temporary file
/// into, which is what used to make a bundle report failure after it had already been written.
#[test]
fn a_relative_destination_is_resolved_against_the_current_directory() {
    let directory = tempfile::tempdir().expect("a directory");
    let program = std::env::current_exe().expect("this test binary");
    let written = std::process::Command::new(&program)
        .arg("--exact")
        .arg("doctor::tests::writes_a_bundle_to_a_bare_name")
        .arg("--ignored")
        .arg("--nocapture")
        .current_dir(directory.path())
        .env("KR_BUNDLE_NAME", "support.tar")
        .output()
        .expect("the child runs");
    assert!(
        written.status.success(),
        "{}",
        String::from_utf8_lossy(&written.stderr)
    );
    assert!(
        directory.path().join("support.tar").exists(),
        "the bundle is in the directory the command ran in"
    );
}

/// The half of the test above that runs in the child, in its own directory.
#[test]
#[ignore = "run by a_relative_destination_is_resolved_against_the_current_directory"]
fn writes_a_bundle_to_a_bare_name() {
    let name = std::env::var("KR_BUNDLE_NAME").expect("the name the parent chose");
    let bundle = ComposedBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        result(),
        Vec::new(),
    );
    bundle::write(std::path::Path::new(&name), &bundle, None)
        .expect("a bare file name resolves against the current directory");
}

/// A name longer than a `ustar` header's hundred bytes.
const LONG_ENTRY_NAME: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn\
                               nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";

/// KR-REQ-26.44: an entry the archive format cannot carry is refused rather than truncated.
#[test]
fn an_entry_the_format_cannot_carry_is_refused() {
    let directory = tempfile::tempdir().expect("a directory");
    let bundle = ComposedBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        result(),
        Vec::new(),
    );
    let content = Approved::for_test(bundle::Content::new(
        LONG_ENTRY_NAME,
        kr_protocol::hostinfo::export::Sentence::new().stated("a name longer than a header holds"),
        Vec::new(),
    ));
    let refused = bundle::write(
        &directory.path().join("support.tar"),
        &bundle,
        Some(&content),
    )
    .expect_err("a name the header cannot carry");
    assert!(
        format!("{refused}").contains("longer than an archive entry name"),
        "{refused}"
    );
}

/// KR-REQ-26.16: the command's edit is the same validated one the host applies.
#[test]
fn the_commands_edit_validates_before_it_writes_and_refuses_a_document_it_must_not_rewrite() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();

    let revision = configuration::apply(
        &environment,
        &kr_protocol::hostinfo::configuration::Change::SleepInhibition(
            kr_protocol::desktop::SleepInhibitionSetting::MainsOnly,
        ),
    )
    .expect("the owner's choice");
    assert_eq!(revision, 1);
    let loaded = configuration::load(&environment);
    assert_eq!(loaded.status.state, DocumentState::Loaded);
    assert_eq!(
        loaded
            .preferences()
            .and_then(|set| set.sleep_inhibition.0)
            .expect("the chosen setting"),
        kr_protocol::desktop::SleepInhibitionSetting::MainsOnly
    );

    let refused = configuration::apply(
        &environment,
        &kr_protocol::hostinfo::configuration::Change::SessionLimit(Some(0)),
    )
    .expect_err("a ceiling that admits nothing");
    assert!(
        format!("{refused}").contains("admit no session"),
        "{refused}"
    );
    assert_eq!(
        configuration::load(&environment).revision(),
        1,
        "a refused edit applies no revision"
    );

    let unknown = ConfigurationDocument {
        version: 99,
        ..ConfigurationDocument::empty()
    };
    kr_ipc::paths::write_owner_only_file(
        &configuration::document_path(&environment),
        kr_protocol::hostinfo::configuration::contents(&unknown).as_bytes(),
    )
    .expect("writes a document from a later build");
    let refused = configuration::apply(
        &environment,
        &kr_protocol::hostinfo::configuration::Change::SleepInhibition(
            kr_protocol::desktop::SleepInhibitionSetting::Off,
        ),
    )
    .expect_err("a document this build must not rewrite");
    assert!(format!("{refused}").contains("version 99"), "{refused}");
}

/// The entry names of a `ustar` archive, in order.
fn entry_names(bytes: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut offset = 0;
    while offset + 512 <= bytes.len() {
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        assert_eq!(&header[257..263], b"ustar\0", "a ustar header");
        let name = header[..100]
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| char::from(*byte))
            .collect::<String>();
        let size = usize::from_str_radix(
            std::str::from_utf8(&header[124..135])
                .expect("an octal size")
                .trim_end_matches(char::from(0))
                .trim(),
            8,
        )
        .expect("an octal size");
        // The checksum is what a reader verifies, so this verifies it too.
        let stated = usize::from_str_radix(
            std::str::from_utf8(&header[148..154]).expect("an octal checksum"),
            8,
        )
        .expect("an octal checksum");
        // The checksum is computed with its own eight bytes read as spaces, which is the one
        // rule of the format a reader cannot skip.
        let mut recomputed: usize = header.iter().map(|byte| usize::from(*byte)).sum();
        for byte in &header[148..156] {
            recomputed -= usize::from(*byte);
            recomputed += usize::from(b' ');
        }
        assert_eq!(
            stated, recomputed,
            "the header checksum is right for {name}"
        );
        names.push(name);
        offset += 512 + size.div_ceil(512) * 512;
    }
    names
}

/// KR-REQ-07.12: the standalone start's check says whose the environment's scheduled task is and
/// whether it is the one this installation registers, and apart from that where a start can use
/// it and the task's last result, one for all of its runs; the same task seen from an interactive
/// session and from session 0, or with another last result, is said differently. A task that is
/// not usable fails with its remedy, and a task nothing chooses any more is a warning.
#[test]
fn the_standalone_starts_check_says_whose_valid_and_available_apart() {
    use kr_controller::supervision::windows::{Difference, LastResult, Standing};

    use crate::startup::task::Report;

    let environment_id = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
    let report = |standing, program_present, session, last_result| Report {
        environment_id,
        standing,
        program_present,
        session,
        last_result,
    };
    let signed_in = task_check(
        &report(
            Ok(Standing::Owned(Vec::new())),
            true,
            Some(2),
            Some(LastResult::Ended(0)),
        ),
        true,
    );
    assert_eq!(signed_in.id(), TASK_CHECK);
    assert_eq!(signed_in.status, DoctorStatus::Ok);
    for part in [
        &format!("the scheduled task of environment {environment_id}"),
        "is this environment's own and the one this installation registers",
        "you are signed in to login session 2, where the task can start the daemon",
        "its last run succeeded, for all of its runs",
        "signing out ends it and every session",
    ] {
        assert!(
            signed_in.detail().contains(part),
            "{part}: {}",
            signed_in.detail()
        );
    }
    let services = task_check(
        &report(
            Ok(Standing::Owned(Vec::new())),
            true,
            Some(0),
            Some(LastResult::Ended(0x8007_10e0)),
        ),
        true,
    );
    assert_eq!(services.status, DoctorStatus::Ok);
    assert!(
        services
            .detail()
            .contains("this command runs in no interactive session (login session 0)")
            && services
                .detail()
                .contains("its last run ended with code 2147946720"),
        "{}",
        services.detail()
    );
    assert_ne!(signed_in.detail(), services.detail());
    for (standing, program_present, remedy) in [
        (Ok(Standing::Absent), true, "to register it"),
        (
            Ok(Standing::Owned(vec![Difference::Disabled])),
            true,
            "to repair it",
        ),
        (Ok(Standing::Owned(Vec::new())), false, "install kr again"),
    ] {
        let failed = task_check(&report(standing, program_present, Some(1), None), true);
        assert_eq!(failed.status, DoctorStatus::Failed);
        assert!(
            failed.remedy().unwrap_or_default().contains(remedy),
            "{remedy}: {:?}",
            failed.remedy()
        );
        assert!(failed.detail().contains("its last result cannot be read"));
    }
    let unused = task_check(
        &report(Ok(Standing::Owned(Vec::new())), true, Some(1), None),
        false,
    );
    assert_eq!(unused.status, DoctorStatus::Warning);
    assert!(unused.detail().contains("nothing uses it"));
}
