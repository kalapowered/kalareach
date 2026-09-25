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

fn result() -> HostDoctorResult {
    HostDoctorResult::new(checks(), configured())
}

/// KR-REQ-01.23: the default output shows evidence for what did not pass, and nothing else.
#[test]
fn the_default_output_shows_evidence_only_where_a_check_did_not_pass() {
    let text = doctor_lines(&result(), false);
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
    let text = doctor_lines(&result(), true);
    for evidence in [
        "[path withheld, 23 bytes]",
        "1 verified, 1 quarantined",
        "no catalogue is synchronised on this host",
    ] {
        assert!(text.contains(evidence), "{evidence} is missing: {text}");
    }
}

/// KR-REQ-01.23: the summary counts every verdict.
#[test]
fn the_summary_counts_each_verdict() {
    let text = doctor_lines(&result(), false);
    let last = text.lines().next_back().expect("a summary line");
    assert_eq!(
        last,
        "3 checks: 1 passed, 1 with something worth knowing, 0 failed, 1 not applicable"
    );
}

/// KR-REQ-26.13, KR-REQ-01.23: each configurable default is shown with its value and its source,
/// and the owner is shown where their own files are.
#[test]
fn the_configurable_defaults_are_shown_with_their_value_and_source() {
    let lines = configurable_lines(&configured());
    assert!(
        lines[0].contains("/tmp/kalareach/config.json"),
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
    bundle::write(&path, &bundle, &[]).expect("writes the bundle");

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
    let content = vec![bundle::Content {
        entry: bundle::SESSIONS_ENTRY,
        describes: kr_protocol::hostinfo::export::Sentence::new()
            .stated("every live and closed session with its shell command line"),
        bytes: br#"{"sessions": []}"#.to_vec(),
    }];
    assert!(
        content[0]
            .describe()
            .as_str()
            .contains("shell command line"),
        "the command prints what it will contain before writing"
    );
    let bundle = ComposedBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        result(),
        Vec::new(),
    );
    bundle::write(&path, &bundle, &content).expect("writes the bundle");

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
    bundle::write(std::path::Path::new(&name), &bundle, &[])
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
    let content = vec![bundle::Content {
        entry: LONG_ENTRY_NAME,
        describes: kr_protocol::hostinfo::export::Sentence::new()
            .stated("a name longer than a header holds"),
        bytes: Vec::new(),
    }];
    let refused = bundle::write(&directory.path().join("support.tar"), &bundle, &content)
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
