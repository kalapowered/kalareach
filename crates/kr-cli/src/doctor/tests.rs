//! What the command prints, what it writes and what it refuses to write.

use kr_protocol::hostinfo::configuration::{
    ConfigurationDocument, DocumentState, ValueEffect, ValueSource,
};
use kr_protocol::hostinfo::{
    DoctorCheck, DoctorStatus, EffectiveConfiguration, EffectiveValue, HostDoctorResult,
    SupportBundle,
};
use kr_protocol::scalars::{Nullable, TimestampMs};

use super::*;

fn checks() -> Vec<DoctorCheck> {
    vec![
        DoctorCheck::new(
            "runtime-directory",
            "The runtime directory is owner-only",
            DoctorStatus::Ok,
            "/tmp/kalareach/ab12cd34",
            None,
        ),
        DoctorCheck::new(
            "workers",
            "Every published descriptor answered its challenge",
            DoctorStatus::Warning,
            "1 verified, 1 quarantined",
            Some("A quarantined descriptor is never used.".to_owned()),
        ),
        DoctorCheck::new(
            "catalogue",
            "Catalogue metadata and its capability evidence",
            DoctorStatus::NotApplicable,
            "no catalogue is synchronised on this host",
            None,
        ),
    ]
}

fn configured() -> EffectiveConfiguration {
    let mut effective = EffectiveConfiguration::unread();
    effective.document = "/tmp/kalareach/config.json".to_owned();
    effective.values = vec![EffectiveValue {
        key: "sleep_inhibition".to_owned(),
        about: "whether this host keeps itself awake for work it has admitted".to_owned(),
        value: "mains_only".to_owned(),
        source: ValueSource::HostConfiguration,
        origin: Nullable::some("/tmp/kalareach/config.json".to_owned()),
        variable: Nullable::null(),
        effect: ValueEffect::Immediately,
    }];
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
        "/tmp/kalareach/ab12cd34",
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

/// KR-REQ-26.16, KR-REQ-01.23: each configurable default is shown with its value and its source.
#[test]
fn the_configurable_defaults_are_shown_with_their_value_and_source() {
    let lines = configurable_lines(&configured());
    assert!(lines[0].contains("/tmp/kalareach/config.json"), "{lines:?}");
    assert!(
        lines.iter().any(|line| line
            .contains("sleep_inhibition = mains_only from host_configuration")
            && line.contains("applies immediately")),
        "{lines:?}"
    );
}

/// KR-REQ-26.44: a bundle carries versions, capabilities, checks and nothing content-bearing.
#[test]
fn a_bundle_carries_the_diagnostics_and_no_content_unless_it_was_selected() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("support.tar");
    let bundle = SupportBundle::new(
        TimestampMs::new(1_700_000_000_000),
        vec![kr_protocol::hostinfo::SoftwareComponent {
            component: "kr".to_owned(),
            version: "0.1.0".to_owned(),
        }],
        Vec::new(),
        result(),
        configured(),
        vec![kr_protocol::hostinfo::RedactedError::new(
            "relay",
            "dial failed for https://operator:hunter2@relay.example.com",
        )],
    );
    assert!(!bundle.content.is_present(), "nothing was selected");
    bundle::write(&path, &bundle, &[], "report").expect("writes the bundle");

    let bytes = std::fs::read(&path).expect("reads it back");
    let names = entry_names(&bytes);
    assert_eq!(names, vec![bundle::MANIFEST, bundle::REPORT]);
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("hunter2"),
        "the error was redacted on the way in"
    );
    assert!(
        text.contains("relay.example.com"),
        "and still says what failed"
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
        entry: format!("{}sessions.json", bundle::CONTENT_PREFIX),
        describes: "every live and closed session with its shell command line".to_owned(),
        bytes: br#"{"sessions": []}"#.to_vec(),
    }];
    assert!(
        content[0].describe().contains("shell command line"),
        "the command prints what it will contain before writing"
    );
    let bundle = SupportBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        result(),
        configured(),
        Vec::new(),
    );
    bundle::write(&path, &bundle, &content, "report").expect("writes the bundle");

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
#[test]
fn a_relative_destination_is_resolved_against_the_current_directory() {
    let directory = tempfile::tempdir().expect("a directory");
    let bundle = SupportBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        result(),
        configured(),
        Vec::new(),
    );
    // Written through the same path a bare `--bundle support.tar` takes, without changing this
    // process's own directory: a relative destination has no parent for the atomic replacement to
    // write its temporary file into, which is what used to make a bundle report failure after it
    // had already been written.
    let relative = std::path::Path::new("support.tar");
    assert!(
        relative
            .parent()
            .is_some_and(|parent| parent.as_os_str().is_empty())
    );
    bundle::write(&directory.path().join(relative), &bundle, &[], "report")
        .expect("an absolute destination");
    let here = std::env::current_dir().expect("a current directory");
    bundle::write(
        &here.join("kr-doctor-bundle-test.tar"),
        &bundle,
        &[],
        "report",
    )
    .expect("a destination inside the current directory");
    std::fs::remove_file(here.join("kr-doctor-bundle-test.tar")).expect("removes what it wrote");
}

/// KR-REQ-26.44: an entry the archive format cannot carry is refused rather than truncated.
#[test]
fn an_entry_the_format_cannot_carry_is_refused() {
    let directory = tempfile::tempdir().expect("a directory");
    let bundle = SupportBundle::new(
        TimestampMs::new(1),
        Vec::new(),
        Vec::new(),
        result(),
        configured(),
        Vec::new(),
    );
    let content = vec![bundle::Content {
        entry: format!("{}{}", bundle::CONTENT_PREFIX, "n".repeat(120)),
        describes: "a name longer than a header holds".to_owned(),
        bytes: Vec::new(),
    }];
    let refused = bundle::write(
        &directory.path().join("support.tar"),
        &bundle,
        &content,
        "report",
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
        let mut recomputed: usize = header.iter().map(|byte| usize::from(*byte)).sum();
        for index in 148..156 {
            recomputed -= usize::from(header[index]);
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
