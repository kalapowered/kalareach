//! What this host resolves from a document on disk.

use kr_protocol::hostinfo::configuration::{
    Change, ConfigurationDocument, DocumentState, PreferenceSet, ValueEffect, ValueSource,
};

use super::*;

/// KR-REQ-26.13: the reader finds the document in the environment's own state directory.
#[test]
fn an_absent_document_resolves_every_preference_to_its_product_default() {
    let temp = kr_ipc::testing::TempHost::create();
    let resolver = Resolver::open(&temp.environment());
    assert_eq!(resolver.status().state, DocumentState::Absent);
    assert_eq!(resolver.revision(), 0);

    let power = resolver.sleep_inhibition(None);
    assert_eq!(power.value, SleepInhibitionSetting::Off);
    assert_eq!(power.source, ValueSource::Default);

    let profile = resolver.worker_profile(None, WorkerProfile::HeadlessUser);
    assert_eq!(profile.value, WorkerProfile::HeadlessUser);
    assert_eq!(profile.source, ValueSource::Default);
    assert_eq!(profile.preference.effect, ValueEffect::NewSessionsOnly);
}

/// KR-REQ-26.13: the document is the third rung, and a request beats it.
#[test]
fn a_request_beats_a_profile_and_a_profile_beats_the_document() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let mut document = ConfigurationDocument::empty();
    document.preferences.sleep_inhibition = Nullable::some(SleepInhibitionSetting::MainsOnly);
    document.profiles.insert(
        "review".to_owned(),
        PreferenceSet {
            sleep_inhibition: Nullable::some(SleepInhibitionSetting::Off),
            ..PreferenceSet::default()
        },
    );
    kr_ipc::paths::write_owner_only_file(
        &document_path(&environment),
        configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");

    let resolver = Resolver::open(&environment);
    assert_eq!(resolver.status().state, DocumentState::Loaded);
    let from_document = resolver.sleep_inhibition(None);
    assert_eq!(from_document.value, SleepInhibitionSetting::MainsOnly);
    assert_eq!(from_document.source, ValueSource::HostConfiguration);
    assert_eq!(
        from_document.origin.as_deref(),
        Some(document_path(&environment).display().to_string().as_str())
    );

    let with_profile = Resolver::open(&environment).with_profile(Some("review".to_owned()));
    let from_profile = with_profile.sleep_inhibition(None);
    assert_eq!(from_profile.value, SleepInhibitionSetting::Off);
    assert_eq!(from_profile.source, ValueSource::Profile);
    assert_eq!(from_profile.origin.as_deref(), Some("review"));
    assert_eq!(
        with_profile
            .worker_profile(None, WorkerProfile::DesktopBound)
            .source,
        ValueSource::Default,
        "a profile that chooses nothing here leaves the rung below it standing"
    );

    let requested = with_profile.sleep_inhibition(Some(SleepInhibitionSetting::BatteryToo));
    assert_eq!(requested.value, SleepInhibitionSetting::BatteryToo);
    assert_eq!(requested.source, ValueSource::Request);
}

/// KR-REQ-26.13: a profile a request names and this host does not have contributes nothing.
#[test]
fn an_unknown_profile_falls_through_to_the_document() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let mut document = ConfigurationDocument::empty();
    document.preferences.worker_profile = Nullable::some(WorkerProfile::HeadlessUser);
    kr_ipc::paths::write_owner_only_file(
        &document_path(&environment),
        configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");

    let resolver = Resolver::open(&environment).with_profile(Some("absent".to_owned()));
    let effective = resolver.worker_profile(None, WorkerProfile::DesktopBound);
    assert_eq!(effective.value, WorkerProfile::HeadlessUser);
    assert_eq!(effective.source, ValueSource::HostConfiguration);
}

/// KR-REQ-26.13: a document this build cannot use leaves it alone and runs on defaults.
#[test]
fn a_document_at_an_unknown_version_is_left_exactly_as_it_was() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let path = document_path(&environment);
    let written = br#"{"version": 4096, "preferences": {"sleep_inhibition": "battery_too"}}"#;
    kr_ipc::paths::write_owner_only_file(&path, written).expect("writes the document");

    let resolver = Resolver::open(&environment);
    assert_eq!(resolver.status().state, DocumentState::UnknownVersion);
    assert_eq!(
        resolver.sleep_inhibition(None).value,
        SleepInhibitionSetting::Off,
        "nothing is read out of a version this build does not know"
    );
    assert!(
        configuration::edit(
            resolver.loaded(),
            &Change::SleepInhibition(SleepInhibitionSetting::Off)
        )
        .is_err(),
        "and an edit refuses rather than overwriting it"
    );
    assert_eq!(
        std::fs::read(&path).expect("the document is still there"),
        written,
        "byte for byte as the owner left it"
    );
}

/// KR-REQ-26.13: the read is bounded, so a large file is refused rather than loaded.
#[test]
fn a_document_larger_than_the_bound_is_refused() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let filler = "x".repeat(usize::try_from(configuration::MAX_LEN).expect("a usize") + 1);
    kr_ipc::paths::write_owner_only_file(&document_path(&environment), filler.as_bytes())
        .expect("writes the document");

    let resolver = Resolver::open(&environment);
    assert_eq!(resolver.status().state, DocumentState::Unreadable);
    assert_eq!(resolver.sleep_inhibition(None).source, ValueSource::Default);
}

/// KR-REQ-26.14: an allowlisted variable is reported at the rung it acts at.
#[test]
fn the_overrides_are_reported_with_their_declared_position() {
    let temp = kr_ipc::testing::TempHost::create();
    let resolver = Resolver::open(&temp.environment());
    let overrides = resolver.overrides();
    assert_eq!(overrides.len(), 2);
    for entry in &overrides {
        assert_eq!(entry.position, ValueSource::Request);
        assert!(!entry.why.is_empty());
        assert!(configuration::allowlisted(&entry.variable).is_some());
    }
    let state = resolver.state_directory();
    assert!(state.value.contains("kr-"), "{}", state.value);
    assert_eq!(
        state.preference.key,
        configuration::STATE_DIRECTORY.key,
        "the directory resolves through the same function as every other preference"
    );
}

/// KR-REQ-26.13: a `power.json` beside the document is stale and is reported, never read.
#[test]
fn a_superseded_power_document_is_named_and_ignored() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    assert!(stale_documents(&environment).is_empty());
    kr_ipc::paths::write_owner_only_file(
        &environment
            .state_dir()
            .join(configuration::SUPERSEDED_FILE_NAME),
        br#"{"version": 1, "sleep_inhibition": "battery_too"}"#,
    )
    .expect("writes the superseded document");

    let resolver = Resolver::open(&environment);
    assert_eq!(resolver.stale_documents().len(), 1);
    assert_eq!(
        resolver.sleep_inhibition(None).value,
        SleepInhibitionSetting::Off,
        "the choice it carried is not read back: nothing was ever installed from it"
    );
}

/// KR-REQ-26.16: a value's report carries its source and whether it applies immediately.
#[test]
fn an_effective_value_carries_its_source_and_its_effect() {
    let temp = kr_ipc::testing::TempHost::create();
    let resolver = Resolver::open(&temp.environment());
    let power = resolver.sleep_inhibition(None);
    let reported = effective_value(&power, power.value.as_str().to_owned());
    assert_eq!(reported.key, "sleep_inhibition");
    assert_eq!(reported.value, "off");
    assert_eq!(reported.source, ValueSource::Default);
    assert_eq!(reported.effect, ValueEffect::Immediately);
    assert!(!reported.variable.is_present());

    let requested = resolver.worker_profile(
        Some(WorkerProfile::DesktopBound),
        WorkerProfile::HeadlessUser,
    );
    let reported = effective_value(&requested, requested.value.as_str().to_owned());
    assert_eq!(reported.source, ValueSource::Request);
    assert_eq!(reported.effect, ValueEffect::NewSessionsOnly);
}
