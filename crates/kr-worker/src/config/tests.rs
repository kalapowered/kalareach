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
        assert!(!entry.why.as_str().is_empty());
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
    let reported = effective_value(
        &power,
        &kr_protocol::hostinfo::export::Declared::term(power.value.as_str()),
    );
    assert_eq!(reported.key, "sleep_inhibition");
    assert_eq!(reported.value(), "off");
    assert_eq!(reported.source, ValueSource::Default);
    assert_eq!(reported.effect, ValueEffect::Immediately);
    assert!(!reported.variable.is_present());

    let requested = resolver.worker_profile(
        Some(WorkerProfile::DesktopBound),
        WorkerProfile::HeadlessUser,
    );
    let reported = effective_value(
        &requested,
        &kr_protocol::hostinfo::export::Declared::term(requested.value.as_str()),
    );
    assert_eq!(reported.source, ValueSource::Request);
    assert_eq!(reported.effect, ValueEffect::NewSessionsOnly);
}

/// KR-REQ-12.07: the command integrations a new session applies resolve on the ladder: a profile's
/// list replaces the host's, an empty one turns every integration off, and a profile that names
/// none leaves the host's; with no document, none is on.
#[test]
fn command_integrations_resolve_on_the_ladder() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let absent = Resolver::open(&environment).command_integrations();
    assert!(absent.value.is_empty());
    assert_eq!(absent.source, ValueSource::Default);
    assert_eq!(absent.preference.effect, ValueEffect::NewSessionsOnly);

    let named = |plugins: &[&str]| -> Vec<String> {
        plugins.iter().map(|plugin| (*plugin).to_owned()).collect()
    };
    let mut document = ConfigurationDocument::empty();
    document.preferences.command_integrations =
        Nullable::some(named(&["kalareach/claude-code", "kalareach/gemini-cli"]));
    for (name, list) in [
        ("quiet", Some(named(&[]))),
        ("one", Some(named(&["kalareach/qoder-cli"]))),
        ("silent", None),
    ] {
        document.profiles.insert(
            name.to_owned(),
            PreferenceSet {
                command_integrations: Nullable(list),
                ..PreferenceSet::default()
            },
        );
    }
    kr_ipc::paths::write_owner_only_file(
        &document_path(&environment),
        configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");

    let host = Resolver::open(&environment).command_integrations();
    assert_eq!(
        host.value,
        named(&["kalareach/claude-code", "kalareach/gemini-cli"])
    );
    assert_eq!(host.source, ValueSource::HostConfiguration);
    for (profile, expected, source) in [
        ("quiet", named(&[]), ValueSource::Profile),
        ("one", named(&["kalareach/qoder-cli"]), ValueSource::Profile),
        (
            "silent",
            named(&["kalareach/claude-code", "kalareach/gemini-cli"]),
            ValueSource::HostConfiguration,
        ),
    ] {
        let resolved = Resolver::open(&environment)
            .with_profile(Some(profile.to_owned()))
            .command_integrations();
        assert_eq!(resolved.value, expected, "{profile}");
        assert_eq!(resolved.source, source, "{profile}");
    }
}

/// KR-REQ-07.25: the variables added to a session started with the host's environment resolve on
/// the ladder: a profile's set replaces the host's, an empty one adds nothing, and a profile that
/// names none leaves the host's; with no document, none is added.
#[test]
fn environment_additions_resolve_on_the_ladder() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let absent = Resolver::open(&environment).environment_additions();
    assert!(absent.value.is_empty());
    assert_eq!(absent.source, ValueSource::Default);
    assert_eq!(absent.preference.effect, ValueEffect::NewSessionsOnly);

    let added = |pairs: &[(&str, &str)]| -> configuration::EnvironmentAdditions {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    };
    let mut document = ConfigurationDocument::empty();
    document.preferences.environment_additions =
        Nullable::some(added(&[("EDITOR", "vim"), ("GOPATH", "/home/a/go")]));
    for (name, set) in [
        ("quiet", Some(added(&[]))),
        ("one", Some(added(&[("EDITOR", "hx")]))),
        ("silent", None),
    ] {
        document.profiles.insert(
            name.to_owned(),
            PreferenceSet {
                environment_additions: Nullable(set),
                ..PreferenceSet::default()
            },
        );
    }
    kr_ipc::paths::write_owner_only_file(
        &document_path(&environment),
        configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");

    let host = Resolver::open(&environment).environment_additions();
    assert_eq!(
        host.value,
        added(&[("EDITOR", "vim"), ("GOPATH", "/home/a/go")])
    );
    assert_eq!(host.source, ValueSource::HostConfiguration);
    for (profile, expected, source) in [
        ("quiet", added(&[]), ValueSource::Profile),
        ("one", added(&[("EDITOR", "hx")]), ValueSource::Profile),
        (
            "silent",
            added(&[("EDITOR", "vim"), ("GOPATH", "/home/a/go")]),
            ValueSource::HostConfiguration,
        ),
    ] {
        let resolved = Resolver::open(&environment)
            .with_profile(Some(profile.to_owned()))
            .environment_additions();
        assert_eq!(resolved.value, expected, "{profile}");
        assert_eq!(resolved.source, source, "{profile}");
    }
}

/// KR-REQ-07.64: the resolver answers the ownership the document records for a package, read when
/// it is opened, and full ownership for every other package and for a host with no document or no
/// usable one.
#[test]
fn an_agents_entry_records_reduced_ownership_for_its_package_only() {
    use kr_protocol::broker::AgentOwnership;
    use kr_protocol::hostinfo::configuration::AgentChoice;

    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let absent = Resolver::open(&environment);
    assert_eq!(
        absent.agent_ownership("kalareach/codex"),
        AgentOwnership::Full
    );
    assert!(absent.reduced_agents().is_empty());

    let mut document = ConfigurationDocument::empty();
    document.agents.insert(
        "kalareach/codex".to_owned(),
        AgentChoice {
            ownership: AgentOwnership::Reduced,
        },
    );
    kr_ipc::paths::write_owner_only_file(
        &document_path(&environment),
        configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");
    let chosen = Resolver::open(&environment);
    assert_eq!(
        chosen.agent_ownership("kalareach/codex"),
        AgentOwnership::Reduced
    );
    assert_eq!(
        chosen.agent_ownership("kalareach/claude-code"),
        AgentOwnership::Full
    );
    assert_eq!(chosen.reduced_agents(), vec!["kalareach/codex".to_owned()]);

    // A document this host cannot use records nothing: the resolver never answers reduced from a
    // document it did not read.
    kr_ipc::paths::write_owner_only_file(
        &document_path(&environment),
        br#"{"version": 1, "agents": {"kalareach/codex": {"ownership": "reduced"}, "x": {}}}"#,
    )
    .expect("writes the document");
    let unusable = Resolver::open(&environment);
    assert_eq!(unusable.status().state, DocumentState::Invalid);
    assert_eq!(
        unusable.agent_ownership("kalareach/codex"),
        AgentOwnership::Full
    );
}
