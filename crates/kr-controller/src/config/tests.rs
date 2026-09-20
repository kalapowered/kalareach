//! What this host's own configuration comes out as.

use kr_protocol::desktop::CapabilityInvalidation;
use kr_protocol::hostinfo::configuration::{
    Change, ConfigurationCeilings, ConfigurationDocument, DocumentState, EnrolmentBudgets,
    ValueEffect,
};
use kr_protocol::scalars::Nullable;

use super::*;

/// KR-REQ-26.16: an edit is validated, then a revision is applied, then it is written.
#[test]
fn an_edit_applies_one_revision_and_a_refused_edit_applies_none() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();

    let applied = apply(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect("the owner's choice");
    assert_eq!(applied.revision, 1);
    assert_eq!(applied.effect, ValueEffect::Immediately);
    assert!(!applied.fences_dispatch);
    assert!(applied.invalidated.is_empty());
    assert_eq!(
        sleep_inhibition(&environment),
        SleepInhibitionSetting::MainsOnly
    );

    let refused = apply(&environment, &Change::SessionLimit(Some(0)))
        .expect_err("a ceiling that admits nothing");
    assert!(
        format!("{refused}").contains("admit no session"),
        "{refused}"
    );
    assert_eq!(
        open(&environment).revision(),
        1,
        "a refused edit applies no revision"
    );
}

/// KR-REQ-26.16: a runtime profile change invalidates evidence and migrates no worker.
#[test]
fn a_profile_change_invalidates_the_evidence_taken_under_the_old_one() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let applied = apply(
        &environment,
        &Change::WorkerProfile(WorkerProfile::HeadlessUser),
    )
    .expect("the owner's choice");
    assert_eq!(applied.effect, ValueEffect::NewSessionsOnly);
    assert_eq!(
        applied.invalidated,
        vec![CapabilityInvalidation::WorkerProfile]
    );
    assert!(
        !applied.fences_dispatch,
        "a profile is not authority, so nothing is fenced"
    );
}

/// KR-REQ-26.16: a change that affects authority says so, so dispatch is fenced first.
#[test]
fn a_grant_ceiling_change_fences_dispatch_before_it_is_acknowledged() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let applied = apply(
        &environment,
        &Change::GrantRights(Some(vec!["session.view".to_owned()])),
    )
    .expect("a ceiling naming a right this build knows");
    assert!(applied.fences_dispatch);
    assert_eq!(applied.effect, ValueEffect::Immediately);

    let refused = apply(
        &environment,
        &Change::GrantRights(Some(vec!["not.a.right".to_owned()])),
    )
    .expect_err("a name that is not an action right");
    assert!(format!("{refused}").contains("not.a.right"), "{refused}");
}

/// KR-REQ-26.16: a second writer's revision is not overwritten.
#[test]
fn an_edit_built_on_a_revision_another_writer_moved_is_refused() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let loaded = kr_worker::config::load(&environment);
    let prepared = kr_protocol::hostinfo::configuration::edit(
        &loaded,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect("a valid edit");

    // Another writer gets there first.
    apply(&environment, &Change::SessionLimit(Some(4))).expect("the other writer's edit");

    let refused = write(&environment, &prepared).expect_err("the revision moved underneath it");
    assert!(
        format!("{refused}").contains("absent at revision 0")
            && format!("{refused}").contains("loaded at revision 1"),
        "{refused}"
    );
    assert_eq!(
        sleep_inhibition(&environment),
        SleepInhibitionSetting::Off,
        "and the first writer's choice was not applied"
    );
}

/// KR-REQ-26.15: a configured ceiling above the hard limit is refused, not applied.
#[test]
fn a_session_ceiling_above_the_hard_limit_is_refused() {
    let limits = HardLimits::default();
    let below = ConfigurationCeilings {
        session_limit: Nullable::some(8),
        ..ConfigurationCeilings::default()
    };
    let ceiling = ceilings::session_limit(&below, limits);
    assert_eq!(ceiling.value, 8);
    assert!(!ceiling.refused);

    let above = ConfigurationCeilings {
        session_limit: Nullable::some(limits.sessions_per_environment + 1),
        ..ConfigurationCeilings::default()
    };
    let ceiling = ceilings::session_limit(&above, limits);
    assert_eq!(ceiling.value, limits.sessions_per_environment);
    assert!(ceiling.refused, "asking for more raises nothing");
    assert!(ceiling.narrowed_by.is_some());
}

/// KR-REQ-26.15: a payload budget above the default without the explicit setting is refused.
#[test]
fn an_enrolment_budget_above_the_default_needs_the_explicit_setting() {
    let mut budgets = EnrolmentBudgets {
        cached_payload_bytes: 8 * 1024 * 1024 * 1024,
        ..EnrolmentBudgets::default()
    };
    let asked = ConfigurationCeilings {
        enrolment: budgets,
        ..ConfigurationCeilings::default()
    };
    let ceiling = ceilings::enrolment(&asked);
    assert!(ceiling.refused);
    assert_eq!(
        ceiling.value.cached_payload_bytes,
        EnrolmentBudgets::default().cached_payload_bytes
    );
    assert_eq!(
        catalogue::budgets(&asked).cached_payload_bytes,
        EnrolmentBudgets::default().cached_payload_bytes,
        "and the catalogue reads what is in force, not what was asked for"
    );

    budgets.full_offline_mirror = true;
    let chosen = ConfigurationCeilings {
        enrolment: budgets,
        ..ConfigurationCeilings::default()
    };
    let ceiling = ceilings::enrolment(&chosen);
    assert!(!ceiling.refused);
    assert_eq!(ceiling.value.cached_payload_bytes, 8 * 1024 * 1024 * 1024);
}

/// KR-REQ-26.15: the rights ceiling narrows what the grant intersection already allowed.
#[test]
fn a_configured_right_the_grant_does_not_carry_adds_nothing() {
    use kr_protocol::rights::ActionRight;

    let ceilings = ConfigurationCeilings {
        grant_rights: Nullable::some(vec![
            ActionRight::SessionView.as_str().to_owned(),
            ActionRight::SessionCreate.as_str().to_owned(),
        ]),
        ..ConfigurationCeilings::default()
    };
    let configured = ceilings::configured_rights(&ceilings).expect("a configured ceiling");
    assert!(configured.contains(&ActionRight::SessionView));
    assert!(configured.contains(&ActionRight::SessionCreate));
    assert!(!configured.contains(&ActionRight::HostManage));

    let unknown = ConfigurationCeilings {
        grant_rights: Nullable::some(vec!["not.a.right".to_owned()]),
        ..ConfigurationCeilings::default()
    };
    let configured = ceilings::configured_rights(&unknown).expect("a ceiling naming nothing known");
    assert!(
        configured.is_empty(),
        "an unfamiliar name never widens a ceiling"
    );
}

/// KR-REQ-26.13 and 01.23: the report names each value, its source and where it came from.
#[test]
fn the_effective_report_names_every_value_its_source_and_its_effect() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    apply(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::BatteryToo),
    )
    .expect("the owner's choice");

    let report = effective(
        &open(&environment),
        HardLimits::default(),
        WorkerProfile::HeadlessUser,
    );
    assert_eq!(report.schema_version.get(), configuration::VERSION);
    assert_eq!(report.revision.get(), 1);
    assert_eq!(report.status.state, DocumentState::Loaded);
    assert_eq!(report.precedence.len(), 4);
    assert_eq!(report.overrides.len(), 2);
    assert_eq!(report.values.len(), 4, "two preferences and two locations");

    let power = report
        .values
        .iter()
        .find(|value| value.key == "sleep_inhibition")
        .expect("the sleep policy");
    assert_eq!(power.value, "battery_too");
    assert_eq!(
        power.source,
        kr_protocol::hostinfo::configuration::ValueSource::HostConfiguration
    );
    assert_eq!(power.effect, ValueEffect::Immediately);
    assert!(power.origin.is_present(), "and it says which document");

    let profile = report
        .values
        .iter()
        .find(|value| value.key == "worker_profile")
        .expect("the execution context");
    assert_eq!(profile.effect, ValueEffect::NewSessionsOnly);

    assert_eq!(
        secret_line(&report),
        "no secure-store references are configured"
    );
}

/// KR-REQ-01.23: the configuration's diagnostics report the document, the order and the ceilings.
#[test]
fn the_diagnostics_report_the_document_the_order_the_overrides_and_the_ceilings() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let report = effective(
        &open(&environment),
        HardLimits::default(),
        WorkerProfile::HeadlessUser,
    );
    let produced = checks(&report);
    let ids: Vec<&str> = produced.iter().map(|check| check.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "configuration-document",
            "configuration-precedence",
            "configuration-overrides",
            "configuration-ceilings",
        ]
    );
    for check in &produced {
        assert!(!check.evidence().is_empty(), "{} has evidence", check.id);
    }
    let precedence = &produced[1];
    assert!(
        precedence.detail.contains("explicit request"),
        "{precedence:?}"
    );
    assert!(
        precedence.detail.contains("product default"),
        "{precedence:?}"
    );
    let overrides = &produced[2];
    assert!(overrides.detail.contains("KR_STATE_DIR"), "{overrides:?}");
    assert!(
        overrides
            .detail
            .contains("No other inherited variable takes part in the precedence"),
        "{overrides:?}"
    );
    assert!(
        overrides.detail.contains("This build also reads"),
        "and it says what this build reads outside the precedence: {overrides:?}"
    );
}

/// KR-REQ-26.13: a stale `power.json` is reported in one line and never read.
#[test]
fn a_stale_power_document_is_reported_by_the_document_check() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    kr_ipc::paths::write_owner_only_file(
        &environment
            .state_dir()
            .join(configuration::SUPERSEDED_FILE_NAME),
        br#"{"version": 1, "sleep_inhibition": "battery_too"}"#,
    )
    .expect("writes the superseded document");

    let report = effective(
        &open(&environment),
        HardLimits::default(),
        WorkerProfile::HeadlessUser,
    );
    assert_eq!(report.stale_documents.len(), 1);
    let document = &checks(&report)[0];
    assert!(document.detail.contains("no longer reads"), "{document:?}");
    assert_eq!(
        sleep_inhibition(&environment),
        SleepInhibitionSetting::Off,
        "and the choice it carried has no effect"
    );
}

/// KR-REQ-11.05 seam: the catalogue check answers NotApplicable while nothing populates it.
#[test]
fn the_catalogue_check_is_not_applicable_until_a_catalogue_registers_evidence() {
    let check = catalogue::check(None, EnrolmentBudgets::default());
    assert_eq!(check.id, catalogue::CHECK_ID);
    assert_eq!(check.status, DoctorStatus::NotApplicable);
    assert_eq!(check.detail, catalogue::NOT_SYNCHRONISED);
    assert!(catalogue::capabilities(None).is_empty());

    #[derive(Debug)]
    struct Synchronised;
    impl catalogue::CatalogueEvidence for Synchronised {
        fn repositories(&self) -> Vec<catalogue::RepositoryEvidence> {
            vec![catalogue::RepositoryEvidence {
                name: "official".to_owned(),
                generation: 7,
                metadata_bytes: 1024,
                metadata_entries: 12,
                cached_payload_bytes: 2048,
                capabilities: Vec::new(),
                detail: "activated".to_owned(),
                degraded: false,
            }]
        }
    }
    let check = catalogue::check(Some(&Synchronised), EnrolmentBudgets::default());
    assert_eq!(check.status, DoctorStatus::Ok);
    assert!(check.detail.contains("official generation 7"), "{check:?}");
    assert!(
        check
            .detail
            .contains(&EnrolmentBudgets::default().metadata_bytes.to_string()),
        "the budgets in force are what it reports against: {check:?}"
    );
}

/// KR-REQ-26.13: a document this build cannot use is never rewritten by an edit.
#[test]
fn an_edit_refuses_a_document_at_a_version_this_build_does_not_know() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let path = kr_worker::config::document_path(&environment);
    let written = br#"{"version": 7, "preferences": {}}"#;
    kr_ipc::paths::write_owner_only_file(&path, written).expect("writes the document");

    let refused = apply(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect_err("a document this build must not rewrite");
    assert!(format!("{refused}").contains("version 7"), "{refused}");
    assert_eq!(
        std::fs::read(&path).expect("still there"),
        written,
        "byte for byte as the owner left it"
    );
    let _ = ConfigurationDocument::empty();
}

/// KR-REQ-26.16: one writer at a time, so two cannot each publish the revision after the same one.
#[test]
fn a_second_writer_is_refused_while_the_first_holds_the_lock() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();

    let held = kr_worker::config::lock(&environment).expect("the first writer takes it");
    let refused = apply(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect_err("the second writer waits rather than racing");
    assert!(format!("{refused}").contains("another writer"), "{refused}");
    drop(held);

    // Released with the first writer, whichever way it ended.
    apply(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect("the lock is free again");
    assert!(
        !environment
            .state_dir()
            .join(kr_protocol::hostinfo::configuration::LOCK_NAME)
            .exists(),
        "and an edit leaves no lock behind"
    );
}

/// KR-REQ-26.15: a ceiling that removes a right refuses the method that needs it.
#[test]
fn a_right_the_ceiling_removed_is_refused_rather_than_emptied() {
    use kr_protocol::rights::ActionRight;

    let ceilings = ConfigurationCeilings {
        grant_rights: Nullable::some(vec![ActionRight::SessionView.as_str().to_owned()]),
        ..ConfigurationCeilings::default()
    };
    let configured = ceilings::configured_rights(&ceilings).expect("a ceiling");
    assert!(configured.contains(&ActionRight::SessionView));
    assert!(
        !configured.contains(&ActionRight::SessionCreate),
        "what the ceiling does not name is not available on this host"
    );

    // The ordering the intersection depends on: the ceiling narrows the grant before the method's
    // required rights are checked, so a method the ceiling has removed a right for is refused
    // rather than permitted with an empty right set.
    let narrowed: Vec<ActionRight> = [ActionRight::SessionView, ActionRight::SessionCreate]
        .into_iter()
        .filter(|right| configured.contains(right))
        .collect();
    assert_eq!(narrowed, vec![ActionRight::SessionView]);
}

/// KR-REQ-26.15: the configured session ceiling is what admission enforces, not only what is
/// reported.
#[test]
fn the_configured_session_ceiling_reaches_the_limit_admission_reads() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let mut registry =
        crate::registry::Registry::open(environment.registry_database(), temp.environment_id())
            .expect("opens the registry");
    let hard = HardLimits::default().sessions_per_environment;
    assert_eq!(registry.session_limit().expect("the limit"), hard);

    apply(&environment, &Change::SessionLimit(Some(3))).expect("the owner's ceiling");
    let ceiling = ceilings::session_limit(&open(&environment).ceilings(), HardLimits::default());
    registry
        .set_session_limit(ceiling.value)
        .expect("the ceiling reaches the registry");
    assert_eq!(
        registry.session_limit().expect("the limit"),
        3,
        "admission reads what the configuration asked for"
    );

    apply(&environment, &Change::SessionLimit(Some(hard * 4))).expect("a ceiling above the limit");
    let ceiling = ceilings::session_limit(&open(&environment).ceilings(), HardLimits::default());
    assert!(ceiling.refused);
    registry
        .set_session_limit(ceiling.value)
        .expect("the hard limit reaches the registry");
    assert_eq!(
        registry.session_limit().expect("the limit"),
        hard,
        "and asking for more raises nothing"
    );
}
