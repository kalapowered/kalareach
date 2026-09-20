//! What this host's own configuration comes out as.

use kr_protocol::desktop::CapabilityInvalidation;
use kr_protocol::hostinfo::configuration::{
    Change, ConfigurationCeilings, ConfigurationDocument, DocumentState, EnrolmentBudgets,
    ValueEffect,
};
use kr_protocol::scalars::Nullable;

use super::*;

/// One edit, applied the way the host applies it, with the lock released before the assertion.
fn edit_once(environment: &kr_ipc::paths::EnvironmentPaths, change: &Change) -> Result<Applied> {
    apply(environment, change, HardLimits::default()).map(|edit| edit.applied.clone())
}

/// KR-REQ-26.16: an edit is validated, then a revision is applied, then it is written.
#[test]
fn an_edit_applies_one_revision_and_a_refused_edit_applies_none() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();

    let applied = edit_once(
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

    let refused = edit_once(&environment, &Change::SessionLimit(Some(0)))
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
    let applied = edit_once(
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
    let applied = edit_once(
        &environment,
        &Change::GrantRights(Some(vec!["session.view".to_owned()])),
    )
    .expect("a ceiling naming a right this build knows");
    assert!(applied.fences_dispatch);
    assert_eq!(applied.effect, ValueEffect::Immediately);

    let refused = edit_once(
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
    edit_once(&environment, &Change::SessionLimit(Some(4))).expect("the other writer's edit");

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

/// KR-REQ-26.15: the configured number applies, and a resource limit narrows it when one exists.
///
/// Section 2 makes 128 the default admission and says the owner configures it, so a number above
/// 128 is the owner's choice rather than something to refuse. What narrows it is what this machine
/// can actually run, and this host establishes no such limit yet: with none established the
/// owner's number stands, and with one established a larger number is refused.
#[test]
fn the_configured_session_number_is_narrowed_only_by_a_resource_limit() {
    let unmeasured = HardLimits::default();
    assert_eq!(unmeasured.sessions_per_environment, None);

    let none_chosen = ConfigurationCeilings::default();
    let ceiling = ceilings::session_limit(&none_chosen, unmeasured);
    assert_eq!(ceiling.configured, None);
    assert_eq!(
        ceiling.value,
        kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64,
        "the product default is the bottom rung"
    );

    let raised = ConfigurationCeilings {
        session_limit: Nullable::some(512),
        ..ConfigurationCeilings::default()
    };
    let ceiling = ceilings::session_limit(&raised, unmeasured);
    assert_eq!(
        ceiling.value, 512,
        "the owner's own number, with nothing to narrow it"
    );
    assert!(!ceiling.refused);

    let measured = HardLimits {
        sessions_per_environment: Some(64),
    };
    let ceiling = ceilings::session_limit(&raised, measured);
    assert_eq!(ceiling.value, 64);
    assert!(
        ceiling.refused,
        "asking for more than the machine allows raises nothing"
    );
    assert!(ceiling.narrowed_by.is_some());

    let lowered = ConfigurationCeilings {
        session_limit: Nullable::some(8),
        ..ConfigurationCeilings::default()
    };
    assert_eq!(ceilings::session_limit(&lowered, measured).value, 8);
}

/// KR-REQ-26.15: an edit the intersection would refuse is refused before it is written.
#[test]
fn an_edit_the_intersection_would_refuse_leaves_the_document_alone() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    apply(
        &environment,
        &Change::SessionLimit(Some(3)),
        HardLimits::default(),
    )
    .expect("the owner's number");

    let measured = HardLimits {
        sessions_per_environment: Some(4),
    };
    let refused = apply(&environment, &Change::SessionLimit(Some(512)), measured)
        .expect_err("more than this machine allows");
    assert!(
        format!("{refused}").contains("more permissive"),
        "{refused}"
    );
    let resolver = open(&environment);
    assert_eq!(resolver.revision(), 1, "a refused edit applies no revision");
    assert_eq!(
        configured_session_limit(&resolver, measured),
        Some(3),
        "and the number the owner accepted is still the one in force"
    );
}

/// KR-REQ-26.15: a payload budget above the default without the explicit setting is refused.
#[test]
fn an_enrolment_budget_above_the_default_needs_the_explicit_setting() {
    let mut budgets = EnrolmentBudgets {
        cached_payload_bytes: 8 * 1024 * 1024 * 1024,
        ..EnrolmentBudgets::default()
    };
    let asked = ConfigurationCeilings {
        enrolment: Nullable::some(budgets),
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
        enrolment: Nullable::some(budgets),
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
    edit_once(
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

    let refused = edit_once(
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
    let refused = edit_once(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect_err("the second writer waits rather than racing");
    assert!(format!("{refused}").contains("another writer"), "{refused}");
    drop(held);

    // Released with the first writer, whichever way it ended.
    edit_once(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect("the lock is free again");
    assert!(
        environment
            .state_dir()
            .join(kr_protocol::hostinfo::configuration::LOCK_NAME)
            .exists(),
        "the lock file remains in place and is free to acquire"
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

/// KR-REQ-26.15: the configured session number is what admission enforces, and a document this
/// host cannot use never lifts a restriction the owner accepted.
#[test]
fn the_configured_session_number_reaches_the_limit_admission_reads() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let mut registry =
        crate::registry::Registry::open(environment.registry_database(), temp.environment_id())
            .expect("opens the registry");
    let limits = HardLimits::default();
    assert_eq!(
        registry.session_limit().expect("the limit"),
        kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64
    );

    assert_eq!(
        configured_session_limit(&open(&environment), limits),
        None,
        "a document that says nothing about it changes nothing"
    );

    edit_once(&environment, &Change::SessionLimit(Some(3))).expect("the owner's number");
    let limit = configured_session_limit(&open(&environment), limits).expect("a configured number");
    registry
        .set_session_limit(limit)
        .expect("the number reaches the registry");
    assert_eq!(registry.session_limit().expect("the limit"), 3);

    // A document this build cannot use says nothing, so the number the owner accepted stands.
    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(&environment),
        br#"{"version": 4096}"#,
    )
    .expect("a document from a later build");
    assert_eq!(
        configured_session_limit(&open(&environment), limits),
        None,
        "and a restriction is never lifted because a file could not be read"
    );
}

/// KR-REQ-26.15: the configured ceiling narrows the grant before the method's rights are checked.
///
/// This calls the intersection itself rather than reproducing it: a ceiling that removes a right
/// the method needs has to come back as a refusal, not as a permission with nothing in it.
#[test]
fn the_ceiling_narrows_the_grant_the_decision_is_taken_against() {
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvironmentId, GrantId, SessionId};
    use kr_protocol::method::Method;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Uuid};

    let environment_id = EnvironmentId::new(Uuid::from_bytes([0xe0; 16]));
    let session_id = SessionId::new(Uuid::from_bytes([0xa0; 16]));
    let grant = Grant {
        grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::These {
            environment_ids: [environment_id].into_iter().collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: [session_id].into_iter().collect(),
        },
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::from_iter([]),
            named_approvals: CanonicalSet::from_iter([]),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    };
    let record = crate::grants::GrantRecord {
        session_id: Some(session_id),
        grant: grant.clone(),
        issued_at_ms: 1_000,
        activated_at_ms: Some(1_000),
        revoked_at_ms: None,
        revoked_by_parent: None,
    };
    let mut policy = crate::grants::HostPolicy::personal(AuthorityRevision::new(1));
    let request = |method| crate::grants::AccessRequest {
        method,
        ingress: ActorIngress::PairedDevice,
        environment_id,
        session_id: Some(session_id),
        claims_geometry: false,
        recipient_account: None,
        own_subject: None,
        now_ms: 1_000,
    };

    // No ceiling: the grant decides on its own, and the input right is in the decision.
    let open_host = ConfigurationCeilings::default();
    let decided = ceilings::decide_with_ceiling(
        &open_host,
        &grant,
        &record,
        &mut policy,
        request(Method::SessionRead),
    )
    .expect("the grant decides");
    assert!(
        decided
            .permitted
            .rights
            .contains(&ActionRight::TerminalInput)
    );
    assert!(decided.removed.is_empty());

    // A ceiling that keeps only the view right takes the input right out of the decision, and
    // takes it out before the decision rather than after it.
    let narrowed = ConfigurationCeilings {
        grant_rights: Nullable::some(vec![ActionRight::SessionView.as_str().to_owned()]),
        ..ConfigurationCeilings::default()
    };
    let decided = ceilings::decide_with_ceiling(
        &narrowed,
        &grant,
        &record,
        &mut policy,
        request(Method::SessionRead),
    )
    .expect("a method the remaining right answers for");
    assert!(decided.permitted.rights.contains(&ActionRight::SessionView));
    assert!(
        !decided
            .permitted
            .rights
            .contains(&ActionRight::TerminalInput),
        "what the ceiling removed is gone from the decision"
    );
    assert!(decided.removed.contains(&ActionRight::TerminalInput));
    assert!(
        decided.refused_rights.is_empty(),
        "the ceiling named nothing the grant does not carry"
    );

    // A ceiling naming a right the grant never carried adds nothing and is reported.
    let wider = ConfigurationCeilings {
        grant_rights: Nullable::some(vec![
            ActionRight::SessionView.as_str().to_owned(),
            ActionRight::HostManage.as_str().to_owned(),
        ]),
        ..ConfigurationCeilings::default()
    };
    let decided = ceilings::decide_with_ceiling(
        &wider,
        &grant,
        &record,
        &mut policy,
        request(Method::SessionRead),
    )
    .expect("the grant still decides");
    assert!(!decided.permitted.rights.contains(&ActionRight::HostManage));
    assert!(decided.refused_rights.contains(&ActionRight::HostManage));
}
