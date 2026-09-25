//! What this host's own configuration comes out as.

use kr_protocol::desktop::CapabilityInvalidation;
use kr_protocol::hostinfo::configuration::{
    Change, ConfigurationCeilings, ConfigurationDocument, ConfiguredEnrolmentBudgets,
    DocumentState, EnrolmentBudgets, ValueEffect,
};
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::scalars::Nullable;

use super::*;

/// One edit, applied the way the host applies it, with the lock released before the assertion.
fn edit_once(
    environment: &kr_ipc::paths::EnvironmentPaths,
    change: &Change,
) -> Result<WrittenEdit> {
    apply(environment, change, HardLimits::default())
}

/// One edit, and what the document it wrote owes beyond being written.
///
/// Read from the two documents rather than from the change, because that is what the daemon
/// does: a person editing the same file in a text editor owes the same effects.
fn edit_and_owed(
    environment: &kr_ipc::paths::EnvironmentPaths,
    change: &Change,
) -> Result<(WrittenEdit, configuration::Owed)> {
    let before = kr_worker::config::load(environment).document;
    let edit = edit_once(environment, change)?;
    let after = kr_worker::config::load(environment).document;
    let owed = configuration::owed(before.as_ref(), after.as_ref());
    Ok((edit, owed))
}

/// The report of a host acting on exactly what its document says.
fn reported(environment: &kr_ipc::paths::EnvironmentPaths) -> EffectiveConfiguration {
    effective(
        &Accepted::in_force(open(environment), HardLimits::default()),
        HardLimits::default(),
        WorkerProfile::HeadlessUser,
    )
}

/// KR-REQ-26.16: an edit is validated, then a revision is applied, then it is written.
#[test]
fn an_edit_applies_one_revision_and_a_refused_edit_applies_none() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();

    let (applied, owed) = edit_and_owed(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
    )
    .expect("the owner's choice");
    assert_eq!(applied.revision, 1);
    assert_eq!(applied.effect, ValueEffect::Immediately);
    assert!(!owed.fences_dispatch);
    assert!(owed.invalidated.is_empty());
    assert_eq!(
        sleep_inhibition(&environment),
        SleepInhibitionSetting::MainsOnly
    );
    drop(applied);

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
    let (applied, owed) = edit_and_owed(
        &environment,
        &Change::WorkerProfile(WorkerProfile::HeadlessUser),
    )
    .expect("the owner's choice");
    assert_eq!(applied.effect, ValueEffect::NewSessionsOnly);
    assert_eq!(
        owed.invalidated,
        vec![CapabilityInvalidation::WorkerProfile]
    );
    assert!(
        !owed.fences_dispatch,
        "a profile is not authority, so nothing is fenced"
    );
    drop(applied);

    // The same profile again is a new revision of the document and no movement at all, so it
    // invalidates nothing: what decides an effect is what changed, not what was asked for.
    let (_applied, owed) = edit_and_owed(
        &environment,
        &Change::WorkerProfile(WorkerProfile::HeadlessUser),
    )
    .expect("the owner's choice again");
    assert!(
        owed.invalidated.is_empty(),
        "a value that did not move invalidates nothing: {owed:?}"
    );
}

/// KR-REQ-26.16: a change that affects authority says so, so dispatch is fenced first.
#[test]
fn a_grant_ceiling_change_fences_dispatch_before_it_is_acknowledged() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let (applied, owed) = edit_and_owed(
        &environment,
        &Change::GrantRights(Some(vec!["session.view".to_owned()])),
    )
    .expect("a ceiling naming a right this build knows");
    assert!(owed.fences_dispatch);
    assert_eq!(applied.effect, ValueEffect::Immediately);
    drop(applied);

    let refused = edit_once(
        &environment,
        &Change::GrantRights(Some(vec!["not.a.right".to_owned()])),
    )
    .expect_err("a name that is not an action right");
    // The name is not repeated: a right a document invented is a name somebody wrote, and a
    // refusal travels into a diagnostic and a support bundle.
    let refused = format!("{refused}");
    assert!(!refused.contains("not.a.right"), "{refused}");
    assert!(
        refused.contains("a configured right ([name withheld, 11 bytes]) is not an action right"),
        "{refused}"
    );
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
        session_limit_in_force(&resolver, measured),
        Some(3),
        "and the number the owner accepted is still the one in force"
    );
}

/// KR-REQ-26.15: a payload budget above the default without the explicit setting is refused.
#[test]
fn an_enrolment_budget_above_the_default_needs_the_explicit_setting() {
    let mut budgets = ConfiguredEnrolmentBudgets {
        cached_payload_bytes: Nullable::some(8 * 1024 * 1024 * 1024),
        ..ConfiguredEnrolmentBudgets::default()
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

    budgets.full_offline_mirror = Nullable::some(true);
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

    let report = reported(&environment);
    assert_eq!(report.schema_version.get(), configuration::VERSION);
    assert_eq!(report.revision.get(), 1);
    assert_eq!(report.status.state, DocumentState::Loaded);
    assert_eq!(report.precedence.len(), 4);
    assert_eq!(report.overrides.len(), 2);
    assert_eq!(
        report.values.len(),
        4 + configuration::SELECTIONS.len(),
        "two preferences, two locations and every selection read at the next start"
    );
    for (row, selection) in report.values[4..].iter().zip(configuration::SELECTIONS) {
        assert_eq!(row.key, selection.key);
        assert_eq!(row.effect, ValueEffect::NextStart);
        assert_eq!(
            row.source,
            kr_protocol::hostinfo::configuration::ValueSource::Default,
            "{} is not in this document",
            row.key
        );
    }

    let power = report
        .values
        .iter()
        .find(|value| value.key == "sleep_inhibition")
        .expect("the sleep policy");
    assert_eq!(power.value(), "battery_too");
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
        secret_line(&report).render(),
        "no secure-store references are configured"
    );
}

/// KR-REQ-01.23: the configuration's diagnostics report the document, the order and the ceilings.
#[test]
fn the_diagnostics_report_the_document_the_order_the_overrides_and_the_ceilings() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let report = reported(&environment);
    let produced = checks(&report);
    let ids: Vec<&str> = produced.iter().map(|check| check.id()).collect();
    assert_eq!(
        ids,
        vec![
            "configuration-document",
            "configuration-in-force",
            "configuration-precedence",
            "configuration-overrides",
            "configuration-ceilings",
        ]
    );
    for check in &produced {
        assert!(!check.evidence().is_empty(), "{} has evidence", check.id());
    }
    let by_id = |id: &str| {
        produced
            .iter()
            .find(|check| check.id() == id)
            .unwrap_or_else(|| panic!("the {id} check"))
    };
    let precedence = by_id("configuration-precedence");
    assert!(
        precedence.detail().contains("explicit request"),
        "{precedence:?}"
    );
    assert!(
        precedence.detail().contains("product default"),
        "{precedence:?}"
    );
    let overrides = by_id("configuration-overrides");
    assert!(overrides.detail().contains("KR_STATE_DIR"), "{overrides:?}");
    assert!(
        overrides
            .detail()
            .contains("No other inherited variable takes part in the precedence"),
        "{overrides:?}"
    );
    assert!(
        overrides.detail().contains("This build also reads"),
        "and it says what this build reads outside the precedence: {overrides:?}"
    );
    // KR-REQ-26.14: the certificate store variables other programs read are named whether or not
    // they are set, with where an authority given only through them has to go.
    for variable in configuration::CERTIFICATE_STORE_VARIABLES {
        assert!(overrides.detail().contains(variable), "{overrides:?}");
    }
    assert!(
        overrides
            .detail()
            .contains("until it is installed in the system store"),
        "{overrides:?}"
    );
    // The endpoint's relays and discovery servers are verified against other anchors, and the
    // sentence says which rather than claiming the system store for them.
    assert!(
        overrides.detail().contains("network.relay_trust_anchors"),
        "{overrides:?}"
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

    let report = reported(&environment);
    assert_eq!(report.stale_documents.len(), 1);
    let document = &checks(&report)[0];
    assert!(
        document.detail().contains("no longer reads"),
        "{document:?}"
    );
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
    assert_eq!(check.id(), catalogue::CHECK_ID);
    assert_eq!(check.status, DoctorStatus::NotApplicable);
    assert_eq!(check.detail(), catalogue::NOT_SYNCHRONISED);
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
    assert!(
        check
            .detail()
            .contains("[name withheld, 8 bytes] generation 7"),
        "a repository's own name comes from the catalogue: {check:?}"
    );
    assert!(
        check
            .detail()
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
        session_limit_in_force(&open(&environment), limits),
        None,
        "a document that says nothing about it changes nothing"
    );

    edit_once(&environment, &Change::SessionLimit(Some(3))).expect("the owner's number");
    let limit = session_limit_in_force(&open(&environment), limits).expect("a configured number");
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
        session_limit_in_force(&open(&environment), limits),
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
        own_subject: None,
        now_ms: 1_000,
        continuous_now: kr_transport::clock::ContinuousClock::now(
            &kr_transport::clock::ManualClock::new(),
        ),
    };

    // No ceiling: the grant decides on its own, and the input right is in the decision.
    let open_host = ConfigurationCeilings::default();
    let decided = ceilings::decide_with_ceiling(
        ceilings::configured_rights(&open_host).as_ref(),
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
        ceilings::configured_rights(&narrowed).as_ref(),
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
        ceilings::configured_rights(&wider).as_ref(),
        &grant,
        &record,
        &mut policy,
        request(Method::SessionRead),
    )
    .expect("the grant still decides");
    assert!(!decided.permitted.rights.contains(&ActionRight::HostManage));
    assert!(decided.refused_rights.contains(&ActionRight::HostManage));

    // A method that needs a right the ceiling removed is refused by that right's name, and the
    // refusal says the configuration removed it rather than that the grant lacks it.
    let refused = ceilings::decide_with_ceiling(
        ceilings::configured_rights(&narrowed).as_ref(),
        &grant,
        &record,
        &mut policy,
        request(Method::InputWrite),
    )
    .expect_err("the input right is gone from this host");
    assert_eq!(
        refused,
        ceilings::CeilingRefusal::RemovedByConfiguration {
            right: ActionRight::TerminalInput
        }
    );
    assert!(
        refused.detail().contains("terminal.input") && refused.detail().contains("configuration"),
        "{}",
        refused.detail()
    );

    // And a method that needs a right the grant never carried is the grant's refusal, whatever
    // the ceiling names.
    let refused = ceilings::decide_with_ceiling(
        ceilings::configured_rights(&wider).as_ref(),
        &grant,
        &record,
        &mut policy,
        request(Method::DeviceList),
    )
    .expect_err("the grant carries no host.manage");
    assert_eq!(
        refused,
        ceilings::CeilingRefusal::Refused(crate::grants::Refusal::MissingRight {
            right: ActionRight::HostManage
        })
    );

    // What the ceiling in force removes from every grant, named from the vocabulary.
    let removed = ceilings::removed_by(
        &ceilings::configured_rights(&narrowed).expect("a configured ceiling"),
    );
    assert_eq!(removed.len(), ActionRight::ALL.len() - 1);
    assert!(!removed.contains(&ActionRight::SessionView));
}

/// A decision says when time alone ends it: the grant's expiry, or for a caller away from this
/// machine the end of the bounded offline validity, whichever comes first, and nothing when neither
/// can be represented.
#[test]
fn a_decision_lapses_at_its_grants_expiry_or_the_end_of_the_offline_bound() {
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvironmentId, GrantId};
    use kr_protocol::method::Method;
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, DurationMs, TimestampMs, Uuid};
    use kr_protocol::sharing::OfflineValidityPolicy;

    let environment_id = EnvironmentId::new(Uuid::from_bytes([0xe1; 16]));
    let grant = |expiry| Grant {
        grant_id: GrantId::new(Uuid::from_bytes([2; 16])),
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf2; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf3; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView].into_iter().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry,
        organisation: Nullable::null(),
    };
    let lapses = |expiry, offline: Option<OfflineValidityPolicy>, ingress| {
        let grant = grant(expiry);
        let record = crate::grants::GrantRecord {
            session_id: None,
            grant: grant.clone(),
            issued_at_ms: 1_000,
            activated_at_ms: Some(1_000),
            revoked_at_ms: None,
            revoked_by_parent: None,
        };
        let mut policy = crate::grants::HostPolicy::personal(AuthorityRevision::new(1));
        policy.set_offline_validity(offline);
        policy.publish_unanchored(&policy.clone());
        ceilings::decide_with_ceiling(
            None,
            &grant,
            &record,
            &mut policy,
            crate::grants::AccessRequest {
                method: Method::SessionList,
                ingress,
                environment_id,
                session_id: None,
                claims_geometry: false,
                own_subject: None,
                now_ms: 1_000,
                continuous_now: kr_transport::clock::ContinuousClock::now(
                    &kr_transport::clock::ManualClock::new(),
                ),
            },
        )
        .expect("the grant decides")
        .lapses_at_ms
    };
    let expiring = GrantExpiry::At {
        expires_at_ms: TimestampMs::new(9_000),
    };
    let bounded = OfflineValidityPolicy {
        maximum_offline_ms: DurationMs::new(1_000),
        last_synchronised_at_ms: Nullable::some(TimestampMs::new(500)),
    };
    let remote = ActorIngress::PairedDevice;

    assert_eq!(lapses(GrantExpiry::Never, None, remote), None);
    assert_eq!(lapses(expiring, None, remote), Some(9_000));
    assert_eq!(
        lapses(GrantExpiry::Never, Some(bounded), remote),
        Some(1_501),
        "the bound holds through its last millisecond"
    );
    assert_eq!(lapses(expiring, Some(bounded), remote), Some(1_501));
    assert_eq!(
        lapses(GrantExpiry::Never, Some(bounded), ActorIngress::LocalIpc),
        None,
        "a person at this machine is not held to the offline bound"
    );
    let unbounded = OfflineValidityPolicy {
        maximum_offline_ms: DurationMs::new(u64::MAX),
        last_synchronised_at_ms: Nullable::some(TimestampMs::new(1)),
    };
    assert_eq!(
        lapses(GrantExpiry::Never, Some(unbounded), remote),
        None,
        "a bound that ends beyond every representable moment ends at none of them"
    );
    assert_eq!(lapses(expiring, Some(unbounded), remote), Some(9_000));
}

/// KR-REQ-26.15: the report names the rights ceiling in force and what it removes, and keeps a
/// ceiling this host accepted when the document in front of it decides nothing.
#[test]
fn the_report_names_what_the_rights_ceiling_removes() {
    use kr_protocol::rights::ActionRight;

    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    edit_once(
        &environment,
        &Change::GrantRights(Some(vec![
            ActionRight::SessionView.as_str().to_owned(),
            ActionRight::TerminalInput.as_str().to_owned(),
        ])),
    )
    .expect("a ceiling");
    let report = reported(&environment);
    let rights = report
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "grant_rights")
        .expect("the rights ceiling");
    assert_eq!(rights.value.as_str(), "session.view, terminal.input");
    let removed = rights
        .narrowed_by
        .as_ref()
        .expect("what it removes")
        .as_str();
    assert!(
        removed.starts_with("this ceiling removes terminal.geometry, "),
        "{removed}"
    );
    assert!(
        removed.contains("host.manage, voice.use from every grant on this host"),
        "{removed}"
    );
    assert!(!removed.contains("session.view,"), "{removed}");

    // The document becomes unreadable; the ceiling this host accepted is what it still enforces.
    let resolver = open(&environment);
    let accepted = Accepted {
        rights: EnforcedRights {
            ceiling: ceilings::configured_rights(&resolver.ceilings()),
            from_document: false,
        },
        ..Accepted::in_force(
            Resolver::from_loaded(
                kr_protocol::hostinfo::configuration::unreadable(
                    Sentence::new().stated("this file must not be a symbolic link"),
                ),
                &environment,
            ),
            HardLimits::default(),
        )
    };
    let report = effective(
        &accepted,
        HardLimits::default(),
        WorkerProfile::HeadlessUser,
    );
    let rights = report
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "grant_rights")
        .expect("the rights ceiling");
    assert_eq!(rights.value.as_str(), "session.view, terminal.input");
    assert!(
        !rights.configured.is_present(),
        "the document asks for nothing"
    );
    assert!(
        rights
            .narrowed_by
            .as_ref()
            .expect("why")
            .as_str()
            .starts_with("this host is still enforcing the ceiling it last accepted"),
        "{:?}",
        rights.narrowed_by
    );
}

/// KR-REQ-01.23, KR-REQ-26.16: effects that failed leave the report describing what is enforced,
/// and say plainly that the document is not in force.
#[test]
fn a_document_whose_effects_failed_is_reported_as_not_in_force() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    edit_once(&environment, &Change::SessionLimit(Some(9))).expect("the owner's ceiling");

    // What the daemon hands the report when the number a document asks for could not be recorded:
    // the number still in force, and the sentence saying why it is not the one written down.
    let accepted = Accepted {
        sessions: Enforced {
            value: 4,
            from_document: false,
        },
        not_in_force: Some(Sentence::new().stated("this host still admits 4 sessions")),
        ..Accepted::in_force(open(&environment), HardLimits::default())
    };
    let report = effective(
        &accepted,
        HardLimits::default(),
        WorkerProfile::HeadlessUser,
    );
    let ceiling = report
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "session_limit")
        .expect("the session ceiling");
    assert_eq!(
        ceiling.configured.as_ref().map(Sentence::as_str),
        Some("9"),
        "the report says what the document asks for"
    );
    assert_eq!(
        ceiling.value.as_str(),
        "4",
        "and prints the number admission is enforcing, not the one it asked for"
    );
    let produced = checks(&report);
    let in_force = produced
        .iter()
        .find(|check| check.id() == "configuration-in-force")
        .expect("the in-force check");
    assert_eq!(in_force.status, DoctorStatus::Failed);
    assert!(
        in_force.detail().contains("still admits 4 sessions"),
        "{in_force:?}"
    );
    assert!(
        in_force.remedy().is_some(),
        "and it says what to do: {in_force:?}"
    );
}

/// KR-REQ-01.23: an enrolment section that names one budget is one budget the owner configured,
/// not ten.
#[test]
fn each_enrolment_budget_keeps_whether_it_was_configured_or_defaulted() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();

    let report = reported(&environment);
    let enrolment = report
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "enrolment")
        .expect("the enrolment ceiling");
    assert_eq!(
        enrolment.source,
        configuration::ValueSource::Default,
        "a host that configured nothing reports the defaults as defaults"
    );
    assert!(
        enrolment.origin.0.is_none(),
        "and names no document as their origin: {:?}",
        enrolment.origin
    );

    // One budget raised, the other nine left out of the document entirely.
    let raised = ConfiguredEnrolmentBudgets {
        retained_generations: Nullable::some(5),
        ..ConfiguredEnrolmentBudgets::default()
    };
    edit_once(&environment, &Change::Enrolment(raised)).expect("the owner's budget");

    let report = reported(&environment);
    let enrolment = report
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "enrolment")
        .expect("the enrolment ceiling");
    assert_eq!(
        enrolment.source,
        configuration::ValueSource::HostConfiguration,
        "the section the owner wrote is the host's configuration"
    );
    assert!(
        enrolment
            .value
            .as_str()
            .contains("configured here: retained_generations"),
        "and the report names the one budget they chose: {}",
        enrolment.value
    );
    assert_eq!(
        raised.supplied(),
        vec!["retained_generations"],
        "the rest are the schema's own numbers"
    );

    // A budget written with the number the schema already uses. Equality would call it a default;
    // presence calls it what it is, which is a number this host's owner wrote down.
    let spelled_out = ConfiguredEnrolmentBudgets {
        metadata_bytes: Nullable::some(EnrolmentBudgets::default().metadata_bytes),
        ..ConfiguredEnrolmentBudgets::default()
    };
    edit_once(&environment, &Change::Enrolment(spelled_out)).expect("the owner's budget");
    let report = reported(&environment);
    let enrolment = report
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "enrolment")
        .expect("the enrolment ceiling");
    assert_eq!(
        enrolment.source,
        configuration::ValueSource::HostConfiguration,
        "a budget spelled out is a budget somebody chose"
    );
    assert!(
        enrolment.origin.is_present(),
        "and the document they wrote it in is named: {:?}",
        enrolment.origin
    );
    assert!(
        enrolment
            .value
            .as_str()
            .contains("configured here: metadata_bytes"),
        "{}",
        enrolment.value
    );
}

/// KR-REQ-26.14: the network and the voice broker in force are what the running services report,
/// and a document that now selects something other than what this host started with is reported as
/// applying at the next start.
#[test]
fn the_network_check_says_what_is_in_force_and_what_waits_for_the_next_start() {
    let mut document = ConfigurationDocument::empty();
    document.network.enabled = Nullable::some(true);
    document.network.relay_urls = Nullable::some(vec!["https://relay.example.com".to_owned()]);
    document.network.dns_origin = Nullable::some("discovery.example.com".to_owned());
    let started = Started::of(Some(&document));
    let endpoint = crate::service::net::config::NetworkSettings::from_selection(&document.network)
        .expect("a usable selection")
        .expect("this host joins")
        .endpoint;
    let running = Running {
        network: Some(RunningNetwork::of(&endpoint, 2)),
        names_a_broker: false,
    };

    let check = network_check(&started, Some(&document), running);
    assert_eq!(check.id(), "configuration-network");
    assert_eq!(check.status, DoctorStatus::Ok, "{check:?}");
    assert_eq!(
        check.detail(),
        "this host is on the network: its endpoint holds 2 sockets, with 1 relays and 1 \
         discovery services selected; its voice service names no managed broker"
    );

    // The owner turns the network off and names a broker while the host runs.
    let mut edited = document.clone();
    edited.network.enabled = Nullable::some(false);
    edited.voice.broker_origin = Nullable::some("https://voice.example.com".to_owned());
    let check = network_check(&started, Some(&edited), running);
    assert_eq!(check.status, DoctorStatus::Warning);
    assert!(
        check.detail().ends_with("which applies at the next start"),
        "{check:?}"
    );
    assert!(
        check
            .remedy()
            .is_some_and(|remedy| remedy.contains("Restart"))
    );

    // A host on no network says so, and a document it cannot use selects nothing too.
    let quiet = network_check(&Started::default(), None, Running::default());
    assert_eq!(quiet.status, DoctorStatus::Ok);
    assert_eq!(
        quiet.detail(),
        "this host is not on the network, and serves its local endpoint alone; its voice \
         service names no managed broker"
    );
}
