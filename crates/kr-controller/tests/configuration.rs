//! The configuration this daemon answers with, over the paired-device path.
//!
//! What these demonstrate. KR-REQ-26.13: `host.doctor` reports the schema version, the OS
//! appropriate locations, the precedence order and each effective value with its source.
//! KR-REQ-26.14: only the documented allowlist participates, at the position it declares, and an
//! inherited variable outside it changes nothing. KR-REQ-26.15: the configured ceilings intersect
//! and a more permissive one is refused; a secret is a named reference and no value is exported.
//! KR-REQ-26.16: an edit is validated before a revision is applied, and a change that affects
//! authority advances the revision before the caller is told it is in force. KR-REQ-01.23: every
//! existing check id is still there, with the configuration's own checks beside them.
//!
//! The diagnostics are a read the daemon answers itself, so no worker is started here.

mod net_support;

use kr_controller::config;
use kr_controller::config::ceilings;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::desktop::{CapabilityInvalidation, SleepInhibitionSetting};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::hostinfo::HostDoctorResult;
use kr_protocol::hostinfo::configuration::{
    Change, ConfigurationDocument, DocumentState, SecretReference, ValueEffect, ValueSource,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::Host;

/// A grant that sees a session and nothing more, which is all the host's own reads need.
const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

/// The check ids this product has published and may not quietly drop.
const ESTABLISHED_CHECKS: &[&str] = &[
    "runtime-directory",
    "supervisor",
    "workers",
    "sleep-setting",
    "authority-revision",
];

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// KR-REQ-01.23, KR-REQ-26.13: every established check is still there, and the configuration's
/// own checks are beside them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_diagnostics_keep_every_established_check_and_add_the_configuration() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;

    let result: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );
    let ids: Vec<&str> = result
        .checks
        .iter()
        .map(|check| check.id.as_str())
        .collect();
    for established in ESTABLISHED_CHECKS {
        assert!(
            ids.contains(established),
            "{established} is missing: {ids:?}"
        );
    }
    assert!(
        ids.iter().any(|id| id.starts_with("logout-")),
        "the per-profile logout checks are still reported: {ids:?}"
    );
    for added in [
        "configuration-document",
        "configuration-precedence",
        "configuration-overrides",
        "configuration-ceilings",
        "configuration-secrets",
        "catalogue",
    ] {
        assert!(ids.contains(&added), "{added} is missing: {ids:?}");
    }
    assert!(result.healthy, "a fresh host passes its own diagnostics");

    session.close();
    host.stop().await;
}

/// KR-REQ-26.13: the report names the schema version, the locations and each value's source.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_report_names_the_schema_the_locations_and_where_each_value_came_from() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;

    let result: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );
    let reported = &result.configuration;
    assert_eq!(
        reported.schema_version.get(),
        kr_protocol::hostinfo::configuration::VERSION
    );
    assert_eq!(reported.status.state, DocumentState::Absent);
    assert_eq!(
        reported.precedence,
        vec![
            "an explicit request or command-line option".to_owned(),
            "the selected session or environment profile".to_owned(),
            "the per-user host configuration".to_owned(),
            "the product default".to_owned(),
        ],
        "the order section 26 states, in that order"
    );
    assert_eq!(
        reported.runtime_directory,
        host.tree()
            .environment()
            .runtime_dir()
            .display()
            .to_string()
    );
    assert_eq!(
        reported.state_directory,
        host.tree().environment().state_dir().display().to_string()
    );
    for value in &reported.values {
        // A directory an allowlisted variable supplied is reported at the request rung, which is
        // where the allowlist declares it; everything else on a fresh host is the product default.
        // Both cases are here because a build machine gives this run its own tree through those
        // variables and a developer's machine does not.
        match value.variable.0.as_deref() {
            Some(variable) => {
                assert_eq!(value.source, ValueSource::Request, "{}", value.key);
                assert!(
                    kr_protocol::hostinfo::configuration::allowlisted(variable).is_some(),
                    "{variable} supplied a value without being on the allowlist"
                );
            }
            None => assert_eq!(
                value.source,
                ValueSource::Default,
                "{} has no chosen value on a fresh host",
                value.key
            ),
        }
        assert!(
            !value.about.is_empty(),
            "{} says what it decides",
            value.key
        );
    }
    assert!(
        reported.values.iter().any(
            |value| value.key == "sleep_inhibition" && value.effect == ValueEffect::Immediately
        )
    );
    assert!(
        reported
            .values
            .iter()
            .any(|value| value.key == "worker_profile"
                && value.effect == ValueEffect::NewSessionsOnly),
        "an execution context applies to sessions created afterwards, and says so"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.14: the allowlist is the whole of what participates, at its declared position.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_documented_overrides_participate_and_they_say_where() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;

    let result: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );
    let variables: Vec<&str> = result
        .configuration
        .overrides
        .iter()
        .map(|entry| entry.variable.as_str())
        .collect();
    assert_eq!(variables, vec!["KR_RUNTIME_DIR", "KR_STATE_DIR"]);
    for entry in &result.configuration.overrides {
        assert_eq!(entry.position, ValueSource::Request);
        assert!(!entry.why.is_empty());
    }
    let check = result
        .checks
        .iter()
        .find(|check| check.id == "configuration-overrides")
        .expect("the overrides check");
    assert!(
        check
            .detail
            .contains("No other inherited variable takes part in the precedence"),
        "{check:?}"
    );
    assert!(
        check.detail.contains("This build also reads"),
        "and it names what this build reads outside the precedence: {check:?}"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.15: a configured budget more permissive than section 11 allows never applies.
///
/// Two gates, and this shows both. The document is refused when it is read, so nothing is taken
/// out of it and every value is the product default; and the intersection refuses the budget on
/// its own account, so a document that reached the ceiling function by some other path would still
/// not get what it asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_more_permissive_configured_ceiling_is_refused_rather_than_applied() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let environment = host.tree().environment();

    let mut document = ConfigurationDocument::empty();
    document.ceilings.enrolment = Nullable::some(
        kr_protocol::hostinfo::configuration::ConfiguredEnrolmentBudgets {
            cached_payload_bytes: Nullable::some(8 * 1024 * 1024 * 1024),
            ..Default::default()
        },
    );
    let asked = ceilings::enrolment(&document.ceilings);
    assert!(
        asked.refused,
        "the intersection refuses it on its own account"
    );
    assert_eq!(
        asked.value.cached_payload_bytes,
        kr_protocol::hostinfo::configuration::DEFAULT_CACHED_PAYLOAD_BYTES
    );

    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(&environment),
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");

    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;
    let result: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );
    assert_eq!(
        result.configuration.status.state,
        DocumentState::Invalid,
        "the document is refused rather than partly believed"
    );
    assert!(
        result
            .configuration
            .status
            .detail
            .contains("full_offline_mirror"),
        "and it says which rule refused it: {}",
        result.configuration.status.detail
    );
    let ceiling = result
        .configuration
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "enrolment")
        .expect("the enrolment ceiling");
    assert!(
        ceiling.value.contains("1073741824 cached payload bytes"),
        "the budget in force is section 11's own: {}",
        ceiling.value
    );
    let check = result
        .checks
        .iter()
        .find(|check| check.id == "configuration-document")
        .expect("the document check");
    assert_eq!(check.status, kr_protocol::hostinfo::DoctorStatus::Warning);
    assert!(check.remedy.is_present(), "and it says what to do about it");

    session.close();
    host.stop().await;
}

/// KR-REQ-26.15: a secret is a named reference, and the report carries no value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_reaches_the_report_as_a_name_and_never_as_a_value() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let environment = host.tree().environment();
    let mut document = ConfigurationDocument::empty();
    document.secrets.push(SecretReference {
        name: "relay".to_owned(),
        store: "login_keychain".to_owned(),
        item: "kalareach/relay".to_owned(),
    });
    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(&environment),
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");

    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;
    let result: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );
    assert_eq!(result.configuration.secrets.len(), 1);
    let reference = &result.configuration.secrets[0];
    assert_eq!(reference.name, "relay");
    assert_eq!(reference.store, "login_keychain");
    assert_eq!(reference.item, "kalareach/relay");
    let encoded = serde_json::to_value(reference).expect("serialises");
    let mut fields: Vec<&String> = encoded
        .as_object()
        .expect("a reference is an object")
        .keys()
        .collect();
    fields.sort();
    assert_eq!(
        fields,
        vec!["item", "name", "store"],
        "a reference has no field a value would fit in"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.16: a change affecting authority advances the revision before it is acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_affecting_authority_fences_dispatch_before_it_is_acknowledged() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let controller = host.controller();

    let before = controller
        .announce_authority_revision()
        .await
        .expect("the revision in force")
        .authority_revision;
    let applied = controller
        .apply_configuration(&Change::GrantRights(Some(vec![
            ActionRight::SessionView.as_str().to_owned(),
        ])))
        .await
        .expect("the ceiling is applied");
    assert!(applied.fences_dispatch);
    let after = controller
        .announce_authority_revision()
        .await
        .expect("the revision in force")
        .authority_revision;
    assert!(
        after > before,
        "the revision advanced before this returned: {before:?} then {after:?}"
    );

    // A change that is not about authority does not advance it, and does not migrate a worker.
    let applied = controller
        .apply_configuration(&Change::WorkerProfile(
            kr_protocol::identity::WorkerProfile::HeadlessUser,
        ))
        .await
        .expect("the execution context is applied");
    assert!(!applied.fences_dispatch);
    assert_eq!(applied.effect, ValueEffect::NewSessionsOnly);
    assert_eq!(
        applied.invalidated,
        vec![CapabilityInvalidation::WorkerProfile]
    );
    assert_eq!(
        controller
            .announce_authority_revision()
            .await
            .expect("the revision in force")
            .authority_revision,
        after,
        "and nothing about authority moved"
    );

    host.stop().await;
}

/// KR-REQ-26.16: the daemon and the command write the same document, and the daemon reads it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_written_setting_is_what_the_daemon_reports_and_acts_on() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let environment = host.tree().environment();

    let applied = config::apply(
        &environment,
        &Change::SleepInhibition(SleepInhibitionSetting::MainsOnly),
        config::HardLimits::default(),
    )
    .expect("the owner's choice");
    assert_eq!(applied.revision, 1);
    drop(applied);

    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;
    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &session
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    assert_eq!(info.power.setting, SleepInhibitionSetting::MainsOnly);

    let result: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );
    assert_eq!(result.configuration.revision.get(), 1);
    let value = result
        .configuration
        .values
        .iter()
        .find(|value| value.key == "sleep_inhibition")
        .expect("the sleep policy");
    assert_eq!(value.value, "mains_only");
    assert_eq!(value.source, ValueSource::HostConfiguration);
    assert!(
        value.origin.0.as_deref().is_some_and(|origin| origin
            .ends_with(kr_protocol::hostinfo::configuration::FILE_NAME)),
        "and it names the document it came from: {:?}",
        value.origin
    );
    let check = result
        .checks
        .iter()
        .find(|check| check.id == "sleep-setting")
        .expect("the sleep check");
    assert!(
        check.detail.contains("per-user host configuration"),
        "the check says which rung the value came from: {check:?}"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.15: a configured session ceiling is what this host admits against, not only what it
/// reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_configured_session_ceiling_is_the_limit_this_host_admits_against() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let controller = host.controller();

    controller
        .apply_configuration(&Change::SessionLimit(Some(3)))
        .await
        .expect("the owner's ceiling");

    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;
    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &session
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    assert_eq!(
        info.session_limit.get(),
        3,
        "the limit a create is admitted against is the configured one"
    );

    controller
        .apply_configuration(&Change::SessionLimit(None))
        .await
        .expect("the ceiling is cleared");
    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &session
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    assert_eq!(
        info.session_limit.get(),
        kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64,
        "and clearing it puts the product default back"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.13: a configured execution context is what this host creates sessions in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_configured_execution_context_is_the_one_a_session_is_created_in() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let controller = host.controller();
    // Whatever this platform answers, the configuration chooses the other one, so the assertion
    // is about the configuration reaching session creation rather than about this machine.
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;
    let before: kr_protocol::hostinfo::HostInfoResult = typed(
        &session
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    let chosen = match before.default_worker_profile {
        kr_protocol::identity::WorkerProfile::DesktopBound => {
            kr_protocol::identity::WorkerProfile::HeadlessUser
        }
        kr_protocol::identity::WorkerProfile::HeadlessUser => {
            kr_protocol::identity::WorkerProfile::DesktopBound
        }
    };
    controller
        .apply_configuration(&Change::WorkerProfile(chosen))
        .await
        .expect("the owner's execution context");

    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &session
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    assert_eq!(
        info.default_worker_profile, chosen,
        "a create that chooses nothing gets what the configuration chose, not the platform's own \
         answer"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.15, KR-REQ-26.16: a document edited underneath this host is accepted before it is
/// reported, so a ceiling a diagnostic prints is a ceiling admission is enforcing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_edited_underneath_this_host_is_accepted_before_it_is_reported() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let controller = host.controller();

    controller
        .apply_configuration(&Change::SessionLimit(Some(9)))
        .await
        .expect("the owner's ceiling");

    // A person editing their own configuration file, with no daemon involved: a new revision and
    // a lower number, written the way the host writes it.
    let document = kr_worker::config::document_path(controller.paths());
    let contents = std::fs::read_to_string(&document).expect("the document this host wrote");
    let mut edited: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON");
    let revision = edited["revision"].as_u64().expect("a revision") + 1;
    edited["revision"] = serde_json::json!(revision);
    edited["ceilings"]["session_limit"] = serde_json::json!(4);
    kr_ipc::paths::write_owner_only_file(
        &document,
        serde_json::to_string(&edited).expect("JSON").as_bytes(),
    )
    .expect("the edited document");

    let effective = controller.effective_configuration().await;
    assert_eq!(
        effective.revision.get(),
        revision,
        "the report names the revision this host accepted"
    );
    let ceiling = effective
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "session_limit")
        .expect("the session ceiling");
    assert_eq!(ceiling.value, "4", "and the ceiling it now holds");

    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;
    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &session
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    assert_eq!(
        info.session_limit.get(),
        4,
        "admission enforces exactly what the report printed"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-01.23, KR-REQ-26.15: a document this host cannot use lifts no restriction, and the
/// report prints the number still in force rather than the product default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_this_build_cannot_use_keeps_the_ceiling_and_reports_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let controller = host.controller();

    controller
        .apply_configuration(&Change::SessionLimit(Some(4)))
        .await
        .expect("the owner's ceiling");

    // A document written by a build that knows a schema this one does not. It is left alone and
    // read as nothing, which must not be read as "no ceiling".
    let document = kr_worker::config::document_path(controller.paths());
    let contents = std::fs::read_to_string(&document).expect("the document this host wrote");
    let mut edited: serde_json::Value = serde_json::from_str(&contents).expect("valid JSON");
    edited["version"] = serde_json::json!(u64::from(u32::MAX));
    kr_ipc::paths::write_owner_only_file(
        &document,
        serde_json::to_string(&edited).expect("JSON").as_bytes(),
    )
    .expect("the document from a later build");

    let effective = controller.effective_configuration().await;
    assert_eq!(effective.status.state, DocumentState::UnknownVersion);
    let ceiling = effective
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "session_limit")
        .expect("the session ceiling");
    assert_eq!(
        ceiling.value, "4",
        "the number in force is the one this host accepted, not the product default"
    );
    assert_eq!(
        ceiling.source,
        ValueSource::HostConfiguration,
        "and it did not come from the product: {ceiling:?}"
    );
    assert!(
        ceiling
            .narrowed_by
            .as_ref()
            .is_some_and(|why| why.contains("last accepted")),
        "and the report says why it is that number: {ceiling:?}"
    );

    // The same answer with no document at all. Removing the file is not a way to lift a ceiling.
    std::fs::remove_file(&document).expect("the owner deletes their configuration");
    let effective = controller.effective_configuration().await;
    assert_eq!(effective.status.state, DocumentState::Absent);
    assert_eq!(
        effective
            .ceilings
            .iter()
            .find(|ceiling| ceiling.key == "session_limit")
            .expect("the session ceiling")
            .value,
        "4"
    );

    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;
    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &session
            .read(Method::HostInfo, &())
            .await
            .expect("host.info is served to the device"),
    );
    assert_eq!(
        info.session_limit.get(),
        4,
        "admission enforces exactly what the report printed"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.16: a grant ceiling edited outside this daemon fences dispatch, and a profile edited
/// outside it invalidates the evidence taken under the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_external_edit_fences_dispatch_and_invalidates_evidence() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let controller = host.controller();
    let mut control = host.client().await;

    let before = controller
        .announce_authority_revision()
        .await
        .expect("this host's authority revision")
        .authority_revision;
    let evidence_before = evidence_revision(&mut control, host.environment_id).await;
    let info: kr_protocol::hostinfo::HostInfoResult = typed(
        &control
            .request(Method::HostInfo, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.info succeeds"),
    );
    // Whatever this platform answers, the document chooses the other one, so the evidence has to
    // move whether this test runs on a desktop or on a headless build machine.
    let chosen = match info.default_worker_profile {
        kr_protocol::identity::WorkerProfile::DesktopBound => {
            kr_protocol::identity::WorkerProfile::HeadlessUser
        }
        kr_protocol::identity::WorkerProfile::HeadlessUser => {
            kr_protocol::identity::WorkerProfile::DesktopBound
        }
    };

    // One edit, made the way a person makes it: a text editor and no daemon. It moves both the
    // authority ceiling and the profile a session is created in.
    let document = kr_worker::config::document_path(controller.paths());
    let mut edited = ConfigurationDocument::empty();
    edited.revision = 1;
    edited.ceilings.grant_rights =
        Nullable::some(vec![ActionRight::SessionView.as_str().to_owned()]);
    edited.preferences.worker_profile = Nullable::some(chosen);
    kr_ipc::paths::write_owner_only_file(
        &document,
        kr_protocol::hostinfo::configuration::contents(&edited).as_bytes(),
    )
    .expect("the edited document");

    // Reading the configuration is what accepts it, and accepting it is what owes the effects.
    let effective = controller.effective_configuration().await;
    assert_eq!(effective.revision.get(), 1);
    assert!(
        effective.not_in_force.0.is_none(),
        "every effect landed: {:?}",
        effective.not_in_force
    );

    let after = controller
        .announce_authority_revision()
        .await
        .expect("this host's authority revision")
        .authority_revision;
    assert!(
        after > before,
        "the ceiling somebody else wrote fenced dispatch: {before:?} to {after:?}"
    );
    // The fence reached the connections admitted under the authority it withdrew, which is what
    // fencing dispatch means, so the evidence is read on a new one.
    assert_eq!(
        control
            .request(
                Method::EnvironmentCapabilities,
                &kr_protocol::desktop::EnvironmentCapabilitiesParams {
                    environment_id: host.environment_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect_err("a connection admitted under the withdrawn authority is not served")
            .code,
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    let mut control = host.client().await;
    assert!(
        evidence_revision(&mut control, host.environment_id).await > evidence_before,
        "and the evidence taken under the old profile was replaced"
    );

    // Reading it again changes nothing. An effect is owed by a document that moved, not by every
    // person who asks what the configuration is.
    controller.effective_configuration().await;
    assert_eq!(
        controller
            .announce_authority_revision()
            .await
            .expect("this host's authority revision")
            .authority_revision,
        after,
        "a document that did not move fences nothing"
    );

    host.stop().await;
}

/// KR-REQ-26.16: a change affecting authority is not acknowledged while a worker still holds work
/// admitted under the authority it withdrew.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unacknowledged_fence_is_reported_rather_than_called_done() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let controller = host.controller();

    // No worker is running here, so every barrier holds and the change completes. The assertion
    // is that completion is what the barrier says rather than what the write said.
    let applied = controller
        .apply_configuration(&Change::GrantRights(Some(vec![
            ActionRight::SessionView.as_str().to_owned(),
        ])))
        .await
        .expect("a change that fences dispatch");
    assert!(applied.fences_dispatch, "the change affects authority");
    assert!(
        applied.barrier_holds && applied.pending_workers == 0,
        "and it is acknowledged only because every barrier held: {applied:?}"
    );

    // A worker this daemon cannot reach and cannot account for: durably recorded, never verified,
    // and its process still running. It is exactly the worker section 9 will not let a revocation
    // report as done, because work admitted under the withdrawn authority may still be in it.
    let mut unreachable = std::process::Command::new("/bin/sleep")
        .arg("120")
        // A directory on the internal disk, never the workspace this test was built in.
        .current_dir(std::env::temp_dir())
        .spawn()
        .expect("a process this daemon can be told about");
    let session_id = record_unreachable_worker(controller.paths(), unreachable.id());

    let refused = controller
        .apply_configuration(&Change::GrantRights(Some(vec![
            ActionRight::SessionRename.as_str().to_owned(),
        ])))
        .await
        .expect_err("a fence no worker has acknowledged is not a change in force");
    let refused = format!("{refused}");
    assert!(
        refused.contains("revision 2 is written"),
        "the revision that was written is named: {refused}"
    );
    assert!(
        refused.contains("1 of this host's workers have not acknowledged"),
        "and so is what is outstanding: {refused}"
    );
    assert!(
        refused.contains(&session_id.to_string()),
        "and which worker it is: {refused}"
    );

    // Asking for the same change again is told the same thing. The document does not move, so
    // nothing derived from it would raise the fence a second time; what is outstanding is this
    // host's own debt, and a caller told the second attempt succeeded would be told the barrier
    // holds when it does not.
    let again = controller
        .apply_configuration(&Change::GrantRights(Some(vec![
            ActionRight::SessionRename.as_str().to_owned(),
        ])))
        .await
        .expect_err("the fence is still not acknowledged");
    assert!(
        format!("{again}").contains("have not acknowledged"),
        "{again}"
    );

    // The revision is on disk and the ceiling is in force, which is what "written and not
    // acknowledged" means: the change is not undone by the worker that has not answered.
    let effective = controller.effective_configuration().await;
    assert!(
        effective
            .fence_outstanding
            .as_ref()
            .is_some_and(|pending| pending.contains(&session_id.to_string())),
        "and the report says so too: {:?}",
        effective.fence_outstanding
    );
    assert!(
        effective.not_in_force.0.is_none(),
        "the values are in force; what is outstanding is the acknowledgement: {:?}",
        effective.not_in_force
    );
    assert_eq!(effective.revision.get(), 3);
    assert_eq!(
        effective
            .ceilings
            .iter()
            .find(|ceiling| ceiling.key == "grant_rights")
            .expect("the rights ceiling")
            .value,
        ActionRight::SessionRename.as_str()
    );

    // The worker ends. A revocation is complete for a worker once it acknowledges the revision or
    // is confirmed gone, so the barrier holds from here on without anything being written again.
    unreachable.kill().expect("the recorded process ends");
    unreachable.wait().expect("and is collected");
    let barrier = controller
        .announce_authority_revision()
        .await
        .expect("the revocation is announced again");
    assert!(
        barrier.holds(),
        "a worker confirmed gone satisfies the barrier: {barrier:?}"
    );
    assert!(
        controller
            .effective_configuration()
            .await
            .fence_outstanding
            .0
            .is_none(),
        "and the debt is settled without anything being written again"
    );
    controller
        .apply_configuration(&Change::GrantRights(None))
        .await
        .expect("a change is acknowledged once every barrier holds");

    host.stop().await;
}

/// The revision this host's capability evidence is published under.
async fn evidence_revision(
    control: &mut kr_ipc::client::LocalClient,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> kr_protocol::ids::CapabilityRevision {
    let result: kr_protocol::desktop::EnvironmentCapabilitiesResult = typed(
        &control
            .request(
                Method::EnvironmentCapabilities,
                &kr_protocol::desktop::EnvironmentCapabilitiesParams { environment_id },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("environment.capabilities succeeds"),
    );
    result
        .desktop
        .records
        .iter()
        .map(|record| record.revision)
        .max()
        .expect("this host publishes capability records")
}

/// Records a live worker this daemon has never reached, and returns its session.
///
/// Straight into the registry, which is where a worker that outlived a daemon is found on the next
/// start: durable membership is the registry's, and the verified directory is only what this
/// daemon has managed to speak to since.
fn record_unreachable_worker(
    paths: &kr_ipc::paths::EnvironmentPaths,
    pid: u32,
) -> kr_protocol::ids::SessionId {
    let mut registry =
        kr_controller::registry::Registry::open(paths.registry_database(), paths.environment_id())
            .expect("the registry this daemon keeps its workers in");
    let admission = registry
        .reserve(
            &kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
                .expect("a principal"),
            kr_ipc::new_uuid(),
            kr_protocol::scalars::Digest256::from_bytes([7; 32]),
            &[0xa0],
            kr_protocol::scalars::TimestampMs::new(1),
        )
        .expect("a reservation");
    let reservation = admission.reservation;
    registry
        .set_phase(
            reservation.reservation_id,
            kr_controller::registry::LaunchPhase::Claimed,
        )
        .expect("the reservation is claimed");
    registry
        .record_worker(
            reservation.reservation_id,
            &kr_controller::registry::WorkerRecord {
                session_id: reservation.session_id,
                display_number: reservation.display_number,
                public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([9; 32]),
                process_identity: kr_ipc::identity::process_start_identity(pid)
                    .expect("the kernel describes a process this test started"),
                endpoint: paths
                    .state_dir()
                    .join("unreachable.sock")
                    .display()
                    .to_string(),
                profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                state: kr_protocol::session::SessionState::Live,
                acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
            },
        )
        .expect("the worker is recorded");
    reservation.session_id
}
