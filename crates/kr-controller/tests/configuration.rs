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
        assert_eq!(
            value.source,
            ValueSource::Default,
            "{} has no chosen value on a fresh host",
            value.key
        );
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
            .contains("Any other inherited variable changes nothing"),
        "{check:?}"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-26.15: a configured ceiling above the hard limit is refused and reported as refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_more_permissive_configured_ceiling_is_refused_rather_than_applied() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let environment = host.tree().environment();
    let limits = config::HardLimits::default();

    // Written directly rather than through the edit, because the edit's own validation is not what
    // this is about: what this shows is that a document asking for more than the product allows
    // does not get it.
    let mut document = ConfigurationDocument::empty();
    document.ceilings.session_limit =
        Nullable::some(limits.sessions_per_environment.saturating_mul(4));
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
    let ceiling = result
        .configuration
        .ceilings
        .iter()
        .find(|ceiling| ceiling.key == "session_limit")
        .expect("the session ceiling");
    assert!(ceiling.refused, "asking for more raises nothing");
    assert_eq!(ceiling.value, limits.sessions_per_environment.to_string());
    let check = result
        .checks
        .iter()
        .find(|check| check.id == "configuration-ceilings")
        .expect("the ceilings check");
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
    )
    .expect("the owner's choice");
    assert_eq!(applied.revision, 1);

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
