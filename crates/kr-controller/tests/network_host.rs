//! The host's own method groups at both of its doors: the environment's owner on the local socket,
//! and a paired device on an authorised iroh connection, asking the same daemon.
//!
//! Two groups are here. The host diagnostics are served at both doors, and what leaves for a
//! device is the owner's own answer with every name and path held to its class and its length,
//! and with what the host measured about itself only when the device manages the host.
//! The skill setup group is served at the local door alone: a device whose grant manages the host
//! is refused each of its methods, and nothing is written for it. So is `device.revoke`: a remote
//! owner's revocation of a device reaches the host through the signed authority feed, never as a
//! live call on a paired connection.
//!
//! The daemon starts no worker, so every answer here is one it gives itself. Everything a test
//! writes is in its own temporary host tree on the internal disk.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::HostDoctorResult;
use kr_protocol::hostinfo::configuration::{ConfigurationDocument, SecretReference};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::{DeviceRevokeParams, RevocationResult};
use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};
use net_support::{Device, Host, RawDevice};

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// A name an owner gave a secure-store reference, and wrote the secret itself into.
const CREDENTIAL: &str = "relay-token-7d1f0c9a52e84b36";

/// KR-REQ-23.25: `host.doctor` is served at both doors, to a paired device and to the owner, and
/// its diagnostics carry no credential out of the host. The device reads the same checks as the
/// owner, in the same order, with the same titles, statuses and remedies; a credential the owner
/// put in the configuration, and the paths of this host's directories and document, are in the
/// owner's answer and nowhere in the device's, where each stands as its class and its length.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_diagnostics_answer_both_doors_and_carry_no_credential_to_a_device() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let environment = host.tree().environment();
    let mut document = ConfigurationDocument::empty();
    document.secrets.push(SecretReference {
        name: CREDENTIAL.to_owned(),
        store: "login_keychain".to_owned(),
        item: "kalareach/relay".to_owned(),
    });
    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(&environment),
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");
    let (_device, session) =
        net_support::paired_device(&host, &owner, &[ActionRight::SessionView]).await;
    let mut local = host.client().await;

    let owners: HostDoctorResult = typed(
        &local
            .request(Method::HostDoctor, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.doctor is served on the local socket"),
    );
    let devices: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );

    // The same diagnostics, check by check: the same checks in the same order, each with the
    // same title, status and remedy, and the same verdict.
    let checks = |result: &HostDoctorResult| {
        result
            .checks
            .iter()
            .map(|check| {
                (
                    check.id().to_owned(),
                    check.title().to_owned(),
                    check.status,
                    check.remedy().map(str::to_owned),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(checks(&devices), checks(&owners));
    assert_eq!(devices.healthy, owners.healthy);
    assert_eq!(
        devices.configuration.secrets.len(),
        owners.configuration.secrets.len()
    );

    // What the owner wrote and where this host keeps its files reach the owner's own answer, and
    // leave for the device as their class and their length: the credential, the environment's
    // directories and the document's path.
    assert_eq!(owners.configuration.secrets[0].name, CREDENTIAL);
    assert_eq!(
        devices.configuration.secrets[0].name,
        format!("[name withheld, {} bytes]", CREDENTIAL.len())
    );
    let withheld = [
        CREDENTIAL.to_owned(),
        environment.runtime_dir().display().to_string(),
        environment.state_dir().display().to_string(),
        kr_worker::config::document_path(&environment)
            .display()
            .to_string(),
    ];
    let owners_text = serde_json::to_string(&owners).expect("the answer serialises");
    let devices_text = serde_json::to_string(&devices).expect("the answer serialises");
    for value in &withheld {
        // As the answer spells it: a backslash in a Windows path is written as two.
        let spelled = serde_json::to_string(value).expect("the value serialises");
        let spelled = &spelled[1..spelled.len() - 1];
        assert!(
            owners_text.contains(spelled),
            "the owner's own report names {value}: {owners_text}"
        );
        assert!(
            !devices_text.contains(spelled),
            "{value} reached a paired device: {devices_text}"
        );
    }

    session.close();
    host.stop().await;
}

/// The state a diagnostics answer gives of the host's metrics, as the wire carries it.
fn metrics_state(answer: &ParamsValue) -> Option<&kr_cbor::CanonicalValue> {
    kr_worker::history_filter::retained::member(answer, "metrics")
}

/// Whether `state` is the host's report, held under its own name.
fn is_counted(state: Option<&kr_cbor::CanonicalValue>) -> bool {
    matches!(state, Some(kr_cbor::CanonicalValue::Map(map)) if map.get("counted").is_some())
}

/// Whether `state` is the host saying it gives the caller no metrics.
fn is_withheld(state: Option<&kr_cbor::CanonicalValue>) -> bool {
    matches!(state, Some(kr_cbor::CanonicalValue::Text(word)) if word == "withheld")
}

/// The diagnostics as the owner at the machine, a device that manages the host and a device that
/// only views a session each read them.
async fn read_all(
    local: &mut kr_ipc::client::LocalClient,
    managing: &kr_client::session::Session,
    viewing: &kr_client::session::Session,
) -> (ParamsValue, ParamsValue, ParamsValue) {
    let at_the_machine = local
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket");
    let by_the_manager = managing
        .read::<_, ParamsValue>(Method::HostDoctor, &())
        .await
        .expect("host.doctor is served to a device that manages the host");
    let by_the_viewer = viewing
        .read::<_, ParamsValue>(Method::HostDoctor, &())
        .await
        .expect("host.doctor is served to a device that views a session");
    (at_the_machine, by_the_manager, by_the_viewer)
}

/// KR-REQ-26.43: what the host measured about itself is read by its owner and by a paired device
/// whose grant holds `host.manage`, as a report that may hold nothing; a device without it is told
/// the host withholds them, which is not a report that counts nothing. The counts name a bundled
/// connector that failed, which is a fact about the host and not about any session, so a right
/// over one session does not reach them; the rest of the diagnostics are the same for that device
/// as for the manager.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_26_43_the_hosts_metrics_reach_a_paired_device_only_under_host_management() {
    use kr_protocol::metrics::{Adapter, HostMetrics, MetricOutcome};

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_manager, managing) = net_support::paired_device(
        &host,
        &owner,
        &[ActionRight::HostManage, ActionRight::SessionView],
    )
    .await;
    let (_viewer, viewing) =
        net_support::paired_device(&host, &owner, &[ActionRight::SessionView]).await;
    let mut local = host.client().await;

    // Nothing counted yet: the owner and the manager are told so, and the viewer is told it is not
    // told, which is another thing.
    let (at_the_machine, by_the_manager, by_the_viewer) =
        read_all(&mut local, &managing, &viewing).await;
    assert!(
        is_counted(metrics_state(&at_the_machine)),
        "{at_the_machine:?}"
    );
    assert!(
        is_counted(metrics_state(&by_the_manager)),
        "{by_the_manager:?}"
    );
    assert!(
        is_withheld(metrics_state(&by_the_viewer)),
        "a device that holds only session.view is not given a report: {by_the_viewer:?}"
    );

    host.controller()
        .metrics()
        .adapter_failed(Adapter::Codex, MetricOutcome::Unavailable);
    let (at_the_machine, by_the_manager, by_the_viewer) =
        read_all(&mut local, &managing, &viewing).await;
    let (at_the_machine, by_the_manager, by_the_viewer): (
        HostDoctorResult,
        HostDoctorResult,
        HostDoctorResult,
    ) = (
        typed(&at_the_machine),
        typed(&by_the_manager),
        typed(&by_the_viewer),
    );
    for (who, answer) in [
        ("the owner at the machine", &at_the_machine),
        ("a device that manages the host", &by_the_manager),
    ] {
        let Some(HostMetrics::Counted(report)) = &answer.metrics else {
            panic!("{who} is given the report: {answer:?}");
        };
        assert_eq!(report.adapter_failure.len(), 1, "{who}: {answer:?}");
        let series = &report.adapter_failure[0];
        assert_eq!(series.adapter, Adapter::Codex, "{who}");
        assert_eq!(series.outcome, MetricOutcome::Unavailable, "{who}");
        assert_eq!(series.count.get(), 1, "{who}");
    }
    assert_eq!(
        by_the_viewer.metrics,
        Some(HostMetrics::Withheld),
        "a device that holds only session.view is not given the host's metrics"
    );
    // The metrics are all that is left out for it: the checks are the manager's own.
    let verdicts = |result: &HostDoctorResult| {
        result
            .checks
            .iter()
            .map(|check| (check.id().to_owned(), check.status))
            .collect::<Vec<_>>()
    };
    assert_eq!(verdicts(&by_the_viewer), verdicts(&by_the_manager));

    managing.close();
    viewing.close();
    host.stop().await;
}

/// KR-REQ-23.33: the skill setup group needs the host owner at the machine. A paired device whose
/// grant manages the host is refused `agent_tools.install`, `agent_tools.status` and
/// `agent_tools.remove` through the daemon, and the refused installation writes nothing: no action
/// record and no file in the project it named. The control: the owner's own install of the same
/// target at the same scope is served, and reported installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_is_refused_the_skill_setup_and_nothing_is_written_for_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let project = host.tree().root().join("project");
    std::fs::create_dir_all(project.join(".codex")).expect("a project directory");
    let params = AgentToolsParams {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        project_dir: Nullable::some(project.display().to_string()),
    };
    let files = |directory: &std::path::Path| {
        walk(directory)
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
    };
    let before = files(&project);
    let actions = host
        .tree()
        .environment()
        .state_dir()
        .join("agent-tools/actions");

    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::HostManage, ActionRight::SessionView]),
    )
    .await;
    let raw = RawDevice::connect(&host, &device, &record).await;
    raw.claim();
    for method in [Method::AgentToolsInstall, Method::AgentToolsRemove] {
        let refused = net_support::refusal(
            raw.mutate(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await,
        );
        assert_eq!(
            refused.code,
            ErrorCode::PermissionDenied,
            "{} reached a paired device: {refused:?}",
            method.as_str()
        );
    }
    let refused = net_support::refusal(raw.read(Method::AgentToolsStatus, &params).await);
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    raw.close();
    assert_eq!(
        files(&project),
        before,
        "a refused installation wrote nothing"
    );
    assert!(
        walk(&actions).is_empty(),
        "and recorded no action it would have to answer for"
    );

    // The owner at the machine is served the same installation.
    let mut local = host.client().await;
    let installed: kr_protocol::skill::AgentToolsInstallResult = typed(
        &local
            .mutate(
                Method::AgentToolsInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the owner installs the skill"),
    );
    assert!(!installed.already_installed);
    assert_ne!(
        files(&project),
        before,
        "the owner's installation wrote files"
    );
    let status: kr_protocol::skill::AgentToolsStatusResult = typed(
        &local
            .request(Method::AgentToolsStatus, &params)
            .await
            .expect("the call reaches the daemon")
            .expect("the owner reads the status"),
    );
    assert!(status.installed, "{status:?}");
    host.stop().await;
}

/// KR-REQ-23.27: `device.revoke` is the owner's at this machine. A paired device whose grant
/// manages the host is refused it as it is any method its door does not list, and the
/// device it named stays paired with the grants it holds. The control: the owner's own revocation
/// of the same device is served and ends its pairing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_is_refused_the_revocation_of_a_device_and_the_owner_is_not() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let managing = Device::create().await;
    let managing_record = net_support::pair_with(
        &host,
        &managing,
        &owner,
        net_support::proposal(&[ActionRight::HostManage, ActionRight::SessionView]),
    )
    .await;
    let target = Device::create().await;
    let target_record = net_support::pair_with(
        &host,
        &target,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let params = DeviceRevokeParams {
        device_id: target_record.device_id,
    };
    let still_paired = || {
        host.network()
            .devices()
            .record_for_device(target_record.device_id)
            .expect("readable")
            .expect("the record")
            .is_paired()
    };

    let raw = RawDevice::connect(&host, &managing, &managing_record).await;
    raw.claim();
    let refused = net_support::refusal(
        raw.mutate(
            Method::DeviceRevoke,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params,
        )
        .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    raw.close();
    assert!(still_paired(), "the refused call revoked nothing");

    let mut local = host.client().await;
    let _: RevocationResult = typed(
        &local
            .mutate(
                Method::DeviceRevoke,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the owner revokes the device"),
    );
    assert!(!still_paired(), "the owner's revocation ended the pairing");
    host.stop().await;
}

/// KR-REQ-23.27, KR-REQ-10.45: `device.revoke` through the daemon, with a worker inside a dispatch
/// transition, is answered as pending with that worker named and the reason, and the fence the
/// worker makes afterwards completes it: asking again under a new action identifier answers a
/// barrier that holds, with the undispatched action the revoked device had in the worker named.
/// Not shown here: a repeat under the first call's own action identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_revocation_is_pending_for_a_held_worker_until_the_worker_fences() {
    let net_support::worker::Adopted {
        host,
        owner,
        workers,
    } = net_support::worker::Adopted::start(1).await;
    let worker = &workers[0];
    let (_device, record) = net_support::recipient(&host, &owner).await;
    worker.seed_undispatched_intents(
        &kr_transport::listener::device_principal(&record.device_id),
        1,
    );
    let mut client = host.client().await;
    let mutation = client
        .compose(
            Method::DeviceRevoke,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &DeviceRevokeParams {
                device_id: record.device_id,
            },
        )
        .await
        .expect("the revocation is composed");

    let boundary = worker.hold_the_dispatch_boundary().await;
    let pending: RevocationResult = typed(
        &client
            .repeat(&mutation)
            .await
            .expect("the call reaches the daemon")
            .expect("the owner revokes the device"),
    );
    let waited_for = pending
        .barrier
        .workers
        .iter()
        .find(|reported| reported.session_id == worker.session_id)
        .expect("the worker is in the barrier");
    assert!(!pending.barrier.holds(), "{:?}", pending.barrier);
    assert_eq!(pending.barrier.pending(), vec![worker.session_id]);
    assert!(
        waited_for.detail.contains("has not acknowledged revision"),
        "the status says what the revocation waits for: {:?}",
        waited_for.detail
    );
    boundary.release();
    worker.service.fence_what_is_owed_for_tests();

    // The device is revoked already, so asking again under a new action withdraws nothing and
    // advances no revision: it reports the barrier as it stands, and the fence the worker made
    // is what it holds on.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let done = loop {
        let again: RevocationResult = typed(
            &client
                .mutate(
                    Method::DeviceRevoke,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(host.environment_id),
                    &DeviceRevokeParams {
                        device_id: record.device_id,
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("the revocation is answered"),
        );
        if again.barrier.holds() {
            break again;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the revocation never held: {:?}",
            again.barrier
        );
        tokio::task::yield_now().await;
    };
    assert_eq!(done.authority_revision, pending.authority_revision);
    let fenced = done
        .barrier
        .workers
        .iter()
        .find(|reported| reported.session_id == worker.session_id)
        .expect("the worker is in the barrier");
    assert_eq!(
        fenced.state,
        kr_protocol::action::BarrierState::Acknowledged,
        "{fenced:?}"
    );
    assert_eq!(
        fenced.rejected_actions.len(),
        1,
        "the action the device had in the worker is named: {fenced:?}"
    );
    drop(client);
    host.stop().await;
    drop(workers);
}

/// Every file under `directory`, in a stable order; nothing when it does not exist.
fn walk(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found.sort();
    found
}
