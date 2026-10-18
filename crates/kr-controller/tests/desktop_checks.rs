//! The disclosed checks, asked for at the host's own socket and performed in a session's worker.
//!
//! KR-REQ-03.29: the checks run from the same worker context an agent uses, and their findings
//! reach `environment.capabilities`, which never performs them. A real daemon adopts a real worker
//! service here; nothing is stood in for. The worker runs in this test's process, so what these
//! cases show is the request path from the owner's socket to the worker and back, and the rule for
//! what the daemon holds. They do not show which signed program a platform files a permission
//! under, which only a run on a Mac with a graphical login can.

mod net_support;

use std::time::Duration;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::desktop::{
    CapabilityChecks, CapabilityChecksFailure, CapabilityChecksState, CapabilityEvidenceSource,
    CapabilityState, EnvironmentCapabilitiesCheckParams, EnvironmentCapabilitiesParams,
    EnvironmentCapabilitiesResult, capabilities,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs};
use net_support::Host;
use net_support::worker::Adopted;

const PATIENCE: Duration = Duration::from_secs(60);

/// A document that has this host create its sessions headless, whatever machine the test runs on,
/// so the worker the test adopts is the one the checks are performed in.
fn headless() -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.preferences.worker_profile = Nullable::some(WorkerProfile::HeadlessUser);
    document
}

fn typed<T: kr_protocol::wire::WireMessage>(value: &kr_protocol::envelope::ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// The request that asks for the checks, as the setup assistant's command builds it.
async fn request_for(
    host: &Host,
    client: &mut kr_ipc::client::LocalClient,
    action: ActionId,
    file: Option<&std::path::Path>,
) -> kr_protocol::envelope::MutationRequest {
    client
        .compose(
            Method::EnvironmentCapabilitiesCheck,
            action,
            ActionTarget::environment(host.environment_id),
            &EnvironmentCapabilitiesCheckParams {
                environment_id: host.environment_id,
                authorised_file: Nullable(file.map(|path| path.display().to_string())),
            },
        )
        .await
        .expect("the request is built")
}

/// Asks for the checks at the daemon's own socket, as the setup assistant's command does.
async fn ask(
    host: &Host,
    action: ActionId,
    file: Option<&std::path::Path>,
) -> Result<CapabilityChecks, kr_protocol::error::ProtocolError> {
    let mut client = host.client().await;
    let request = request_for(host, &mut client, action, file).await;
    send(&mut client, &request).await
}

/// Sends a request exactly as it was built, on any connection.
async fn send(
    client: &mut kr_ipc::client::LocalClient,
    request: &kr_protocol::envelope::MutationRequest,
) -> Result<CapabilityChecks, kr_protocol::error::ProtocolError> {
    client
        .repeat(request)
        .await
        .expect("the call reaches the daemon")
        .map(|answer| typed(&answer))
}

/// What `environment.capabilities` shows at the owner's socket.
async fn shown(host: &Host) -> EnvironmentCapabilitiesResult {
    let mut client = host.client().await;
    typed(
        &client
            .request(
                Method::EnvironmentCapabilities,
                &EnvironmentCapabilitiesParams {
                    environment_id: host.environment_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("environment.capabilities succeeds"),
    )
}

/// Reads until the checks stand as `state`, or the patience runs out.
async fn until(host: &Host, state: CapabilityChecksState) -> EnvironmentCapabilitiesResult {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let answer = shown(host).await;
        if answer.checks.state == state {
            return answer;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the checks did not come to {state:?}: {:?}",
            answer.checks
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// KR-REQ-03.29: the owner asks, the daemon has a session's worker perform the checks, and what the
/// worker found stands in the capability records until something ends it.
///
/// The read check is the one every context performs, so it is the one this shows end to end: a file
/// the owner named is read in the worker, the record is a disclosed probe naming the session whose
/// worker read it, and it stays when the file is gone because it is what was found, not a reading
/// of the file. A device is shown the same record with the path withheld. An exact repeat of the
/// action is answered from what was kept and starts no second run.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_owner_asks_for_the_checks_and_the_findings_stand_in_the_records() {
    let adopted = Adopted::start_with_document(1, &headless()).await;
    let host = &adopted.host;
    let session_id = adopted.workers[0].session_id;

    let before = shown(host).await;
    assert_eq!(before.checks.state, CapabilityChecksState::NotRun);
    assert!(
        before
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .is_none(),
        "no platform query answers the read check, so there is no record before it is performed"
    );

    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    let action = ActionId::new(kr_ipc::new_uuid());
    let mut first = host.client().await;
    let request = request_for(host, &mut first, action, Some(&file)).await;
    let asked = send(&mut first, &request).await.expect("asked");
    assert!(
        matches!(
            asked.state,
            CapabilityChecksState::Running | CapabilityChecksState::Current
        ),
        "the answer comes back at once and says where the checks stand: {asked:?}"
    );
    let done = until(host, CapabilityChecksState::Current).await;
    assert_eq!(done.checks.session_id.as_ref(), Some(&session_id));

    let record = done
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record");
    assert_eq!(record.state, CapabilityState::QualifiedAvailable);
    assert_eq!(
        record.evidence_source,
        CapabilityEvidenceSource::DisclosedProbe
    );
    assert_eq!(
        record.subject.session_id.as_ref(),
        Some(&session_id),
        "the record names the session whose worker performed the check"
    );
    assert!(
        record
            .disabled_reason
            .as_ref()
            .is_some_and(|reason| reason.as_str().contains("25 bytes")),
        "the worker read what the file held: {:?}",
        record.disabled_reason
    );

    // What was found stands after the file is gone, and a repeat of the action neither starts
    // another run nor changes what is held.
    std::fs::remove_file(&file).expect("removes the file");
    let mut later_connection = host.client().await;
    let repeated = send(&mut later_connection, &request)
        .await
        .expect("asked again");
    assert_eq!(repeated, asked, "the kept answer, not a second run");
    // The same identifier for another request is a reused identifier.
    let mut other = host.client().await;
    let different = request_for(host, &mut other, action, None).await;
    let conflict = send(&mut other, &different)
        .await
        .expect_err("a reused identifier");
    assert_eq!(
        conflict.code,
        kr_protocol::error::ErrorCode::IdConflict,
        "{conflict:?}"
    );
    let later = shown(host).await;
    assert_eq!(later.checks, done.checks, "no second run began");
    assert_eq!(
        later
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .map(|record| (record.state, record.observed_at_ms)),
        Some((record.state, record.observed_at_ms)),
    );

    // A device sees the finding with the path withheld, and cannot ask for the checks: the method
    // is the owner's socket's alone.
    let (_device, device) =
        net_support::paired_device(host, &adopted.owner, &[ActionRight::SessionView]).await;
    let remote: EnvironmentCapabilitiesResult = device
        .read(
            Method::EnvironmentCapabilities,
            &EnvironmentCapabilitiesParams {
                environment_id: host.environment_id,
            },
        )
        .await
        .expect("environment.capabilities is served to the device");
    let remote_record = remote
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the device is shown the finding");
    assert_eq!(remote_record.state, CapabilityState::QualifiedAvailable);
    assert!(
        remote_record
            .identity
            .binary
            .as_ref()
            .is_some_and(|binary| binary.starts_with("[path withheld")),
        "{:?}",
        remote_record.identity.binary
    );
    assert_eq!(remote.checks.state, CapabilityChecksState::Current);

    // And what the device is shown is all it can do with them: asking for a run is the owner's
    // socket's alone, and what the refusal leaves behind is no run.
    let refused = device
        .mutate(
            Method::EnvironmentCapabilitiesCheck,
            ActionTarget::environment(host.environment_id),
            None,
            &kr_protocol::envelope::ParamsValue::empty(),
            &EnvironmentCapabilitiesCheckParams {
                environment_id: host.environment_id,
                authorised_file: Nullable::null(),
            },
            kr_protocol::scalars::DurationMs::new(120_000),
        )
        .await
        .expect_err("a paired device cannot ask for the checks");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused:?}"
    );
    assert_eq!(shown(host).await.checks, done.checks, "no run was started");

    device.close();
    adopted.stop().await;
}

/// Reads until the checks have finished a run later than `after`, whatever state they stand in.
async fn until_a_run_after(host: &Host, after: TimestampMs) -> EnvironmentCapabilitiesResult {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let answer = shown(host).await;
        if answer.checks.state == CapabilityChecksState::Current
            && answer
                .checks
                .finished_at_ms
                .as_ref()
                .is_some_and(|finished| *finished > after)
        {
            return answer;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no later run finished: {:?}",
            answer.checks
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// KR-REQ-03.29: a run asked for after one has finished is a run of its own, findings that come out
/// the same leave the capability revision where it was, and findings that differ move it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_later_run_replaces_the_findings_and_moves_the_revision_only_when_they_differ() {
    let adopted = Adopted::start_with_document(1, &headless()).await;
    let host = &adopted.host;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    ask(host, ActionId::new(kr_ipc::new_uuid()), Some(&file))
        .await
        .expect("asked");
    let first = until(host, CapabilityChecksState::Current).await;
    let first_record = first
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record")
        .clone();
    let first_finished = first
        .checks
        .finished_at_ms
        .0
        .expect("a finished run says when");

    // The same file again: another run, the same finding, so the revision stays.
    ask(host, ActionId::new(kr_ipc::new_uuid()), Some(&file))
        .await
        .expect("asked again");
    let second = until_a_run_after(host, first_finished).await;
    let second_record = second
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record");
    assert_eq!(second_record.disabled_reason, first_record.disabled_reason);
    assert_eq!(
        second_record.revision, first_record.revision,
        "a finding that came out the same is not a change of evidence"
    );
    let second_finished = second.checks.finished_at_ms.0.expect("when it finished");

    // The file changed: the next run finds something else, and the revision says so.
    std::fs::write(&file, b"a longer text than the first one held").expect("the changed file");
    ask(host, ActionId::new(kr_ipc::new_uuid()), Some(&file))
        .await
        .expect("asked a third time");
    let third = until_a_run_after(host, second_finished).await;
    let third_record = third
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record");
    assert!(
        third_record
            .disabled_reason
            .as_ref()
            .is_some_and(|reason| reason.as_str().contains("37 bytes")),
        "{:?}",
        third_record.disabled_reason
    );
    assert!(third_record.revision.get() > second_record.revision.get());

    adopted.stop().await;
}

/// KR-REQ-03.29: with no session to perform them in, nothing is started and the answer says why,
/// and a later read shows the same, so the setup assistant can tell a person to start a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_no_session_nothing_is_started_and_the_answer_says_why() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let asked = ask(&host, ActionId::new(kr_ipc::new_uuid()), None)
        .await
        .expect("asked");
    assert_eq!(asked.state, CapabilityChecksState::Failed, "{asked:?}");
    assert_eq!(
        asked.failure.as_ref(),
        Some(&CapabilityChecksFailure::NoSession)
    );
    let answer = shown(&host).await;
    assert_eq!(answer.checks.state, CapabilityChecksState::Failed);
    assert!(
        answer
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .is_none(),
        "nothing was performed, so there is no finding"
    );
    host.stop().await;
}

/// KR-REQ-03.29: a path that is not absolute is refused before a run is started, and a request
/// for another environment is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_that_is_not_absolute_and_another_environment_are_refused() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let relative = ask(
        &host,
        ActionId::new(kr_ipc::new_uuid()),
        Some(std::path::Path::new("relative/path.txt")),
    )
    .await
    .expect_err("a relative path");
    assert_eq!(
        relative.code,
        kr_protocol::error::ErrorCode::InvalidArgument,
        "{relative:?}"
    );
    let mut client = host.client().await;
    let elsewhere = client
        .mutate(
            Method::EnvironmentCapabilitiesCheck,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &EnvironmentCapabilitiesCheckParams {
                environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
                authorised_file: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("another environment");
    assert_eq!(
        elsewhere.code,
        kr_protocol::error::ErrorCode::InvalidArgument,
        "{elsewhere:?}"
    );
    host.stop().await;
}
