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
    CapabilityInvalidation, CapabilityState, DesktopContext, EnvironmentCapabilitiesCheckParams,
    EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult, capabilities,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::configuration::{Change, ConfigurationDocument};
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

/// Runs one whole operation of a case under `PATIENCE`, so a daemon that stops answering at any
/// step of it ends the case at that limit and not at the runner's.
async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, work).await.expect(what)
}

/// Asks for the checks at the daemon's own socket, as the setup assistant's command does: the
/// connection, the request's building and its answer, all within `PATIENCE`.
async fn ask(
    host: &Host,
    action: ActionId,
    file: Option<&std::path::Path>,
) -> Result<CapabilityChecks, kr_protocol::error::ProtocolError> {
    within(
        "the daemon takes the request for the checks in time",
        async {
            let mut client = host.client().await;
            let request = request_for(host, &mut client, action, file).await;
            send(&mut client, &request).await
        },
    )
    .await
}

/// Sends a request exactly as it was built, on any connection, and waits for its answer within
/// `PATIENCE`.
async fn send(
    client: &mut kr_ipc::client::LocalClient,
    request: &kr_protocol::envelope::MutationRequest,
) -> Result<CapabilityChecks, kr_protocol::error::ProtocolError> {
    within(
        "the daemon answers the request for the checks in time",
        async {
            client
                .repeat(request)
                .await
                .expect("the call reaches the daemon")
                .map(|answer| typed(&answer))
        },
    )
    .await
}

/// What `environment.capabilities` shows at the owner's socket: the connection and the answer,
/// within `PATIENCE`.
async fn shown(host: &Host) -> EnvironmentCapabilitiesResult {
    within("the daemon shows the capabilities in time", async {
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
    })
    .await
}

/// Reads until the checks stand as `state`, all of it within `PATIENCE`: the reads and the waits
/// between them are one operation, and what the last read showed is told when it ends.
async fn until(host: &Host, state: CapabilityChecksState) -> EnvironmentCapabilitiesResult {
    let mut last = None;
    let reached = tokio::time::timeout(PATIENCE, async {
        loop {
            let answer = shown(host).await;
            if answer.checks.state == state {
                return answer;
            }
            last = Some(answer.checks);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    match reached {
        Ok(answer) => answer,
        Err(elapsed) => panic!(
            "the checks did not come to {state:?}; the last read showed {last:?}: {elapsed:?}"
        ),
    }
}

/// KR-REQ-03.29: the owner asks, the daemon has a session's worker perform the checks, and what the
/// worker found stands in the capability records until something ends it.
///
/// The read check is the one every context performs, so it is the one this shows end to end: a file
/// the owner named is read in the worker, the record is a disclosed probe naming the session whose
/// worker read it, and it stays when the file is gone because it is what was found, not a reading
/// of the file. A device is shown the same record, which names no path. An exact repeat of the
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

    // A device sees the finding with no path, and cannot ask for the checks: the method is the
    // owner's socket's alone.
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
    assert_eq!(
        remote_record.identity.binary.as_ref(),
        None,
        "the read check runs no installed program, so its record names none"
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

/// Whether any file under `root` holds `needle`, and which.
fn a_file_under_holds(root: &std::path::Path, needle: &[u8]) -> Option<std::path::PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("reads a directory of the tree") {
            let entry = entry.expect("an entry of the tree");
            let kind = entry.file_type().expect("the entry's type");
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let bytes = std::fs::read(entry.path()).expect("reads a file of the tree");
                if bytes.windows(needle.len()).any(|window| window == needle) {
                    return Some(entry.path());
                }
            }
        }
    }
    None
}

/// KR-REQ-03.29: the file the owner nominated is named in no record the daemon shows or keeps.
///
/// The reason says the file as its class and its length. The record's `identity.binary` names an
/// installed program, and the read check runs none, so it is null: a person's path never travels
/// in a field the export boundary would have to withhold a second time, with the length of the
/// withheld text. The owner's reply, a paired device's reply and every file this host's tree holds
/// after the run carry no part of the path, whose last component holds a marker nothing else could
/// say.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_nominated_path_is_in_no_record_the_daemon_shows_or_keeps() {
    let adopted = Adopted::start_with_document(1, &headless()).await;
    let host = &adopted.host;

    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let marker = format!("kr-nominated-{}", kr_ipc::new_uuid());
    let file = directory.path().join(format!("{marker}.txt"));
    std::fs::write(&file, b"the person nominated this").expect("the test's file");
    let path_bytes = file.display().to_string().len();

    ask(host, ActionId::new(kr_ipc::new_uuid()), Some(&file))
        .await
        .expect("asked");
    let owner = until(host, CapabilityChecksState::Current).await;
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

    for (reader, shown) in [("the owner", &owner), ("a paired device", &remote)] {
        let record = shown
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .unwrap_or_else(|| panic!("{reader} is shown the read check's record"));
        assert_eq!(
            record.state,
            CapabilityState::QualifiedAvailable,
            "{reader}"
        );
        assert_eq!(
            record.identity.binary.as_ref(),
            None,
            "{reader}: the read check runs no installed program, so its record names none"
        );
        let text = serde_json::to_string(shown).expect("the reply as text");
        assert!(
            !text.contains(&marker),
            "{reader} is shown the nominated path: {text}"
        );
    }
    let withheld = format!("[path withheld, {path_bytes} bytes]");
    let reason = owner
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .and_then(|record| record.disabled_reason.as_ref())
        .expect("the owner is told what the read came to");
    assert!(
        reason.as_str().contains(&withheld),
        "the reason says the file as its class and its length: {reason}"
    );

    // Nothing the host keeps holds the path either: the answer to the request, the findings and
    // the rest of its tree.
    if let Some(found) = a_file_under_holds(host.tree().root(), marker.as_bytes()) {
        panic!("the host keeps the nominated path in {}", found.display());
    }

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

/// KR-REQ-03.29: a permission withdrawn between two runs is found when the checks are performed
/// again, as `permission_required`, and the repeat moves the capability revision.
///
/// The daemon cannot read a permission, so a person asks again. The permission here is the one the
/// filesystem keeps for the nominated file, which the worker meets the way it meets a privacy
/// grant: it performs the read and the operating system answers.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_permission_withdrawn_is_found_when_the_checks_are_performed_again() {
    use std::os::unix::fs::PermissionsExt as _;

    let adopted = Adopted::start_with_document(1, &headless()).await;
    let host = &adopted.host;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    ask(host, ActionId::new(kr_ipc::new_uuid()), Some(&file))
        .await
        .expect("asked");
    let ready = until(host, CapabilityChecksState::Current).await;
    let before = ready
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record")
        .clone();
    assert_eq!(before.state, CapabilityState::QualifiedAvailable);
    let finished = ready
        .checks
        .finished_at_ms
        .0
        .expect("a finished run says when");

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000))
        .expect("the permission is withdrawn");
    // The worker runs in this process. An account that can read through a withdrawn mode (the
    // superuser, or one holding a capability that overrides file permissions) cannot show this.
    assert!(
        std::fs::File::open(&file).is_err(),
        "run as an account the withdrawn permission binds"
    );

    ask(host, ActionId::new(kr_ipc::new_uuid()), Some(&file))
        .await
        .expect("asked again");
    let repeated = until_a_run_after(host, finished).await;
    let after = repeated
        .desktop
        .record(capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record");
    assert_eq!(
        after.state,
        CapabilityState::PermissionRequired,
        "{:?}",
        after.disabled_reason
    );
    assert_eq!(
        after.evidence_source,
        CapabilityEvidenceSource::DisclosedProbe
    );
    // A file in a folder that no privacy grant covers is refused by the filesystem's own
    // permissions, and the reason says so rather than naming a grant to give.
    let reason = after.disabled_reason.as_ref().expect("a refusal says why");
    assert!(
        reason
            .as_str()
            .contains("No privacy permission is known for that path"),
        "{reason}"
    );
    assert!(
        !reason.as_str().contains("granted per signed application"),
        "{reason}"
    );
    assert!(
        after.revision.get() > before.revision.get(),
        "a finding that changed is a change of evidence"
    );

    adopted.stop().await;
}

/// KR-REQ-03.29: the answer given to a request for the checks is kept for 30 days and outlives the
/// daemon: a repeat on a later connection after a restart, when the window it was sent in is gone,
/// is given the answer it was given and no run of its own, and another request under the same
/// identifier is refused as a reused identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_answer_to_a_request_outlives_the_daemon_and_the_identifier_stays_the_requests() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let mut first = host.client().await;
    let request = request_for(&host, &mut first, action, None).await;
    let asked = send(&mut first, &request).await.expect("asked");
    assert_eq!(asked.state, CapabilityChecksState::Failed, "{asked:?}");
    drop(first);

    let host = host.restart().await;
    // The daemon that answered is gone with every window it issued, and the host has asked nothing
    // since it started.
    assert_eq!(
        shown(&host).await.checks.state,
        CapabilityChecksState::NotRun,
        "nothing a restart could carry is held in memory"
    );
    let mut later = host.client().await;
    let repeated = send(&mut later, &request).await.expect("asked again");
    assert_eq!(
        repeated, asked,
        "the answer that was given, with the time it was given, and not a run of its own"
    );
    assert_eq!(
        shown(&host).await.checks.state,
        CapabilityChecksState::NotRun,
        "and the repeat started nothing"
    );
    let different = request_for(
        &host,
        &mut later,
        action,
        Some(std::path::Path::new("/tmp/x")),
    )
    .await;
    let conflict = send(&mut later, &different)
        .await
        .expect_err("a reused identifier");
    assert_eq!(
        conflict.code,
        kr_protocol::error::ErrorCode::IdConflict,
        "{conflict:?}"
    );
    host.stop().await;
}

/// KR-REQ-03.29, KR-REQ-09.14: an answer that cannot be written down is not given. The start is
/// refused with the host's storage error, no run is started and the checks stand as they did, and
/// once the record can be written again the same request is a first request and starts the run.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_answer_that_cannot_be_written_down_refuses_the_start_and_starts_no_run() {
    let adopted = Adopted::start_with_document(1, &headless()).await;
    let host = &adopted.host;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    // The record takes no row, as a disk that is full or a file that is read-only takes none.
    let record =
        rusqlite::Connection::open(host.capability_answers_database()).expect("opens the record");
    record
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own use");
    record
        .execute_batch(
            "CREATE TRIGGER no_room BEFORE INSERT ON capability_answers
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("puts the fault in the record");

    let mut client = host.client().await;
    let request = request_for(
        host,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        Some(&file),
    )
    .await;
    let refused = send(&mut client, &request)
        .await
        .expect_err("an answer that cannot be written down is not given");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::StorageUnavailable,
        "{refused:?}"
    );
    assert_eq!(
        shown(host).await.checks.state,
        CapabilityChecksState::NotRun,
        "the checks stand as they did: no run was started, and none is left owing an end"
    );

    record
        .execute_batch("DROP TRIGGER no_room")
        .expect("clears the fault");
    let asked = send(&mut client, &request).await.expect("asked");
    assert!(
        matches!(
            asked.state,
            CapabilityChecksState::Running | CapabilityChecksState::Current
        ),
        "the same request, now that it can be recorded, starts the run: {asked:?}"
    );
    until(host, CapabilityChecksState::Current).await;
}

/// KR-REQ-03.29, KR-REQ-09.14: two connections that ask under one action identifier, each in a
/// window of its own, are two requests, and only the one that is answered first is run. The other
/// looked for an answer before the first was written; it is refused as a reused identifier when it
/// goes on, and starts no second run.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_connections_asking_under_one_identifier_start_one_run_and_the_later_is_refused() {
    let adopted = Adopted::start_with_document(1, &headless()).await;
    let host = &adopted.host;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");

    let action = ActionId::new(kr_ipc::new_uuid());
    let mut looked_first = host.client().await;
    let mut answered_first = host.client().await;
    let late = request_for(host, &mut looked_first, action, Some(&file)).await;
    let early = request_for(host, &mut answered_first, action, Some(&file)).await;

    let (arrived, go) = host.pause_retained_lookup();
    let waiting = tokio::spawn(async move { send(&mut looked_first, &late).await });
    arrived.await.expect("the request has looked for an answer");
    let asked = send(&mut answered_first, &early)
        .await
        .expect("the request answered first is run");
    let _ = go.send(());

    let conflict = waiting
        .await
        .expect("the request ran")
        .expect_err("the request that looked before the answer was written is refused");
    assert_eq!(
        conflict.code,
        kr_protocol::error::ErrorCode::IdConflict,
        "{conflict:?}"
    );
    let done = until(host, CapabilityChecksState::Current).await;
    assert_eq!(
        done.checks.started_at_ms, asked.started_at_ms,
        "one run: the findings are those of the request that was answered"
    );
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

/// KR-REQ-11.17, the profile clause: capability evidence taken under one execution profile is
/// invalidated when the profile changes, and the evidence is not served again.
///
/// A real daemon adopts a real worker, the owner has the checks performed, and a configuration edit
/// that changes the worker profile goes through the daemon's own path for such an edit. The edit
/// names the evidence it invalidates, the finding is gone from the records, and the checks read as
/// stale rather than as the run that is no longer about this host. A reading that changes nothing
/// leaves the finding where it was, so what ended it is the profile and not the second reading.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_17_findings_taken_under_one_profile_end_when_the_profile_changes() {
    let adopted = Adopted::start_with_document(1, &headless()).await;
    let host = &adopted.host;

    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");
    ask(host, ActionId::new(kr_ipc::new_uuid()), Some(&file))
        .await
        .expect("asked");
    let done = until(host, CapabilityChecksState::Current).await;
    assert!(
        done.desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .is_some_and(|record| record
                .invalidation
                .contains(&CapabilityInvalidation::WorkerProfile)),
        "the finding names the profile change among what ends it"
    );
    let again = shown(host).await;
    assert_eq!(
        again.checks.state,
        CapabilityChecksState::Current,
        "a reading that changes nothing ends nothing"
    );
    assert!(
        again
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .is_some()
    );

    let applied = host
        .controller()
        .apply_configuration(&Change::WorkerProfile(WorkerProfile::DesktopBound))
        .await
        .expect("the profile edit is applied");
    assert_eq!(
        applied.invalidated,
        vec![CapabilityInvalidation::WorkerProfile]
    );

    let after = shown(host).await;
    assert_eq!(
        after.checks.state,
        CapabilityChecksState::Stale,
        "the run was taken under the profile this host no longer creates sessions in"
    );
    assert!(
        after
            .desktop
            .record(capabilities::AUTHORISED_FILE_READ)
            .is_none(),
        "the finding is not served under the new profile: {:?}",
        after.desktop.record(capabilities::AUTHORISED_FILE_READ)
    );
    adopted.stop().await;
}

/// A graphical login of a case's own, in the headless profile this host is set to create sessions
/// with, so that the adopted worker is the one the checks are performed in. The login's generation
/// is what a case moves to show a new login.
struct Login(std::sync::atomic::AtomicU64);

impl Login {
    fn new(generation: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::atomic::AtomicU64::new(generation)))
    }

    fn becomes(&self, generation: u64) {
        self.0
            .store(generation, std::sync::atomic::Ordering::SeqCst);
    }
}

impl kr_controller::desktop::DesktopSource for Login {
    fn current(&self, boot: kr_protocol::identity::BootIdentity) -> DesktopContext {
        use kr_protocol::desktop::{
            ContainerEnvironment, DesktopAvailability, DesktopGenerationSource, DesktopSessionKind,
            DisplayServer,
        };
        use kr_protocol::ids::DesktopSessionId;
        use kr_protocol::scalars::U64;

        let generation = self.0.load(std::sync::atomic::Ordering::SeqCst);
        DesktopContext {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new(format!(
                    "macos_security_session:user=someone:uid=501:session=1:generation={generation}"
                ))
                .expect("a desktop name"),
            ),
            kind: DesktopSessionKind::MacosSecuritySession,
            platform_session: Nullable::some("1".to_owned()),
            login_generation: Nullable::some(U64::new(generation)),
            generation_source: DesktopGenerationSource::MacosSessionCreator,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(501)),
            boot_identity: boot,
            graphic_access: true,
            remote: false,
            availability: DesktopAvailability::Available,
            container: ContainerEnvironment::Host,
            display_server: DisplayServer::Quartz,
            compositor: Nullable::some("Aqua".to_owned()),
            worker_profile: WorkerProfile::HeadlessUser,
        }
    }
}

/// Starts a daemon with one adopted worker, whose desktop is read from `login`.
async fn adopted_on(login: &std::sync::Arc<Login>) -> Adopted {
    let adopted = Adopted::start_with_document(1, &headless()).await;
    adopted
        .host
        .controller()
        .read_the_desktop_from(login.clone())
        .await;
    adopted
}

/// What a worker's answer holds for the screen-image check: about the adopted worker's session, by
/// a disclosed probe, and naming the program it ran when there is one, with the digest it read.
fn finding(
    adopted: &Adopted,
    state: CapabilityState,
    program: Option<&std::path::Path>,
) -> kr_protocol::desktop::CapabilityRecord {
    use kr_protocol::desktop::{CapabilityIdentity, CapabilityRecord, CapabilitySubject};
    use kr_protocol::hostinfo::export::Sentence;
    use kr_protocol::ids::{CapabilityId, CapabilityRevision};
    use kr_protocol::scalars::U64;

    let path = program.map(|path| path.display().to_string());
    CapabilityRecord {
        capability: CapabilityId::new(capabilities::SCREEN_CAPTURE).expect("a capability"),
        version: U64::new(1),
        subject: CapabilitySubject {
            environment_id: adopted.host.environment_id,
            desktop_session_id: Nullable::null(),
            session_id: Nullable::some(adopted.workers[0].session_id),
            application: Nullable::null(),
            terminal: Nullable::null(),
        },
        revision: CapabilityRevision::new(0),
        state,
        evidence_source: CapabilityEvidenceSource::DisclosedProbe,
        identity: CapabilityIdentity {
            binary: Nullable(path.clone()),
            version: Nullable(
                path.as_deref()
                    .and_then(kr_worker::desktop::capability::facility_identity),
            ),
            package: Nullable::null(),
            schema: Nullable(path.as_ref().map(|_| "a-route".to_owned())),
            profile: Nullable::null(),
        },
        invalidation: kr_worker::desktop::probe::invalidation(),
        disabled_reason: Nullable(
            (state != CapabilityState::QualifiedAvailable)
                .then(|| Sentence::new().stated("a permission the check needs is not granted")),
        ),
        observed_at_ms: TimestampMs::new(1),
    }
}

/// Has the daemon hold `records` as the answer of the worker's run.
async fn the_worker_answers(
    adopted: &Adopted,
    records: Vec<kr_protocol::desktop::CapabilityRecord>,
) {
    adopted
        .host
        .controller()
        .hold_scripted_findings(records)
        .await
        .expect("a run begins in the adopted worker's session");
}

/// What `environment.capabilities` shows of the screen-image check: where the checks stand, the
/// record's state and what it came from.
async fn the_screen_image_check(
    host: &Host,
) -> (
    CapabilityChecksState,
    CapabilityState,
    CapabilityEvidenceSource,
) {
    let shown = shown(host).await;
    let record = shown
        .desktop
        .record(capabilities::SCREEN_CAPTURE)
        .expect("the platform has a record of the check");
    (shown.checks.state, record.state, record.evidence_source)
}

/// KR-REQ-03.29, S-4: the findings are held against the tool the worker ran, as
/// `environment.capabilities` reads them. The worker's answer names its own tool by path and
/// digest: replacing that file ends the findings, and replacing another file beside it, which the
/// worker never ran, does not.
///
/// The limit: this case does not put a candidate on the daemon's own search path. The routes
/// name absolute paths only, so the daemon's search finds none, and a case cannot set the
/// environment's search path (`unsafe_code` is forbidden). Once a row names a program by a bare
/// name, a case adds that candidate.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn what_is_held_follows_the_tool_the_worker_ran_and_not_another_beside_it() {
    let login = Login::new(2);
    let adopted = adopted_on(&login).await;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let worker_tool = directory.path().join("the-workers-tool");
    let another_tool = directory.path().join("the-controllers-candidate");
    std::fs::write(&worker_tool, b"the first build").expect("the worker's tool");
    std::fs::write(&another_tool, b"the first build").expect("another tool");

    the_worker_answers(
        &adopted,
        vec![finding(
            &adopted,
            CapabilityState::QualifiedAvailable,
            Some(&worker_tool),
        )],
    )
    .await;
    let held = (
        CapabilityChecksState::Current,
        CapabilityState::QualifiedAvailable,
        CapabilityEvidenceSource::DisclosedProbe,
    );
    assert_eq!(
        the_screen_image_check(&adopted.host).await,
        held,
        "nothing moved"
    );

    std::fs::write(&another_tool, b"the second build").expect("the replacement");
    assert_eq!(
        the_screen_image_check(&adopted.host).await,
        held,
        "a tool the worker never ran is not what the findings are about"
    );

    std::fs::write(&worker_tool, b"the second build").expect("the replacement");
    let (checks, _, source) = the_screen_image_check(&adopted.host).await;
    assert_eq!(
        checks,
        CapabilityChecksState::Stale,
        "the worker's own tool was replaced"
    );
    assert_ne!(
        source,
        CapabilityEvidenceSource::DisclosedProbe,
        "the finding is gone from the record"
    );
    adopted.stop().await;
}

/// KR-REQ-03.29, S-12: what a permission withdrawn since the first run comes to, as
/// `environment.capabilities` shows it. With no second run the first finding stands, which is the
/// limit the words state. A second run that the permission refuses replaces the first finding.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_run_finds_a_permission_withdrawn_since_in_what_the_daemon_shows() {
    let login = Login::new(2);
    let adopted = adopted_on(&login).await;

    the_worker_answers(
        &adopted,
        vec![finding(&adopted, CapabilityState::QualifiedAvailable, None)],
    )
    .await;
    let first = (
        CapabilityChecksState::Current,
        CapabilityState::QualifiedAvailable,
        CapabilityEvidenceSource::DisclosedProbe,
    );
    assert_eq!(the_screen_image_check(&adopted.host).await, first);
    assert_eq!(
        the_screen_image_check(&adopted.host).await,
        first,
        "with no second run the first finding stands"
    );

    the_worker_answers(
        &adopted,
        vec![finding(&adopted, CapabilityState::PermissionRequired, None)],
    )
    .await;
    assert_eq!(
        the_screen_image_check(&adopted.host).await,
        (
            CapabilityChecksState::Current,
            CapabilityState::PermissionRequired,
            CapabilityEvidenceSource::DisclosedProbe
        ),
        "the second run found the permission withdrawn"
    );
    adopted.stop().await;
}

/// KR-REQ-03.29, KR-REQ-11.17, S-13: findings held against a login go stale when the login
/// changes, as `environment.capabilities` shows it, through the daemon's own reading of the
/// desktop, which here is scripted. This is the clause the worker's suite says it does not cover.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn held_findings_go_stale_in_what_the_daemon_shows_when_the_login_changes() {
    let login = Login::new(2);
    let adopted = adopted_on(&login).await;

    the_worker_answers(
        &adopted,
        vec![finding(&adopted, CapabilityState::QualifiedAvailable, None)],
    )
    .await;
    assert_eq!(
        the_screen_image_check(&adopted.host).await,
        (
            CapabilityChecksState::Current,
            CapabilityState::QualifiedAvailable,
            CapabilityEvidenceSource::DisclosedProbe
        ),
        "the same login"
    );

    login.becomes(3);
    adopted
        .host
        .controller()
        .read_the_desktop_from(login.clone())
        .await;
    let (checks, _, source) = the_screen_image_check(&adopted.host).await;
    assert_eq!(
        checks,
        CapabilityChecksState::Stale,
        "a login that changed ends them"
    );
    assert_ne!(
        source,
        CapabilityEvidenceSource::DisclosedProbe,
        "the finding is gone from the record"
    );
    adopted.stop().await;
}
