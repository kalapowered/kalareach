//! The disclosed desktop checks, performed at the control daemon's request over a connection of its
//! own.
//!
//! What is proved here is the worker's side: the connection nothing else may use, the request that
//! names the file the read check reads and nothing else, the record that names the session whose
//! worker performed the check, and what a file that is not a file does. The daemon's side, and the
//! findings reaching `environment.capabilities`, are the daemon's own suite.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::BoundLink;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::desktop::{
    CapabilityEvidenceSource, CapabilityState, DesktopChecksAnswer, DesktopChecksRequest,
    capabilities,
};
use kr_protocol::envelope::{ControlFrame, Outcome};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    BuildId, ControllerGeneration, EnvironmentId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::ControllerConnectionRole;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long an answer may take. The file read is bounded by its own five seconds.
const LIVENESS: Duration = Duration::from_secs(30);

struct Host {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    _runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A headless session whose root shell sleeps, and its worker serving the local endpoint.
async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let journal_path = environment.journal_database(session_id);
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec sleep 300"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(journal_path.clone()),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        _service: service,
        _runtime: runtime,
        session_id,
        environment_id,
        endpoint,
        controller,
        boot,
    }
}

/// A connection of the daemon's, declared for `role` and speaking for generation one.
async fn daemon(host: &Host, role: ControllerConnectionRole) -> BoundLink {
    let mut client = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
    client
        .send(&ControlFrame::ControllerRole(role))
        .await
        .expect("declares the role");
    match client.recv().await.expect("the worker answers") {
        ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
        other => panic!("the worker answered {other:?}"),
    }
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    client
}

fn request(host: &Host, id: u64, file: Option<&str>) -> DesktopChecksRequest {
    DesktopChecksRequest {
        request_id: RequestId::new(id),
        environment_id: host.environment_id,
        authorised_file: Nullable(file.map(str::to_owned)),
    }
}

/// What came back for one request.
#[derive(Debug)]
enum Answer {
    Findings(Box<DesktopChecksAnswer>),
    Refused(RequestId, ErrorCode),
}

async fn answer(link: &mut BoundLink) -> Answer {
    tokio::time::timeout(LIVENESS, async {
        loop {
            match link.recv().await.expect("the worker answers") {
                ControlFrame::DesktopChecksAnswer(found) => return Answer::Findings(found),
                ControlFrame::Response(response) => match response.outcome {
                    Outcome::Error(error) => {
                        return Answer::Refused(response.request_id, error.code);
                    }
                    other => panic!("the worker answered {other:?}"),
                },
                ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
                other => panic!("the worker answered {other:?}"),
            }
        }
    })
    .await
    .expect("the worker answers in time")
}

async fn ask(link: &mut BoundLink, request: DesktopChecksRequest) -> Answer {
    link.send(&ControlFrame::DesktopChecks(request))
        .await
        .expect("writes the request");
    answer(link).await
}

/// KR-REQ-03.29: the checks connection takes the checks request and nothing else, is the one place a request is
/// served, and a newer one replaces it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_checks_connection_carries_the_checks_request_only_and_a_newer_one_replaces_it() {
    let host = host().await;

    // The authority connection is not the place: the request is refused there.
    let mut authority = daemon(&host, ControllerConnectionRole::Authority).await;
    match ask(&mut authority, request(&host, 3, None)).await {
        Answer::Refused(id, code) => {
            assert_eq!(id, RequestId::new(3));
            assert_eq!(code, ErrorCode::PermissionDenied);
        }
        other => panic!("the authority connection performed the checks: {other:?}"),
    }

    let mut first = daemon(&host, ControllerConnectionRole::Checks).await;
    // Nothing else is served on it, and the refusal names the request it answers.
    first
        .send(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id: RequestId::new(5),
            method: kr_protocol::method::Method::SessionRead.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params: kr_protocol::envelope::ParamsValue::from_typed(
                &kr_protocol::session::SessionReadParams {
                    session_id: host.session_id,
                },
            )
            .expect("encodes"),
        }))
        .await
        .expect("writes");
    assert!(
        matches!(
            answer(&mut first).await,
            Answer::Refused(id, ErrorCode::PermissionDenied) if id == RequestId::new(5)
        ),
        "another request was served on the checks connection"
    );
    match ask(&mut first, request(&host, 1, None)).await {
        Answer::Findings(found) => assert_eq!(found.request_id, RequestId::new(1)),
        other => panic!("the checks connection performed nothing: {other:?}"),
    }

    // A newer connection takes over, and the one before it is fenced: an explicit refusal or a
    // closed connection, and not a stalled one.
    let mut second = daemon(&host, ControllerConnectionRole::Checks).await;
    match ask(&mut second, request(&host, 2, None)).await {
        Answer::Findings(found) => assert_eq!(found.request_id, RequestId::new(2)),
        other => panic!("the newer checks connection performed nothing: {other:?}"),
    }
    first
        .send(&ControlFrame::DesktopChecks(request(&host, 4, None)))
        .await
        .ok();
    let replied = tokio::time::timeout(LIVENESS, first.recv())
        .await
        .expect("the older connection answers or closes, and does not stall");
    let fenced = match replied {
        Err(_) => true,
        Ok(ControlFrame::Response(response)) => matches!(response.outcome, Outcome::Error(_)),
        Ok(_) => false,
    };
    assert!(fenced, "the older connection is fenced");
}

/// KR-REQ-03.29: the read check reads the file the daemon named, in this worker, and the record names the session
/// whose worker read it. A file that is not a regular file is not read, and a path that is not
/// absolute is refused before anything is performed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_read_check_reads_the_named_file_here_and_names_this_session() {
    let host = host().await;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the test's file");
    let mut link = daemon(&host, ControllerConnectionRole::Checks).await;

    let found = match ask(&mut link, request(&host, 1, file.to_str())).await {
        Answer::Findings(found) => found,
        other => panic!("the file was not read: {other:?}"),
    };
    assert_eq!(found.session_id, host.session_id);
    let record = found
        .records
        .iter()
        .find(|record| record.capability.as_str() == capabilities::AUTHORISED_FILE_READ)
        .expect("the read check has a record");
    assert_eq!(record.state, CapabilityState::QualifiedAvailable);
    assert_eq!(
        record.evidence_source,
        CapabilityEvidenceSource::DisclosedProbe
    );
    assert_eq!(record.subject.session_id.as_ref(), Some(&host.session_id));
    assert!(
        record
            .disabled_reason
            .as_ref()
            .is_some_and(|reason| reason.as_str().contains("25 bytes")),
        "{:?}",
        record.disabled_reason
    );
    // A headless session is asked for the read alone: no check that acts on a desktop is
    // performed, and none has a record.
    assert_eq!(found.records.len(), 1, "{:?}", found.records);

    // A directory is not a file, and nothing is read from it.
    let not_a_file = match ask(&mut link, request(&host, 2, directory.path().to_str())).await {
        Answer::Findings(found) => found,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        not_a_file.records[0].state,
        CapabilityState::TemporarilyUnavailable,
        "{:?}",
        not_a_file.records[0].disabled_reason
    );

    // A path that is not absolute is refused, and the connection goes on serving.
    match ask(&mut link, request(&host, 3, Some("relative/path"))).await {
        Answer::Refused(id, code) => {
            assert_eq!(id, RequestId::new(3));
            assert_eq!(code, ErrorCode::InvalidArgument);
        }
        other => panic!("a relative path was accepted: {other:?}"),
    }
    match ask(&mut link, request(&host, 4, None)).await {
        Answer::Findings(found) => assert_eq!(found.request_id, RequestId::new(4)),
        other => panic!("{other:?}"),
    }
}

/// KR-REQ-03.29: a pipe in place of the nominated file is not opened for a writer that is not coming: the check
/// answers that it is not a file.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pipe_in_place_of_the_named_file_is_answered_and_not_waited_for() {
    let host = host().await;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let pipe = directory.path().join("authorised.pipe");
    let made = std::process::Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success());
    let mut link = daemon(&host, ControllerConnectionRole::Checks).await;
    match ask(&mut link, request(&host, 1, pipe.to_str())).await {
        Answer::Findings(found) => {
            let reason = found.records[0]
                .disabled_reason
                .as_ref()
                .map(|reason| reason.as_str().to_owned())
                .unwrap_or_default();
            assert!(reason.contains("not a regular file"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}
