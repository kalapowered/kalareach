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
    CapabilityEvidenceSource, CapabilityInvalidation, CapabilityState, DesktopChecksAnswer,
    DesktopChecksRequest, capabilities,
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
use kr_worker::desktop::capability::facility_identity;
use kr_worker::desktop::probe::{Fingerprint, stale};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long an answer may take. The file read is bounded by its own five seconds.
const LIVENESS: Duration = Duration::from_secs(30);

struct Host {
    _service: Arc<WorkerService>,
    _runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
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

/// One path as the person left it: its modification time and its permissions.
#[derive(Debug, PartialEq, Eq)]
struct Left {
    modified: std::time::SystemTime,
    mode: u32,
}

fn left(path: &std::path::Path) -> Left {
    let metadata = std::fs::metadata(path).expect("the path's metadata");
    #[cfg(unix)]
    let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
    #[cfg(not(unix))]
    let mode = u32::from(metadata.permissions().readonly());
    Left {
        modified: metadata.modified().expect("a modification time"),
        mode,
    }
}

/// What is around one nominated file: the directory as the person left it, which moves its
/// modification time when a name is added, removed or renamed, and every name in it with its bytes,
/// its modification time and its mode bits (on Windows, its read-only attribute).
fn directory_state(directory: &std::path::Path) -> (Left, Vec<(String, Vec<u8>, Left)>) {
    let mut names: Vec<_> = std::fs::read_dir(directory)
        .expect("lists the directory")
        .map(|entry| {
            let path = entry.expect("an entry").path();
            (
                path.file_name()
                    .expect("a name")
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(&path).expect("reads the file"),
                left(&path),
            )
        })
        .collect();
    names.sort_by(|first, second| first.0.cmp(&second.0));
    (left(directory), names)
}

/// KR-REQ-03.30, KR-REQ-11.16: the authorised-file check leaves the file the person nominated and
/// everything beside it as they were: the same names, bytes, modification times and mode bits (on Windows, the
/// read-only attribute), in the same directory. The owner, extended attributes and access lists are
/// not compared. The run performed the read: a headless session is asked for that check alone, so
/// there is no check that sends a keystroke to hold back. That the one check which sends input is
/// withheld without an isolated context of its own is the probe's own unit cases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_authorised_file_check_leaves_the_file_and_its_directory_as_they_were() {
    let host = host().await;
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the nominated file");
    std::fs::write(directory.path().join("beside.txt"), b"not nominated").expect("another file");
    // A mode the process's umask would not give a new file, so that a read that set the mode to
    // the usual one, or to the owner's alone, changes it whatever the umask is.
    #[cfg(unix)]
    for name in ["authorised.txt", "beside.txt"] {
        std::fs::set_permissions(
            directory.path().join(name),
            std::os::unix::fs::PermissionsExt::from_mode(0o640),
        )
        .expect("a mode of the test's choosing");
    }
    let before = directory_state(directory.path());
    let mut link = daemon(&host, ControllerConnectionRole::Checks).await;

    for id in 1..=2 {
        match ask(&mut link, request(&host, id, file.to_str())).await {
            Answer::Findings(found) => {
                let [record] = &found.records[..] else {
                    panic!("the read is the one check performed: {:?}", found.records);
                };
                assert_eq!(
                    record.capability.as_str(),
                    capabilities::AUTHORISED_FILE_READ
                );
                assert_eq!(record.state, CapabilityState::QualifiedAvailable);
                assert_eq!(
                    record.evidence_source,
                    CapabilityEvidenceSource::DisclosedProbe
                );
            }
            other => panic!("the checks were not performed: {other:?}"),
        }
        assert_eq!(
            directory_state(directory.path()),
            before,
            "the person's files are as they were after request {id}"
        );
    }
}

/// Every name under `root` with what the person left in it, as one digest: for a file its bytes, its
/// modification time and its mode bits (on Windows, its read-only attribute), and for a directory
/// its modification time, which moves when a name is added, removed or renamed. `except` is left
/// out of the digest, so that the file a probe was pointed at can be told apart from the rest.
fn tree_digest(root: &std::path::Path, except: Option<&std::path::Path>) -> String {
    use sha2::{Digest as _, Sha256};

    fn walk(
        directory: &std::path::Path,
        root: &std::path::Path,
        except: Option<&std::path::Path>,
        hasher: &mut Sha256,
    ) {
        let mut paths: Vec<_> = std::fs::read_dir(directory)
            .expect("lists the directory")
            .map(|entry| entry.expect("an entry").path())
            .collect();
        paths.sort();
        for path in paths {
            if except == Some(path.as_path()) {
                continue;
            }
            hasher.update(
                path.strip_prefix(root)
                    .expect("under the root")
                    .to_string_lossy()
                    .as_bytes(),
            );
            hasher.update(format!("{:?}", left(&path)).as_bytes());
            if path.is_dir() {
                walk(&path, root, except, hasher);
            } else {
                hasher.update(std::fs::read(&path).expect("reads the file"));
            }
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", left(root)).as_bytes());
    walk(root, root, except, &mut hasher);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// KR-REQ-11.16, the clause that no unrelated user data is mutated: a probe pointed at one file
/// leaves every other file in the person's tree as it was.
///
/// The tree is the person's own, several directories deep, with the nominated file in the middle of
/// it and other files above, beside and below it, each with a modification time and a mode that a
/// probe which touched or rewrote it would change. A digest of everything but the nominated file
/// is taken before the worker performs the probe and after each of two runs, and a second digest
/// of the whole tree includes the nominated file too. A last step changes one file on purpose and
/// shows that the digest sees it, so that equal digests mean an untouched tree and not a digest
/// that sees nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_16_a_probe_leaves_every_file_it_was_not_pointed_at_as_it_was() {
    let host = host().await;
    let tree = kr_ipc::testing::PrivateTempDir::create();
    let root = tree.path();
    let at = |parts: &[&str]| {
        parts
            .iter()
            .fold(root.to_path_buf(), |path, part| path.join(part))
    };
    let nominated = at(&["projects", "notes", "authorised.txt"]);
    let others = [
        at(&["projects", "notes", "beside.txt"]),
        at(&["projects", "other", "report.txt"]),
        at(&["archive", "2024", "ledger.csv"]),
        at(&["top.txt"]),
    ];
    for path in std::iter::once(&nominated).chain(others.iter()) {
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("makes the directories");
    }
    std::fs::write(&nominated, b"the person nominated this").expect("the nominated file");
    for (index, path) in others.iter().enumerate() {
        std::fs::write(path, format!("not nominated {index}")).expect("another file");
    }
    // A modification time long ago and a mode that the process's umask would not give a new file,
    // so that a probe that touched a file, or created it again, changes what is digested.
    for (index, path) in std::iter::once(&nominated).chain(others.iter()).enumerate() {
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("opens the file to date it");
        file.set_modified(
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + index as u64),
        )
        .expect("sets a modification time");
        #[cfg(unix)]
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o640))
            .expect("a mode of the test's choosing");
    }
    let rest_before = tree_digest(root, Some(&nominated));
    let whole_before = tree_digest(root, None);

    let mut link = daemon(&host, ControllerConnectionRole::Checks).await;
    for id in 1..=2 {
        match ask(&mut link, request(&host, id, nominated.to_str())).await {
            Answer::Findings(found) => {
                let [record] = &found.records[..] else {
                    panic!("the read is the one check performed: {:?}", found.records);
                };
                assert_eq!(
                    record.state,
                    CapabilityState::QualifiedAvailable,
                    "the probe ran and read the file: {:?}",
                    record.disabled_reason
                );
            }
            other => panic!("the checks were not performed: {other:?}"),
        }
        assert_eq!(
            tree_digest(root, Some(&nominated)),
            rest_before,
            "every file the probe was not pointed at is as it was after request {id}"
        );
        assert_eq!(
            tree_digest(root, None),
            whole_before,
            "the nominated file is as it was too after request {id}"
        );
    }

    std::fs::write(&others[3], b"changed").expect("changes one file on purpose");
    assert_ne!(
        tree_digest(root, Some(&nominated)),
        rest_before,
        "the digest sees a file that was changed"
    );
}

/// The record the worker gives for the read check, performed on a file of this test's own.
async fn a_real_finding(host: &Host) -> kr_protocol::desktop::CapabilityRecord {
    let directory = tempfile::tempdir().expect("a directory of this test's own");
    let file = directory.path().join("authorised.txt");
    std::fs::write(&file, b"the person nominated this").expect("the nominated file");
    let mut link = daemon(host, ControllerConnectionRole::Checks).await;
    match ask(&mut link, request(host, 1, file.to_str())).await {
        Answer::Findings(found) => found.records[0].clone(),
        other => panic!("the checks were not performed: {other:?}"),
    }
}

/// KR-REQ-11.17, the desktop generation clause: a finding the worker made is ended by a new
/// graphical login and by nothing else.
///
/// The record comes from the worker's own run over its checks connection, and what ends it is what
/// the record says ends it: it names the desktop generation, it stands while the generation is the
/// one it was taken in, it is ended by the next login, and a record that does not name the
/// generation is not ended by one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_17_a_finding_ends_when_the_desktop_generation_it_was_taken_in_changes() {
    let host = host().await;
    let mut record = a_real_finding(&host).await;
    assert!(
        record
            .invalidation
            .contains(&CapabilityInvalidation::DesktopGeneration),
        "the record names the generation among what ends it: {:?}",
        record.invalidation
    );
    let taken = Fingerprint {
        desktop_generation: Some(11),
        ..Fingerprint::default()
    };
    assert!(
        stale(&record, &taken, &taken).is_empty(),
        "a finding stands while the login it was taken in is the one there is"
    );
    let next_login = Fingerprint {
        desktop_generation: Some(12),
        ..taken.clone()
    };
    assert_eq!(
        stale(&record, &taken, &next_login),
        vec![CapabilityInvalidation::DesktopGeneration]
    );
    record
        .invalidation
        .retain(|trigger| *trigger != CapabilityInvalidation::DesktopGeneration);
    assert!(
        stale(&record, &taken, &next_login).is_empty(),
        "a record that does not name the generation is not ended by it"
    );
}

/// KR-REQ-11.17, the binary clause: a finding the worker made is ended when the tool it was made
/// with is replaced or can no longer be identified, and not while the tool is the same file.
///
/// The record comes from the worker's own run. The tool is a file of this test's own, identified by
/// what the host digests of a facility, and an upgrade is its bytes being replaced in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_17_a_finding_ends_when_the_tool_it_was_taken_with_is_replaced() {
    let host = host().await;
    let record = a_real_finding(&host).await;
    assert!(
        record
            .invalidation
            .contains(&CapabilityInvalidation::BinaryIdentity),
        "the record names the binary among what ends it: {:?}",
        record.invalidation
    );
    let tree = kr_ipc::testing::PrivateTempDir::create();
    let tool = tree.path().join("tool");
    std::fs::write(&tool, b"the tool as it was installed").expect("the tool");
    let identity = |path: &std::path::Path| {
        facility_identity(path.to_str().expect("a UTF-8 path")).map(|said| format!("{said:?}"))
    };
    let taken = Fingerprint {
        facility: identity(&tool),
        ..Fingerprint::default()
    };
    assert!(taken.facility.is_some(), "the tool is identified");
    assert!(
        stale(
            &record,
            &taken,
            &Fingerprint {
                facility: identity(&tool),
                ..Fingerprint::default()
            }
        )
        .is_empty(),
        "the same file is the same tool"
    );

    std::fs::write(&tool, b"the tool as an upgrade left it").expect("the upgraded tool");
    let upgraded = Fingerprint {
        facility: identity(&tool),
        ..Fingerprint::default()
    };
    assert_eq!(
        stale(&record, &taken, &upgraded),
        vec![CapabilityInvalidation::BinaryIdentity]
    );

    std::fs::remove_file(&tool).expect("removes the tool");
    let removed = Fingerprint {
        facility: identity(&tool),
        ..Fingerprint::default()
    };
    assert_eq!(
        removed.facility, None,
        "a tool that is gone has no identity"
    );
    assert_eq!(
        stale(&record, &taken, &removed),
        vec![CapabilityInvalidation::BinaryIdentity]
    );
}
