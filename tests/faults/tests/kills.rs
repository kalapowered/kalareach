//! Processes killed at named points, and what is left of their session.
//!
//! The control daemon runs in this test's process, as the host suites run it, and starts each
//! session's worker as a detached process of its own: the real `kr-worker` this workspace builds,
//! whose version is checked to be this build's, copied to the internal disk with everything else a
//! launched process touches. The session's root program asks for bracketed paste, records every
//! byte of input it reads, as it reads it, in a file of its own, so what reached the application is
//! read from the application's own record, and writes a numbered line every twentieth of a second
//! once the test releases it. A terminal is a local client on the worker's own endpoint, as a
//! person's is. A client that is to be killed is one of two kinds. The first is this test binary
//! run again, as a process of its own, in a mode where it attaches through the harness's own
//! terminal code and nothing else: it is no `kr attach`, and shows only what the worker does when a
//! lease holder's connection dies. The second is the built `kr attach` itself, run by a shell on a
//! pseudo-terminal as a person runs it, which answers the terminal queries the command asks.
//!
//! A kill happens only at a named point that the peers prove. A paste is open once the program's
//! record holds the paste's start and the first half of what was pasted. Output is flowing once the
//! program has been released, which the test does only after every terminal has subscribed, and a
//! terminal has been shown three of its lines whole: a terminal that subscribed later would be
//! painted the screen instead, and would never see them. A signal goes only to a process this test
//! started and has not collected. The root program ends itself, by a signal to its own process
//! number, when this test creates a file it watches for, so nothing is signalled by a number
//! this test does not hold.
//!
//! Each fault has its control: the same run without the fault, in which what the fault causes is
//! absent.
//!
//! The stage runs on Unix: a Windows worker ends through its job object, which is the Windows
//! machine's to show.

#![cfg(unix)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_controller::registry::Registry;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{DetachedSupervisor, NoTerminal};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::identity::{ProcessState, process_start_identity, process_state};
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActionId, ActorId, AttachmentId, BuildId, DraftId, EnvironmentId, InputLeaseEpoch,
    InputSequence, SessionEpoch, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult, InputContent, InputWriteParams};
use kr_protocol::insertion::{InsertionBegin, InsertionReport, ReportedOutcome};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::scalars::{Bytes, CanonicalSet, Digest256, Nullable, U64};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, Dimensions, Presentation, SESSION_CLOSED_EVENT,
    SessionCloseParams, SessionCreateParams, SessionCreateResult, SessionReadParams,
    SessionReadResult, SessionState, ShellMode,
};

use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    AttachmentHandle, ChunkDescriptor, DraftCreateParams, DraftCreateResult, DraftRecord,
    DraftState, InsertionMethod, InsertionState, UploadBeginParams, UploadChunkParams,
    UploadFinishParams,
};

#[path = "../../../crates/kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How long a wait for something that has to happen is given. It fails when the thing never
/// happens; it measures nothing.
const LIVENESS: Duration = Duration::from_secs(120);

/// How long a closed session is watched for anything starting again: longer than anything in a
/// closure waits, so a restart would follow inside it.
const RESTART_WATCH: Duration = Duration::from_secs(3);

/// The session's root program.
///
/// The terminal is put into raw mode first, so every byte of input reaches the record as it was
/// written and nothing is echoed. Its reader, a child that copies the terminal's input into the
/// record, starts before anything is written. It writes no numbered line until the test creates
/// `kr-flow-go`, once every terminal has subscribed, and ends itself by a signal to its own process
/// number when the test creates `kr-die`.
const ROOT_PROGRAM: &str = r#"#!/bin/sh
stty raw -echo -opost 2>/dev/null
printf '\033[?2004h'
printf '%s\n' "$$" > root.pid
exec 3<&0
cat <&3 > input.record 3<&- &
printf '%s\n' "$!" > reader.pid
while [ ! -e kr-flow-go ]; do sleep 0.05; done
n=0
while :; do
  if [ -e kr-die ]; then kill -KILL "$$"; fi
  n=$((n + 1)); printf 'kr-flow-%d\r\n' "$n"; sleep 0.05
done
"#;

/// What a paste's start and the first half of what was pasted look like, as a terminal sends them.
const PASTE_OPEN: &[u8] = b"\x1b[200~first-half-";

/// What a paste's end looks like.
const PASTE_END: &[u8] = b"\x1b[201~";

/// The environment variables that start the client half, and tell it what to do.
const HALF_ROOT: &str = "KR_KILLS_ROOT";
const HALF_ENVIRONMENT: &str = "KR_KILLS_ENVIRONMENT";
const HALF_SESSION: &str = "KR_KILLS_SESSION";
const HALF_WRITE: &str = "KR_KILLS_WRITE";
const HALF_READY: &str = "KR_KILLS_READY";

/// The client half's name, as the test harness selects it.
const CLIENT_HALF: &str = "serve_a_client_half_for_the_kill_stage";

/// An offer of one attachment to a session's agent that a worker claimed.
struct Offer {
    action_id: ActionId,
    draft_id: DraftId,
    transfer_id: kr_protocol::ids::TransferId,
    attempt: U64,
}

impl Offer {
    /// The report of what became of the offer.
    fn reported(&self, outcome: ReportedOutcome) -> InsertionReport {
        InsertionReport {
            action_id: self.action_id,
            draft_id: self.draft_id,
            transfer_id: self.transfer_id,
            attempt: self.attempt,
            outcome,
        }
    }
}

/// The principal the daemon makes of a local client of this user.
fn local_actor() -> ActorId {
    ActorId::new(format!("local:{}", kr_ipc::paths::current_uid())).expect("a principal")
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Waits for `check` to give something, polling, for at most [`LIVENESS`].
async fn until<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let started = tokio::time::Instant::now();
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "waited {LIVENESS:?} for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A program this workspace builds, beside this test.
///
/// A test run of this crate alone does not build the programs, so one an earlier build left in the
/// target directory could be started, and every check below would be about another build. The
/// version a program reports is checked against this build's where the test starts it, which
/// catches a program of another release or protocol and not a stale build of this one, so build
/// the programs before a run of this crate alone.
fn built_program(name: &str, package: &str) -> PathBuf {
    let mut directory = std::env::current_exe().expect("this test's own path");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let built = directory.join(name);
    assert!(
        built.is_file(),
        "the kill stage starts a real {name} and there is none at {}; build it with `cargo build \
         -p {package}` or run scripts/end-to-end.sh, which does",
        built.display()
    );
    built
}

/// The worker this workspace builds, beside this test.
fn built_worker() -> PathBuf {
    built_program("kr-worker", "kr-worker")
}

/// The host: its tree, which ends everything its daemon started however the test ends, and the
/// daemon, serving on this test's runtime.
struct Host {
    tree: teardown::Tree,
    environment_id: EnvironmentId,
    root_program: PathBuf,
    controller: Arc<Controller>,
}

impl Host {
    async fn start() -> Self {
        let tree = teardown::Tree::create();
        let environment = tree.environment();
        let environment_id = tree.environment_id();
        let worker = tree.root().join("kr-worker");
        kr_ipc::testing::place_and_start_once(&built_worker(), &worker, &["--version"]);
        let said = std::process::Command::new(&worker)
            .arg("--version")
            .env_clear()
            .current_dir(tree.root())
            .output()
            .expect("the worker says its version");
        let this = format!(
            "kr-worker {} (protocol {})",
            env!("CARGO_PKG_VERSION"),
            kr_protocol::hello::PACKAGE_VERSION
        );
        assert_eq!(
            String::from_utf8_lossy(&said.stdout).trim(),
            this,
            "the worker at {} is of another version; build this one",
            worker.display()
        );
        let root_program = tree.root().join("kr-kill-root");
        kr_ipc::testing::place_script(&root_program, ROOT_PROGRAM);
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: tree.supervisor(Box::new(DetachedSupervisor::new())),
            worker_program: worker,
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the client endpoint");
        tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
        tokio::spawn(Arc::clone(&controller).serve_clients(clients));
        Self {
            tree,
            environment_id,
            root_program,
            controller,
        }
    }

    /// Publishes a file for a session: the upload is made and finished in the transfer service,
    /// which is set-up and not what the tests below are about.
    fn publish_for(&self, session_id: SessionId, bytes: &[u8]) -> AttachmentHandle {
        let service = self.controller.transfer().service();
        let actor = local_actor();
        let digest = Digest256::from_bytes(kr_cbor::sha256(bytes));
        let length = U64::new(bytes.len() as u64);
        let begun = service
            .upload_begin(
                &actor,
                &UploadBeginParams {
                    environment_id: self.environment_id,
                    session_id: Nullable::some(session_id),
                    device_id: Nullable::null(),
                    declared_byte_len: length,
                    declared_digest: digest,
                    declared_media_type: "application/octet-stream".to_owned(),
                    original_file_name: "notes.bin".to_owned(),
                },
                None,
                None,
            )
            .expect("reserves the upload");
        assert_eq!(begun.layout.chunk_count, U64::new(1), "one chunk holds it");
        service
            .upload_chunk(
                &actor,
                &UploadChunkParams {
                    transfer_id: begun.transfer_id,
                    chunk: ChunkDescriptor {
                        index: U64::new(0),
                        byte_len: length,
                        digest,
                    },
                    bytes: Bytes::new(bytes.to_vec()),
                },
                None,
            )
            .expect("takes the chunk");
        service
            .upload_finish(
                &actor,
                &UploadFinishParams {
                    transfer_id: begun.transfer_id,
                    declared_byte_len: length,
                    declared_digest: digest,
                },
                None,
            )
            .expect("publishes the attachment")
            .handle
    }

    /// What a person's attachment to a session's draft comes to at the daemon: a draft that targets
    /// the session is created and the file is bound to it, both through the daemon's own methods,
    /// as a manual terminal workflow, which the daemon binds with no declaration from an
    /// integration and which no upstream evidence confirms.
    async fn attach_manually(
        &self,
        session_id: SessionId,
        bytes: &[u8],
    ) -> (DraftId, AttachmentHandle) {
        let handle = self.publish_for(session_id, bytes);
        let draft: DraftCreateResult = self
            .daemon()
            .await
            .mutate(
                Method::DraftCreate,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(session_id),
                &DraftCreateParams {
                    environment_id: self.environment_id,
                    device_id: Nullable::null(),
                    session_id: Nullable::some(session_id),
                    application_instance_id: Nullable::null(),
                    text: "have a look at this".to_owned(),
                },
            )
            .await
            .expect("the create reaches the daemon")
            .unwrap_or_else(|error| panic!("the daemon refused the draft: {error}"))
            .to_typed()
            .expect("decodes the draft");
        let bound = self
            .bind(
                session_id,
                draft.draft.draft_id,
                draft.draft.revision,
                &handle,
            )
            .await
            .unwrap_or_else(|error| panic!("the daemon refused the binding: {error}"));
        assert_eq!(bound.attachment.state, InsertionState::Recorded);
        (draft.draft.draft_id, handle)
    }

    /// What an adapter's offer of an attachment to a session's agent comes to once an integration
    /// has declared the typed path for the operation: a draft that targets the session is created
    /// and the file is bound to it as a typed submission, through the transfer service.
    ///
    /// The daemon binds a typed submission only for a path an integration declared, and none can
    /// today, so this stands for the binding the declaring integration will make; what an offer
    /// does with the binding once it exists is the daemon's and the worker's.
    fn offer_declared_attachment(
        &self,
        session_id: SessionId,
        bytes: &[u8],
    ) -> (DraftId, AttachmentHandle) {
        let handle = self.publish_for(session_id, bytes);
        let service = self.controller.transfer().service();
        let actor = local_actor();
        let draft = service
            .draft_create(
                &actor,
                &DraftCreateParams {
                    environment_id: self.environment_id,
                    device_id: Nullable::null(),
                    session_id: Nullable::some(session_id),
                    application_instance_id: Nullable::null(),
                    text: "have a look at this".to_owned(),
                },
                None,
                None,
            )
            .expect("creates the draft")
            .draft;
        let bound = service
            .draft_add_attachment(
                &actor,
                &AgentDraftAddAttachmentParams {
                    draft_id: draft.draft_id,
                    expected_revision: draft.revision,
                    transfer_id: handle.transfer_id,
                    contribution: AttachmentContribution {
                        operation_id: "attach".to_owned(),
                        accepted_media_types: vec![handle.declared_media_type.clone()],
                        max_byte_len: U64::new(1024),
                        max_count: U64::new(2),
                        insertion_method: InsertionMethod::TypedSubmission,
                        external_destination: Nullable::null(),
                        model_media_capability: false,
                    },
                },
                None,
                None,
            )
            .expect("binds the attachment");
        assert_eq!(bound.attachment.state, InsertionState::Recorded);
        (draft.draft_id, handle)
    }

    /// Binds a published file to a draft through the daemon, as a manual terminal workflow.
    async fn bind(
        &self,
        session_id: SessionId,
        draft_id: DraftId,
        expected_revision: kr_protocol::ids::DraftRevision,
        handle: &AttachmentHandle,
    ) -> Result<AgentDraftAddAttachmentResult, kr_protocol::error::ProtocolError> {
        self.daemon()
            .await
            .mutate(
                Method::AgentDraftAddAttachment,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(session_id),
                &AgentDraftAddAttachmentParams {
                    draft_id,
                    expected_revision,
                    transfer_id: handle.transfer_id,
                    contribution: AttachmentContribution {
                        operation_id: "attach".to_owned(),
                        accepted_media_types: vec![handle.declared_media_type.clone()],
                        max_byte_len: U64::new(1024),
                        max_count: U64::new(2),
                        insertion_method: InsertionMethod::ManualTerminalWorkflow,
                        external_destination: Nullable::null(),
                        model_media_capability: false,
                    },
                },
            )
            .await
            .expect("the call reaches the daemon")
            .map(|answer| answer.to_typed().expect("decodes the binding"))
    }

    /// Claims the one attachment of a draft for an offer to the session's agent, as the session's
    /// worker does, and returns what the claim is for.
    fn claim(&self, session_id: SessionId, draft_id: DraftId, handle: &AttachmentHandle) -> Offer {
        let service = self.controller.transfer().service();
        let facts = service
            .insertion_facts(&local_actor(), session_id, draft_id)
            .expect("the draft's facts");
        let now = kr_ipc::clock::boot_elapsed_ms();
        let offer = Offer {
            action_id: ActionId::new(kr_ipc::new_uuid()),
            draft_id,
            transfer_id: handle.transfer_id,
            attempt: facts.bindings[0].attempt,
        };
        service
            .insertion_begin(
                &local_actor(),
                session_id,
                &InsertionBegin {
                    action_id: offer.action_id,
                    draft_id,
                    transfer_id: handle.transfer_id,
                    attempt: offer.attempt,
                    max_count: U64::new(2),
                    deadline_boot_ms: U64::new(now + 60_000),
                },
                &kr_ipc::clock::SystemSharedClock,
            )
            .expect("the attachment is claimed for the offer");
        offer
    }

    /// The draft as the transfer service holds it.
    fn draft(&self, draft_id: DraftId) -> DraftRecord {
        self.controller
            .transfer()
            .service()
            .draft(&local_actor(), draft_id)
            .expect("reads the draft")
    }

    fn environment(&self) -> EnvironmentPaths {
        self.tree.environment()
    }

    /// A working directory of its own for one session.
    fn work(&self, name: &str) -> PathBuf {
        let work = self.tree.root().join(name);
        std::fs::create_dir_all(&work).expect("a working directory");
        work
    }

    /// Lets the root program of the session working in `work` write. Every terminal that is to see
    /// its output live has subscribed by now, so what they are shown are whole lines.
    fn release_output(&self, work: &Path) {
        std::fs::write(work.join("kr-flow-go"), b"").expect("releases the root program");
    }

    fn target(&self, session_id: SessionId) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    async fn daemon(&self) -> LocalClient {
        let endpoint = self
            .environment()
            .controller_endpoint()
            .expect("the daemon's endpoint");
        LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the daemon")
    }

    /// Creates a session running the root program in `work`, and waits until the program is
    /// running: its reader has started and its record is open. It writes no line yet.
    async fn create(&self, work: &Path) -> (SessionId, Dimensions) {
        let created: SessionCreateResult = self
            .daemon()
            .await
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.environment_id),
                &SessionCreateParams {
                    environment_id: self.environment_id,
                    presentation: Presentation::Attach,
                    shell: Nullable::some(self.root_program.display().to_string()),
                    shell_mode: ShellMode::NativeCompat,
                    cwd: Nullable::some(work.display().to_string()),
                    dimensions: Nullable::null(),
                    worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    palette: Nullable::null(),
                    environment_snapshot: vec![kr_protocol::session::EnvironmentVariable {
                        name: "PATH".to_owned(),
                        value: "/usr/bin:/bin".to_owned(),
                    }],
                    launch_profile: kr_protocol::session::LaunchProfile::default(),
                    terminal: Nullable::null(),
                },
            )
            .await
            .expect("the create reaches the daemon")
            .unwrap_or_else(|error| panic!("the daemon refused the create: {error}"))
            .to_typed()
            .expect("decodes the create");
        until("the root program to start", || {
            ["root.pid", "reader.pid", "input.record"]
                .iter()
                .all(|file| work.join(file).is_file())
                .then_some(())
        })
        .await;
        (created.session.session_id, created.session.dimensions)
    }

    async fn read(&self, session_id: SessionId) -> SessionReadResult {
        self.daemon()
            .await
            .request(Method::SessionRead, &SessionReadParams { session_id })
            .await
            .expect("the read reaches the daemon")
            .unwrap_or_else(|error| panic!("the daemon refused the read: {error}"))
            .to_typed()
            .expect("decodes the read")
    }

    /// The closure the daemon records for a session, once it has one.
    async fn closure(&self, session_id: SessionId) -> ClosureRecord {
        let started = tokio::time::Instant::now();
        loop {
            let read = self.read(session_id).await;
            if read.session.state == SessionState::Closed
                && let Some(closure) = read.session.closure.as_ref()
            {
                return closure.clone();
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the daemon recorded no closure within {LIVENESS:?}: {read:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn close(&self, session_id: SessionId) {
        let _ = self
            .daemon()
            .await
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(session_id),
                &SessionCloseParams { session_id },
            )
            .await
            .expect("the close reaches the daemon")
            .unwrap_or_else(|error| panic!("the daemon refused the close: {error}"));
    }

    /// The process identity of the worker the daemon started for a session.
    async fn worker_of(&self, session_id: SessionId) -> ProcessStartIdentity {
        let environment = self.environment();
        until("the session's worker record", || {
            Registry::open(environment.registry_database(), self.environment_id)
                .ok()?
                .workers()
                .ok()?
                .into_iter()
                .find(|worker| worker.session_id == session_id)
                .map(|worker| worker.process_identity)
        })
        .await
    }

    /// Watches a closed session for a while and requires that nothing starts again: it stays
    /// closed, and no worker of its is running.
    async fn nothing_restarts(&self, session_id: SessionId) {
        let started = tokio::time::Instant::now();
        while started.elapsed() < RESTART_WATCH {
            let read = self.read(session_id).await;
            assert_eq!(
                read.session.state,
                SessionState::Closed,
                "the session stays closed"
            );
            let workers =
                Registry::open(self.environment().registry_database(), self.environment_id)
                    .expect("opens the registry")
                    .workers()
                    .expect("reads the worker records");
            assert!(
                workers
                    .iter()
                    .filter(|worker| worker.session_id == session_id)
                    .all(|worker| !matches!(
                        process_state(&worker.process_identity),
                        ProcessState::Running
                    )),
                "no worker of the closed session is running: {workers:?}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Starts the client half: a process of its own that attaches to the session, takes the input
    /// lease, writes `bytes`, and waits to be killed. It is this test binary, copied to the
    /// internal disk with everything else a launched process touches.
    async fn client_half(&self, session_id: SessionId, work: &Path, bytes: &[u8]) -> Half {
        let program = self.tree.root().join("kr-kill-client-half");
        kr_ipc::testing::place_program(
            &std::env::current_exe().expect("this test's own executable"),
            &program,
        );
        let ready = work.join("client-half.ready");
        let log_path = work.join("client-half.log");
        let log = std::fs::File::create(&log_path).expect("the half's log");
        let child = std::process::Command::new(&program)
            .args([
                "--exact",
                CLIENT_HALF,
                "--include-ignored",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env(HALF_ROOT, self.tree.root())
            .env(HALF_ENVIRONMENT, self.environment_id.to_string())
            .env(HALF_SESSION, session_id.to_string())
            .env(HALF_WRITE, hex::encode(bytes))
            .env(HALF_READY, &ready)
            .current_dir(work)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("starts the client half");
        let mut half = Half { child: Some(child) };
        until("the client half to write what it was given", || {
            if ready.is_file() {
                return Some(());
            }
            let ended = half
                .child
                .as_mut()
                .and_then(|child| child.try_wait().ok().flatten());
            assert!(
                ended.is_none(),
                "the client half ended ({ended:?}) before it wrote what it was given: {}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            );
            None
        })
        .await;
        half
    }

    /// The session's state as its worker answers it to a connection that attaches to nothing, so
    /// that asking leaves every terminal's stream as it was.
    ///
    /// The connection, the worker's proof of its descriptor and the snapshot are one wait, bounded
    /// as a whole: a worker that holds the connection open and never answers fails here, naming the
    /// step, and does not hold the caller's own deadline off.
    async fn snapshot_of(&self, session_id: SessionId) -> EventsSnapshotResult {
        tokio::time::timeout(LIVENESS, self.read_snapshot_of(session_id))
            .await
            .unwrap_or_else(|_| {
                panic!("waited {LIVENESS:?} for the worker to answer the snapshot of its session")
            })
    }

    async fn read_snapshot_of(&self, session_id: SessionId) -> EventsSnapshotResult {
        let descriptor = kr_ipc::descriptor::read_all(&self.environment())
            .expect("reads the runtime directory")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the session's descriptor is published");
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        client
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers the descriptor's challenge");
        client
            .request(
                Method::EventsSnapshot,
                &EventsSnapshotParams {
                    session_id,
                    agent_resources_from: Nullable::null(),
                },
            )
            .await
            .expect("the snapshot reaches the worker")
            .expect("the worker answers the snapshot")
            .to_typed()
            .expect("decodes the snapshot")
    }

    /// Starts the built `kr attach` for a session, on a pseudo-terminal of its own, and waits until
    /// it is attached and holds the input lease, as a connection of its own that attaches to
    /// nothing reads the session's state. The programs run are the built `kr` and its guard, copied
    /// to the internal disk with everything else a launched process touches.
    ///
    /// The command asks its terminal what it is and gives up on the answer after one second. A host
    /// that is slow to run the thread that answers can make it refuse a terminal that was never at
    /// fault, which is a failure of this setup and no verdict on what the case does after it. A
    /// refusal that says so is therefore followed by another start on a fresh pseudo-terminal, and
    /// the starts together are bounded by [`LIVENESS`]. The case goes on only once the command is
    /// attached.
    async fn attach_process(
        &self,
        session_id: SessionId,
        work: &Path,
        dimensions: Dimensions,
    ) -> AttachProcess {
        let programs = self.tree.root().join("kr-programs");
        std::fs::create_dir_all(&programs).expect("a directory for the programs");
        for name in ["kr", "kr-attach-guard"] {
            kr_ipc::testing::place_and_start_once(
                &built_program(name, "kr-cli"),
                &programs.join(name),
                &["--version"],
            );
        }
        let kr = programs.join("kr");
        // The guard is the program `kr attach` hands the terminal to. Each reports the version of its
        // package, so a guard of another package version fails here, and a stale build of the same
        // version does not (two releases can carry one): the programs are built together before a
        // run of this crate alone, as the comment on `built_program` says.
        let version_of = |name: &str| {
            let said = std::process::Command::new(programs.join(name))
                .arg("--version")
                .env_clear()
                .output()
                .expect("the program says its version");
            assert!(said.status.success(), "{name} --version ends in failure");
            let said = String::from_utf8_lossy(&said.stdout).trim().to_owned();
            assert!(!said.is_empty(), "{name} --version says nothing");
            said.split_once(' ')
                .map_or_else(|| said.clone(), |(_, rest)| rest.to_owned())
        };
        assert_eq!(
            version_of("kr"),
            version_of("kr-attach-guard"),
            "`kr` and its guard report different versions; build both with `cargo build -p kr-cli`"
        );
        let limit = tokio::time::Instant::now() + LIVENESS;
        let mut starts = 0_u32;
        loop {
            starts += 1;
            match self
                .start_attach(&kr, session_id, work, dimensions, limit, starts)
                .await
            {
                Start::Attached(attach) => return attach,
                Start::Refused(shown) => {
                    assert!(
                        tokio::time::Instant::now() < limit,
                        "`kr attach` was refused its terminal {starts} times within {LIVENESS:?}; \
                         the last terminal was sent: {shown}"
                    );
                    eprintln!(
                        "start {starts} of `kr attach` was refused its terminal because the \
                         probe's second passed; starting it again on a fresh one; the terminal was \
                         sent: {shown}"
                    );
                }
            }
        }
    }

    /// One start of the built `kr attach` on a pseudo-terminal of its own, up to `limit`: attached
    /// and holding the keys, or refused its terminal because the probe's second passed.
    async fn start_attach(
        &self,
        kr: &Path,
        session_id: SessionId,
        work: &Path,
        dimensions: Dimensions,
        limit: tokio::time::Instant,
        start: u32,
    ) -> Start {
        let pty = portable_pty::native_pty_system()
            // The session's own size: a terminal of another size is drawn a window of the screen,
            // and every terminal of the session is then sent screens in place of the application's
            // output as it wrote it.
            .openpty(portable_pty::PtySize {
                rows: u16::try_from(dimensions.rows.get()).expect("a row count"),
                cols: u16::try_from(dimensions.columns.get()).expect("a column count"),
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let typing = Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
        let shown = Arc::new(Mutex::new(Vec::new()));
        let mut reader = pty.master.try_clone_reader().expect("a reader");
        let (answers, output) = (Arc::clone(&typing), Arc::clone(&shown));
        let (listening, ready) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            let mut answered = 0;
            // Said before the first read, and the command is not started until it is heard.
            let _ = listening.send(());
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let mut shown = output
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                shown.extend_from_slice(&buffer[..read]);
                // Each time the command asks what the terminal is, it is told.
                while answered < occurrences(&shown, TERMINAL_QUESTION) {
                    let mut typing = answers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if typing
                        .write_all(TERMINAL_ANSWER)
                        .and_then(|()| typing.flush())
                        .is_err()
                    {
                        return;
                    }
                    answered += 1;
                }
            }
        });
        // The command asks the terminal what it is as soon as it starts, and gives up on an answer
        // after one second. The thread that answers is therefore running before the command
        // exists: started after it, a delay of a second between the two would make `kr attach`
        // refuse a terminal that was never at fault. A delay of that length after the thread has
        // read the question is not prevented by the order, and `attach_process` starts the
        // command again on a fresh terminal when it is refused for it.
        ready
            .recv_timeout(LIVENESS)
            .expect("the thread that answers the command's terminal queries started");
        let mut command = portable_pty::CommandBuilder::new("/bin/sh");
        command.arg("-c");
        // The trailing read keeps the shell from replacing itself with `kr`.
        command.arg(format!("'{}' attach {session_id}; read -r _", kr.display()));
        command.env_clear();
        command.env("PATH", "/usr/bin:/bin");
        command.env("TERM", "xterm-256color");
        command.env("HOME", self.tree.paths().state_root());
        command.env("KR_RUNTIME_DIR", self.tree.paths().runtime_root());
        command.env("KR_STATE_DIR", self.tree.paths().state_root());
        command.cwd(work);
        let shell = pty.slave.spawn_command(command).expect("starts the shell");
        let shell_pid = shell.process_id().expect("the shell has a process number");
        let mut attach = AttachProcess {
            shell,
            attach: None,
            typing,
            shown,
            _terminal: pty.master,
        };
        let mut state = String::from("the shell has not started `kr attach`");
        loop {
            // The command that a refused terminal ends may be gone before it is looked for, so its
            // refusal is read from what the terminal was sent as well.
            if attach.attach.is_none()
                && let Some(pid) = child_running(shell_pid, kr)
            {
                attach.attach = process_start_identity(pid).ok();
            }
            if attach.attach.is_some() {
                let read = self.snapshot_of(session_id).await;
                if read.attachments.len() == 2 && read.lease.holder.0.is_some() {
                    return Start::Attached(attach);
                }
                state = format!("{read:?}");
            }
            let shown = attach.shown();
            if shown.contains(PROBE_TIMED_OUT) {
                return Start::Refused(shown);
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "`kr attach` was not attached and holding the keys within {LIVENESS:?} (start \
                 {start}): {state}; the terminal was sent: {shown}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// What `kr attach` says when the probe's one second passed before the terminal had answered what
/// it was asked: the one refusal of a terminal that is about the answers arriving late, and so
/// about how soon the host ran the thread that gives them, and not about the command.
const PROBE_TIMED_OUT: &str = "the one-second bound passed with answers outstanding";

/// How one start of `kr attach` ended.
enum Start {
    /// It is attached and holds the keys.
    Attached(AttachProcess),
    /// It was refused its terminal because the probe's second passed. What the terminal was sent
    /// is kept for the failure of a setup that never gets past it.
    Refused(String),
}

/// The client half this test started, killed however the test ends.
struct Half {
    child: Option<std::process::Child>,
}

impl Half {
    /// Kills the client half where it stands, and collects it.
    fn kill(&mut self) -> std::process::ExitStatus {
        let child = self.child.as_mut().expect("the half is running");
        child.kill().expect("kills the client half");
        let status = child.wait().expect("collects the client half");
        self.child = None;
        status
    }
}

impl Drop for Half {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// What a terminal that has negotiated the Kitty keyboard protocol at level 5 and
/// `modifyOtherKeys` at level 2 answers the questions `kr attach` asks before it changes anything,
/// ending with the device attributes that close the exchange.
const TERMINAL_ANSWER: &[u8] = b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c";

/// The question that ends with those device attributes.
const TERMINAL_QUESTION: &[u8] = b"\x1b[c";

/// A real `kr attach`, started by a shell on a pseudo-terminal as a person's terminal window starts
/// one. The shell stays the session leader and `kr attach` is its child, as it is in a window:
/// ending a session leader takes the terminal from every process that holds it, and `kr attach`
/// is never one.
struct AttachProcess {
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    /// The `kr` process itself, not the shell that started it, once the shell has started it.
    attach: Option<ProcessStartIdentity>,
    typing: Arc<Mutex<Box<dyn std::io::Write + Send>>>,
    shown: Arc<Mutex<Vec<u8>>>,
    _terminal: Box<dyn portable_pty::MasterPty + Send>,
}

impl AttachProcess {
    /// Types `bytes` on the terminal, as a person's keys reach `kr attach`.
    fn type_bytes(&self, bytes: &[u8]) {
        let mut typing = self
            .typing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        typing.write_all(bytes).expect("types on the terminal");
        typing.flush().expect("flushes the terminal");
    }

    /// Everything the terminal has been sent, as text.
    fn shown(&self) -> String {
        let shown = self
            .shown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&shown).escape_debug().to_string()
    }

    /// The `kr attach` process, which the shell has started by the time anything asks.
    fn process(&self) -> &ProcessStartIdentity {
        self.attach.as_ref().expect("the shell started `kr attach`")
    }

    /// Kills the `kr attach` process outright: a signal no handler can catch.
    fn kill(&self) {
        let pid = rustix::process::Pid::from_raw(
            i32::try_from(self.process().pid.get()).expect("a number"),
        )
        .expect("a process number");
        rustix::process::kill_process(pid, rustix::process::Signal::KILL)
            .expect("kills the attach process");
    }
}

impl Drop for AttachProcess {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("the attach terminal was sent: {}", self.shown());
        }
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

/// The child of `shell` that runs the program at `program`, if it has started one.
fn child_running(shell: u32, program: &Path) -> Option<u32> {
    let listing = std::process::Command::new("pgrep")
        .args(["-P", &shell.to_string()])
        .output()
        .expect("lists the shell's children");
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .find(|pid| {
            let named = std::process::Command::new("ps")
                .args(["-o", "command=", "-p", &pid.to_string()])
                .output()
                .expect("names the process");
            String::from_utf8_lossy(&named.stdout)
                .trim_start()
                .starts_with(&program.display().to_string())
        })
}

/// The process a session's root program wrote the number of, as the kernel describes it now.
fn process(work: &Path, file: &str) -> ProcessStartIdentity {
    let pid: u32 = std::fs::read_to_string(work.join(file))
        .expect("the file the program wrote")
        .trim()
        .parse()
        .expect("a process number");
    process_start_identity(pid).unwrap_or_else(|error| panic!("process {pid} from {file}: {error}"))
}

fn running(identity: &ProcessStartIdentity) -> bool {
    matches!(process_state(identity), ProcessState::Running)
}

async fn ended(identity: &ProcessStartIdentity, what: &str) {
    until(&format!("{what} to end"), || {
        matches!(process_state(identity), ProcessState::Ended).then_some(())
    })
    .await;
}

/// The program's record of every byte of input it read.
fn record(work: &Path) -> Vec<u8> {
    std::fs::read(work.join("input.record")).expect("the program's record")
}

async fn recorded(work: &Path, bytes: &[u8]) {
    until(&format!("the program to record {bytes:?}"), || {
        record(work)
            .windows(bytes.len())
            .any(|window| window == bytes)
            .then_some(())
    })
    .await;
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Kills a worker this test's daemon started, which is this test process's own child, and
/// collects how it ended.
async fn kill_worker(worker: &ProcessStartIdentity) -> rustix::process::WaitStatus {
    let parent = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &worker.pid.get().to_string()])
        .output()
        .expect("the process table");
    assert_eq!(
        String::from_utf8_lossy(&parent.stdout).trim(),
        std::process::id().to_string(),
        "the worker is this test's own child"
    );
    assert!(running(worker), "the worker is running before it is killed");
    let pid = rustix::process::Pid::from_raw(i32::try_from(worker.pid.get()).expect("a number"))
        .expect("a process number");
    rustix::process::kill_process(pid, rustix::process::Signal::KILL).expect("kills the worker");
    until("the killed worker to be collected", || {
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
            .expect("the worker is this test's child")
            .map(|(_, status)| status)
    })
    .await
}

/// Collects a worker this test's daemon started once it has ended by itself.
async fn collect_worker(worker: &ProcessStartIdentity) -> rustix::process::WaitStatus {
    let pid = rustix::process::Pid::from_raw(i32::try_from(worker.pid.get()).expect("a number"))
        .expect("a process number");
    until("the worker to end", || {
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
            .expect("the worker is this test's child")
            .map(|(_, status)| status)
    })
    .await
}

/// How an attachment's stream ended.
#[derive(Debug)]
enum Ended {
    /// The session said it closed, and how.
    Closed(Box<ClosureRecord>),
    /// The connection ended with no closure before it.
    Lost,
}

/// A terminal attached on this machine, on the worker's own endpoint.
struct Terminal {
    client: LocalClient,
    session_id: SessionId,
    attachment_id: AttachmentId,
    target: ActionTarget,
    epoch: Option<InputLeaseEpoch>,
    sequence: u64,
    shown: Vec<u8>,
}

impl Terminal {
    async fn attach(
        environment: &EnvironmentPaths,
        session_id: SessionId,
        dimensions: Dimensions,
    ) -> Self {
        let descriptor = kr_ipc::descriptor::read_all(environment)
            .expect("reads the runtime directory")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the session's descriptor is published");
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        client
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers the descriptor's challenge");
        let target = ActionTarget {
            environment_id: descriptor.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the attach reaches the worker")
            .expect("the worker attaches the terminal")
            .to_typed()
            .expect("decodes the attach");
        let attachment_id = attached.attachment.attachment_id;
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the subscribe reaches the worker")
            .expect("the worker subscribes the terminal");
        Self {
            client,
            session_id,
            attachment_id,
            target,
            epoch: None,
            sequence: 0,
            shown: Vec::new(),
        }
    }

    /// Takes the input lease, and returns what the worker answered.
    async fn acquire(&mut self) -> InputAcquireResult {
        let acquired: InputAcquireResult = self
            .client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                self.target.clone(),
                &InputAcquireParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("the acquire reaches the worker")
            .expect("the worker hands this terminal the keys")
            .to_typed()
            .expect("decodes the acquire");
        self.epoch = Some(acquired.lease.epoch);
        self.sequence = 0;
        acquired
    }

    /// Types `bytes` under this terminal's lease.
    async fn write(&mut self, bytes: &[u8]) {
        let epoch = self.epoch.expect("this terminal holds the keys");
        let _: kr_protocol::input::InputWriteResult = self
            .client
            .request(
                Method::InputWrite,
                &InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch,
                    sequence: InputSequence::new(self.sequence),
                    input: InputContent::Bytes {
                        bytes: Bytes::new(bytes.to_vec()),
                    },
                },
            )
            .await
            .expect("the write reaches the worker")
            .expect("the worker takes the bytes")
            .to_typed()
            .expect("decodes the write");
        self.sequence += 1;
    }

    /// Reads what the session sends until `text` has been shown.
    async fn until_shown(&mut self, text: &str) {
        let started = tokio::time::Instant::now();
        while !String::from_utf8_lossy(&self.shown).contains(text) {
            let left = LIVENESS.saturating_sub(started.elapsed());
            match tokio::time::timeout(left, self.client.recv()).await {
                Ok(Ok(ControlFrame::Notification(notification)))
                    if notification.event_type.as_str() == "session.output" =>
                {
                    if let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                    {
                        self.shown.extend_from_slice(event.bytes.as_slice());
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!("the connection ended before {text:?} was shown: {error}"),
                Err(_) => panic!(
                    "{text:?} was not shown within {LIVENESS:?}; this terminal was shown {:?}",
                    String::from_utf8_lossy(&self.shown)
                ),
            }
        }
    }

    /// Reads what the session sends until the stream ends, and says how it ended.
    async fn until_ended(&mut self) -> Ended {
        let started = tokio::time::Instant::now();
        loop {
            let left = LIVENESS.saturating_sub(started.elapsed());
            match tokio::time::timeout(left, self.client.recv()).await {
                Ok(Ok(ControlFrame::Notification(notification)))
                    if notification.event_type.as_str() == SESSION_CLOSED_EVENT =>
                {
                    return Ended::Closed(Box::new(
                        notification
                            .payload
                            .to_typed::<ClosureRecord>()
                            .expect("decodes the closure"),
                    ));
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return Ended::Lost,
                Err(_) => panic!("the stream did not end within {LIVENESS:?}"),
            }
        }
    }

    /// The session's own state, as its worker answers it.
    async fn snapshot(&mut self) -> EventsSnapshotResult {
        self.client
            .request(
                Method::EventsSnapshot,
                &EventsSnapshotParams {
                    session_id: self.session_id,
                    agent_resources_from: Nullable::null(),
                },
            )
            .await
            .expect("the snapshot reaches the worker")
            .expect("the worker answers the snapshot")
            .to_typed()
            .expect("decodes the snapshot")
    }
}

/// The client half: attaches to the session named in its environment, takes the input lease,
/// writes what it was given, says so, and waits to be killed. It does nothing unless the kill
/// stage started it.
#[test]
#[ignore = "the client half of the kill stage, run only as that stage's own child process"]
fn serve_a_client_half_for_the_kill_stage() {
    let variables = [
        HALF_ROOT,
        HALF_ENVIRONMENT,
        HALF_SESSION,
        HALF_WRITE,
        HALF_READY,
    ]
    .map(std::env::var);
    let [Ok(root), Ok(environment), Ok(session), Ok(write), Ok(ready)] = variables else {
        return;
    };
    let root = PathBuf::from(root);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async move {
            let paths = kr_ipc::paths::HostPaths::new(root.join("r"), root.join("s"))
                .expect("the host's roots");
            let environment_id = EnvironmentId::new(
                environment
                    .parse::<kr_protocol::scalars::Uuid>()
                    .expect("an environment identifier"),
            );
            let session_id = SessionId::new(
                session
                    .parse::<kr_protocol::scalars::Uuid>()
                    .expect("a session identifier"),
            );
            let environment = paths.environment(environment_id);
            let read = kr_ipc::descriptor::read_all(&environment).expect("the descriptors");
            let dimensions = read
                .into_iter()
                .filter_map(|entry| entry.descriptor.ok())
                .find(|descriptor| descriptor.session_id == session_id)
                .map(|_| kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS)
                .expect("the session's descriptor");
            let mut terminal = Terminal::attach(&environment, session_id, dimensions).await;
            terminal.acquire().await;
            terminal
                .write(&hex::decode(write).expect("hexadecimal bytes"))
                .await;
            std::fs::write(ready, b"").expect("says it has written");
            std::future::pending::<()>().await;
        });
}

/// KR-REQ-27.05, a worker killed on its own: the worker is killed while a paste is open at the
/// application and output is flowing. The root program and its reader end with it, every
/// terminal's connection ends with no closure (a killed worker says nothing), the daemon records
/// the closure the worker could not and serves it with no worker, and nothing starts again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_killed_with_a_paste_open_and_output_flowing_ends_its_session_and_nothing_else() {
    let host = Host::start().await;
    let work = host.work("worker-killed");
    let (session_id, dimensions) = host.create(&work).await;
    let environment = host.environment();
    let mut holder = Terminal::attach(&environment, session_id, dimensions).await;
    holder.acquire().await;
    let mut onlooker = Terminal::attach(&environment, session_id, dimensions).await;
    holder.write(PASTE_OPEN).await;
    recorded(&work, PASTE_OPEN).await;
    host.release_output(&work);
    onlooker.until_shown("kr-flow-3\r\n").await;
    let (worker, root, reader) = (
        host.worker_of(session_id).await,
        process(&work, "root.pid"),
        process(&work, "reader.pid"),
    );

    let status = kill_worker(&worker).await;
    assert_eq!(
        status.terminating_signal(),
        Some(libc::SIGKILL),
        "the kill is what ended the worker: {status:?}"
    );
    ended(&root, "the root program").await;
    ended(&reader, "the root program's reader").await;
    for terminal in [&mut holder, &mut onlooker] {
        let how = terminal.until_ended().await;
        assert!(
            matches!(how, Ended::Lost),
            "a killed worker told a terminal nothing: {how:?}"
        );
    }
    let closure = host.closure(session_id).await;
    assert_eq!(closure.reason, ClosureReason::WorkerCrash, "{closure:?}");
    host.nothing_restarts(session_id).await;
}

/// KR-REQ-24.09: a worker's death invalidates the insertion its agent never confirmed and leaves
/// the completed file's identity alone. A binding made after the end is refused, and the session
/// that stays up keeps its insertion as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_workers_unconfirmed_insertion_fails_and_its_completed_upload_keeps_its_identity() {
    let host = Host::start().await;
    let (ended_work, kept_work) = (host.work("insertion-ended"), host.work("insertion-kept"));
    let (ended, _) = host.create(&ended_work).await;
    let (kept, _) = host.create(&kept_work).await;
    let (ended_draft, ended_handle) = host
        .attach_manually(ended, b"for the session that ends")
        .await;
    let (kept_draft, kept_handle) = host
        .attach_manually(kept, b"for the session that stays")
        .await;
    let before = host.draft(ended_draft);

    let worker = host.worker_of(ended).await;
    kill_worker(&worker).await;
    let closure = host.closure(ended).await;
    assert_eq!(closure.reason, ClosureReason::WorkerCrash, "{closure:?}");

    let after = until("the dead worker's insertion to fail", || {
        let draft = host.draft(ended_draft);
        (draft.attachments[0].state == InsertionState::Failed).then_some(draft)
    })
    .await;
    assert!(after.revision.get() > before.revision.get(), "{after:?}");
    assert_eq!(
        after.state,
        DraftState::Orphaned,
        "a draft whose session ended is kept for explicit retargeting"
    );
    assert_eq!(
        after.attachments[0].handle, ended_handle,
        "the completed file's identity is what it was"
    );
    let service = host.controller.transfer().service();
    assert_eq!(
        service
            .attachment_handle(&local_actor(), ended_handle.transfer_id)
            .expect("the upload is still published"),
        ended_handle
    );

    // A session that has ended is given no new binding, whatever its path: a later one is refused.
    let late = host.publish_for(ended, b"too late for the session that ended");
    let refusal = host
        .bind(ended, ended_draft, after.revision, &late)
        .await
        .expect_err("a binding for an ended session is refused");
    assert_eq!(
        refusal.code,
        kr_protocol::error::ErrorCode::SessionClosed,
        "{refusal:?}"
    );

    // The control: the session whose worker lives has the insertion it had.
    let held = host.draft(kept_draft);
    assert_eq!(
        held.attachments[0].state,
        InsertionState::Recorded,
        "{held:?}"
    );
    assert_eq!(held.state, DraftState::Open, "{held:?}");
    assert_eq!(held.attachments[0].handle, kept_handle);
}

/// KR-REQ-24.09: a worker killed while an attachment is being offered to its agent leaves the offer
/// ended, the draft that targeted the session orphaned and the completed file's identity alone, and
/// a report that arrives afterwards is refused as one for a session that has ended. The session
/// whose worker lives keeps its offer in flight and its draft open, and the offer is reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_workers_offer_in_flight_fails_its_draft_is_orphaned_and_a_late_report_is_refused() {
    let host = Host::start().await;
    let (ended_work, kept_work) = (host.work("offer-ended"), host.work("offer-kept"));
    let (ended, _) = host.create(&ended_work).await;
    let (kept, _) = host.create(&kept_work).await;
    let (ended_draft, ended_handle) =
        host.offer_declared_attachment(ended, b"offered to the session that ends");
    let (kept_draft, kept_handle) =
        host.offer_declared_attachment(kept, b"offered to the session that stays");
    let ended_offer = host.claim(ended, ended_draft, &ended_handle);
    let kept_offer = host.claim(kept, kept_draft, &kept_handle);
    let claimed = host.draft(ended_draft);
    assert_eq!(claimed.attachments[0].state, InsertionState::Inserting);
    assert_eq!(
        host.draft(kept_draft).attachments[0].state,
        InsertionState::Inserting
    );

    let worker = host.worker_of(ended).await;
    kill_worker(&worker).await;
    let closure = host.closure(ended).await;
    assert_eq!(closure.reason, ClosureReason::WorkerCrash, "{closure:?}");

    let after = until("the dead worker's offer to fail", || {
        let draft = host.draft(ended_draft);
        (draft.attachments[0].state == InsertionState::Failed).then_some(draft)
    })
    .await;
    assert_eq!(after.state, DraftState::Orphaned, "{after:?}");
    assert_eq!(
        after.revision.get(),
        claimed.revision.get() + 1,
        "the closure moved the draft once"
    );
    assert_eq!(
        after.attachments[0].handle, ended_handle,
        "the upload is kept"
    );
    assert_eq!(after.text, claimed.text, "and so is the draft's text");

    // The worker's report of what its agent answered arrives too late to change what the end
    // decided.
    let service = host.controller.transfer().service();
    let late = service
        .record_insertion_outcome(
            &local_actor(),
            ended,
            &ended_offer.reported(ReportedOutcome::AcceptedByAgent {
                provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
                evidence: "upstream request 1".to_owned(),
            }),
        )
        .expect_err("a report for a session that has ended is refused");
    assert_eq!(
        late.code(),
        kr_protocol::error::ErrorCode::SessionClosed,
        "{late:?}"
    );
    assert_eq!(
        host.draft(ended_draft).attachments[0].state,
        InsertionState::Failed
    );

    // The control: the session whose worker lives keeps its offer in flight, and the report of it
    // is recorded.
    let held = host.draft(kept_draft);
    assert_eq!(held.state, DraftState::Open, "{held:?}");
    assert_eq!(held.attachments[0].state, InsertionState::Inserting);
    service
        .record_insertion_outcome(
            &local_actor(),
            kept,
            &kept_offer.reported(ReportedOutcome::AcceptedByAgent {
                provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
                evidence: "upstream request 1".to_owned(),
            }),
        )
        .expect("the live session's report is recorded");
    let reported = host.draft(kept_draft);
    assert_eq!(
        reported.attachments[0].state,
        InsertionState::AcceptedByAgent
    );
    assert_eq!(reported.attachments[0].handle, kept_handle);
}

/// The control: the same session closed on request instead is closed as requested, every terminal
/// is told so, and the worker ends by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_closed_on_request_is_not_ended_as_a_killed_worker_ends_one() {
    let host = Host::start().await;
    let work = host.work("closed-on-request");
    let (session_id, dimensions) = host.create(&work).await;
    let environment = host.environment();
    let mut holder = Terminal::attach(&environment, session_id, dimensions).await;
    holder.acquire().await;
    let mut onlooker = Terminal::attach(&environment, session_id, dimensions).await;
    holder.write(PASTE_OPEN).await;
    recorded(&work, PASTE_OPEN).await;
    host.release_output(&work);
    onlooker.until_shown("kr-flow-3\r\n").await;
    let worker = host.worker_of(session_id).await;

    host.close(session_id).await;
    for terminal in [&mut holder, &mut onlooker] {
        let how = terminal.until_ended().await;
        assert!(
            matches!(&how, Ended::Closed(closed) if closed.reason == ClosureReason::CloseRequested),
            "each terminal is told the session was closed on request: {how:?}"
        );
    }
    let status = collect_worker(&worker).await;
    assert_eq!(status.exit_status(), Some(0), "{status:?}");
    let closure = host.closure(session_id).await;
    assert_eq!(closure.reason, ClosureReason::CloseRequested, "{closure:?}");
    host.nothing_restarts(session_id).await;
}

/// What follows a lease holder's death with a paste open at the application, whichever kind of
/// client it was: the application is sent the paste's end, once; the dead client's attachment and
/// the lease go; the next terminal to take the keys is told a paste was closed, and what it types
/// reaches the application after the paste's end; and the worker, the root program and the session
/// go on. Ends the session and collects its worker.
async fn the_next_holder_types_after_the_closed_paste(
    host: &Host,
    work: &Path,
    session_id: SessionId,
    next: &mut Terminal,
    worker: &ProcessStartIdentity,
    root: &ProcessStartIdentity,
) {
    recorded(work, PASTE_END).await;
    let alone = until_alone(next).await;
    assert!(
        alone.lease.holder.0.is_none(),
        "nobody holds the keys: {alone:?}"
    );
    let acquired = next.acquire().await;
    assert!(
        acquired.closed_open_paste,
        "the next holder is told a paste was closed: {acquired:?}"
    );
    next.write(b"kr-after").await;
    recorded(work, b"kr-after").await;
    let record = record(work);
    assert_eq!(
        record,
        [PASTE_OPEN, PASTE_END, b"kr-after"].concat(),
        "the paste was closed once, and the next holder's input came after it: {:?}",
        String::from_utf8_lossy(&record)
    );
    assert!(running(worker), "the worker goes on");
    assert!(running(root), "the root program goes on");
    assert_eq!(
        host.read(session_id).await.session.state,
        SessionState::Live
    );
    host.close(session_id).await;
    let _ = collect_worker(worker).await;
}

/// KR-REQ-27.05, a client killed on its own: the client holding the input lease is killed while
/// its paste is open at the application. The worker ends its attachment and its lease and closes
/// the paste, once; the next terminal to take the keys is told a paste was closed, and what it
/// types reaches the application after the paste's end. The worker, the root program and the
/// session go on. The client is this test binary run again, through the harness's terminal code,
/// and not `kr attach`; the case after this one kills the built command.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_killed_with_a_paste_open_has_it_closed_once_and_the_next_holder_types_after_it() {
    let host = Host::start().await;
    let work = host.work("client-killed");
    let (session_id, dimensions) = host.create(&work).await;
    let mut next = Terminal::attach(&host.environment(), session_id, dimensions).await;
    let mut half = host.client_half(session_id, &work, PASTE_OPEN).await;
    recorded(&work, PASTE_OPEN).await;
    host.release_output(&work);
    next.until_shown("kr-flow-3\r\n").await;
    let (worker, root) = (host.worker_of(session_id).await, process(&work, "root.pid"));

    let status = half.kill();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL),
        "{status:?}"
    );
    the_next_holder_types_after_the_closed_paste(
        &host, &work, session_id, &mut next, &worker, &root,
    )
    .await;
}

/// KR-REQ-27.05, the attach process killed on its own: the built `kr attach`, run on a terminal as a
/// person runs it, holds the input lease with a paste open at the application, and is killed
/// outright with a signal it cannot catch. The worker ends its attachment and its lease and closes
/// the paste, once; the next terminal to take the keys is told a paste was closed, and what it
/// types reaches the application after the paste's end. The worker, the root program and the
/// session go on. Before the kill the command is shown to be the one holding the keys, with the
/// paste still open at the application.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_attach_process_killed_with_a_paste_open_has_it_closed_once_and_the_session_goes_on()
{
    let host = Host::start().await;
    let work = host.work("attach-killed");
    let (session_id, dimensions) = host.create(&work).await;
    let mut next = Terminal::attach(&host.environment(), session_id, dimensions).await;
    let attach = host.attach_process(session_id, &work, dimensions).await;
    attach.type_bytes(PASTE_OPEN);
    recorded(&work, PASTE_OPEN).await;
    assert_eq!(
        occurrences(&record(&work), PASTE_END),
        0,
        "the paste is still open at the application before the kill"
    );
    host.release_output(&work);
    next.until_shown("kr-flow-3\r\n").await;
    let (worker, root) = (host.worker_of(session_id).await, process(&work, "root.pid"));
    assert!(running(attach.process()), "`kr attach` is running");

    attach.kill();
    ended(attach.process(), "the attach process").await;
    the_next_holder_types_after_the_closed_paste(
        &host, &work, session_id, &mut next, &worker, &root,
    )
    .await;
}

/// The control: a client killed with no paste open leaves nothing to close. The application is
/// sent no paste's end, and the next holder is told of none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_killed_with_no_paste_open_has_no_paste_closed() {
    let host = Host::start().await;
    let work = host.work("client-killed-typing");
    let (session_id, dimensions) = host.create(&work).await;
    let mut next = Terminal::attach(&host.environment(), session_id, dimensions).await;
    let mut half = host.client_half(session_id, &work, b"kr-typed-").await;
    recorded(&work, b"kr-typed-").await;
    host.release_output(&work);
    next.until_shown("kr-flow-3\r\n").await;
    let worker = host.worker_of(session_id).await;

    let _ = half.kill();
    let alone = until_alone(&mut next).await;
    assert!(
        alone.lease.holder.0.is_none(),
        "nobody holds the keys: {alone:?}"
    );
    let acquired = next.acquire().await;
    assert!(
        !acquired.closed_open_paste,
        "no paste was open to close: {acquired:?}"
    );
    next.write(b"kr-after").await;
    recorded(&work, b"kr-after").await;
    let record = record(&work);
    assert_eq!(
        record,
        b"kr-typed-kr-after".to_vec(),
        "{:?}",
        String::from_utf8_lossy(&record)
    );
    assert_eq!(occurrences(&record, PASTE_END), 0);
    host.close(session_id).await;
    let _ = collect_worker(&worker).await;
}

/// Waits until `terminal` is the session's only attachment, and returns the snapshot that says so.
async fn until_alone(terminal: &mut Terminal) -> EventsSnapshotResult {
    let started = tokio::time::Instant::now();
    loop {
        let snapshot = terminal.snapshot().await;
        if snapshot.attachments.len() == 1 {
            return snapshot;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the killed client's attachment was not ended within {LIVENESS:?}: {snapshot:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether a closure record names the kill signal, which the platform spells in its own words.
fn names_the_kill(closure: &ClosureRecord) -> bool {
    closure
        .root_signal
        .0
        .as_ref()
        .is_some_and(|signal| signal.to_ascii_lowercase().contains("kill"))
}

/// KR-REQ-27.05, the root program killed on its own: the root program kills itself while its
/// output flows. The session closes with the kill signal that ended it, every terminal is told so,
/// the worker ends by itself, the record stays with the daemon, and nothing starts again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_root_program_killed_during_output_closes_its_session_with_the_signal_and_tells_everyone()
{
    let host = Host::start().await;
    let work = host.work("root-killed");
    let (session_id, dimensions) = host.create(&work).await;
    let environment = host.environment();
    let mut first = Terminal::attach(&environment, session_id, dimensions).await;
    let mut second = Terminal::attach(&environment, session_id, dimensions).await;
    host.release_output(&work);
    first.until_shown("kr-flow-3\r\n").await;
    let (worker, root) = (host.worker_of(session_id).await, process(&work, "root.pid"));

    std::fs::write(work.join("kr-die"), b"").expect("asks the root program to kill itself");
    ended(&root, "the root program").await;
    for terminal in [&mut first, &mut second] {
        let how = terminal.until_ended().await;
        assert!(
            matches!(&how, Ended::Closed(closure)
                if closure.reason == ClosureReason::RootSignal && names_the_kill(closure)),
            "each terminal is told the kill signal ended the root program: {how:?}"
        );
    }
    let status = collect_worker(&worker).await;
    assert_eq!(status.exit_status(), Some(0), "{status:?}");
    let closure = host.closure(session_id).await;
    assert_eq!(closure.reason, ClosureReason::RootSignal, "{closure:?}");
    assert!(
        names_the_kill(&closure),
        "the record names the kill signal: {closure:?}"
    );
    host.nothing_restarts(session_id).await;
}

/// The control: a root program nobody kills goes on, and so does its session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_root_program_nobody_kills_goes_on_writing() {
    let host = Host::start().await;
    let work = host.work("root-kept");
    let (session_id, dimensions) = host.create(&work).await;
    let mut first = Terminal::attach(&host.environment(), session_id, dimensions).await;
    host.release_output(&work);
    first.until_shown("kr-flow-3\r\n").await;
    let (worker, root) = (host.worker_of(session_id).await, process(&work, "root.pid"));
    first.until_shown("kr-flow-9\r\n").await;
    assert!(running(&root), "the root program goes on");
    assert_eq!(
        host.read(session_id).await.session.state,
        SessionState::Live
    );
    host.close(session_id).await;
    let _ = collect_worker(&worker).await;
}
