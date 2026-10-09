//! Processes killed at named points, and what is left of their session.
//!
//! The control daemon runs in this test's process, as the host suites run it, and starts each
//! session's worker as a detached process of its own: the real `kr-worker` this workspace builds,
//! whose version is checked to be this build's, copied to the internal disk with everything else a
//! launched process touches. The session's root program asks for bracketed paste, records every
//! byte of input it reads, as it reads it, in a file of its own, so what reached the application is
//! read from the application's own record, and writes a numbered line every twentieth of a second
//! once the test releases it. A terminal is a local client on the worker's own endpoint, as a
//! person's is; a client that is to be killed is this test binary run again, as a process of its
//! own, in a mode where it does that and nothing else.
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

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
use kr_protocol::input::{InputAcquireParams, InputAcquireResult, InputWriteParams};
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

/// A boot clock that reads one moment.
#[derive(Debug)]
struct FixedClock(u64);

impl kr_ipc::clock::SharedClock for FixedClock {
    fn boot_elapsed_ms(&self) -> u64 {
        self.0
    }
}

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

/// The worker this workspace builds, beside this test.
///
/// A test run of this crate alone does not build the worker, so one an earlier build left in the
/// target directory could be started, and every check below would be about another build. The
/// version the worker reports is checked against this build's, which catches a worker of another
/// release or protocol and not a stale build of this one, so build the worker before a run of this
/// crate alone.
fn built_worker() -> PathBuf {
    let mut directory = std::env::current_exe().expect("this test's own path");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let built = directory.join("kr-worker");
    assert!(
        built.is_file(),
        "the kill stage starts a real worker and there is none at {}; build it with `cargo build \
         -p kr-worker` or run scripts/end-to-end.sh, which does",
        built.display()
    );
    built
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
        std::fs::write(&root_program, ROOT_PROGRAM).expect("writes the root program");
        std::fs::set_permissions(&root_program, std::fs::Permissions::from_mode(0o700))
            .expect("the root program runs");
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

    /// What an adapter's offer of an attachment to a session's agent comes to at the daemon: a draft
    /// that targets the session is created and the file is bound to it, both through the daemon's
    /// own methods, as an insertion no upstream evidence has confirmed.
    async fn offer_attachment(
        &self,
        session_id: SessionId,
        bytes: &[u8],
    ) -> (DraftId, AttachmentHandle) {
        self.offer_attachment_by(
            session_id,
            bytes,
            InsertionMethod::VerifiedComposerInsertion,
        )
        .await
    }

    /// The same, for an attachment to be inserted by `method`.
    async fn offer_attachment_by(
        &self,
        session_id: SessionId,
        bytes: &[u8],
        method: InsertionMethod,
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
                method,
            )
            .await
            .unwrap_or_else(|error| panic!("the daemon refused the binding: {error}"));
        assert_eq!(bound.attachment.state, InsertionState::Recorded);
        (draft.draft.draft_id, handle)
    }

    /// Binds a published file to a draft through the daemon.
    async fn bind(
        &self,
        session_id: SessionId,
        draft_id: DraftId,
        expected_revision: kr_protocol::ids::DraftRevision,
        handle: &AttachmentHandle,
        method: InsertionMethod,
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
                        insertion_method: method,
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
                &FixedClock(now),
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
                    bytes: Bytes::new(bytes.to_vec()),
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
                Err(_) => panic!("{text:?} was not shown within {LIVENESS:?}"),
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
        .offer_attachment(ended, b"for the session that ends")
        .await;
    let (kept_draft, kept_handle) = host
        .offer_attachment(kept, b"for the session that stays")
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

    // Nothing is offered to the agent of a session that has ended: a later binding is refused.
    let late = host.publish_for(ended, b"too late for the session that ended");
    let refusal = host
        .bind(
            ended,
            ended_draft,
            after.revision,
            &late,
            InsertionMethod::VerifiedComposerInsertion,
        )
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
    let (ended_draft, ended_handle) = host
        .offer_attachment_by(
            ended,
            b"offered to the session that ends",
            InsertionMethod::TypedSubmission,
        )
        .await;
    let (kept_draft, kept_handle) = host
        .offer_attachment_by(
            kept,
            b"offered to the session that stays",
            InsertionMethod::TypedSubmission,
        )
        .await;
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

/// KR-REQ-27.05, a client killed on its own: the client holding the input lease is killed while
/// its paste is open at the application. The worker ends its attachment and its lease and closes
/// the paste, once; the next terminal to take the keys is told a paste was closed, and what it
/// types reaches the application after the paste's end. The worker, the root program and the
/// session go on.
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
    recorded(&work, PASTE_END).await;
    let alone = until_alone(&mut next).await;
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
    recorded(&work, b"kr-after").await;
    let record = record(&work);
    assert_eq!(
        record,
        [PASTE_OPEN, PASTE_END, b"kr-after"].concat(),
        "the paste was closed once, and the next holder's input came after it: {:?}",
        String::from_utf8_lossy(&record)
    );
    assert!(running(&worker), "the worker goes on");
    assert!(running(&root), "the root program goes on");
    assert_eq!(
        host.read(session_id).await.session.state,
        SessionState::Live
    );
    host.close(session_id).await;
    let _ = collect_worker(&worker).await;
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
