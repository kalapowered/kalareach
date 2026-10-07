//! Privacy mode through the control daemon, and the session names it serves.
//!
//! One real daemon on the loopback network, started the way a host starts one, and a real worker
//! it adopts: the worker's own service on its own socket, with its journal, its spool and its
//! shell, run in this process as the barrier and attention suites run one. The daemon finds it at
//! its start the way a daemon that restarted finds the workers it left running, by the registry's
//! row, the published descriptor and a challenge. `privacy.set` reaches the daemon on its local
//! socket, `privacy.status` there and from a paired device, and `session.describe` and
//! `session.rename` at both doors. What each test asserts is read back from the store that holds
//! it: the privacy record, the backup store, the delivery journal, the description store, the
//! attention inbox and the worker's own session.
//!
//! The delivery gate is shown on the delivery module itself, with a transport and a credential
//! store that answer when the test lets them. The two moments it guards, a send on the wire when
//! privacy mode is turned on and a send claimed before the boundary and presented after it, cannot
//! be held open inside a running daemon, whose senders are real.
//!
//! No description process runs here, so inference in flight cannot be shown: a generated
//! description is written to the store as the description service would have written it.
//!
//! Everything is on the internal disk: the environment is a temporary host tree, and the session's
//! shell runs a POSIX shell from a directory inside it.

mod net_support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::session::Session as DeviceSession;
use kr_controller::backup::BackupService;
use kr_controller::backup::store::{Publication, Step};
use kr_controller::describe::DescribeModule;
use kr_controller::privacy::{EnvironmentPrivacy, PRIVACY_RECORD};
use kr_controller::push::DeliveryModule;
use kr_controller::registry::{Registry, WorkerRecord};
use kr_controller::service::Controller;
use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::backup::{
    ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, ObjectSource, seal_archive,
    stage_object,
};
use kr_crypto::keys::{
    AuthorisationKeyPair, DeviceKeys, NotificationPreviewKeyPair, StoredEnvelopeKeyPair,
};
use kr_crypto::store::{MemoryStore, open_store_in};
use kr_delivery::destination::{
    DeliveryRule, Destination, DestinationId, DestinationKind, DestinationRecord,
    ExternalDestination, Idempotency, PreviewKeys, PushDestination,
};
use kr_delivery::external::{ExternalMessage, ExternalOutcome, ExternalSender};
use kr_delivery::journal::{
    Claim, DeliveryRecord, DeliveryState, EventKey, EventSource, TakenEvent, Transition,
};
use kr_delivery::producer::{
    Audience, DEFAULT_NOTIFICATION_LIFETIME_MS, Notice, RecipientAuthority, RecipientScope,
};
use kr_delivery::push::{DeliveryStatus, PushSender, SendOutcome, SenderCredentials, StatusAnswer};
use kr_describe::context::{ContextBinding, ContextRevision, CursorInterval};
use kr_describe::metadata::{ActivityText, Title};
use kr_describe::output::{GeneratedDescription, ProducedUnder};
use kr_describe::profile::ProfileRevision;
use kr_describe::store::DescriptionStore;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::agent::{AgentApprovalRespondParams, AgentMutationTarget};
use kr_protocol::attention::{
    AttentionItem, AttentionReadParams, AttentionReadResult, AttentionRule,
};
use kr_protocol::broker::{BrokerGrant, BrokerGrants, IntegrationMode};
use kr_protocol::describe::{
    LabelSource, SessionDescribeParams, SessionDescribeResult, SessionRenameParams,
    SessionRenameResult,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::SessionSelector;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActionId, AgentBindingRevision, ApplicationInstanceId, ArchiveId, AuthorityRevision,
    BackupGeneration, BackupObjectId, BrokerBindingId, BuildId, CapabilityId, CapabilityRevision,
    ConnectionId, ControllerGeneration, DeviceId, EnvironmentId, InstallationId, NotificationId,
    PluginId, PublisherId, PushSenderRecordId, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyDisabled, PrivacyReport, PrivacySessionStanding, PrivacySetParams,
    PrivacyStatusParams,
};
use kr_protocol::push::{
    PushAlert, PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest, PushDeliveryState,
    PushUrgency,
};
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionCreateParams, QuestionKind,
    QuestionReadParams, QuestionReadResult, QuestionResolveResult, QuestionState,
};
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, ReceiptState};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    Digest256, DurationMs, Nullable, SecretBytes32, TimestampMs, U64, Uuid,
};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::broker::{
    BrokerError, BrokerTransport, Credential, ManagedProcess, PendingTransmission, TransportHandle,
    UpstreamDispatch, UpstreamOutcome, UpstreamRequest, subject,
};
use kr_worker::history_filter::ViewerScope;
use kr_worker::privacy::PrivacyGeneration;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

use net_support::{Device, Host, RawDevice, connect, pair_with, proposal};

/// How long a test waits for something the daemon's own tick or the worker has to do.
const PATIENCE: Duration = Duration::from_secs(60);

/// Who these tests hand a backup attempt to.
const EXECUTOR: &str = "the test transport";

/// The directory the session's shell runs in. Its name is the session's deterministic title.
const PROJECT: &str = "privacy-project";

/// The session's shell: it prints the file `mark` in its directory about twenty times a second, so
/// the session has output arriving whenever the test has written one, for at most ten minutes. It
/// keeps every byte it printed in the file `said`, and the number of the last pass it finished in
/// the file `pass`, so that a test can tell when the worker has read everything the shell printed.
const MARKING: &str = "i=0; while [ $i -lt 12000 ]; do cat mark 2>/dev/null | tee -a said; \
                       i=$((i + 1)); echo $i > pass.tmp; mv pass.tmp pass; sleep 0.05; done";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn now() -> TimestampMs {
    kr_ipc::now_ms()
}

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

/// Waits until `holds` says it does, or the patience runs out.
async fn until(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !holds() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// A worker in this process, and the daemon that adopts it
// ---------------------------------------------------------------------------------------------

/// A worker for one session, in this process, on an environment tree a daemon of it serves.
struct Worker {
    runtime: Arc<SessionRuntime>,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    project: PathBuf,
}

impl Worker {
    /// Starts a worker for one session and records it the way a daemon records one it adopts: a
    /// registry row and a published descriptor. A daemon started afterwards reaches it at its
    /// start. No daemon may be running on the tree while this runs.
    async fn start(tree: &kr_ipc::testing::TempHost, display: u64) -> Self {
        let environment = tree.environment();
        let environment_id = tree.environment_id();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let controller_key = {
            let store = open_store_in(&environment.secrets_dir()).expect("a secret store");
            *ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                .expect("the daemon's identity")
                .public_key()
        };
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let display_number = DisplayNumber::new(display);
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session_id,
                SessionEpoch::V1,
                boot.clone(),
                process.clone(),
                PROTOCOL_VERSION,
            )
            .expect("a session key"),
        );
        let project = tree.root().join(PROJECT);
        std::fs::create_dir_all(&project).expect("the project directory");
        let journal_path = environment.journal_database(session_id);
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number,
            shell: ShellCommand {
                cwd: project.display().to_string(),
                ..kr_worker::testing::posix_script(MARKING)
            },
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
            .worker_endpoint(display_number)
            .expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let public_key = *identity.public_key();
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                identity,
                endpoint.clone(),
                ServiceBinding {
                    environment_id,
                    boot_identity: boot.clone(),
                    controller_public_key: controller_key,
                    controller_generation: ControllerGeneration::new(1),
                    journal_path: Some(journal_path),
                    build_id: build(),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        let mut registry =
            Registry::open(environment.registry_database(), environment_id).expect("the registry");
        registry
            .adopt_worker(
                &WorkerRecord {
                    session_id,
                    display_number,
                    public_key,
                    process_identity: process.clone(),
                    endpoint: endpoint.as_text(),
                    profile: WorkerProfile::HeadlessUser,
                    state: SessionState::Live,
                    acknowledged_revision: AuthorityRevision::new(0),
                },
                // A headless worker is bound to no desktop.
                Some(&kr_protocol::identity::DesktopBinding::none()),
            )
            .expect("the worker is recorded");
        drop(registry);
        kr_ipc::descriptor::publish(
            &environment,
            &WorkerDescriptor {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id,
                display_number,
                boot_identity: boot,
                process_start_identity: process,
                protocol_version: PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: public_key,
                worker_profile: WorkerProfile::HeadlessUser,
                published_at_ms: now(),
            },
        )
        .expect("the worker's descriptor is published");
        Self {
            runtime,
            service,
            session_id,
            endpoint,
            project,
        }
    }

    /// The privacy generation the session holds, and whether privacy mode is on in it.
    fn privacy(&self) -> (u64, bool) {
        let privacy = self.runtime.session().privacy();
        (privacy.generation().get(), privacy.is_enabled())
    }

    /// How many bytes of output the session retains.
    fn retained(&self) -> u64 {
        self.runtime.session().retained_output_bytes()
    }

    /// Everything the session retains of its output, from the oldest byte it still holds.
    fn history(&self) -> String {
        let session = self.runtime.session();
        let page = session
            .history_page(0, 1024 * 1024)
            .expect("the history reads");
        String::from_utf8_lossy(page.bytes.as_slice()).into_owned()
    }

    /// Sets what the session's shell prints from now on. A mark has no line ends, which a terminal
    /// would print as two bytes, so that what the shell recorded is what the worker counts.
    fn mark(&self, text: &str) {
        assert!(!text.contains('\n'), "a mark has no line end: {text:?}");
        std::fs::write(self.project.join("mark"), text).expect("the mark is written");
    }

    /// Everything the shell has printed so far, as it recorded it.
    fn said(&self) -> String {
        String::from_utf8_lossy(&std::fs::read(self.project.join("said")).unwrap_or_default())
            .into_owned()
    }

    /// The number of the last pass the shell finished over the mark.
    #[cfg(unix)]
    fn pass(&self) -> u64 {
        std::fs::read_to_string(self.project.join("pass"))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Waits until the worker has read the output the shell printed after the worker's output
    /// cursor stood at `since`, once the mark is empty.
    ///
    /// The shell finishes two passes after the mark was emptied: the second read the mark as it
    /// stands, and printed nothing, so the shell has said all it will say. What it recorded is then
    /// the whole of what it wrote to the terminal, and the worker has read it all when its cursor
    /// stands at the last byte of it. Nothing here is a delay: a worker that has not read what was
    /// written waits the test out.
    #[cfg(unix)]
    async fn has_read_all_that_was_said(&self, _since: u64) {
        let emptied_at = self.pass();
        until("the shell finishing two passes over the empty mark", || {
            self.pass() >= emptied_at + 2
        })
        .await;
        let written = self.said().len() as u64;
        until("the worker reading all that the shell wrote", || {
            self.runtime.session().output_cursor() == written
        })
        .await;
    }

    /// Waits until the worker has read output that arrived after its output cursor stood at
    /// `since`.
    ///
    /// A Windows pseudo-console draws what the shell prints again, in sequences of its own, so the
    /// bytes the worker reads are not the bytes the shell wrote and cannot be counted against
    /// them. What can be waited for is output arriving after `since`, which the worker counts as it
    /// appends it to its history, whether it keeps it or not. That is some of what the shell
    /// printed, and not all of it: a case that turns privacy mode off afterwards cannot take the
    /// rest as read, and says by the cursor what it relies on.
    #[cfg(windows)]
    async fn has_read_all_that_was_said(&self, since: u64) {
        until("the worker reading output that arrived", || {
            self.runtime.session().output_cursor() > since
        })
        .await;
    }

    /// The worker's output cursor: how many bytes of output it has read.
    fn output_cursor(&self) -> u64 {
        self.runtime.session().output_cursor()
    }

    /// The cursor the output the session retains starts at, after any range it gave up.
    fn retained_from(&self) -> u64 {
        self.runtime
            .session()
            .history_page(0, 1024 * 1024)
            .expect("the history reads")
            .from_cursor
            .get()
    }

    /// The action target of this session.
    fn target(&self, environment_id: EnvironmentId) -> ActionTarget {
        ActionTarget {
            environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Asks a question from inside the session, as a verified source bound to it does.
    fn ask(&self, request: &str, question: &str) -> Question {
        self.service
            .questions()
            .create(
                &kr_worker::questions::VerifiedSource {
                    process: kr_ipc::identity::current_process_start_identity()
                        .expect("a process identity"),
                    executable: Some("/bin/agent".to_owned()),
                    session_member: true,
                    ancestry: true,
                    launch_channel: true,
                    connection_id: ConnectionId::new(kr_ipc::new_uuid()),
                },
                &QuestionCreateParams {
                    session_id: self.session_id,
                    request_id: request.to_owned(),
                    agent_name: Nullable::some("an agent".to_owned()),
                    context: "the release is tagged".to_owned(),
                    question: question.to_owned(),
                    kind: QuestionKind::Confirm,
                    choices: Vec::new(),
                    requested_expiry_ms: Nullable::null(),
                    wait_ms: Nullable::null(),
                },
                kr_worker::questions::Now {
                    utc_ms: kr_ipc::now_ms(),
                    boot_ms: kr_ipc::clock::boot_elapsed_ms(),
                },
            )
            .expect("a verified source asks")
            .0
            .question
    }

    /// The owner's own client on this worker's socket, as a terminal on this machine reaches it.
    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the worker")
    }
}

/// A daemon on the network with one adopted worker, and the keys of the environment's owner.
struct Environment {
    host: Host,
    owner: DeviceKeys,
    worker: Worker,
}

impl Environment {
    /// Starts a daemon on a fresh environment, bootstraps its owner, stops it, starts a worker on
    /// the tree, and starts the daemon again, which adopts the worker.
    async fn start() -> Self {
        Self::start_seeded(|_| ()).await
    }

    /// Starts as [`Self::start`] does, after `seed` has been given the environment's state
    /// directory while no daemon runs on it.
    async fn start_seeded(seed: impl FnOnce(&std::path::Path)) -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let stopped = host.shut_down().await;
        seed(stopped.tree().environment().state_dir());
        let worker = Worker::start(stopped.tree(), 1).await;
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let environment = Self {
            host,
            owner,
            worker,
        };
        environment.until_adopted().await;
        environment
    }

    /// Stops the daemon and starts another on the same tree, which finds the worker still
    /// running. Every client of the daemon is closed first.
    async fn restart(self) -> Self {
        let Self {
            host,
            owner,
            worker,
        } = self;
        let host = host.restart().await;
        let environment = Self {
            host,
            owner,
            worker,
        };
        environment.until_adopted().await;
        environment
    }

    async fn stop(self) {
        self.host.stop().await;
    }

    fn controller(&self) -> &Arc<Controller> {
        self.host.controller()
    }

    fn environment_id(&self) -> EnvironmentId {
        self.host.environment_id
    }

    /// Waits until the daemon serves the worker's session.
    async fn until_adopted(&self) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut client = self.host.client().await;
            let read = client
                .request(
                    Method::SessionRead,
                    &kr_protocol::session::SessionReadParams {
                        session_id: self.worker.session_id,
                    },
                )
                .await
                .expect("the call reaches the daemon");
            if read.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the daemon never reached the worker: {read:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Turns privacy mode on or off at the daemon's local socket.
    async fn set(&self, enabled: bool) -> Result<PrivacyReport, ProtocolError> {
        let mut client = self.host.client().await;
        client
            .mutate(
                Method::PrivacySet,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.environment_id()),
                &PrivacySetParams { enabled },
            )
            .await
            .expect("the call reaches the daemon")
            .map(|value| value.to_typed().expect("decodes"))
    }

    /// Reads where privacy mode stands at the daemon's local socket.
    async fn status(&self) -> PrivacyReport {
        let mut client = self.host.client().await;
        client
            .request(Method::PrivacyStatus, &PrivacyStatusParams {})
            .await
            .expect("the call reaches the daemon")
            .expect("privacy mode's report")
            .to_typed()
            .expect("decodes")
    }

    /// Reads the report until `holds` says it does, or the patience runs out.
    async fn status_until(
        &self,
        what: &str,
        holds: impl Fn(&PrivacyReport) -> bool,
    ) -> PrivacyReport {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let report = self.status().await;
            if holds(&report) {
                return report;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{what} did not happen: {report:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Waits until the worker's session holds `generation` in the state given.
    async fn worker_holds(&self, generation: u64, enabled: bool) {
        until("the worker's session taking the generation", || {
            self.worker.privacy() == (generation, enabled)
        })
        .await;
    }

    /// Reads the owner's inbox at the daemon's local socket until `holds` says it does.
    async fn inbox_until(
        &self,
        what: &str,
        holds: impl Fn(&[AttentionItem]) -> bool,
    ) -> Vec<AttentionItem> {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut client = self.host.client().await;
            let read: AttentionReadResult = client
                .request(
                    Method::AttentionRead,
                    &AttentionReadParams {
                        session_id: Nullable::null(),
                        include_acknowledged: true,
                        max_items: U64::new(50),
                        after: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("the inbox reads")
                .to_typed()
                .expect("decodes");
            if holds(&read.items) {
                return read.items;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{what} did not happen: {:?}",
                read.items
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Reads one session's name at the daemon's local socket.
    async fn describe(&self, session_id: SessionId) -> SessionDescribeResult {
        let mut client = self.host.client().await;
        client
            .request(
                Method::SessionDescribe,
                &SessionDescribeParams { session_id },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the session's name")
            .to_typed()
            .expect("decodes")
    }

    /// Renames the worker's session at the daemon's local socket.
    async fn rename(&self, title: Option<&str>) -> SessionRenameResult {
        let mut client = self.host.client().await;
        client
            .mutate(
                Method::SessionRename,
                ActionId::new(kr_ipc::new_uuid()),
                self.worker.target(self.environment_id()),
                &SessionRenameParams {
                    session_id: self.worker.session_id,
                    title: Nullable(title.map(str::to_owned)),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the session is renamed")
            .to_typed()
            .expect("decodes")
    }

    /// Pairs a device under `proposal` and connects it.
    async fn device(&self, proposal: kr_protocol::pairing::ProposedGrant) -> Paired {
        let device = Device::create().await;
        let record = pair_with(&self.host, &device, &self.owner, proposal).await;
        let session = connect(&self.host, &device, &record).await;
        Paired {
            _device: device,
            session,
        }
    }

    /// Pairs a device under `proposal` and connects it as one that submits the action identifiers
    /// it is given, and presents one again on a later connection.
    async fn raw_device(&self, proposal: kr_protocol::pairing::ProposedGrant) -> RawPaired {
        let device = Device::create().await;
        let record = pair_with(&self.host, &device, &self.owner, proposal).await;
        let connection = RawDevice::connect(&self.host, &device, &record).await;
        RawPaired {
            device,
            record,
            connection,
        }
    }

    /// Reads the privacy record's generation and state, and each session obligation, from its
    /// file.
    fn record(&self) -> ((i64, i64), Vec<(String, i64)>) {
        let record = rusqlite::Connection::open_with_flags(
            self.host
                .tree()
                .environment()
                .state_dir()
                .join(PRIVACY_RECORD),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("the privacy record");
        let state = record
            .query_row(
                "SELECT generation, enabled FROM privacy_record WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the record");
        let mut statement = record
            .prepare("SELECT session_id, generation FROM privacy_obligations ORDER BY session_id")
            .expect("the obligations");
        let obligations = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("the obligations")
            .collect::<Result<Vec<_>, _>>()
            .expect("the obligations");
        (state, obligations)
    }

    /// The environment's description store, beside the daemon's own handle on it.
    fn descriptions(&self) -> DescriptionStore {
        DescriptionStore::open(self.host.tree().environment().state_dir())
            .expect("the description store")
    }

    /// Admits one backup generation into the daemon's backup service.
    fn admit(
        &self,
        producer: &Producer,
        generation: u8,
    ) -> kr_controller::error::Result<kr_controller::backup::Admitted> {
        producer.admit(self.controller().backup(), generation)
    }

    /// Admits one backup generation and carries it as far as its publication on the wire: every
    /// object arrived, the upload finished, and the descriptor left this host. Returns the
    /// publication attempt, which is what an answer about it names.
    fn publication_on_the_wire(&self, producer: &Producer, generation: u8) -> u64 {
        let backup = self.controller().backup();
        let admitted = self.admit(producer, generation).expect("admitted");
        let backup_generation = BackupGeneration::new(u64::from(generation));
        backup
            .note_dispatched(admitted.sequence, EXECUTOR, now())
            .expect("the upload is on its way");
        for row in backup
            .objects(archive_id(), backup_generation)
            .expect("a read")
        {
            backup
                .note_object_uploaded(
                    admitted.sequence,
                    archive_id(),
                    backup_generation,
                    row.object_id,
                    now(),
                )
                .expect("the object arrived");
        }
        backup
            .note_attempt_accepted(admitted.sequence, now())
            .expect("the upload finished");
        let publication = backup
            .outbox()
            .expect("a read")
            .into_iter()
            .find(|attempt| attempt.step == Step::Publish)
            .expect("a publication attempt")
            .sequence;
        backup
            .note_dispatched(publication, EXECUTOR, now())
            .expect("the publication is on its way");
        publication
    }

    /// Admits one notice for a webhook and claims it, as a delivery pass does, so it is on the
    /// wire. Nothing the daemon runs carries it, so nothing but this test settles it.
    fn delivery_on_the_wire(&self) -> NotificationId {
        let event = EventKey::announcement(None, "an-item", 0x44);
        let notification_id = NotificationId::new(Uuid::from_bytes([0x45; 16]));
        let consumer = EventSource::Attention.consumer("session-1");
        self.controller()
            .delivery
            .with(|producer| {
                let journal = producer.journal_mut();
                journal.register_consumer(&consumer, 1).expect("a consumer");
                journal
                    .configure_destination(&hook())
                    .expect("a destination");
                journal
                    .take_events(
                        &consumer,
                        &[TakenEvent {
                            key: event.clone(),
                            source_cursor: 1,
                            session_id: None,
                            recorded_at_ms: now(),
                            notice: Vec::new(),
                        }],
                        1,
                    )
                    .expect("a page");
                journal
                    .admit(&DeliveryRecord {
                        notification_id,
                        event: event.clone(),
                        destination_id: DestinationId::new("hook").expect("an identifier"),
                        state: DeliveryState::Admitted,
                        privacy_generation: 0,
                        destination_digest: hook().binding_digest(),
                        authority_digest: String::new(),
                        content: Some(vec![b'x'; 100]),
                        payload_bytes: 100,
                        expires_at_ms: TimestampMs::new(now().get() + 3_600_000),
                        admitted_at_ms: now(),
                        attempts: 0,
                        suppression: None,
                        detail: None,
                        dispatched: false,
                    })
                    .expect("admitted");
                assert!(matches!(
                    journal
                        .claim(notification_id, now().get())
                        .expect("a claim"),
                    Claim::Taken(_)
                ));
                Ok(())
            })
            .expect("the delivery journal");
        notification_id
    }

    /// The destination's answer to the delivery on the wire arrives: it took it.
    fn delivery_answered(&self, notification_id: NotificationId) {
        self.controller()
            .delivery
            .with(|producer| {
                producer
                    .journal_mut()
                    .record_attempt(&Transition {
                        notification_id,
                        attempt: 1,
                        state: DeliveryState::Accepted,
                        started_at_ms: now(),
                        settled_at_ms: Some(now()),
                        next_attempt_at_ms: None,
                        next: kr_delivery::push::NextAction::None,
                        detail: Some("the destination took it".to_owned()),
                        suppression: None,
                        left_this_host: true,
                        reported_by_destination: false,
                    })
                    .expect("a transition");
                Ok(())
            })
            .expect("the delivery journal");
    }

    /// Whether the daemon's delivery journal holds a privacy fence.
    fn delivery_is_fenced(&self) -> bool {
        self.controller()
            .delivery
            .with(|producer| Ok(producer.journal().is_fenced().expect("a read")))
            .expect("the delivery journal")
    }

    /// The state the daemon's delivery journal records for one notification.
    fn delivery_state(&self, notification_id: NotificationId) -> DeliveryState {
        delivery_state(&self.controller().delivery, notification_id)
    }
}

/// A paired device's connection to the daemon, with the device's own endpoint, which the
/// connection ends with.
struct Paired {
    _device: Device,
    session: DeviceSession,
}

impl std::ops::Deref for Paired {
    type Target = DeviceSession;

    fn deref(&self) -> &DeviceSession {
        &self.session
    }
}

/// A paired device that submits the action identifiers it is given: its keys and its record, with
/// which it connects again to a daemon that restarted, and its connection.
struct RawPaired {
    device: Device,
    record: DeviceRecord,
    connection: RawDevice,
}

/// The state a delivery journal records for one notification.
fn delivery_state(module: &DeliveryModule, notification_id: NotificationId) -> DeliveryState {
    module
        .with(|producer| {
            Ok(producer
                .journal()
                .deliveries()
                .expect("a read")
                .into_iter()
                .find(|record| record.notification_id == notification_id)
                .expect("the notification's record")
                .state)
        })
        .expect("the delivery journal")
}

/// The keys a backup generation is sealed and published with.
struct Producer {
    writer: AuthorisationKeyPair,
    sender: StoredEnvelopeKeyPair,
    device: StoredEnvelopeKeyPair,
}

impl Producer {
    fn generate() -> Self {
        Self {
            writer: AuthorisationKeyPair::generate().expect("a writer key"),
            sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
            device: StoredEnvelopeKeyPair::generate().expect("a device key"),
        }
    }

    /// Seals and admits one backup generation with one member object, enrolling the writer first.
    fn admit(
        &self,
        backup: &BackupService,
        generation: u8,
    ) -> kr_controller::error::Result<kr_controller::backup::Admitted> {
        backup
            .enrol_writer(self.writer.key_id(), archive_id(), now())
            .expect("the writer is enrolled");
        let objects = [stage_object(
            &ObjectSource {
                object_id: BackupObjectId::new(Uuid::from_bytes([generation; 16])),
                filename: "history.cbor",
                plaintext: b"what a session said",
            },
            KeyRotation::INITIAL,
        )
        .expect("a staged object")];
        let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
        assert!(recipients.add(*self.device.public()));
        let sealed = seal_archive(
            &self.writer,
            &self.sender,
            &recipients,
            &ArchivePlan {
                archive_id: archive_id(),
                backup_generation: BackupGeneration::new(u64::from(generation)),
                owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
                manifest_object_id: BackupObjectId::new(Uuid::from_bytes([0x80 + generation; 16])),
                created_at_ms: now(),
            },
            &objects,
        )
        .expect("a sealed archive");
        backup.admit(&sealed, &objects, self.writer.key_id(), now())
    }
}

/// A webhook destination, which sends with no credential.
fn hook() -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::new("hook").expect("an identifier"),
        destination: Destination::External(ExternalDestination {
            kind: DestinationKind::Webhook,
            endpoint: "https://example.invalid/hook".to_owned(),
            idempotency: Idempotency::Unsupported,
            credential: None,
        }),
        rule: Some(DeliveryRule {
            name: "on failure".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(1),
    }
}

/// A generated description, as a local model would have produced it under `generation`.
fn generated(title: &str, generation: u64) -> GeneratedDescription {
    GeneratedDescription {
        title: Title::new(title).expect("a title"),
        activity: ActivityText::new("Checks the release notes").expect("activity text"),
        cursor: CursorInterval::new(3, 11),
        revision: ContextRevision::new(2),
        produced_under: ProducedUnder {
            session_epoch: SessionEpoch::V1,
            binding: ContextBinding::new("desktop-1/terminal/epoch-1"),
            context_revision: ContextRevision::new(2),
            cursor: CursorInterval::new(3, 11),
            profile_id: "minicpm".to_owned(),
            profile_revision: ProfileRevision::new(4),
            generation: PrivacyGeneration::new(generation),
        },
    }
}

/// How much one subsystem has outstanding in a report.
fn outstanding(report: &PrivacyReport, subsystem: &str) -> u64 {
    match &report.completion {
        PrivacyCompletion::Complete => 0,
        PrivacyCompletion::Reconciling { outstanding }
        | PrivacyCompletion::Unavailable { outstanding, .. } => outstanding
            .iter()
            .filter(|owed| owed.subsystem == subsystem)
            .map(|owed| owed.count.get())
            .sum(),
    }
}

/// A grant carrying exactly the rights named, whose history reaches back to the start of time.
fn reaching(actions: &[ActionRight]) -> kr_protocol::pairing::ProposedGrant {
    let mut proposal = proposal(actions);
    proposal.history.lower_bound_ms = Nullable::some(TimestampMs::new(1));
    proposal
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.27, KR-REQ-24.28 and KR-REQ-24.29 through the daemon
// ---------------------------------------------------------------------------------------------

/// KR-REQ-24.27: turning privacy mode on at the daemon records the generation, with the session
/// that holds content owed its own cleanup, and then takes every subsystem through its steps, each
/// read back from its own store: the backup service fenced, admitting nothing more; the delivery
/// journal fenced, with the send on the wire counted; generated descriptions removed and pins kept;
/// the worker told the generation on the daemon's tick, its retained output removed and none of the
/// output still arriving kept. A result of the generation before that comes back afterwards is
/// recorded as a copy elsewhere, never as this host's.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_27_turning_privacy_on_records_the_generation_and_takes_every_subsystem_through_its_steps()
 {
    let environment = Environment::start().await;
    let worker = &environment.worker;
    worker.mark("what the session said");
    until("the session retaining its output", || worker.retained() > 0).await;
    let producer = Producer::generate();
    let publication = environment.publication_on_the_wire(&producer, 1);
    let delivery = environment.delivery_on_the_wire();
    let store = environment.descriptions();
    store
        .publish(
            &worker.session_id,
            &generated("Reads the report", 0),
            now().get(),
        )
        .expect("a generated description");
    let named = SessionId::new(kr_ipc::new_uuid());
    store
        .pin(
            &named,
            &Title::new("Release prep").expect("a title"),
            "local:someone",
            now().get(),
        )
        .expect("a pin");

    let report = environment
        .set(true)
        .await
        .expect("privacy mode is turned on");
    assert!(report.enabled);
    assert_eq!(report.generation.get(), 1);
    assert_eq!(
        report.disabled,
        vec![
            PrivacyDisabled::ContentHistoryRetention,
            PrivacyDisabled::DescriptionInference,
            PrivacyDisabled::Sync,
            PrivacyDisabled::Backup,
        ]
    );
    assert!(
        report.sessions.iter().any(|owed| {
            owed.session_id == worker.session_id
                && owed.generation.get() == 1
                && owed.standing == PrivacySessionStanding::AwaitingWorker
        }),
        "the session holding content owes its own cleanup: {:?}",
        report.sessions
    );

    // The record, on the disk: generation 1, on, and every obligation at that generation.
    let (state, obligations) = environment.record();
    assert_eq!(state, (1, 1));
    assert!(
        obligations.iter().all(|(_, generation)| *generation == 1),
        "{obligations:?}"
    );

    // The backup service: fenced at that generation, and admitting nothing behind the fence.
    let backup = environment.controller().backup();
    assert_eq!(backup.fenced_at().expect("a read"), Some(1));
    assert!(
        environment.admit(&producer, 2).is_err(),
        "no backup generation is admitted while privacy mode is on"
    );
    assert!(
        outstanding(&report, "backup") > 0,
        "the publication on the wire is still to settle: {:?}",
        report.completion
    );

    // The delivery journal: fenced, and the send on the wire counted rather than forgotten.
    assert!(environment.delivery_is_fenced());
    assert_eq!(outstanding(&report, "delivery"), 1);

    // The descriptions: every generated one removed, every pin kept.
    assert!(
        store
            .generated(&worker.session_id)
            .expect("a read")
            .is_none(),
        "the generated description is gone"
    );
    assert!(
        store.pinned(&named).expect("a read").is_some(),
        "and the pin is kept"
    );

    // The worker's session: told the generation, its retained output removed, and the output
    // still arriving not kept.
    environment.worker_holds(1, true).await;
    assert_eq!(worker.retained(), 0, "the retained output is removed");
    let private_from = worker.output_cursor();
    worker.mark("what the session said while private");
    until("the shell printing it", || {
        worker.said().contains("while private")
    })
    .await;
    worker.mark("");
    worker.has_read_all_that_was_said(private_from).await;
    assert_eq!(
        worker.retained(),
        0,
        "output produced while privacy mode is on is not retained"
    );
    assert!(worker.history().is_empty());

    // A result of the generation before, recorded as what it is.
    assert_eq!(
        backup
            .note_published(publication, PrivacyGeneration::INITIAL, now())
            .expect("the answer is recorded"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );
    environment.delivery_answered(delivery);
    environment.stop().await;
}

/// KR-REQ-24.28 and KR-REQ-24.29: privacy mode reports complete only once what was in flight has
/// settled and the worker has said its own cleanup is complete; until then it reconciles, naming
/// what is outstanding, and turning it off is refused. What had already left this host is listed
/// as retained, not erased. Turning it off records the next generation, retention starts again
/// from that point, and nothing omitted while it was on comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_28_completion_waits_for_what_is_in_flight_and_what_had_left_is_listed() {
    let environment = Environment::start().await;
    let worker = &environment.worker;
    worker.mark("before");
    until("the session retaining its output", || worker.retained() > 0).await;
    let producer = Producer::generate();
    let publication = environment.publication_on_the_wire(&producer, 1);
    let delivery = environment.delivery_on_the_wire();

    let report = environment
        .set(true)
        .await
        .expect("privacy mode is turned on");
    assert!(
        matches!(report.completion, PrivacyCompletion::Reconciling { .. }),
        "{:?}",
        report.completion
    );
    assert!(outstanding(&report, "backup") > 0);
    assert_eq!(outstanding(&report, "delivery"), 1);
    assert_eq!(outstanding(&report, "sessions"), 1);

    // Turning it off is refused while any of it is owed, and the refusal says what is.
    let refused = environment
        .set(false)
        .await
        .expect_err("privacy mode stays on while its cleanup is owed");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable);
    assert!(refused.message.contains("backup"), "{}", refused.message);
    assert!(refused.message.contains("delivery"), "{}", refused.message);

    // The worker answers, and the session owes nothing more; what is in flight still holds
    // completion back.
    let report = environment
        .status_until("the session's cleanup", |report| {
            report
                .sessions
                .iter()
                .all(|owed| owed.session_id != worker.session_id)
        })
        .await;
    assert_eq!(outstanding(&report, "sessions"), 0);
    assert!(
        !matches!(report.completion, PrivacyCompletion::Complete),
        "{:?}",
        report.completion
    );
    let (_, obligations) = environment.record();
    assert!(
        obligations.is_empty(),
        "the session's obligation ended on the disk too: {obligations:?}"
    );

    // The delivery's answer arrives, and then the publication's, late: the one is settled, the
    // other recorded as a copy the generation before left.
    environment.delivery_answered(delivery);
    let report = environment.status().await;
    assert_eq!(outstanding(&report, "delivery"), 0);
    assert!(
        !matches!(report.completion, PrivacyCompletion::Complete),
        "the publication has not answered: {:?}",
        report.completion
    );
    assert_eq!(
        environment
            .controller()
            .backup()
            .note_published(publication, PrivacyGeneration::INITIAL, now())
            .expect("the answer is recorded"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );
    let report = environment
        .status_until("completion", |report| {
            report.completion == PrivacyCompletion::Complete
        })
        .await;

    // What had left is shown, and no copy is claimed to be erased or erasable from here.
    assert!(
        report
            .exported
            .iter()
            .any(|copy| copy.kind.starts_with("backup") && !copy.deletable),
        "{:?}",
        report.exported
    );
    assert!(
        report
            .exported
            .iter()
            .any(|copy| copy.kind.contains("webhook")),
        "{:?}",
        report.exported
    );
    assert!(report.unlisted.is_empty(), "{:?}", report.unlisted);
    assert!(!report.kept.is_empty(), "what is kept is named");

    // While it is on, the session says something that is never kept. It falls silent before
    // privacy mode is turned off. Where the terminal passes the shell's bytes as they are, the
    // worker has read everything the shell wrote by then, so all it said is read while privacy
    // mode is still on. Where it does not, the worker has read some of it, and what comes back
    // when privacy mode is turned off is told by the cursor below.
    let private_from = worker.output_cursor();
    worker.mark("while private");
    until("the shell printing it", || {
        worker.said().contains("while private")
    })
    .await;
    worker.mark("");
    worker.has_read_all_that_was_said(private_from).await;
    assert_eq!(worker.retained(), 0);

    // Turning it off: the next generation, recorded, and the worker told.
    let turned_off_from = worker.output_cursor();
    let report = environment
        .set(false)
        .await
        .expect("privacy mode is turned off");
    assert!(!report.enabled);
    assert_eq!(report.generation.get(), 2);
    assert!(report.disabled.is_empty());
    assert_eq!(environment.record().0, (2, 0));
    environment.worker_holds(2, false).await;
    assert!(
        !environment.delivery_is_fenced(),
        "the delivery fence is lifted"
    );
    assert!(
        environment.admit(&producer, 2).is_ok(),
        "backup production starts again"
    );

    // Retention starts again from here, and nothing omitted comes back.
    worker.mark("after");
    until("the session retaining its output again", || {
        worker.history().contains("after")
    })
    .await;
    let history = worker.history();
    assert!(!history.contains("before"), "{history}");
    // Nothing the worker read while privacy mode was on comes back: what it retains starts where
    // its cursor stood when privacy mode was turned off, or after it.
    assert!(
        worker.retained_from() >= turned_off_from,
        "the retained output starts at {}, before the {turned_off_from} the worker had read",
        worker.retained_from()
    );
    #[cfg(unix)]
    assert!(!history.contains("while private"), "{history}");
    environment
        .status_until("the worker's answer for the new generation", |report| {
            report.completion == PrivacyCompletion::Complete
        })
        .await;
    environment.stop().await;
}

/// KR-REQ-24.28 and KR-REQ-24.27: a daemon that restarts in the middle of the change reads the
/// record before anything runs and finishes what it asks: privacy mode is still on at the same
/// generation, the backup fence still stands and nothing is admitted behind it, the delivery that
/// was on the wire is left unresolved, shown rather than sent again, the worker is told again, and
/// the change completes once the late publication answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_28_a_restart_in_the_middle_finishes_the_change_and_resumes_nothing() {
    let environment = Environment::start().await;
    let producer = Producer::generate();
    let publication = environment.publication_on_the_wire(&producer, 1);
    let delivery = environment.delivery_on_the_wire();
    let before = environment
        .set(true)
        .await
        .expect("privacy mode is turned on");
    assert!(
        !matches!(before.completion, PrivacyCompletion::Complete),
        "{:?}",
        before.completion
    );

    let environment = environment.restart().await;

    // The record is read before anything runs.
    let report = environment.status().await;
    assert!(report.enabled);
    assert_eq!(report.generation.get(), 1);
    assert_eq!(environment.record().0, (1, 1));
    let backup = environment.controller().backup();
    assert_eq!(backup.fenced_at().expect("a read"), Some(1));
    assert!(
        environment.admit(&producer, 2).is_err(),
        "nothing is admitted behind the fence after the restart"
    );
    assert!(environment.delivery_is_fenced());

    // The delivery that was on the wire when the daemon stopped is unresolved: a webhook cannot
    // say whether a second copy would be a duplicate, so it is not sent again, and it is shown as
    // a copy that may have left.
    assert_eq!(
        environment.delivery_state(delivery),
        DeliveryState::DuplicateUncertain
    );
    assert!(
        report
            .exported
            .iter()
            .any(|copy| copy.kind.contains("webhook")),
        "{:?}",
        report.exported
    );

    // The worker is told again by the new daemon, and the change is not complete while the
    // publication has not answered, restart or none.
    environment.worker_holds(1, true).await;
    let report = environment
        .status_until("the session's cleanup after the restart", |report| {
            report.sessions.is_empty()
        })
        .await;
    assert!(
        outstanding(&report, "backup") > 0,
        "a restart is no evidence about an attempt: {:?}",
        report.completion
    );
    assert_eq!(
        backup
            .note_published(publication, PrivacyGeneration::INITIAL, now())
            .expect("the answer is recorded"),
        Publication::RetainedArtifact {
            privacy_generation: 0
        }
    );
    environment
        .status_until("completion after the restart", |report| {
            report.completion == PrivacyCompletion::Complete
        })
        .await;
    environment.stop().await;
}

/// KR-REQ-24.28: a question and an approval pending when privacy mode is turned on keep working
/// under the grants they had. The question stays in the owner's inbox, with its words withheld
/// from the moment the session applied the generation, and a paired device whose grant lets it
/// respond answers it through the daemon, while one whose grant does not is refused. The approval
/// is answered at the session's own socket, the upstream takes the answer, and the receipt keeps
/// its state while the content of the action goes where it settled.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_28_a_pending_question_and_approval_are_still_answered_and_their_bodies_not_exported()
 {
    let environment = Environment::start().await;
    let worker = &environment.worker;
    let upstream = Arc::new(CountingUpstream::default());
    register_agent(worker, Arc::clone(&upstream));
    open_gateway(worker, Arc::clone(&upstream));
    let answered_before = pending_approval(worker, 11);
    let pending = pending_approval(worker, 12);
    let asked = worker.ask("deploy-1", "Deploy the release to production?");

    // The control: an approval answered while privacy mode is off keeps its receipt's body.
    let (action_id, actor_id) =
        answer_approval(worker, environment.environment_id(), answered_before).await;
    assert_eq!(receipt_body(worker, &actor_id, action_id), (true, true));

    // Before privacy mode the owner's inbox carries the question's words.
    environment
        .inbox_until("the question with its words", |items| {
            items.iter().any(|item| {
                item.rule == AttentionRule::PendingInput
                    && item.summary.0.as_deref() == Some("Deploy the release to production?")
            })
        })
        .await;

    environment
        .set(true)
        .await
        .expect("privacy mode is turned on");
    environment.worker_holds(1, true).await;

    // The question is still pending and still in the inbox, and its words are not served.
    let items = environment
        .inbox_until("the question without its words", |items| {
            items
                .iter()
                .any(|item| item.rule == AttentionRule::PendingInput && item.summary.0.is_none())
        })
        .await;
    assert!(
        items
            .iter()
            .all(|item| item.summary.0.as_deref() != Some("Deploy the release to production?")),
        "{items:?}"
    );

    // A device that may view the session but not respond is refused; one that may respond
    // answers, through the daemon, at the revision it was shown.
    let viewer = environment
        .device(proposal(&[ActionRight::SessionView]))
        .await;
    let responder = environment
        .device(reaching(&[
            ActionRight::SessionView,
            ActionRight::QuestionRespond,
        ]))
        .await;
    let answer = QuestionAnswerParams {
        session_id: worker.session_id,
        question_id: asked.question_id,
        expected_revision: asked.revision,
        answer: QuestionAnswer::Decision { decided: true },
    };
    let refused = viewer
        .mutate(
            Method::QuestionAnswer,
            worker.target(environment.environment_id()),
            None,
            &ParamsValue::empty(),
            &answer,
            DurationMs::new(120_000),
        )
        .await
        .expect_err("an answer without the right is refused");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    let read: QuestionReadResult = responder
        .read(
            Method::QuestionRead,
            &QuestionReadParams {
                session_id: worker.session_id,
                question_id: Nullable::some(asked.question_id),
                include_resolved: false,
            },
        )
        .await
        .expect("the question reads under the grant");
    assert_eq!(read.questions.len(), 1);
    assert_eq!(read.questions[0].state, QuestionState::Pending);
    let resolved: QuestionResolveResult = responder
        .mutate(
            Method::QuestionAnswer,
            worker.target(environment.environment_id()),
            None,
            &ParamsValue::empty(),
            &answer,
            DurationMs::new(120_000),
        )
        .await
        .expect("the question is answered while privacy mode is on")
        .to_typed()
        .expect("decodes");
    assert_eq!(resolved.state, QuestionState::Answered);
    viewer.close();
    responder.close();

    // The approval pending since before privacy mode, answered at the session's socket by the
    // owner at this machine. The upstream takes the answer, and the receipt keeps its state while
    // its body, the envelope and what it came to, goes where the action settled.
    let (action_id, actor_id) =
        answer_approval(worker, environment.environment_id(), pending).await;
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the upstream took both answers"
    );
    assert_eq!(
        receipt_body(worker, &actor_id, action_id),
        (false, false),
        "the answer's envelope and result are not kept as history"
    );
    environment.stop().await;
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-18.08: a delivery of an item whose words are a session's record carries none of them
// ---------------------------------------------------------------------------------------------

/// A gateway that takes every notification it is given and keeps the bodies it was asked to
/// deliver, on this machine's loopback interface and nowhere else.
#[derive(Debug, Default)]
struct TakingGateway {
    bodies: Mutex<Vec<Vec<u8>>>,
}

impl kr_client::services::ServiceHttp for TakingGateway {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        let request: PushDeliveryRequest = serde_json::from_slice(body).expect("a request");
        self.bodies
            .lock()
            .expect("not poisoned")
            .push(body.to_vec());
        let answer = serde_json::json!({
            "ok": true,
            "data": PushDeliveryAck {
                decided_at_ms: now(),
                notification_id: request.notification_id,
                state: PushDeliveryState::Queued,
                suppression: Nullable::null(),
            },
        });
        Box::pin(async move {
            Ok(kr_client::services::ServiceHttpAnswer {
                status: 200,
                body: serde_json::to_vec(&answer).expect("an answer"),
            })
        })
    }
}

/// Every origin reached through one transport.
#[derive(Debug)]
struct OneGateway(Arc<TakingGateway>);

impl kr_controller::push::transport::DeliveryTransports for OneGateway {
    fn to(
        &self,
        _origin: &kr_protocol::service::GatewayOrigin,
    ) -> Result<Arc<dyn kr_client::services::ServiceHttp>, String> {
        Ok(Arc::clone(&self.0) as Arc<dyn kr_client::services::ServiceHttp>)
    }
}

/// KR-REQ-18.08, KR-REQ-16.13: a question asked inside a session is an item whose words are the
/// session's own record, which the attention store keeps no copy of. When the daemon delivers it
/// to a paired device, the journal's files and the preview the device opens hold none of the
/// words: the notice carries the host's own words, and for a question there are none. The premise
/// is read back from the store: the item's text is where to read the question, not the question.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_18_08_a_delivered_question_leaves_none_of_the_sessions_words_in_the_journal_or_the_preview()
 {
    const WORDS: &str = "Deploy the release to production?";
    let environment = Environment::start().await;
    let worker = &environment.worker;
    let controller = environment.controller();
    let phone = environment
        .raw_device(reaching(&[ActionRight::SessionView]))
        .await;
    let preview_key = NotificationPreviewKeyPair::generate().expect("a keypair");
    let sender = PushSenderRecordId::new(Uuid::from_bytes([0x51; 16]));
    controller
        .delivery()
        .configure(&DestinationRecord {
            id: DestinationId::new(phone.record.device_id.to_string()).expect("an identifier"),
            destination: Destination::Push(Box::new(PushDestination {
                installation_id: InstallationId::new(Uuid::from_bytes([0x52; 16])),
                sender_record_id: sender,
                preview_keys: PreviewKeys::only(*preview_key.public(), 1),
                previews_enabled: true,
                mailbox_key: None,
            })),
            rule: Some(DeliveryRule {
                name: "anything that wants a person".to_owned(),
                grant_id: Some(phone.record.grant.grant_id),
            }),
            enabled: true,
            configured_at_ms: now(),
        })
        .expect("a destination");
    let current = kr_ipc::now_ms().get();
    controller
        .delivery_runtime()
        .credentials()
        .hold(PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(current + 29 * 24 * 60 * 60 * 1000),
            issued_at_ms: TimestampMs::new(current - 1_000),
            sender_record_id: sender,
            ..credential(0)
        });
    let gateway = Arc::new(TakingGateway::default());
    assert!(controller.attach_delivery_transport(Arc::new(OneGateway(Arc::clone(&gateway)))));

    let _asked = worker.ask("deploy-1", WORDS);
    until("the question being delivered", || {
        !gateway.bodies.lock().expect("not poisoned").is_empty()
    })
    .await;

    // The premise: the question is in the store as an item whose text is a record of the session.
    let reads_from_the_record = controller
        .attention()
        .take_for_delivery(|store, _| {
            store
                .engine()
                .expect("the store is this owner's")
                .items()
                .filter(|item| item.rule == AttentionRule::PendingInput)
                .all(|item| matches!(item.text, kr_attention::engine::Text::Record(_)))
        })
        .expect("the store is taken");
    assert!(reads_from_the_record);

    let body = gateway.bodies.lock().expect("not poisoned")[0].clone();
    let request: PushDeliveryRequest = serde_json::from_slice(&body).expect("a request");
    let host_preview = controller
        .delivery()
        .with(|producer| Ok(*producer.preview_public()))
        .expect("the host's preview key");
    let opened = kr_delivery::preview::open_preview(
        &preview_key,
        &host_preview,
        request.preview.as_ref().expect("a preview"),
        kr_ipc::now_ms().get(),
    )
    .expect("the device opens its own preview");
    assert_eq!(
        opened.summary, "",
        "the host has no words of its own for a question"
    );
    assert!(!format!("{opened:?}").contains(WORDS));
    let state = environment
        .host
        .tree()
        .environment()
        .state_dir()
        .to_path_buf();
    let holds = |bytes: &[u8], words: &str| {
        bytes
            .windows(words.len())
            .any(|window| window == words.as_bytes())
    };
    // The scan reads what it is pointed at: it finds words planted among other bytes, and it finds
    // the one word this host does record about the delivery, the paired device it was for.
    assert!(holds(format!("a{WORDS}b").as_bytes(), WORDS));
    let device = phone.record.device_id.to_string();
    let mut found_the_device = false;
    for name in [
        "delivery.sqlite3",
        "delivery.sqlite3-wal",
        "delivery.sqlite3-shm",
    ] {
        let Ok(bytes) = std::fs::read(state.join(name)) else {
            assert_ne!(
                name, "delivery.sqlite3",
                "the journal's own file is the one that is scanned"
            );
            continue;
        };
        assert!(!holds(&bytes, WORDS), "{name} holds the question");
        found_the_device |= holds(&bytes, &device);
    }
    assert!(
        found_the_device,
        "the scan reads a file that records the delivery"
    );
    environment.stop().await;
}

/// A web service on this machine's loopback interface that answers every request with 200 and
/// keeps the body of each, and nowhere else.
struct Webhook {
    address: String,
    port: u16,
    bodies: Arc<Mutex<Vec<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Webhook {
    fn start() -> Self {
        use std::io::{Read, Write};
        use std::sync::atomic::Ordering;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (kept, stopping) = (Arc::clone(&bodies), Arc::clone(&stop));
        std::thread::spawn(move || {
            for connection in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut connection) = connection else {
                    continue;
                };
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                let (head, wanted) = loop {
                    if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (end + 4, length);
                    }
                    match connection.read(&mut chunk) {
                        Ok(0) | Err(_) => break (request.len(), 0),
                        Ok(read) => request.extend_from_slice(&chunk[..read]),
                    }
                };
                while request.len() < head + wanted {
                    match connection.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&chunk[..read]),
                    }
                }
                if wanted > 0 {
                    kept.lock()
                        .expect("not poisoned")
                        .push(String::from_utf8_lossy(&request[head..]).into_owned());
                }
                let _ = connection.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                );
            }
        });
        Self {
            address: format!("http://127.0.0.1:{port}/hook"),
            port,
            bodies,
            stop,
        }
    }

    /// The body of every request this service was sent, in order.
    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().expect("not poisoned").clone()
    }
}

impl Drop for Webhook {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // The accepting thread is waiting for one more connection, and this is it.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// KR-REQ-18.08: a host sends content to an external destination only under an explicit recipient
/// policy and a content policy, and the daemon a person runs holds to both over a real connection.
/// Four webhooks on this machine's loopback interface are configured on one daemon, the managed
/// transport a shipped daemon attaches reaches them, and a question is asked inside a real
/// session. The webhook whose rule names a grant that reaches the session is told once: what it
/// receives says its recipients can read it and carries none of the words of the question or of
/// its context, and the journal's files carry none either. The webhook with no rule at all,
/// the one whose rule names the grant of a device that has since been unpaired and the one whose
/// grant reaches another session than this one are sent nothing, the first two with a refusal
/// recorded in the journal.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_18_08_an_external_destination_is_told_only_under_its_rule_and_its_grant() {
    const WORDS: &str = "Deploy the release to production?";
    const CONTEXT: &str = "the release is tagged";
    let environment = Environment::start().await;
    let controller = environment.controller();
    let reaching_this_session = environment
        .raw_device(reaching(&[ActionRight::SessionView]))
        .await;
    let unpaired_since = environment
        .raw_device(reaching(&[ActionRight::SessionView]))
        .await;
    let mut another_session = reaching(&[ActionRight::SessionView]);
    another_session.session_selector = SessionSelector::These {
        session_ids: [SessionId::new(Uuid::from_bytes([0x77; 16]))]
            .into_iter()
            .collect(),
    };
    let reaching_another = environment.raw_device(another_session).await;

    let told = Webhook::start();
    let ruleless = Webhook::start();
    let unpaired = Webhook::start();
    let elsewhere = Webhook::start();
    let destination = |id: &str, hook: &Webhook, grant: Option<&RawPaired>| DestinationRecord {
        id: DestinationId::new(id).expect("an identifier"),
        destination: Destination::External(ExternalDestination {
            kind: DestinationKind::Webhook,
            endpoint: hook.address.clone(),
            idempotency: Idempotency::Unsupported,
            credential: None,
        }),
        rule: grant.map(|paired| DeliveryRule {
            name: "anything that wants a person".to_owned(),
            grant_id: Some(paired.record.grant.grant_id),
        }),
        enabled: true,
        configured_at_ms: now(),
    };
    for record in [
        destination("told", &told, Some(&reaching_this_session)),
        destination("ruleless", &ruleless, None),
        destination("unpaired", &unpaired, Some(&unpaired_since)),
        destination("elsewhere", &elsewhere, Some(&reaching_another)),
    ] {
        controller
            .delivery()
            .configure(&record)
            .expect("a destination");
    }
    // The recipient's pairing ends through the owner's own call, before anything is asked.
    let mut owner = environment.host.client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        environment.environment_id(),
        &mut owner,
        Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: unpaired_since.record.device_id,
        },
    )
    .await
    .expect("the owner unpairs the device");
    assert!(controller.attach_delivery_transport(Arc::new(
        kr_controller::push::transport::ManagedTransports::new(None)
    )));

    let _asked = environment.worker.ask("deploy-1", WORDS);
    until(
        "the webhook under a grant that reaches the session being told",
        || !told.bodies().is_empty(),
    )
    .await;

    // Every destination was decided in the transaction that admitted the message above.
    let records = controller
        .delivery()
        .with(|producer| Ok(producer.journal().deliveries().expect("a read")))
        .expect("the journal");
    let state_of = |id: &str| {
        records
            .iter()
            .filter(|record| record.destination_id.as_str() == id)
            .map(|record| record.state)
            .collect::<Vec<_>>()
    };
    assert_eq!(state_of("ruleless"), [DeliveryState::Refused]);
    assert_eq!(state_of("unpaired"), [DeliveryState::Refused]);
    assert!(
        state_of("elsewhere").is_empty(),
        "a message about a session the grant does not reach is not one this destination wants"
    );
    assert!(ruleless.bodies().is_empty(), "no rule, so nothing is sent");
    assert!(
        unpaired.bodies().is_empty(),
        "a grant whose device was unpaired admits nothing"
    );
    assert!(
        elsewhere.bodies().is_empty(),
        "a grant that does not reach the session is told nothing about it"
    );

    // What the one told destination received, and what the journal kept.
    let received = told.bodies();
    assert_eq!(received.len(), 1, "told once: {received:?}");
    let message: serde_json::Value = serde_json::from_str(&received[0]).expect("a JSON message");
    assert!(
        message["body"]
            .as_str()
            .is_some_and(|body| body.ends_with(kr_delivery::external::RECIPIENTS_CAN_READ)),
        "the message says its recipients can read it: {message}"
    );
    for words in [WORDS, CONTEXT] {
        assert!(
            !received[0].contains(words),
            "the session's words reached the webhook: {words}"
        );
    }
    let state = environment
        .host
        .tree()
        .environment()
        .state_dir()
        .to_path_buf();
    let holds = |bytes: &[u8], words: &str| {
        bytes
            .windows(words.len())
            .any(|window| window == words.as_bytes())
    };
    let mut found_the_destination = false;
    for name in [
        "delivery.sqlite3",
        "delivery.sqlite3-wal",
        "delivery.sqlite3-shm",
    ] {
        let Ok(bytes) = std::fs::read(state.join(name)) else {
            assert_ne!(
                name, "delivery.sqlite3",
                "the journal's own file is the one that is scanned"
            );
            continue;
        };
        for words in [WORDS, CONTEXT] {
            assert!(!holds(&bytes, words), "{name} holds the words: {words}");
        }
        // The scan reads a file that records the delivery: it finds the destination's own name.
        found_the_destination |= holds(&bytes, "ruleless");
    }
    assert!(
        found_the_destination,
        "the scan reads what the journal kept"
    );
    drop(owner);
    environment.stop().await;
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.34, KR-REQ-22.17 and KR-REQ-24.14: the session's name at both doors
// ---------------------------------------------------------------------------------------------

/// KR-REQ-23.34, KR-REQ-22.17 and KR-REQ-24.14: `session.describe` is a filtered read at both
/// doors and `session.rename` writes a pin at both, each under its own right. Generated text is
/// served to the owner at this machine and to a device whose grant reaches back to the session's
/// start, and never to one whose grant does not, nor to one without `session.view`. A pin a device
/// wrote is what both doors answer, it survives privacy mode, and it survives the daemon that
/// served it. While privacy mode is on the title is the metadata one, whatever the store holds,
/// and after it a description produced under the private generation is never served.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_34_the_session_name_is_a_filtered_read_and_a_pinned_write_at_both_doors() {
    let environment = Environment::start().await;
    let session_id = environment.worker.session_id;
    let store = environment.descriptions();
    store
        .publish(
            &session_id,
            &generated("Checks the release", 0),
            now().get(),
        )
        .expect("a generated description");

    // The owner at this machine reaches the whole session.
    let local = environment.describe(session_id).await;
    assert_eq!(local.source, LabelSource::Generated);
    assert_eq!(local.title, "Checks the release");
    assert!(local.activity_text.0.is_some());
    assert!(local.provenance.0.is_some());

    // A device whose grant reaches back to the session's start is served the same; one whose grant
    // retains no history is served the metadata title and no generated text; one without
    // `session.view` is refused.
    let reaching_device = environment
        .device(reaching(&[ActionRight::SessionView]))
        .await;
    let partial_device = environment
        .device(proposal(&[ActionRight::SessionView]))
        .await;
    let renamer = environment
        .device(proposal(&[ActionRight::SessionRename]))
        .await;
    let described: SessionDescribeResult = reaching_device
        .read(
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await
        .expect("described to a device reaching the whole session");
    assert_eq!(described.source, LabelSource::Generated);
    assert_eq!(described.title, "Checks the release");
    let described: SessionDescribeResult = partial_device
        .read(
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await
        .expect("described to a device reaching part of the session");
    assert_eq!(described.source, LabelSource::Metadata);
    assert!(described.title.contains(PROJECT), "{}", described.title);
    assert!(described.activity_text.0.is_none());
    assert!(described.provenance.0.is_none());
    let refused = renamer
        .read::<_, SessionDescribeResult>(
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await
        .expect_err("a device without session.view reads no name");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");

    // A device without `session.rename` cannot pin; one with it can, and both doors answer the pin.
    let refused = reaching_device
        .mutate(
            Method::SessionRename,
            environment.worker.target(environment.environment_id()),
            None,
            &ParamsValue::empty(),
            &SessionRenameParams {
                session_id,
                title: Nullable::some("Not mine to name".to_owned()),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect_err("a device without session.rename pins nothing");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    let renamed: SessionRenameResult = renamer
        .mutate(
            Method::SessionRename,
            environment.worker.target(environment.environment_id()),
            None,
            &ParamsValue::empty(),
            &SessionRenameParams {
                session_id,
                title: Nullable::some("Release prep".to_owned()),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect("the session is renamed from a device")
        .to_typed()
        .expect("decodes");
    assert_eq!(renamed.title, "Release prep");
    assert_eq!(renamed.source, LabelSource::Pinned);
    assert!(renamed.pinned);
    let local = environment.describe(session_id).await;
    assert_eq!(
        (local.title.as_str(), local.source),
        ("Release prep", LabelSource::Pinned)
    );
    let described: SessionDescribeResult = partial_device
        .read(
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await
        .expect("described");
    assert_eq!(
        (described.title.as_str(), described.source),
        ("Release prep", LabelSource::Pinned)
    );
    let pin = store
        .pinned(&session_id)
        .expect("a read")
        .expect("the pin is in the store");
    assert!(
        pin.pinned_by.starts_with("device:"),
        "the pin names the device that set it: {}",
        pin.pinned_by
    );

    // Privacy mode keeps the pin, and without one the title is the metadata one, even with a
    // description of the private generation in the store.
    environment
        .set(true)
        .await
        .expect("privacy mode is turned on");
    assert_eq!(
        environment.describe(session_id).await.source,
        LabelSource::Pinned,
        "a pin survives privacy mode"
    );
    let cleared = environment.rename(None).await;
    assert_eq!(cleared.source, LabelSource::Metadata);
    assert!(!cleared.pinned);
    store
        .publish(&session_id, &generated("Private work", 1), now().get())
        .expect("a description of the private generation");
    for described in [
        environment.describe(session_id).await,
        reaching_device
            .read(
                Method::SessionDescribe,
                &SessionDescribeParams { session_id },
            )
            .await
            .expect("described"),
    ] {
        assert_eq!(described.source, LabelSource::Metadata, "{described:?}");
        assert!(described.title.contains(PROJECT), "{}", described.title);
        assert!(described.activity_text.0.is_none());
    }

    // After privacy mode, what was produced under its generation is still never served.
    environment
        .status_until("the enabling's completion", |report| {
            report.completion == PrivacyCompletion::Complete
        })
        .await;
    environment
        .set(false)
        .await
        .expect("privacy mode is turned off");
    store
        .publish(&session_id, &generated("Private work", 1), now().get())
        .expect("a description of the private generation");
    assert_eq!(
        environment.describe(session_id).await.source,
        LabelSource::Metadata,
        "a description of an earlier generation is not the current one"
    );
    store
        .publish(&session_id, &generated("Public work", 2), now().get())
        .expect("a description of the generation in force");
    let local = environment.describe(session_id).await;
    assert_eq!(
        (local.title.as_str(), local.source),
        ("Public work", LabelSource::Generated)
    );

    // A pin outlives the daemon that served it.
    let pinned = environment.rename(Some("Release prep")).await;
    assert_eq!(pinned.source, LabelSource::Pinned);
    reaching_device.close();
    partial_device.close();
    renamer.close();
    let environment = environment.restart().await;
    let local = environment.describe(session_id).await;
    assert_eq!(
        (local.title.as_str(), local.source),
        ("Release prep", LabelSource::Pinned)
    );
    environment.stop().await;
}

/// KR-REQ-24.14: a pin outlives the session it names. The session is closed through the daemon,
/// and once the daemon reports it closed both doors still answer the pin; a rename of the closed
/// session still clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_14_a_pin_outlives_the_session_closing() {
    let environment = Environment::start().await;
    let session_id = environment.worker.session_id;
    let reader = environment
        .device(reaching(&[ActionRight::SessionView]))
        .await;
    let pinned = environment.rename(Some("Release prep")).await;
    assert_eq!(pinned.source, LabelSource::Pinned);

    let mut client = environment.host.client().await;
    let _: kr_protocol::session::SessionCloseResult = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            environment.worker.target(environment.environment_id()),
            &kr_protocol::session::SessionCloseParams { session_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the session closes")
        .to_typed()
        .expect("decodes");
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let read: kr_protocol::session::SessionReadResult = client
            .request(
                Method::SessionRead,
                &kr_protocol::session::SessionReadParams { session_id },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the closed session is read")
            .to_typed()
            .expect("decodes");
        if read.session.state == SessionState::Closed {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the daemon never reported the session closed: {:?}",
            read.session.state
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let local = environment.describe(session_id).await;
    assert_eq!(
        (local.title.as_str(), local.source),
        ("Release prep", LabelSource::Pinned)
    );
    let described: SessionDescribeResult = reader
        .read(
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await
        .expect("described to a device");
    assert_eq!(
        (described.title.as_str(), described.source),
        ("Release prep", LabelSource::Pinned)
    );
    let cleared = environment.rename(None).await;
    assert_eq!(cleared.source, LabelSource::Metadata);
    assert!(!cleared.pinned);
    reader.close();
    environment.stop().await;
}

/// KR-REQ-24.28: an obligation for a session that has no worker and no launch does not hold
/// turning privacy mode off back. The record a daemon that stopped left says privacy mode is on and
/// that one more session, whose journal is on the disk, owes its cleanup; no worker is recorded for
/// it and the registry holds no reservation that could still produce one, so the daemon takes it for
/// ended and says so. Privacy mode is then turned off, and the obligation stays, because what the
/// session kept is the archive's.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_28_an_obligation_with_no_worker_and_no_launch_does_not_hold_privacy_mode_on() {
    let gone = SessionId::new(kr_ipc::new_uuid());
    let environment = Environment::start_seeded(|state_dir| {
        let record =
            rusqlite::Connection::open(state_dir.join(PRIVACY_RECORD)).expect("the privacy record");
        record
            .execute(
                "UPDATE privacy_record SET generation = 1, enabled = 1, changed_at_ms = ?1
                  WHERE id = 0",
                [i64::try_from(now().get()).expect("a time")],
            )
            .expect("privacy mode is on in the record");
        record
            .execute(
                "INSERT INTO privacy_obligations (session_id, generation, recorded_at_ms)
                 VALUES (?1, 1, ?2)",
                rusqlite::params![
                    gone.to_string(),
                    i64::try_from(now().get()).expect("a time")
                ],
            )
            .expect("an obligation for a session that has gone");
    })
    .await;

    // The daemon read the record: privacy mode is on. Its live session answers for itself; the
    // session that has gone is taken for ended.
    let report = environment
        .status_until(
            "the daemon taking the session that has gone for ended",
            |report| {
                report.enabled
                    && report.sessions.iter().any(|owed| {
                        owed.session_id == gone
                            && matches!(owed.standing, PrivacySessionStanding::WorkerEnded)
                    })
                    && report.sessions.iter().all(|owed| owed.session_id == gone)
            },
        )
        .await;
    assert!(
        !matches!(report.completion, PrivacyCompletion::Complete),
        "what the session that has gone kept is not gone: {:?}",
        report.completion
    );
    let off = environment
        .set(false)
        .await
        .expect("a session that has gone does not hold privacy mode on");
    assert!(!off.enabled);
    assert!(
        off.sessions.iter().any(|owed| owed.session_id == gone),
        "its obligation stays: {:?}",
        off.sessions
    );
    environment.stop().await;
}

/// A rename's answer, decoded.
fn renamed(answer: ParamsValue) -> SessionRenameResult {
    answer.to_typed().expect("a rename's answer decodes")
}

/// One clearing of a session's name at each door, each under an action identifier of its own, for
/// presenting again as a caller does whose answer never arrived.
struct Clearings {
    owners: kr_protocol::envelope::MutationRequest,
    devices: ActionId,
    window: kr_protocol::ids::ActionWindowId,
    target: ActionTarget,
    params: SessionRenameParams,
}

impl Clearings {
    /// Presents both again, the owner's on a connection of its own, and returns what each is told.
    async fn presented(
        &self,
        environment: &Environment,
        device: &RawDevice,
    ) -> (SessionRenameResult, SessionRenameResult) {
        let owners = environment
            .host
            .client()
            .await
            .repeat(&self.owners)
            .await
            .expect("the call reaches the daemon")
            .expect("the owner's clearing is answered from its record");
        let devices = device
            .mutate_in(
                self.window.clone(),
                Method::SessionRename,
                self.devices,
                self.target.clone(),
                &self.params,
            )
            .await
            .expect("the device's clearing is answered from its record");
        (renamed(owners), renamed(devices))
    }
}

/// What a retained clearing must be: what the action first came to, which is the deterministic
/// title, and none of the generated text the store held.
fn holds_no_generated_text(answer: &SessionRenameResult, first: &SessionRenameResult) {
    assert_eq!(
        answer, first,
        "a retry is answered with what the action came to"
    );
    assert_eq!(answer.source, LabelSource::Metadata, "{answer:?}");
    assert!(!answer.pinned, "{answer:?}");
    assert!(answer.title.contains(PROJECT), "{}", answer.title);
    assert!(
        !answer.title.contains("Checks the release"),
        "generated text is in the answer: {}",
        answer.title
    );
}

/// KR-REQ-24.28 and KR-REQ-24.14: a rename that clears a pin answers with the deterministic title,
/// never with generated text, so the record its action keeps for a retry holds none. A retry
/// answered from that record at either door, once privacy mode has removed the generated
/// description and once the daemon has restarted, is the answer the action first came to, and no
/// generated text is in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_28_a_repeated_clearing_is_answered_from_its_record_without_generated_text() {
    let environment = Environment::start().await;
    let session_id = environment.worker.session_id;
    let store = environment.descriptions();
    store
        .publish(
            &session_id,
            &generated("Checks the release", 0),
            now().get(),
        )
        .expect("a generated description");

    // One clearing at each door before privacy mode: the owner's at this machine, and a device's
    // that may rename and view the session.
    let target = environment.worker.target(environment.environment_id());
    let params = SessionRenameParams {
        session_id,
        title: Nullable::null(),
    };
    let mut owner = environment.host.client().await;
    let device = environment
        .raw_device(proposal(&[
            ActionRight::SessionRename,
            ActionRight::SessionView,
        ]))
        .await;
    let clearings = Clearings {
        owners: owner
            .compose(
                Method::SessionRename,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &params,
            )
            .await
            .expect("the owner's clearing is composed"),
        devices: ActionId::new(kr_ipc::new_uuid()),
        window: device.connection.action_window_id(),
        target,
        params,
    };
    let first_owner = renamed(
        owner
            .repeat(&clearings.owners)
            .await
            .expect("the call reaches the daemon")
            .expect("the owner clears the name"),
    );
    let first_device = renamed(
        device
            .connection
            .mutate_in(
                clearings.window.clone(),
                Method::SessionRename,
                clearings.devices,
                clearings.target.clone(),
                &clearings.params,
            )
            .await
            .expect("the device clears the name"),
    );

    // Privacy mode removes the generated description, and a retry at either door is answered from
    // the record its action kept.
    environment
        .set(true)
        .await
        .expect("privacy mode is turned on");
    assert_eq!(
        store.generated_count().expect("a read"),
        0,
        "privacy mode removed the generated description"
    );
    let (again_owner, again_device) = clearings.presented(&environment, &device.connection).await;
    holds_no_generated_text(&again_owner, &first_owner);
    holds_no_generated_text(&again_device, &first_device);

    // A daemon that restarted answers the same.
    drop(owner);
    device.connection.close();
    let environment = environment.restart().await;
    let connection = RawDevice::connect(&environment.host, &device.device, &device.record).await;
    let (again_owner, again_device) = clearings.presented(&environment, &connection).await;
    holds_no_generated_text(&again_owner, &first_owner);
    holds_no_generated_text(&again_device, &first_device);
    connection.close();
    environment.stop().await;
}

/// KR-REQ-23.34: a device that may rename a session and may not view it renames it, and does not
/// learn what its action came to by presenting the action again. A retained answer, a name or a
/// refusal, goes back only under present view authority over the session it names; a device that
/// may view it is answered from the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_34_a_repeated_rename_is_answered_only_under_view_authority_over_its_session() {
    let environment = Environment::start().await;
    let session_id = environment.worker.session_id;
    let target = environment.worker.target(environment.environment_id());
    let pinning = SessionRenameParams {
        session_id,
        title: Nullable::some("Release prep".to_owned()),
    };
    let too_long = SessionRenameParams {
        session_id,
        title: Nullable::some("x".repeat(65)),
    };
    for (rights, views) in [
        (vec![ActionRight::SessionRename], false),
        (
            vec![ActionRight::SessionRename, ActionRight::SessionView],
            true,
        ),
    ] {
        let device = environment.raw_device(proposal(&rights)).await;
        let named = ActionId::new(kr_ipc::new_uuid());
        let refused = ActionId::new(kr_ipc::new_uuid());

        // Both are answered the first time: the right to rename is enough to rename.
        let first = renamed(
            device
                .connection
                .mutate(Method::SessionRename, named, target.clone(), &pinning)
                .await
                .expect("a device that may rename renames"),
        );
        assert_eq!(first.title, "Release prep");
        let refusal = device
            .connection
            .mutate(Method::SessionRename, refused, target.clone(), &too_long)
            .await
            .expect_err("a name that is too long is refused");
        assert_eq!(refusal.code, ErrorCode::InvalidArgument, "{refusal}");

        // Presented again, the name and the refusal are both a read of what the action came to.
        let again = device
            .connection
            .mutate(Method::SessionRename, named, target.clone(), &pinning)
            .await;
        let again_refused = device
            .connection
            .mutate(Method::SessionRename, refused, target.clone(), &too_long)
            .await
            .expect_err("the refusal comes back as a refusal");
        if views {
            assert_eq!(
                renamed(again.expect("a device that may view is answered from the record")),
                first
            );
            assert_eq!(again_refused.code, ErrorCode::InvalidArgument);
        } else {
            let denied = again.expect_err("a device that may not view is not answered");
            assert_eq!(denied.code, ErrorCode::PermissionDenied, "{denied}");
            assert_eq!(
                again_refused.code,
                ErrorCode::PermissionDenied,
                "{again_refused}"
            );
        }
        device.connection.close();
    }
    environment.stop().await;
}

/// KR-REQ-24.29 and section 23: a paired device whose grant carries host management reads where
/// privacy mode stands; one whose grant does not is refused; and no device can turn it on or off,
/// which only the host itself does.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_29_a_device_reads_privacy_mode_under_host_management_and_cannot_change_it() {
    let environment = Environment::start().await;
    environment
        .set(true)
        .await
        .expect("privacy mode is turned on");
    let manager = environment
        .device(proposal(&[ActionRight::HostManage]))
        .await;
    let viewer = environment
        .device(proposal(&[ActionRight::SessionView]))
        .await;
    let read: PrivacyReport = manager
        .read(Method::PrivacyStatus, &PrivacyStatusParams {})
        .await
        .expect("a device with host.manage reads privacy mode");
    assert!(read.enabled);
    assert_eq!(read.generation.get(), 1);
    let refused = viewer
        .read::<_, PrivacyReport>(Method::PrivacyStatus, &PrivacyStatusParams {})
        .await
        .expect_err("a device without host.manage reads nothing of it");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    let refused = manager
        .mutate(
            Method::PrivacySet,
            ActionTarget::environment(environment.environment_id()),
            None,
            &ParamsValue::empty(),
            &PrivacySetParams { enabled: false },
            DurationMs::new(120_000),
        )
        .await
        .expect_err("no device turns privacy mode off");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        environment.status().await.enabled,
        "privacy mode is still on"
    );
    manager.close();
    viewer.close();
    environment.stop().await;
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.27 and KR-REQ-24.28: the delivery gate, on the delivery module
// ---------------------------------------------------------------------------------------------

/// A fixed instant the delivery module's tests start from.
const NOW: u64 = 1_700_000_000_000;

/// The daemon subsystems of one environment and its privacy record, over a directory on the
/// internal disk, with no daemon around them.
struct Subsystems {
    _root: tempfile::TempDir,
    delivery: Arc<DeliveryModule>,
    privacy: Arc<EnvironmentPrivacy>,
    device_preview: NotificationPreviewKeyPair,
}

impl Subsystems {
    fn open() -> Self {
        let root = tempfile::tempdir().expect("a directory on the internal disk");
        let state = root.path();
        let backup = Arc::new(BackupService::open(state).expect("a backup service"));
        backup
            .reconcile(TimestampMs::new(NOW))
            .expect("the startup reconciliation");
        let delivery = Arc::new(
            DeliveryModule::open_at(
                &state.join("delivery.sqlite3"),
                NotificationPreviewKeyPair::generate().expect("a keypair"),
                StoredEnvelopeKeyPair::generate().expect("a keypair"),
                kr_controller::push::secrets::DestinationSecrets::new(
                    Arc::new(MemoryStore::new()),
                    EnvironmentId::new(Uuid::from_bytes([0xee; 16])),
                ),
            )
            .expect("a delivery module"),
        );
        let descriptions = Arc::new(DescribeModule::open(state).expect("a metadata store"));
        let privacy = Arc::new(
            EnvironmentPrivacy::open(state, backup, Arc::clone(&delivery), descriptions)
                .expect("the privacy record"),
        );
        Self {
            _root: root,
            delivery,
            privacy,
            device_preview: NotificationPreviewKeyPair::generate().expect("a keypair"),
        }
    }

    /// A push destination to a paired phone.
    fn phone(&self) -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::new("phone").expect("an identifier"),
            destination: Destination::Push(Box::new(PushDestination {
                installation_id: InstallationId::new(Uuid::from_bytes([2; 16])),
                sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([3; 16])),
                preview_keys: PreviewKeys::only(*self.device_preview.public(), 1),
                previews_enabled: true,
                mailbox_key: Some(
                    *StoredEnvelopeKeyPair::generate()
                        .expect("a keypair")
                        .public(),
                ),
            })),
            rule: Some(DeliveryRule {
                name: "anything that wants a person".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(NOW),
        }
    }

    /// Configures `destination` and produces one notice for it.
    fn produce(&self, destination: &DestinationRecord) -> NotificationId {
        self.delivery.configure(destination).expect("a destination");
        let notice = Notice {
            event: EventKey::announcement(Some(session()), "attention.pending_approval/~abcdef", 1),
            alert: PushAlert::ApprovalWaiting,
            urgency: PushUrgency::Attention,
            rule: "attention.pending_approval".to_owned(),
            summary: "an approval is waiting".to_owned(),
            session_id: Some(session()),
            environment_id: None,
            observed_at_ms: TimestampMs::new(NOW),
            collapse_group: "a-session/attention.pending_approval".to_owned(),
            expires_at_ms: TimestampMs::new(NOW + DEFAULT_NOTIFICATION_LIFETIME_MS),
            audience: Audience::Sessions {
                sessions: vec![session()],
                at_ms: NOW,
            },
        };
        self.delivery
            .with(|producer| {
                let taken = notice.taken(1).expect("an event record");
                producer
                    .take(EventSource::Attention, "session-1", &[taken], 1, NOW)
                    .expect("a page");
                producer
                    .produce(
                        &notice,
                        std::slice::from_ref(destination),
                        &Granted,
                        &[kr_delivery::external::ContentLine {
                            session_id: Some(session()),
                            produced_at_ms: Some(NOW - 1_000),
                            text: "the build failed".to_owned(),
                        }],
                        NOW,
                    )
                    .expect("a decision");
                Ok(())
            })
            .expect("the producer");
        self.delivery
            .with(|producer| {
                Ok(producer
                    .journal()
                    .deliveries()
                    .expect("a read")
                    .into_iter()
                    .next()
                    .expect("one delivery")
                    .notification_id)
            })
            .expect("a read")
    }

    /// Reads the privacy record's generation from its file, apart from the module's own handle.
    fn recorded_generation(&self) -> i64 {
        rusqlite::Connection::open_with_flags(
            self._root.path().join(PRIVACY_RECORD),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("the privacy record")
        .query_row(
            "SELECT generation FROM privacy_record WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .expect("the record")
    }
}

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// Every recipient authority these tests ask about is the owner's, over the one session.
#[derive(Debug)]
struct Granted;

impl Granted {
    fn scope() -> RecipientScope {
        RecipientScope {
            viewer: ViewerScope::owner(),
            sessions: SessionSelector::These {
                session_ids: [session()].into_iter().collect(),
            },
            rights: [kr_protocol::rights::ActionRight::SessionView]
                .into_iter()
                .collect(),
            grant_id: kr_protocol::ids::GrantId::new(Uuid::from_bytes([9; 16])),
            recipient: kr_protocol::ids::DeviceId::new(Uuid::from_bytes([10; 16])),
            history_from_ms: 0,
        }
    }
}

impl RecipientAuthority for Granted {
    fn scope_for(&self, _rule: &DeliveryRule) -> Option<RecipientScope> {
        Some(Self::scope())
    }

    fn device_scope(&self, _destination: &DestinationRecord) -> Option<RecipientScope> {
        Some(Self::scope())
    }
}

/// A gate a double stops at: it says when something arrived there, and waits there until the test
/// lets it go.
#[derive(Debug)]
struct Gate {
    arrived: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    go: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Gate {
    /// A gate, the receiver that hears something arrive at it, and the sender that lets it go.
    fn new() -> (
        Self,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (arrived, arrival) = std::sync::mpsc::channel();
        let (go, going) = std::sync::mpsc::channel();
        (
            Self {
                arrived: Mutex::new(Some(arrived)),
                go: Mutex::new(going),
            },
            arrival,
            go,
        )
    }

    fn pass(&self) {
        if let Some(arrived) = self.arrived.lock().expect("not poisoned").take() {
            let _ = arrived.send(());
        }
        let _ = self.go.lock().expect("not poisoned").recv_timeout(PATIENCE);
    }
}

/// An external destination that holds each message on the wire at its gate, then takes it.
#[derive(Debug)]
struct HeldTransport {
    gate: Gate,
    sent: Mutex<Vec<ExternalMessage>>,
}

impl ExternalSender for HeldTransport {
    fn send(
        &self,
        _destination: &ExternalDestination,
        _credential: Option<&kr_protocol::delivery::DestinationSecret>,
        message: &ExternalMessage,
    ) -> ExternalOutcome {
        self.gate.pass();
        self.sent
            .lock()
            .expect("not poisoned")
            .push(message.clone());
        ExternalOutcome::Delivered
    }
}

/// A gateway that takes whatever it is sent, and remembers it.
#[derive(Debug, Default)]
struct Gateway {
    sent: Mutex<Vec<PushDeliveryRequest>>,
}

impl PushSender for Gateway {
    fn send(
        &self,
        _credential: &PushDeliveryCredential,
        request: &PushDeliveryRequest,
    ) -> SendOutcome {
        self.sent
            .lock()
            .expect("not poisoned")
            .push(request.clone());
        SendOutcome::Decided(Box::new(PushDeliveryAck {
            decided_at_ms: TimestampMs::new(NOW),
            notification_id: request.notification_id,
            state: PushDeliveryState::Queued,
            suppression: Nullable::null(),
        }))
    }
}

impl DeliveryStatus for Gateway {
    fn status(
        &self,
        _credential: &PushDeliveryCredential,
        _notification_id: NotificationId,
    ) -> StatusAnswer {
        StatusAnswer::Unanswered {
            detail: "this gateway answers no question".to_owned(),
        }
    }
}

/// A credential inside its renewal window, whose renewal waits at the gate: a renewal is a call to
/// the gateway, and a send is presented only after it.
#[derive(Debug)]
struct RenewingAtTheGate {
    gate: Gate,
}

fn credential(expires_at_ms: u64) -> PushDeliveryCredential {
    PushDeliveryCredential {
        expires_at_ms: TimestampMs::new(expires_at_ms),
        gateway_origin: kr_protocol::service::GatewayOrigin::new("https://reach.invalid")
            .expect("an origin"),
        installation_id: InstallationId::new(Uuid::from_bytes([2; 16])),
        issued_at_ms: TimestampMs::new(NOW - 1_000),
        revision: kr_protocol::ids::PushSenderRevision::new(1),
        secret: SecretBytes32::from_bytes([9; 32]),
        sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([3; 16])),
    }
}

impl SenderCredentials for RenewingAtTheGate {
    fn current(&self, _sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential> {
        // Two days left, inside section 16's seven-day renewal window.
        Some(credential(NOW + 2 * 24 * 60 * 60 * 1000))
    }

    fn renew(
        &self,
        _held: &PushDeliveryCredential,
    ) -> Result<PushDeliveryCredential, kr_delivery::DeliveryError> {
        self.gate.pass();
        Ok(credential(NOW + 30 * 24 * 60 * 60 * 1000))
    }
}

/// A credential store with a credential far from its renewal.
#[derive(Debug)]
struct Current;

impl SenderCredentials for Current {
    fn current(&self, _sender_record_id: PushSenderRecordId) -> Option<PushDeliveryCredential> {
        Some(credential(NOW + 30 * 24 * 60 * 60 * 1000))
    }

    fn renew(
        &self,
        held: &PushDeliveryCredential,
    ) -> Result<PushDeliveryCredential, kr_delivery::DeliveryError> {
        Ok(held.clone())
    }
}

/// An external destination that takes whatever it is sent at once.
#[derive(Debug)]
struct Taking;

impl ExternalSender for Taking {
    fn send(
        &self,
        _destination: &ExternalDestination,
        _credential: Option<&kr_protocol::delivery::DestinationSecret>,
        _message: &ExternalMessage,
    ) -> ExternalOutcome {
        ExternalOutcome::Delivered
    }
}

/// KR-REQ-24.27 and KR-REQ-24.28: a send on the wire when privacy mode is turned on is waited for.
/// The change is not recorded while the exchange it admitted is under way, and once the destination
/// has answered, the send is settled as having left, counted as nothing outstanding and listed as a
/// copy that left; the change is then recorded and the outbox fenced.
#[test]
fn kr_req_24_27_a_send_on_the_wire_is_waited_for_before_the_change_is_recorded() {
    let subsystems = Arc::new(Subsystems::open());
    let notification_id = subsystems.produce(&hook());
    let (gate, arrival, go) = Gate::new();
    let transport = Arc::new(HeldTransport {
        gate,
        sent: Mutex::new(Vec::new()),
    });

    // A pass presents the message and is held on the wire.
    let pass = std::thread::spawn({
        let subsystems = Arc::clone(&subsystems);
        let transport = Arc::clone(&transport);
        move || {
            subsystems
                .delivery
                .run_due(
                    &Gateway::default(),
                    &Gateway::default(),
                    &Current,
                    transport.as_ref(),
                    &Granted,
                    &|| NOW,
                )
                .expect("a pass")
        }
    });
    arrival
        .recv_timeout(PATIENCE)
        .expect("the message is on the wire");

    // Privacy mode is turned on meanwhile. It waits for the exchange, and records nothing yet.
    let (enabled, enabling) = std::sync::mpsc::channel();
    let turning = std::thread::spawn({
        let subsystems = Arc::clone(&subsystems);
        move || {
            let report = subsystems
                .privacy
                .enable(&[], TimestampMs::new(NOW + 10), &|write| write())
                .expect("privacy mode is turned on");
            let _ = enabled.send(());
            report
        }
    });
    assert!(
        enabling.recv_timeout(Duration::from_millis(500)).is_err(),
        "the change waits for the exchange on the wire"
    );
    assert_eq!(
        subsystems.recorded_generation(),
        0,
        "and is not recorded while it waits"
    );

    // The destination answers.
    go.send(()).expect("the gate is let go");
    assert_eq!(pass.join().expect("the pass ends"), 1);
    let report = turning.join().expect("the change ends");
    assert_eq!(subsystems.recorded_generation(), 1);
    assert_eq!(transport.sent.lock().expect("not poisoned").len(), 1);
    assert_eq!(
        delivery_state(&subsystems.delivery, notification_id),
        DeliveryState::Accepted,
        "the send that was on the wire settled as having left"
    );
    assert_eq!(outstanding(&report.to_wire(), "delivery"), 0);
    assert!(
        report
            .exported
            .iter()
            .any(|copy| copy.kind.contains("webhook")),
        "{:?}",
        report.exported
    );
    assert!(
        subsystems
            .delivery
            .with(|producer| Ok(producer.journal().is_fenced().expect("a read")))
            .expect("the delivery journal"),
        "the outbox is fenced once the change is recorded"
    );
}

/// KR-REQ-24.27: a pass of the attention store that is deciding an announcement holds the privacy
/// state from the moment it reads it to the end of the pass, so turning privacy mode on meanwhile
/// waits for it: nothing is recorded until the pass ends, and what the pass decided is stamped with
/// the state it read, the state before the change. The control: the same pass with no change
/// arriving is stamped the same.
#[test]
fn kr_req_24_27_a_change_of_privacy_mode_waits_for_the_pass_that_is_deciding_an_announcement() {
    for changes in [false, true] {
        let subsystems = Arc::new(Subsystems::open());
        let temp = kr_ipc::testing::TempHost::create();
        let attention = Arc::new(
            kr_controller::attention::AttentionModule::open(
                &temp.environment(),
                kr_ipc::identity::boot_identity().expect("a boot identity"),
            )
            .expect("the attention store opens"),
        );
        attention.attach_privacy(subsystems.privacy.state());
        let failure = kr_attention::SourceEvent::new(
            kr_attention::EventCursor::in_session(
                session(),
                kr_protocol::attention::AttentionSource::Receipts,
                1,
            ),
            TimestampMs::new(NOW),
            kr_attention::EventKind::CommandCompleted {
                session_id: session(),
                command: "make".to_owned(),
                exit_code: 2,
            },
        );
        let (arrived, release) = attention.pause_after_privacy_read();

        // The pass holds the state and has not decided.
        let deciding = std::thread::spawn({
            let attention = Arc::clone(&attention);
            move || attention.observe(&[failure])
        });
        arrived
            .recv_timeout(PATIENCE)
            .expect("the pass holds the state");

        // Privacy mode is turned on meanwhile. It waits for the pass, and records nothing yet.
        let turning = changes.then(|| {
            let (enabled, enabling) = std::sync::mpsc::channel();
            let turning = std::thread::spawn({
                let subsystems = Arc::clone(&subsystems);
                move || {
                    let report = subsystems
                        .privacy
                        .enable(&[], TimestampMs::new(NOW + 10), &|write| write())
                        .expect("privacy mode is turned on");
                    let _ = enabled.send(());
                    report
                }
            });
            assert!(
                enabling.recv_timeout(Duration::from_millis(500)).is_err(),
                "the change waits for the pass that is deciding"
            );
            assert_eq!(
                subsystems.recorded_generation(),
                0,
                "and is not recorded while it waits"
            );
            turning
        });

        release.send(()).expect("the pass goes on");
        deciding
            .join()
            .expect("the pass ends")
            .expect("the store records the failure");
        if let Some(turning) = turning {
            turning.join().expect("the change ends");
        }
        assert_eq!(
            subsystems.recorded_generation(),
            i64::from(changes),
            "changes {changes}"
        );
        let stamps = attention
            .take_for_delivery(|store, _| {
                store
                    .engine()
                    .expect("the store is this owner's")
                    .items()
                    .map(|item| item.decided_privacy)
                    .collect::<Vec<_>>()
            })
            .expect("the store is taken");
        assert_eq!(
            stamps,
            vec![Some(kr_attention::PrivacyStamp {
                generation: 0,
                private: false,
            })],
            "stamped with the state the pass read, changes {changes}"
        );
    }
}

/// KR-REQ-24.27: a send claimed before privacy mode is turned on and presented after it is taken
/// back rather than presented. The pass claims the delivery and renews the credential, which waits
/// on the gateway; privacy mode is turned on during that wait; and the send, admitted under the
/// generation before, is refused at the gate: the gateway never sees it, and it is settled as
/// cancelled with nothing left this host. The control is the same pass with privacy mode off,
/// which presents it.
#[test]
fn kr_req_24_27_a_send_claimed_before_the_boundary_and_presented_after_it_is_taken_back() {
    for private in [false, true] {
        let subsystems = Arc::new(Subsystems::open());
        let notification_id = subsystems.produce(&subsystems.phone());
        let (gate, arrival, go) = Gate::new();
        let credentials = Arc::new(RenewingAtTheGate { gate });
        let gateway = Arc::new(Gateway::default());
        let pass = std::thread::spawn({
            let subsystems = Arc::clone(&subsystems);
            let credentials = Arc::clone(&credentials);
            let gateway = Arc::clone(&gateway);
            move || {
                subsystems
                    .delivery
                    .run_due(
                        gateway.as_ref(),
                        gateway.as_ref(),
                        credentials.as_ref(),
                        &Taking,
                        &Granted,
                        &|| NOW,
                    )
                    .expect("a pass")
            }
        });
        arrival
            .recv_timeout(PATIENCE)
            .expect("the pass claimed the delivery and is renewing its credential");
        if private {
            subsystems
                .privacy
                .enable(&[], TimestampMs::new(NOW + 10), &|write| write())
                .expect("privacy mode is turned on");
        }
        go.send(()).expect("the renewal is let go");
        assert_eq!(pass.join().expect("the pass ends"), 1);
        let sent = gateway.sent.lock().expect("not poisoned").len();
        let state = delivery_state(&subsystems.delivery, notification_id);
        if private {
            assert_eq!(sent, 0, "the gateway never saw it");
            assert_eq!(state, DeliveryState::Cancelled);
            let report = subsystems.privacy.report_now(TimestampMs::new(NOW + 20));
            assert_eq!(outstanding(&report.to_wire(), "delivery"), 0);
            assert!(
                report.exported.is_empty(),
                "nothing left this host: {:?}",
                report.exported
            );
        } else {
            assert_eq!(sent, 1, "with privacy mode off it is presented");
            assert_ne!(state, DeliveryState::Cancelled);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// An approval pending in the session's broker
// ---------------------------------------------------------------------------------------------

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn binding() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([9; 16]))
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new(name).expect("valid")
}

/// The action target of an agent mutation on the suite's instance.
fn agent_target(worker: &Worker, environment_id: EnvironmentId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::some(worker.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::some(instance()),
        agent_binding_revision: Nullable::some(AgentBindingRevision::new(1)),
    }
}

/// A transport that answers at once and counts what it was asked to carry.
#[derive(Debug, Default)]
struct CountingUpstream {
    carried: std::sync::atomic::AtomicUsize,
}

impl UpstreamDispatch for CountingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        self.carried
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PendingTransmission::settled(Ok(UpstreamOutcome {
            upstream_request_id: None,
            turn_id: request.turn_id.clone(),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        })))
    }
}

/// Registers an agent instance in the session, with the evidence that it can answer approvals,
/// and binds the transport an answer goes out on.
fn register_agent(worker: &Worker, upstream: Arc<CountingUpstream>) {
    let broker = worker.service.broker();
    let process = ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
    broker
        .register_instance(
            instance(),
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                instance(),
                process.clone(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: instance(),
                    executable_digest: Digest256::from_bytes([3; 32]),
                    process,
                },
                Credential::from_bytes([9; 32]),
                true,
                TimestampMs::new(1),
            )),
        )
        .expect("the instance is registered");
    broker
        .bind_dispatch(instance(), upstream as Arc<dyn UpstreamDispatch>)
        .expect("the transport is bound");
}

fn approval_table() -> kr_protocol::gateway::DeclarativeTable {
    let mut table = kr_protocol::gateway::DeclarativeTable {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        table_version: kr_protocol::ids::MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: kr_protocol::gateway::NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        params_field: "params".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        entries: vec![kr_protocol::gateway::DeclarativeEntry {
            method: kr_protocol::ids::UpstreamMethod::new("session/request_permission")
                .expect("valid"),
            class: kr_protocol::gateway::NativeMethodClass::Mutation,
            expects_response: true,
            approval_option_field: Nullable::some("option_id".to_owned()),
            reverse: Nullable::null(),
        }],
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

/// Opens the gateway the session's approvals arrive on: the interpreter's grant, the evidence that
/// the instance answers approvals, the qualified table, the authenticated connection and the
/// transport an answer goes out on.
fn open_gateway(worker: &Worker, upstream: Arc<CountingUpstream>) {
    let broker = worker.service.broker();
    broker
        .bind_descriptor(
            binding(),
            instance(),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([
                BrokerGrant::UpstreamAction,
                BrokerGrant::ApprovalInterpreter,
            ]),
            Some(kr_protocol::broker::DecodingTrust {
                plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                publisher_id: PublisherId::new("kalareach").expect("valid"),
                package_digest: Digest256::from_bytes([5; 32]),
                methods: [
                    kr_protocol::ids::UpstreamMethod::new("session/request_permission")
                        .expect("valid"),
                ]
                .into_iter()
                .collect(),
                schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
                max_decisions: U64::new(4),
                may_encode_response: true,
                granted_at: TimestampMs::new(1),
            }),
            TimestampMs::new(1),
        )
        .expect("the binding carries the interpreter grant");
    broker
        .record_capability(kr_protocol::broker::InstanceCapabilityRecord {
            capability_id: capability("agent.approval"),
            capability_version: "1".to_owned(),
            application_instance_id: instance(),
            identity: kr_protocol::broker::InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(1),
            state: kr_protocol::broker::InstanceCapabilityState::QualifiedAvailable,
            source: kr_protocol::broker::InstanceEvidenceSource::HostProbe,
            invalidated_by: [kr_protocol::broker::InstanceInvalidation::BindingChanged]
                .into_iter()
                .collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        })
        .expect("the evidence is recorded");
    broker
        .pin_table(
            instance(),
            kr_worker::broker::PackageIdentity {
                plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                publisher_id: PublisherId::new("kalareach").expect("valid"),
                package_digest: Digest256::from_bytes([5; 32]),
            },
            approval_table(),
            kr_protocol::gateway::RichMethodTable {
                table_version: kr_protocol::ids::MethodTableVersion::new(1),
                upstream_protocol_version: "1".to_owned(),
                entries: vec![kr_protocol::gateway::RichMethodEntry {
                    method: kr_protocol::ids::UpstreamMethod::new("session/cancel").expect("valid"),
                    class: kr_protocol::gateway::NativeMethodClass::Mutation,
                    required_right: ActionRight::AgentCancel,
                    operation: Nullable::some(kr_protocol::gateway::RichOperation::TurnCancel),
                    provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
                }],
            },
        )
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(),
            &[9; 32],
            &ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900),
            &PluginId::new("kalareach.codex").expect("valid"),
            "1",
        )
        .expect("the native connection is authenticated");
    broker.bind_connection_dispatch(
        kr_protocol::ids::GatewayConnectionId::new(1),
        upstream as Arc<dyn UpstreamDispatch>,
    );
}

/// Offers one approval on the gateway, under the agent's own request identifier `native`, as a
/// decoder has given it meaning.
fn pending_approval(worker: &Worker, native: u64) -> kr_protocol::ids::PendingResourceId {
    let broker = worker.service.broker();
    let request = format!(r#"{{"id":{native},"method":"session/request_permission"}}"#);
    let opaque = broker
        .forward_native(
            kr_protocol::ids::GatewayConnectionId::new(1),
            request.as_bytes(),
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    broker
        .interpret(
            binding(),
            opaque.resource_id,
            kr_protocol::broker::DecodedProjection {
                schema_version: "kr-approval/1".to_owned(),
                summary: "the agent wants to write a file".to_owned(),
                decisions: vec![kr_protocol::broker::OfferedDecision {
                    option_id: "allow".to_owned(),
                    label: "Allow".to_owned(),
                }],
            },
            None,
            TimestampMs::new(3),
        )
        .expect("interpreted")
        .resource_id
}

/// Answers one pending approval at the session's socket, as the owner at this machine, and returns
/// the action and the principal its receipt is kept under, once the receipt says it applied.
async fn answer_approval(
    worker: &Worker,
    environment_id: EnvironmentId,
    resource_id: kr_protocol::ids::PendingResourceId,
) -> (ActionId, kr_protocol::ids::ActorId) {
    let mut client = worker.client().await;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    client
        .mutate(
            Method::AgentApprovalRespond,
            action_id,
            agent_target(worker, environment_id),
            &AgentApprovalRespondParams {
                target: AgentMutationTarget {
                    subject: subject(worker.session_id, instance()),
                    binding_revision: AgentBindingRevision::new(1),
                },
                resource_id,
                option_id: "allow".to_owned(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the approval is answered");
    let receipt: ActionReadResult = client
        .request(
            Method::ActionRead,
            &ActionReadParams {
                action_id,
                session_id: None,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the receipt reads")
        .to_typed()
        .expect("decodes");
    assert_eq!(receipt.receipt.state, ReceiptState::Applied);
    (action_id, receipt.receipt.actor_id)
}

/// Whether one action's receipt still holds the envelope its caller sent, and what it came to.
fn receipt_body(
    worker: &Worker,
    actor_id: &kr_protocol::ids::ActorId,
    action_id: ActionId,
) -> (bool, bool) {
    let mut session = worker.runtime.session();
    let journal = session.journal_mut().expect("the session's journal");
    (
        journal
            .read_intent(actor_id, action_id)
            .expect("reads")
            .is_some(),
        journal
            .read_result(actor_id, action_id)
            .expect("reads")
            .is_some(),
    )
}
