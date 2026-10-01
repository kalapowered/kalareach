//! Retained results read under the reader's present authority, through the control daemon.
//!
//! One real daemon on the loopback network, started the way a host starts one, and a real worker it
//! adopts: the worker's own service on its own socket, with its journal, its spool and its shell,
//! run in this process as the privacy and attention suites run one. A paired device reaches the
//! daemon over the network and submits the action identifiers it is given, so a test can present
//! the same action again, and read it by its identifier, as a device that lost its reply does.
//!
//! What each test asserts is read from the daemon's answer to a device, and from the worker's own
//! ledger and journal where a test says what was kept: a device is shown what its present authority
//! reaches of what an action produced, and what the worker keeps is not changed by who reads it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.49 | the `kr_req_10_49_` tests here |
//! | KR-REQ-23.34 | the `kr_req_23_34_` tests here |

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_controller::registry::{Registry, WorkerRecord};
use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AuthorityRevision, BuildId, ConnectionId, ControllerGeneration, EnvironmentId,
    SessionEpoch, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionCancelParams, QuestionCreateParams,
    QuestionKind, QuestionResolveResult, QuestionState,
};
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, ReceiptState};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

use net_support::{Device, Host, RawDevice, pair_with, proposal};

/// How long a test waits for the daemon to reach the worker.
const PATIENCE: Duration = Duration::from_secs(60);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn now() -> TimestampMs {
    kr_ipc::now_ms()
}

// ---------------------------------------------------------------------------------------------
// A worker in this process, and the daemon that adopts it
// ---------------------------------------------------------------------------------------------

/// A worker for one session, in this process, on an environment tree a daemon of it serves.
struct Worker {
    service: Arc<WorkerService>,
    session_id: SessionId,
    _runtime: Arc<SessionRuntime>,
}

impl Worker {
    /// Starts a worker for one session and records it the way a daemon records one it adopts: a
    /// registry row and a published descriptor. A daemon started afterwards reaches it at its
    /// start. No daemon may be running on the tree while this runs.
    async fn start(tree: &kr_ipc::testing::TempHost) -> Self {
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
        let display_number = DisplayNumber::new(1);
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
        let journal_path = environment.journal_database(session_id);
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number,
            shell: kr_worker::testing::posix_script("exec cat"),
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
            service,
            session_id,
            _runtime: runtime,
        }
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
    fn ask(&self, request: &str) -> Question {
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
                    question: format!("Publish the release ({request})?"),
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

    /// What the worker's ledger holds of a question, whatever any caller was shown.
    fn held(&self, question: &Question) -> Question {
        self.service
            .questions()
            .question(question.question_id)
            .expect("the question is in the ledger")
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
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let stopped = host.shut_down().await;
        let worker = Worker::start(stopped.tree()).await;
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

    async fn stop(self) {
        self.host.stop().await;
    }

    fn environment_id(&self) -> EnvironmentId {
        self.host.environment_id
    }

    fn target(&self) -> ActionTarget {
        self.worker.target(self.environment_id())
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

    /// Pairs a device under `proposal` and connects it as one that submits the action identifiers
    /// it is given.
    async fn device(&self, proposal: kr_protocol::pairing::ProposedGrant) -> Paired {
        let device = Device::create().await;
        let record = pair_with(&self.host, &device, &self.owner, proposal).await;
        let connection = RawDevice::connect(&self.host, &device, &record).await;
        Paired {
            _device: device,
            _record: record,
            connection,
        }
    }
}

struct Paired {
    _device: Device,
    _record: DeviceRecord,
    connection: RawDevice,
}

/// A grant carrying exactly the rights named, whose history reaches back to `bound_ms`.
fn from(actions: &[ActionRight], bound_ms: u64) -> kr_protocol::pairing::ProposedGrant {
    let mut proposal = proposal(actions);
    proposal.history.lower_bound_ms = Nullable::some(TimestampMs::new(bound_ms));
    proposal
}

fn yes(environment: &Environment, question: &Question) -> QuestionAnswerParams {
    QuestionAnswerParams {
        session_id: environment.worker.session_id,
        question_id: question.question_id,
        expected_revision: question.revision,
        answer: QuestionAnswer::Decision { decided: true },
    }
}

fn resolved(value: ParamsValue) -> QuestionResolveResult {
    value.to_typed().expect("a resolution result")
}

fn read_by_id(action_id: ActionId) -> ActionReadParams {
    ActionReadParams {
        action_id,
        session_id: None,
    }
}

// ---------------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.49: a device that may answer is shown the answer's question only if it may view the
/// session, and may answer only a question its history reaches. One that views and reaches it is
/// shown the question whole; one that may respond and not view is told the state and none of the
/// question, and still answers; one whose history begins after the question was asked is refused
/// as for a question the session does not hold, and the question is left pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_10_49_a_device_is_shown_a_question_it_answers_as_far_as_its_authority_reaches() {
    let environment = Environment::start().await;
    let viewing = environment.worker.ask("viewing");
    let responding = environment.worker.ask("responding");
    let before = environment.worker.ask("before-the-bound");
    let rights = [ActionRight::SessionView, ActionRight::QuestionRespond];

    // Reaches it and views the session.
    let viewer = environment.device(from(&rights, 1)).await;
    let answered = resolved(
        viewer
            .connection
            .mutate(
                Method::QuestionAnswer,
                ActionId::new(kr_ipc::new_uuid()),
                environment.target(),
                &yes(&environment, &viewing),
            )
            .await
            .expect("the device answers"),
    );
    assert_eq!(answered.state, QuestionState::Answered);
    let shown = answered.question().expect("it is shown the question");
    assert_eq!(shown.question, viewing.question);
    assert_eq!(
        shown.answer.as_ref().map(|record| record.answer.clone()),
        Some(QuestionAnswer::Decision { decided: true })
    );

    // May respond, and not view.
    let responder = environment
        .device(from(&[ActionRight::QuestionRespond], 1))
        .await;
    let answered = resolved(
        responder
            .connection
            .mutate(
                Method::QuestionAnswer,
                ActionId::new(kr_ipc::new_uuid()),
                environment.target(),
                &yes(&environment, &responding),
            )
            .await
            .expect("a device that may respond answers"),
    );
    assert_eq!(answered.state, QuestionState::Answered);
    assert_eq!(answered.question_id, responding.question_id);
    assert_eq!(answered.question(), None);
    assert!(
        !serde_json::to_string(&answered)
            .expect("encodes")
            .contains("Publish the release")
    );
    assert_eq!(
        environment.worker.held(&responding).state,
        QuestionState::Answered,
        "what it answered is held whole"
    );

    // Views, and its history begins after the question.
    let late = environment
        .device(from(&rights, before.created_at_ms.get() + 60_000))
        .await;
    let refused = late
        .connection
        .mutate(
            Method::QuestionAnswer,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &yes(&environment, &before),
        )
        .await
        .expect_err("a question before the device's bound is not its to answer");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
    assert!(
        !refused.message.contains("Publish the release"),
        "{refused}"
    );
    assert_eq!(
        environment.worker.held(&before).state,
        QuestionState::Pending
    );
    let cancelled = late
        .connection
        .mutate(
            Method::QuestionCancel,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &QuestionCancelParams {
                session_id: environment.worker.session_id,
                question_id: before.question_id,
                expected_revision: before.revision,
            },
        )
        .await
        .expect_err("nor to cancel");
    assert_eq!(cancelled.code, ErrorCode::PermissionDenied, "{cancelled}");
    assert_eq!(
        environment.worker.held(&before).state,
        QuestionState::Pending
    );
    environment.stop().await;
}

/// KR-REQ-23.34: `action.read` by the action's identifier is decided over the session the action
/// was performed on: a device that may view it and whose history reaches the question reads the
/// receipt and the question, and a device that may respond and not view is refused, and so is a
/// retry of its answer, which is also a read of the receipt. A device is told nothing of what its
/// action produced by presenting it again once the right to view the session is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_34_an_action_is_read_by_its_identifier_only_under_view_authority_over_its_session()
 {
    let environment = Environment::start().await;
    let rights = [ActionRight::SessionView, ActionRight::QuestionRespond];

    for views in [true, false] {
        let question = environment
            .worker
            .ask(if views { "read-viewing" } else { "read-blind" });
        let device = environment
            .device(from(
                if views {
                    &rights
                } else {
                    &[ActionRight::QuestionRespond]
                },
                1,
            ))
            .await;
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let params = yes(&environment, &question);
        let first = resolved(
            device
                .connection
                .mutate(
                    Method::QuestionAnswer,
                    action_id,
                    environment.target(),
                    &params,
                )
                .await
                .expect("answered"),
        );
        assert_eq!(first.question().is_some(), views, "the first answer");

        let read = device
            .connection
            .read::<_>(Method::ActionRead, &read_by_id(action_id))
            .await;
        let retried = device
            .connection
            .mutate(
                Method::QuestionAnswer,
                action_id,
                environment.target(),
                &params,
            )
            .await;
        if views {
            let read: ActionReadResult = read
                .expect("a device that may view reads its receipt")
                .to_typed()
                .expect("a receipt");
            assert_eq!(read.receipt.state, ReceiptState::Applied);
            let result = resolved(read.result.0.expect("the result is kept"));
            assert_eq!(result.question(), first.question());
            let again = resolved(retried.expect("a retry is answered from the receipt"));
            assert_eq!(again.question(), first.question());
        } else {
            let denied = read.expect_err("a device that may not view is not told what it did");
            assert_eq!(denied.code, ErrorCode::PermissionDenied, "{denied}");
            let denied = retried.expect_err("nor by presenting it again");
            assert_eq!(denied.code, ErrorCode::PermissionDenied, "{denied}");
        }
        device.connection.close();
    }
    environment.stop().await;
}
