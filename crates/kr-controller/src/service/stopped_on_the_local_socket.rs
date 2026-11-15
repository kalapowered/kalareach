//! A control daemon stopped by a request on its local socket: the gate it closes, the creates it
//! waits for, the answer it writes and the stop that follows the answer, through the daemon's own
//! door and a real local connection.
//!
//! The model is the specification's: local peer credentials prove an OS identity, and code that
//! runs as the host's account can end the daemon with the platform's own tools. The request is
//! served on the account's own local socket and asks for the right to manage the host; the daemon
//! knows that a stop was requested there, and no more.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::paths::Endpoint;
#[cfg(unix)]
use kr_protocol::envelope::ControlFrame;
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActorId, BuildId, EnvironmentId};
use kr_protocol::local::{BridgeOrigin, LocalClientKind};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};
use kr_protocol::update::{
    HandoverStep, HostStopParams, HostStopResult, HostUpdateHandoverParams, ReleaseName,
};

use crate::service::Controller;

use super::host::{Handover, StopCause};
use super::the_fence_at_every_effect::{accepted, admitted, daemon, mutation_of, refusal};

/// How long a wait for something that is going to happen is given. A bound on a hang: nothing is
/// decided by how long the daemon takes.
const LIVENESS: Duration = Duration::from_secs(60);

/// How long a case lets something that must not happen have to happen. A case that fails on it
/// fails because the daemon did what it must not; one that passes on it proves nothing by itself,
/// and is paired with the condition that releases what it waited behind.
const NOT_WITHIN: Duration = Duration::from_millis(300);

/// The words a stop requested on the local socket answers a step that would keep the daemon.
const ASKED_TO_STOP: &str = "asked to stop on its local socket";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn target() -> ReleaseName {
    ReleaseName::new("0.2.0+4254aa6e62e5").expect("a release")
}

/// A daemon serving its local endpoint in this process, over a tree of its own.
struct Serving {
    controller: Arc<Controller>,
    endpoint: Endpoint,
    serving: tokio::task::JoinHandle<crate::error::Result<()>>,
    /// Declared last: the fields drop in the order of their declaration, and the daemon's files are
    /// in this tree.
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Starts a daemon whose connections the listener `bind` makes.
async fn serving_on(bind: impl FnOnce(&Endpoint) -> Listener) -> Serving {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = Controller::start(super::a_floor_owed_its_record::setup(&temp))
        .await
        .expect("the daemon starts");
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let listener = bind(&endpoint);
    let serving = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    Serving {
        temp,
        controller,
        endpoint,
        serving,
    }
}

async fn serving() -> Serving {
    serving_on(|endpoint| Listener::bind(endpoint).expect("binds the endpoint")).await
}

impl Serving {
    fn environment_id(&self) -> EnvironmentId {
        self.temp.environment_id()
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the daemon")
    }

    /// Whether the daemon has been told to stop for a stop requested on its local socket.
    async fn is_told_to_stop(&self) -> bool {
        tokio::time::timeout(Duration::ZERO, self.controller.stop_requested())
            .await
            .is_ok()
    }

    /// Waits until the daemon has been told to stop for a stop requested on its local socket.
    async fn told_to_stop(&self) {
        tokio::time::timeout(LIVENESS, self.controller.stop_requested())
            .await
            .expect("the daemon is told to stop");
    }

    /// Waits until the gate refuses a create: the request that closes it has begun.
    async fn until_the_gate_is_closed(&self) {
        let deadline = std::time::Instant::now() + LIVENESS;
        while self.controller.handover.admit().is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "the stop did not close the gate"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// Asks the daemon at `endpoint` to stop, or for its launch alone, on a connection of its own.
async fn ask(
    endpoint: Endpoint,
    environment_id: EnvironmentId,
    launch_only: bool,
) -> Result<HostStopResult, ProtocolError> {
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the daemon");
    asked_on(&mut client, environment_id, launch_only).await
}

/// The same, on a connection that is already open.
async fn asked_on(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    launch_only: bool,
) -> Result<HostStopResult, ProtocolError> {
    client
        .mutate(
            Method::HostStop,
            ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget::environment(environment_id),
            &HostStopParams { launch_only },
        )
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("decodes"))
}

/// A create, which the gate decides on before anything is launched.
fn a_create(environment_id: EnvironmentId) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

/// A create sent to the daemon, and what it answers.
async fn create_on(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
) -> Result<ParamsValue, ProtocolError> {
    client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget::environment(environment_id),
            &a_create(environment_id),
        )
        .await
        .expect("the call reaches the daemon")
}

/// A request for a stop that does not come over the daemon's own local socket, or that a bridge
/// carried, is refused and the daemon goes on: nothing is stopped, the gate is open, and the daemon
/// is not told to stop. The control: the same request from the local socket is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_that_did_not_come_on_the_local_socket_is_refused_and_the_daemon_stays() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let mutation = mutation_of(
        &temp,
        Method::HostStop,
        ParamsValue::from_typed(&HostStopParams { launch_only: false }).expect("encodes"),
    );
    let stop = |actor: ActorId, origin: Option<BridgeOrigin>| {
        let controller = Arc::clone(&controller);
        let mutation = mutation.clone();
        async move {
            controller
                .write_method(
                    &actor,
                    &mutation,
                    Method::HostStop,
                    connection_id,
                    origin,
                    Some(accepted(&controller)),
                    Some(captured),
                )
                .await
                .into_answer_for_test()
        }
    };

    let from_a_bridge = stop(
        actor_id.clone(),
        Some(BridgeOrigin {
            environment_id: EnvironmentId::new(Uuid::from_bytes([0x0a; 16])),
            ingress: kr_protocol::actor::ActorIngress::LocalIpc,
            clipboard_writes: false,
        }),
    )
    .await;
    let refused = refusal(&from_a_bridge).expect("a stop that a bridge carried is refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("process bridge"), "{refused:?}");

    let from_another_actor = stop(ActorId::new("device:test").expect("an actor"), None).await;
    let refused = refusal(&from_another_actor).expect("a stop from another actor is refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("did not arrive there"),
        "{refused:?}"
    );

    drop(
        controller
            .handover
            .admit()
            .expect("the gate is open: nothing was stopped"),
    );
    assert!(
        tokio::time::timeout(Duration::ZERO, controller.stop_requested())
            .await
            .is_err(),
        "the daemon was not told to stop"
    );

    // The control: from the local socket, with no origin, the stop is taken, and the gate closes.
    let taken = stop(actor_id, None).await;
    assert!(
        refusal(&taken).is_none(),
        "a stop from the local socket is taken: {taken:?}"
    );
    assert!(
        controller.handover.admit().is_err(),
        "the stop closed the gate"
    );
}

/// A real helper that declares a bridge's origin is refused over the real socket, and the daemon
/// stays; the control is a client that declares none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_helper_that_declares_a_bridges_origin_is_refused_a_stop_over_the_socket() {
    let daemon = serving().await;
    let mut helper = LocalClient::connect_for_bridge(
        &daemon.endpoint,
        build(),
        BridgeOrigin {
            environment_id: EnvironmentId::new(Uuid::from_bytes([0x0a; 16])),
            ingress: kr_protocol::actor::ActorIngress::LocalIpc,
            clipboard_writes: false,
        },
    )
    .await
    .expect("the helper reaches the daemon");
    let refused = asked_on(&mut helper, daemon.environment_id(), false)
        .await
        .expect_err("a stop that a bridge carried is refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        daemon.controller.handover.admit().is_ok(),
        "the gate is open: nothing was stopped"
    );
    // A round trip on a connection of its own: the refusal's answer has been written and anything
    // the daemon was going to do after it has been done.
    asked_on(&mut daemon.client().await, daemon.environment_id(), true)
        .await
        .expect("the launch is answered");
    assert!(!daemon.is_told_to_stop().await, "the daemon stays");

    // The control: a client that declares no origin is taken.
    ask(daemon.endpoint.clone(), daemon.environment_id(), false)
        .await
        .expect("a stop from the local socket is taken");
    daemon.told_to_stop().await;
}

/// A stop closes the gate before it waits and holds it while it does: a create under way is waited
/// for, so the answer does not come while it is, a create that arrives meanwhile is refused with the
/// stop's own words and no release named, and the answer comes, counting nothing unsettled, once the
/// create has settled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_waits_for_the_creates_under_way_and_refuses_new_ones_with_its_own_words() {
    let daemon = serving().await;
    let under_way = daemon
        .controller
        .handover
        .admit()
        .expect("a create is under way");
    let mut asking = tokio::spawn(ask(daemon.endpoint.clone(), daemon.environment_id(), false));
    daemon.until_the_gate_is_closed().await;

    let refused = daemon
        .controller
        .handover
        .admit()
        .err()
        .expect("the gate is closed");
    assert_eq!(refused.code(), ErrorCode::EnvironmentUnavailable);
    assert!(refused.to_string().contains(ASKED_TO_STOP), "{refused}");
    assert!(!refused.to_string().contains("release"), "{refused}");
    // The same words reach a create over the socket.
    let over_the_socket = create_on(&mut daemon.client().await, daemon.environment_id())
        .await
        .expect_err("no session starts while the daemon stops");
    assert_eq!(over_the_socket.code, ErrorCode::EnvironmentUnavailable);
    assert!(
        over_the_socket.message.contains(ASKED_TO_STOP),
        "{over_the_socket:?}"
    );
    assert!(!over_the_socket.message.contains("release"));

    // The create is under way, so the stop does not answer.
    assert!(
        tokio::time::timeout(NOT_WITHIN, &mut asking).await.is_err(),
        "the stop answered while a create was under way"
    );
    drop(under_way);
    let answered = tokio::time::timeout(LIVENESS, asking)
        .await
        .expect("the stop answers once the create has settled")
        .expect("the task ends")
        .expect("the stop is taken");
    assert_eq!(answered.pid.get(), u64::from(std::process::id()));
    assert_eq!(answered.unsettled.get(), 0, "the create settled");
    daemon.told_to_stop().await;
}

/// The gate's own decisions while it is closed for a stop: an update's `prepare`, `resume` and
/// `stop`, and the end of an attempt, leave it closed and answer that the daemon is stopping in the
/// stop's words, and a create is refused with them. An attempt that was open when the stop came is
/// over, whatever it was waiting for; the control is the gate of an update, which opens again.
#[test]
fn a_gate_closed_for_a_stop_stays_closed_and_an_updates_steps_meet_the_stops_words() {
    let handover = Handover::default();
    let under_way = handover.admit().expect("a create is under way");
    let attempt = handover
        .close(&target(), Duration::from_secs(300), || Ok(()))
        .expect("an attempt begins");
    handover.begin_stop();

    let stops_words = |refused: crate::error::ControllerError| {
        assert_eq!(refused.code(), ErrorCode::EnvironmentUnavailable);
        assert!(refused.to_string().contains(ASKED_TO_STOP), "{refused}");
        assert!(!refused.to_string().contains("update"), "{refused}");
    };
    stops_words(
        handover
            .close(&target(), Duration::from_secs(300), || Ok(()))
            .expect_err("a daemon that stops does not prepare"),
    );
    stops_words(
        handover
            .resume(None, || Ok(()))
            .expect_err("a daemon that stops does not resume"),
    );
    stops_words(
        handover
            .resume(Some(attempt), || Ok(()))
            .expect_err("a daemon that stops does not resume an attempt"),
    );
    stops_words(
        handover
            .stop(Some(attempt), || Ok(()))
            .expect_err("an update's stop does not end the daemon that stops"),
    );
    stops_words(
        handover
            .admit()
            .err()
            .expect("a create is refused while the gate is closed for a stop"),
    );
    assert!(
        !handover.is_current(attempt),
        "the attempt that was open is over"
    );
    assert_eq!(
        handover.end(attempt),
        Some(StopCause::Request),
        "the end of an attempt leaves the gate closed and says why"
    );
    assert!(
        handover.admit().is_err(),
        "the end of an attempt leaves the gate closed"
    );
    handover.begin_stop();
    assert!(handover.admit().is_err(), "a second stop leaves it closed");
    drop(under_way);

    // The control: a gate an update closed opens again at the end of its attempt, and is closed
    // for the update's own words.
    let update = Handover::default();
    let attempt = update
        .close(&target(), Duration::from_secs(300), || Ok(()))
        .expect("an attempt begins");
    let refused = update.admit().err().expect("the gate is closed");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(refused.to_string().contains("making way for release"));
    assert_eq!(update.end(attempt), None, "an update's gate opens");
    drop(update.admit().expect("the gate is open again"));
}

/// A stop that meets an open attempt of an update is taken, and the updater that comes back to its
/// attempt, as an older release's `kr` does, is answered in the stop's words, whatever step it
/// sends: nothing reopens the gate or ends the daemon for the update.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_that_meets_an_open_attempt_is_taken_and_the_updater_meets_the_stops_words() {
    let daemon = serving().await;
    let mut updater = daemon.client().await;
    let step = |step: HandoverStep, attempt: Option<Uuid>| HostUpdateHandoverParams {
        step,
        target: target(),
        attempt: Nullable(attempt),
    };
    let prepared: kr_protocol::update::HostUpdateHandoverResult = updater
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget::environment(daemon.environment_id()),
            &step(HandoverStep::Prepare, None),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the daemon prepares")
        .to_typed()
        .expect("decodes");
    let attempt = prepared.attempt.0.expect("the attempt it began");

    ask(daemon.endpoint.clone(), daemon.environment_id(), false)
        .await
        .expect("a stop that meets an open attempt is taken");
    daemon.told_to_stop().await;

    for (what, params) in [
        ("resume", step(HandoverStep::Resume, Some(attempt))),
        ("stop", step(HandoverStep::Stop, Some(attempt))),
        ("prepare", step(HandoverStep::Prepare, None)),
    ] {
        let refused = updater
            .mutate(
                Method::HostUpdateHandover,
                ActionId::new(kr_ipc::new_uuid()),
                kr_protocol::envelope::ActionTarget::environment(daemon.environment_id()),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect_err("the update's step is refused");
        assert_eq!(refused.code, ErrorCode::EnvironmentUnavailable, "{what}");
        assert!(
            refused.message.contains(ASKED_TO_STOP),
            "{what}: {refused:?}"
        );
    }
}

/// A `prepare` that waits for its creates when a stop comes is answered in the stop's words: the
/// stop ended its attempt and closed the gate for good, so neither "the attempt ended while it
/// waited" nor "the gate is open again" is true of it. The control is the same `prepare` with no
/// stop, which is answered as prepared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prepare_that_waits_when_the_stop_comes_is_answered_in_the_stops_words() {
    let daemon = serving().await;
    let preparing = |daemon: &Serving| {
        let endpoint = daemon.endpoint.clone();
        let environment_id = daemon.environment_id();
        let params = HostUpdateHandoverParams {
            step: HandoverStep::Prepare,
            target: target(),
            attempt: Nullable(None),
        };
        tokio::spawn(async move {
            let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("reaches the daemon");
            client
                .mutate(
                    Method::HostUpdateHandover,
                    ActionId::new(kr_ipc::new_uuid()),
                    kr_protocol::envelope::ActionTarget::environment(environment_id),
                    &params,
                )
                .await
                .expect("the call reaches the daemon")
        })
    };

    // The control: nothing under way and no stop, and the daemon is prepared.
    let prepared = tokio::time::timeout(LIVENESS, preparing(&daemon))
        .await
        .expect("the prepare answers")
        .expect("the task ends");
    assert!(prepared.is_ok(), "{prepared:?}");
    let attempt = prepared
        .expect("prepared")
        .to_typed::<kr_protocol::update::HostUpdateHandoverResult>()
        .expect("decodes")
        .attempt
        .0
        .expect("the attempt");
    daemon
        .controller
        .handover
        .resume(Some(attempt))
        .expect("the control attempt ends");

    // A create is under way, so the prepare waits; the stop comes while it does.
    let under_way = daemon
        .controller
        .handover
        .admit()
        .expect("a create is under way");
    let preparing = preparing(&daemon);
    daemon.until_the_gate_is_closed().await;
    let asking = tokio::spawn(ask(daemon.endpoint.clone(), daemon.environment_id(), false));
    let deadline = std::time::Instant::now() + LIVENESS;
    while !daemon
        .controller
        .handover
        .admit()
        .err()
        .is_some_and(|refused| refused.to_string().contains(ASKED_TO_STOP))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the stop did not close the gate"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop(under_way);

    let refused = tokio::time::timeout(LIVENESS, preparing)
        .await
        .expect("the prepare answers once the create has settled")
        .expect("the task ends")
        .expect_err("a prepare that a stop overtook is refused");
    assert_eq!(refused.code, ErrorCode::EnvironmentUnavailable);
    assert!(refused.message.contains(ASKED_TO_STOP), "{refused:?}");
    assert!(!refused.message.contains("ended while"), "{refused:?}");
    assert!(!refused.message.contains("open again"), "{refused:?}");
    tokio::time::timeout(LIVENESS, asking)
        .await
        .expect("the stop answers")
        .expect("the task ends")
        .expect("the stop is taken");
    daemon.told_to_stop().await;
}

/// The daemon is not told to stop until the answer to the stop has been written: the answer is
/// held at the moment before its write, and nothing has stopped the daemon, and then the write goes
/// on and does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_is_not_told_to_stop_before_its_answer_is_written() {
    let daemon = serving().await;
    let (arrived, release) = daemon.controller.pause_before_a_stop_answer_is_written();
    let mut asking = tokio::spawn(ask(daemon.endpoint.clone(), daemon.environment_id(), false));
    tokio::time::timeout(LIVENESS, arrived)
        .await
        .expect("the stop's answer arrives at its write")
        .expect("the daemon is there");

    assert!(
        !daemon.is_told_to_stop().await,
        "the daemon was told to stop before its answer was written"
    );
    assert!(
        tokio::time::timeout(NOT_WITHIN, &mut asking).await.is_err(),
        "the client has the answer while its write is held"
    );
    release.send(()).expect("the write is let go");
    tokio::time::timeout(LIVENESS, asking)
        .await
        .expect("the answer is written")
        .expect("the task ends")
        .expect("the stop is taken");
    daemon.told_to_stop().await;
}

/// An answer written during another request's wait does not stop the daemon: a request for the
/// launch alone, and a create refused in the stop's words, are answered while the stop waits for a
/// create under way, and the daemon is told to stop when the stop's answer has been written and not
/// before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_answer_to_another_request_during_the_wait_does_not_stop_the_daemon() {
    let daemon = serving().await;
    let under_way = daemon
        .controller
        .handover
        .admit()
        .expect("a create is under way");
    let asking = tokio::spawn(ask(daemon.endpoint.clone(), daemon.environment_id(), false));
    daemon.until_the_gate_is_closed().await;

    let mut other = daemon.client().await;
    let launch = asked_on(&mut other, daemon.environment_id(), true)
        .await
        .expect("the launch is answered during the wait");
    assert_eq!(launch.unsettled.get(), 0, "it counts nothing");
    create_on(&mut other, daemon.environment_id())
        .await
        .expect_err("a create is refused during the wait");
    // The answers above have been written, and the loop that wrote them has gone on to this one.
    asked_on(&mut other, daemon.environment_id(), true)
        .await
        .expect("the launch is answered again");
    assert!(
        !daemon.is_told_to_stop().await,
        "an answer written during the wait stopped the daemon"
    );

    drop(under_way);
    tokio::time::timeout(LIVENESS, asking)
        .await
        .expect("the stop answers once the create has settled")
        .expect("the task ends")
        .expect("the stop is taken");
    daemon.told_to_stop().await;
}

/// A request for the launch alone stops nothing: the gate stays open, nothing is counted, and the
/// daemon is not told to stop however often it is asked. It answers how the daemon was started: its
/// arguments, the variables that decide where it keeps what it keeps, and its working directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_for_the_launch_alone_stops_nothing_and_says_how_the_daemon_was_started() {
    let daemon = serving().await;
    let mut client = daemon.client().await;
    for _ in 0..2 {
        let answered = asked_on(&mut client, daemon.environment_id(), true)
            .await
            .expect("the launch is answered");
        assert_eq!(answered.pid.get(), u64::from(std::process::id()));
        assert_eq!(answered.unsettled.get(), 0);
        let launch = answered
            .launch
            .0
            .expect("the daemon can say how it started");
        assert_eq!(
            launch.arguments,
            std::env::args().skip(1).collect::<Vec<_>>()
        );
        assert_eq!(
            std::path::PathBuf::from(&launch.directory),
            std::env::current_dir().expect("this process's directory")
        );
        let names: Vec<&str> = launch
            .variables
            .iter()
            .map(|variable| variable.name.as_str())
            .collect();
        let expected: Vec<&str> = kr_protocol::hostinfo::configuration::path_variables().collect();
        assert_eq!(names, expected);
        for variable in &launch.variables {
            assert_eq!(
                variable.value.0,
                std::env::var(&variable.name).ok(),
                "{} is as the process has it",
                variable.name
            );
        }
    }
    drop(
        daemon
            .controller
            .handover
            .admit()
            .expect("the gate stays open"),
    );
    assert!(!daemon.is_told_to_stop().await, "nothing was stopped");
}

/// KR-REQ-09.09, 09.12 and 26.16: a host that owes a fence can still be stopped, and the answer,
/// told under the fence like any write's, is withheld as an unknown outcome while the daemon stops all the same; a request for the
/// launch alone is withheld the same way and stops nothing. The control: a method of the list the
/// fence holds by name is still refused for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_an_owed_fence_the_answer_is_withheld_and_the_daemon_stops_all_the_same() {
    let daemon = serving().await;
    daemon.controller.hold_fence(true);

    let held = daemon
        .client()
        .await
        .mutate(
            Method::HostUpdateHandover,
            ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget::environment(daemon.environment_id()),
            &HostUpdateHandoverParams {
                step: HandoverStep::Prepare,
                target: target(),
                attempt: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a method the fence holds is refused for it");
    assert_eq!(held.code, ErrorCode::PermissionDenied, "{held:?}");
    assert!(held.message.contains("fence"), "{held:?}");

    let launch = ask(daemon.endpoint.clone(), daemon.environment_id(), true)
        .await
        .expect_err("the launch is withheld under the fence");
    assert_eq!(launch.code, ErrorCode::OutcomeUnknown, "{launch:?}");
    // A round trip on a connection of its own has finished the launch's request.
    ask(daemon.endpoint.clone(), daemon.environment_id(), true)
        .await
        .expect_err("withheld again");
    assert!(
        !daemon.is_told_to_stop().await,
        "a request for the launch alone stopped the daemon"
    );

    let stopped = ask(daemon.endpoint.clone(), daemon.environment_id(), false)
        .await
        .expect_err("the stop's answer is withheld under the fence");
    assert_eq!(stopped.code, ErrorCode::OutcomeUnknown, "{stopped:?}");
    daemon.told_to_stop().await;
}

/// A client that stops reading does not keep the daemon from stopping: the answer's write waits for
/// the peer for its bound and then ends the connection, and the daemon is told to stop when it has.
///
/// The connection is given a send buffer of a few bytes and the answer is padded to many times
/// that, so that the answer cannot be taken whole by a client that reads nothing, whatever the
/// platform's own accounting of a buffer: the write has to wait for the client, and nothing but its
/// bound ends the wait.
///
/// It runs on Unix alone, where a listener can be given a send buffer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stops_reading_does_not_keep_the_daemon_from_stopping() {
    let daemon =
        serving_on(|endpoint| Listener::bind_with_send_buffer(endpoint, 1).expect("binds")).await;
    // Nothing is written unasked, and the answer is written under a short bound.
    let hour = Duration::from_secs(3_600);
    daemon
        .controller
        .pace_local_connections(hour, hour, Duration::from_millis(200));
    daemon.controller.pad_the_stop_answer(64 * 1024);
    let mut client = daemon.client().await;
    let stop = client
        .compose(
            Method::HostStop,
            ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget::environment(daemon.environment_id()),
            &HostStopParams { launch_only: false },
        )
        .await
        .expect("composes the stop");
    let (mut reader, mut writer, _acknowledgement) = client.into_halves();
    writer
        .write_message(&ControlFrame::Mutation(Box::new(stop)))
        .await
        .expect("the stop is sent");

    // The client reads nothing. The answer's write waits for it, and ends at its bound.
    daemon.told_to_stop().await;
    assert!(
        daemon.controller.local_writes_blocked() >= 1,
        "the answer was taken whole by a client that reads nothing"
    );
    // The connection ended with the write: what the client was sent is read, and then the end.
    let ended = async { while reader.read_message::<ControlFrame>().await.is_ok() {} };
    tokio::time::timeout(LIVENESS, ended)
        .await
        .expect("the connection ends at the answer's bound");
}
