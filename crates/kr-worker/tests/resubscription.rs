//! A subscription replaced on a connection whose client has stopped reading, over the worker's own
//! endpoint.
//!
//! A connection carries one subscription at a time, and asking for another replaces it: that is how
//! a terminal answers a resynchronisation, and how a client moves to another of its attachments.
//! The delivery being replaced can be part way through a frame the client has not read yet.
//! Cutting that frame would end the connection, because nothing else can be written after half a
//! frame, so the stream has to go on whole: the old subscription's last frame, finished, and then
//! the new subscription's.
//!
//! Only a real socket that the client has stopped reading holds a frame part way, and how much of
//! a frame it holds is the sending side's buffer, which differs between platforms and settings.
//! So the worker here serves on a listener whose connections are given a send buffer this test
//! sets, and the frame it is part way through is far larger than that buffer. Unix only, because
//! that buffer is a Unix socket's.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, EnvironmentId, RequestId, SessionEpoch,
    SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{
    EventStream, EventsSubscribeParams, EventsSubscribeResult, OutputEvent,
};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

use common::{LIVENESS_DEADLINE, carries};

/// The send buffer each connection to the worker is given.
///
/// Linux and macOS keep a buffer of this order (Linux doubles what it is asked for), so a frame of
/// [`BATCH_BYTES`] the client is not reading stops part way on both. The test watches it stop part
/// way before relying on it.
const SEND_BUFFER: usize = 4 * 1024;

/// One batch of output, delivered as one frame fifty times larger than [`SEND_BUFFER`].
const BATCH_BYTES: usize = 200 * 1024;

/// The line the session is given behind the batch, before the replacement: the new subscription
/// carries it, and the delivery being replaced must not.
const AFTER: &[u8] = b"kr-after-the-replacement";

/// The identifier of the subscription request that replaces the first.
const REPLACING: u64 = 1000;

/// A session this test hosts, served on its own endpoint.
struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

impl Drop for Host {
    /// Stops the shell this fixture started, however the test ended.
    fn drop(&mut self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.runtime.session().force_close();
        }));
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Hosts a session whose shell waits on its terminal, served on a listener whose connections are
/// given [`SEND_BUFFER`].
///
/// The shell writes nothing, so every byte of output here is one this test gives the session.
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
    let controller =
        kr_ipc::verify::ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity");
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("read -r _"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 4 * 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener =
        Listener::bind_with_send_buffer(&endpoint, SEND_BUFFER).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: None,
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
    }
}

/// Attaches a terminal of the session's own size that only watches, over `client`'s connection.
async fn attach(client: &mut LocalClient, host: &Host) -> AttachmentId {
    attach_asking(client, host, false).await
}

/// Attaches a terminal of the session's own size over `client`'s connection, asking for input as
/// well when `input` says so.
async fn attach_asking(client: &mut LocalClient, host: &Host, input: bool) -> AttachmentId {
    attach_sized(client, host, input, Dimensions::new(80, 24)).await
}

/// The same for a terminal of `dimensions`, which is served a projection when it is not the
/// session's own size.
async fn attach_sized(
    client: &mut LocalClient,
    host: &Host,
    input: bool,
    dimensions: Dimensions,
) -> AttachmentId {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    if input {
        requested.insert(AttachmentCapability::Input);
    }
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(host.session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id: host.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(dimensions),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    attached.attachment.attachment_id
}

/// What a subscription to this attachment's output and state asks for.
fn subscription(host: &Host, attachment_id: AttachmentId) -> EventsSubscribeParams {
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    streams.insert(EventStream::SessionState);
    EventsSubscribeParams {
        session_id: host.session_id,
        attachment_id,
        streams,
        from_cursor: Nullable::null(),
    }
}

/// Gives the session `bytes` as its terminal would, and settles the screen as a quiet terminal
/// does: the two steps the worker takes with a batch its read loop hands over.
fn write_output(host: &Host, bytes: &[u8]) {
    let mut session = host.runtime.session();
    let _ = session.ingest_output(bytes);
    let _ = session.quiesce_output();
}

/// Polls until `condition` holds, and fails with how long it waited when it never does.
async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let started = tokio::time::Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for {what}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Reads the next frame, failing with what ended the stream when something did.
async fn next(client: &mut LocalClient, what: &str) -> ControlFrame {
    match tokio::time::timeout(LIVENESS_DEADLINE, client.recv()).await {
        Ok(Ok(frame)) => frame,
        Ok(Err(error)) => panic!("the stream ended {what}: {error}"),
        Err(_) => panic!("nothing arrived for {LIVENESS_DEADLINE:?} {what}"),
    }
}

/// Where the notifications after the replacing answer have got to.
#[derive(Debug)]
struct Order {
    /// The sequence the old subscription's next notification carries.
    old_next: u64,
    /// How many notifications of the old subscription arrived after the answer.
    old_after: usize,
    /// The sequence the new subscription's next notification carries, once its first has arrived.
    new_next: Option<u64>,
}

/// KR-REQ-08.80: a subscription that replaces another while the old one is part way through a
/// frame its client has not read leaves the stream whole: the old subscription's frame is
/// finished, it is the last the old subscription sends, and the new subscription's first frame
/// follows it.
///
/// One connection holds two attachments, the first subscribed and then the second, which replaces
/// the first's delivery. The connection is stopped just before that replacement, after its answer
/// has gone. The first attachment is still subscribed in the session, so output the session is
/// given then still reaches the delivery being replaced: one batch far larger than the transport
/// holds, which that delivery begins and stops part way through, because the client is not
/// reading, and a line queued behind it. That is the state the replacement meets. The client reads
/// again only once the replacement has happened, and reads until the line arrives through the new
/// subscription: the old delivery has the line ready too, and must not send it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscription_replaced_part_way_through_a_frame_leaves_the_stream_whole() {
    let host = host().await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let first = attach(&mut client, &host).await;
    let second = attach(&mut client, &host).await;
    client
        .request(Method::EventsSubscribe, &subscription(&host, first))
        .await
        .expect("the call reaches the worker")
        .expect("the first subscription succeeds");
    // The screen the first subscription is drawn, before anything else happens on this connection.
    let mut old_next = loop {
        if let ControlFrame::Notification(notification) =
            next(&mut client, "before the first subscription's screen").await
        {
            break notification.sequence.get() + 1;
        }
    };

    // The replacing request is answered, and the connection stops before it replaces the first
    // delivery.
    let pause = host.service.pause_before_replacing_delivery();
    let params = ParamsValue::from_typed(&subscription(&host, second)).expect("encodes");
    client
        .writer()
        .write_message(&ControlFrame::Request(Request {
            request_id: RequestId::new(REPLACING),
            method: Method::EventsSubscribe.into(),
            method_version: MethodVersion::V1,
            params,
        }))
        .await
        .expect("the replacing request reaches the worker");

    // Anything before the answer is the first subscription's.
    let answer = loop {
        match next(&mut client, "before the answer to the replacing request").await {
            ControlFrame::Response(response) if response.request_id.get() == REPLACING => {
                break response;
            }
            ControlFrame::Notification(notification) => {
                assert_eq!(
                    notification.sequence.get(),
                    old_next,
                    "the first subscription's notifications arrive in order"
                );
                old_next += 1;
            }
            _ => {}
        }
    };
    let Outcome::Ok(value) = answer.outcome else {
        panic!(
            "the replacing subscription was refused: {:?}",
            answer.outcome
        );
    };
    let from = value
        .to_typed::<EventsSubscribeResult>()
        .expect("the answer decodes")
        .from_cursor
        .get();
    tokio::time::timeout(LIVENESS_DEADLINE, pause.arrived)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the connection to answer"))
        .expect("the connection says it has answered");

    // The client reads nothing more for now. The delivery being replaced stops part way through
    // the frame that carries the batch, with the line queued behind it.
    write_output(&host, &vec![b'x'; BATCH_BYTES]);
    write_output(&host, b"\r\nkr-after-the-replacement\r\n");
    until(
        "the delivery being replaced to stop part way through a frame",
        || host.service.part_way_through_a_frame(first),
    )
    .await;
    drop(pause.release);
    tokio::time::timeout(LIVENESS_DEADLINE, pause.replaced)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the replacement"))
        .expect("the connection says it has replaced the first delivery");

    // The client reads everything, until the line arrives through the new subscription.
    let mut order = Order {
        old_next,
        old_after: 0,
        new_next: None,
    };
    let mut carried = Vec::new();
    while !carries(&carried, AFTER) {
        let what = format!(
            "after the replacement, with the notifications in this order so far: {order:?}"
        );
        let ControlFrame::Notification(notification) = next(&mut client, &what).await else {
            continue;
        };
        let sequence = notification.sequence.get();
        let output = (notification.event_type.as_str() == "session.output").then(|| {
            notification
                .payload
                .to_typed::<OutputEvent>()
                .expect("an output event decodes")
        });
        match order.new_next {
            None if sequence == order.old_next && sequence != 0 => {
                order.old_next += 1;
                order.old_after += 1;
            }
            None => {
                assert_eq!(
                    sequence, 0,
                    "the notification after the first subscription's last is the new \
                     subscription's first: {order:?}"
                );
                order.new_next = Some(1);
                if let Some(event) = output.as_ref() {
                    carried.extend_from_slice(event.bytes.as_slice());
                }
            }
            Some(expected) => {
                assert_eq!(
                    sequence, expected,
                    "nothing of the first subscription arrives after the new subscription's \
                     first notification: {order:?}"
                );
                if let Some(event) = output.as_ref() {
                    assert!(
                        event.cursor.get() >= from,
                        "the new subscription's output begins at its own cursor {from}, and \
                         this began at {}",
                        event.cursor.get()
                    );
                    carried.extend_from_slice(event.bytes.as_slice());
                }
                order.new_next = Some(expected + 1);
            }
        }
    }
    assert_eq!(
        order.old_after, 1,
        "the frame the first delivery was part way through when it was replaced arrived whole, \
         and nothing of the first subscription after it: {order:?}"
    );
    assert!(
        !host.service.part_way_through_a_frame(second),
        "and nothing is left part way to the client"
    );
}

/// What the first and the second subscription of [`replaced_while_delivering`] each sent.
struct Sent {
    /// The output the first subscription sent after the replacing request was answered.
    old: Vec<u8>,
    /// The output the second subscription sent, from its first notification on.
    new: Vec<u8>,
}

/// Subscribes the first attachment, which holds the input lease, and replaces its subscription with
/// the second's while the delivery of the first is part way through a frame its client has not read.
///
/// `produce` gives the session what the first delivery is then sent. The client reads nothing
/// until the replacement has happened, and then reads until the line [`AFTER`] arrives through the
/// second subscription, so each of the two has been read to its end.
async fn replaced_while_delivering(produce: impl FnOnce(&Host)) -> Sent {
    let host = host().await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let first = attach_asking(&mut client, &host, true).await;
    let second = attach(&mut client, &host).await;
    let _keys =
        common::take_the_keys(&mut client, host.environment_id, host.session_id, first).await;
    client
        .request(Method::EventsSubscribe, &subscription(&host, first))
        .await
        .expect("the call reaches the worker")
        .expect("the first subscription succeeds");
    loop {
        if let ControlFrame::Notification(_) =
            next(&mut client, "before the first subscription's screen").await
        {
            break;
        }
    }

    let pause = host.service.pause_before_replacing_delivery();
    let params = ParamsValue::from_typed(&subscription(&host, second)).expect("encodes");
    client
        .writer()
        .write_message(&ControlFrame::Request(Request {
            request_id: RequestId::new(REPLACING),
            method: Method::EventsSubscribe.into(),
            method_version: MethodVersion::V1,
            params,
        }))
        .await
        .expect("the replacing request reaches the worker");
    loop {
        if let ControlFrame::Response(response) =
            next(&mut client, "before the answer to the replacing request").await
            && response.request_id.get() == REPLACING
        {
            break;
        }
    }
    tokio::time::timeout(LIVENESS_DEADLINE, pause.arrived)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the connection to answer"))
        .expect("the connection says it has answered");

    produce(&host);
    until(
        "the delivery being replaced to stop part way through a frame",
        || host.service.part_way_through_a_frame(first),
    )
    .await;
    drop(pause.release);
    tokio::time::timeout(LIVENESS_DEADLINE, pause.replaced)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the replacement"))
        .expect("the connection says it has replaced the first delivery");

    // Everything the old subscription sent after the replacing answer, and then everything the new
    // one did, whose first notification is the one numbered 0.
    let (mut old, mut new) = (Vec::new(), Vec::new());
    let mut replaced = false;
    while !carries(&new, AFTER) {
        let ControlFrame::Notification(notification) =
            next(&mut client, "after the replacement").await
        else {
            continue;
        };
        replaced |= notification.sequence.get() == 0;
        if notification.event_type.as_str() != "session.output" {
            continue;
        }
        let event = notification
            .payload
            .to_typed::<OutputEvent>()
            .expect("an output event decodes");
        let into = if replaced { &mut new } else { &mut old };
        into.extend_from_slice(event.bytes.as_slice());
    }
    Sent { old, new }
}

/// KR-REQ-08.06, KR-REQ-08.38: a side effect already queued on a subscription that another
/// replaces is still written, once, ahead of the new subscription's first frame.
///
/// The first attachment holds the input lease and is part way through a frame its client has not
/// read, with a bell queued behind the frame. The replacement is the stream's end for everything
/// else on the old subscription, which the new screen covers; a bell is on no screen, so it is the
/// one thing that is not covered, and losing it with the queue would be a side effect that reached
/// nobody and was recorded nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_side_effect_queued_on_a_replaced_subscription_is_still_written_once() {
    let sent = replaced_while_delivering(|host| {
        write_output(host, &vec![b'x'; BATCH_BYTES]);
        write_output(host, b"\x07\r\nkr-after-the-replacement\r\n");
    })
    .await;
    assert_eq!(
        sent.old.iter().filter(|byte| **byte == 0x07).count(),
        1,
        "the bell reached the terminal on the subscription it was queued on"
    );
    assert!(
        !sent.new.contains(&0x07),
        "and is not written again on the one that replaced it"
    );
}

/// KR-REQ-08.06, KR-REQ-08.38: the same when the frame the delivery is part way through is the
/// first of several, so the delivery stops at a frame boundary and not between two deliveries: the
/// frames of the batch that follow are the screen's to cover, and the bell behind them is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_side_effect_behind_a_batch_of_several_frames_is_still_written_once() {
    let sent = replaced_while_delivering(|host| {
        write_output(host, &vec![b'x'; 3 * BATCH_BYTES]);
        write_output(host, b"\x07\r\nkr-after-the-replacement\r\n");
    })
    .await;
    assert_eq!(
        sent.old.iter().filter(|byte| **byte == 0x07).count(),
        1,
        "the bell reached the terminal on the subscription it was queued on"
    );
    assert!(
        !sent.new.contains(&0x07),
        "and is not written again on the one that replaced it"
    );
}

/// KR-REQ-08.06, KR-REQ-08.38: a side effect larger than one frame, replaced part way through, is
/// written whole: a clipboard write cut between two frames would leave the terminal inside an
/// operating-system command, and the screen that follows would be read as the rest of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_side_effect_of_several_frames_is_written_whole_when_it_is_replaced_part_way() {
    let content = vec![b'q'; 300 * 1024];
    let rendered =
        kr_worker::render::side_effect(&kr_term::sideeffect::SideEffectKind::ClipboardWrite {
            selection: kr_term::sideeffect::ClipboardSelection::Clipboard,
            content: content.clone(),
        })
        .expect("a clipboard write is rendered");
    assert!(
        rendered.len() > kr_worker::service::MAX_OUTPUT_EVENT_BYTES,
        "the effect is larger than one frame: {}",
        rendered.len()
    );
    let sent = replaced_while_delivering(|host| {
        write_output(host, &rendered);
        write_output(host, b"\r\nkr-after-the-replacement\r\n");
    })
    .await;
    assert_eq!(
        sent.old, rendered,
        "the whole of the clipboard write reached the terminal on the subscription it was on"
    );
    assert!(
        !carries(&sent.new, b"\x1b]52;"),
        "and is not written again on the one that replaced it"
    );
}

/// KR-REQ-08.06, KR-REQ-08.38: a subscription replaced before it has written anything does not
/// write a side effect it is owed, because the first frame of a stream is the one its client takes
/// for the stream's beginning, and an effect is not that. What it was owed is a durable host event.
///
/// A terminal of another size holds the lease and is subscribed second, while the first
/// subscription's delivery is part way through a frame; the second delivery is made to wait for it,
/// and a third subscription replaces the second before it has begun. A bell is rung in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscription_replaced_before_it_wrote_anything_records_the_effect_it_was_owed() {
    let host = host().await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let watcher = attach(&mut client, &host).await;
    let holder = attach_sized(&mut client, &host, true, Dimensions::new(40, 12)).await;
    host.runtime
        .session()
        .acquire_input(
            holder,
            kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
            None,
        )
        .expect("the terminal of another size takes the keys");
    client
        .request(Method::EventsSubscribe, &subscription(&host, watcher))
        .await
        .expect("the call reaches the worker")
        .expect("the first subscription succeeds");
    loop {
        if let ControlFrame::Notification(_) =
            next(&mut client, "before the first subscription's screen").await
        {
            break;
        }
    }

    // The second subscription is answered and the connection stops before it replaces the first.
    let pause = host.service.pause_before_replacing_delivery();
    for (request, attachment) in [(REPLACING, holder), (REPLACING + 1, watcher)] {
        let params = ParamsValue::from_typed(&subscription(&host, attachment)).expect("encodes");
        client
            .writer()
            .write_message(&ControlFrame::Request(Request {
                request_id: RequestId::new(request),
                method: Method::EventsSubscribe.into(),
                method_version: MethodVersion::V1,
                params,
            }))
            .await
            .expect("the request reaches the worker");
    }
    loop {
        if let ControlFrame::Response(response) =
            next(&mut client, "before the answer to the second subscription").await
            && response.request_id.get() == REPLACING
        {
            break;
        }
    }
    tokio::time::timeout(LIVENESS_DEADLINE, pause.arrived)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the connection to answer"))
        .expect("the connection says it has answered");

    // The first delivery stops part way through a frame, and the bell the holder is owed is queued
    // on the second subscription's stream, which has not begun.
    write_output(&host, &vec![b'x'; BATCH_BYTES]);
    write_output(&host, b"\x07");
    until(
        "the first delivery to stop part way through a frame",
        || host.service.part_way_through_a_frame(watcher),
    )
    .await;
    drop(pause.release);
    tokio::time::timeout(LIVENESS_DEADLINE, pause.replaced)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS_DEADLINE:?} for the replacement"))
        .expect("the connection says it has replaced the first delivery");

    // The client reads again, up to the first frame of the third subscription. Everything the second
    // subscription wrote would be before it, because the third waits for the second to stop.
    let mut answered = false;
    let mut seen = Vec::new();
    loop {
        match next(&mut client, "after the replacements").await {
            ControlFrame::Response(response) if response.request_id.get() == REPLACING + 1 => {
                answered = true;
            }
            ControlFrame::Notification(notification) => {
                if notification.event_type.as_str() == "session.output" {
                    seen.extend_from_slice(
                        notification
                            .payload
                            .to_typed::<OutputEvent>()
                            .expect("an output event decodes")
                            .bytes
                            .as_slice(),
                    );
                }
                if answered && notification.sequence.get() == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(
        !seen.contains(&0x07),
        "the bell is on a stream the client reads, among {} bytes",
        seen.len()
    );
    until("the bell to be recorded", || {
        host.runtime
            .session()
            .journal()
            .and_then(|journal| journal.host_events().ok())
            .is_some_and(|events| events.iter().any(|event| event.kind == "bell"))
    })
    .await;
    let recorded: Vec<String> = host
        .runtime
        .session()
        .journal()
        .expect("the session keeps a journal")
        .host_events()
        .expect("reads the host events")
        .into_iter()
        .map(|event| event.kind)
        .collect();
    assert_eq!(recorded, vec!["bell".to_owned()], "once");
}
