//! A client and a host, in one process, over a real connection.
//!
//! The host here is deliberately thin: it answers control frames and nothing else. What the tests
//! check is the client's half of the contract — the registry decides the call shape, a mutation
//! carries a fresh identifier and the connection's action window, receipts and cursors are
//! tracked, and a reconnect subscribes from a cursor before it installs a snapshot.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::cursors::{Restoration, RestorationStep};
use kr_client::error::ClientError;
use kr_client::services::{NullService, RelayLeaseService, ServiceClients};
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_crypto::connect::{ChallengeLedger, PairedPeer};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, Notification, Outcome, ParamsValue, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    AttachmentId, BootEpoch, BuildId, ClockEpoch, DeviceId, DeviceKeyRevision, EnvironmentId,
    EventSequence, EventType, SessionId, StreamId,
};
use kr_protocol::method::Method;
use kr_protocol::receipt::{Receipt, ReceiptState};
use kr_protocol::recovery::EventStream;
use kr_protocol::scalars::{Digest256, DurationMs, EndpointKey, Nullable, TimestampMs, U64, Uuid};
use kr_transport::clock::{ContinuousClock, ManualClock};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{self, Admitted, HostEpochs, LocalIdentity, PairedDirectory};
use kr_transport::scheduler::SendLimits;
use kr_transport::window::{ActionWindowIssuer, MAX_WINDOW_VALIDITY};
use tokio::sync::Mutex;

struct Side {
    identity: Arc<LocalIdentity>,
    endpoint: Endpoint,
    record: PairedPeer,
}

#[derive(Debug)]
struct OneDevice {
    endpoint_id: EndpointKey,
    record: PairedPeer,
}

impl PairedDirectory for OneDevice {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        (endpoint_id == &self.endpoint_id).then_some(self.record)
    }
}

async fn side(device_byte: u8, listening: bool) -> Side {
    let config = EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    };
    let keys = DeviceKeys::generate().expect("device keys");
    let endpoint = if listening {
        kr_transport::endpoint::bind_listener(&config, &keys.transport)
            .await
            .expect("a listening endpoint")
    } else {
        kr_transport::endpoint::bind_dialer(&config, &keys.transport)
            .await
            .expect("a dialling endpoint")
    };
    let device_id = DeviceId::new(Uuid::from_bytes([device_byte; 16]));
    let record = PairedPeer {
        device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: *keys.authorisation.public(),
        endpoint_id: *keys.transport.public(),
    };
    let identity = Arc::new(LocalIdentity::new(
        device_id,
        DeviceKeyRevision::new(1),
        *keys.transport.public(),
        keys.authorisation.clone(),
        BuildId::new("kr/0.1.0+test").expect("a build identity"),
    ));
    Side {
        identity,
        endpoint,
        record,
    }
}

fn direct_addr(side: &Side) -> EndpointAddr {
    let mut addr = EndpointAddr::new(side.endpoint.id());
    for socket in side.endpoint.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

/// What the test host did and what it should answer.
#[derive(Debug, Default)]
struct HostScript {
    /// How many reads have arrived.
    reads: AtomicU64,
    /// The action identifiers the client submitted, in order.
    actions: Mutex<Vec<kr_protocol::ids::ActionId>>,
    /// The window identifiers the client presented, in order.
    windows: Mutex<Vec<String>>,
    /// Answer the next read with this error instead of a result.
    refuse_reads_with: Mutex<Option<ErrorCode>>,
    /// Answer every mutation with a correlated protocol error instead of a receipt.
    refuse_mutations_with: Mutex<Option<ErrorCode>>,
}

/// Serves one connection: handshake, then control frames until the client goes away.
///
/// Frames sent on `pushes` are written to the client's control stream, which is how the tests make
/// the host emit an event or renew a window over the wire rather than around it.
fn spawn_host(
    host: &Side,
    client_record: PairedPeer,
    script: Arc<HostScript>,
    pushes: Option<tokio::sync::mpsc::Receiver<ControlFrame>>,
) -> tokio::task::JoinHandle<()> {
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory: Arc<dyn PairedDirectory> = Arc::new(OneDevice {
        endpoint_id: client_record.endpoint_id,
        record: client_record,
    });
    let pushes = Arc::new(Mutex::new(pushes));
    tokio::spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let Ok(connection) = incoming.await else {
                continue;
            };
            let identity = Arc::clone(&identity);
            let directory = Arc::clone(&directory);
            let script = Arc::clone(&script);
            let pushes = Arc::clone(&pushes);
            tokio::spawn(async move {
                let clock = ManualClock::new();
                let clock: Arc<dyn ContinuousClock> = Arc::new(clock);
                let issuer = Arc::new(ActionWindowIssuer::new(clock, MAX_WINDOW_VALIDITY));
                let challenges = Arc::new(std::sync::Mutex::new(ChallengeLedger::with_limit(16)));
                let Ok(Admitted::Authorised(authorised)) = handshake::accept(
                    &connection,
                    &identity,
                    HostEpochs {
                        boot_epoch: BootEpoch::new(1),
                        clock_epoch: ClockEpoch::new(1),
                    },
                    directory.as_ref(),
                    &challenges,
                    &issuer,
                )
                .await
                else {
                    return;
                };
                let mut reader = authorised.control_reader;
                let writer = Arc::new(Mutex::new(authorised.control_writer));
                if let Some(mut pushes) = pushes.lock().await.take() {
                    let writer = Arc::clone(&writer);
                    tokio::spawn(async move {
                        while let Some(frame) = pushes.recv().await {
                            if writer.lock().await.write_message(&frame).await.is_err() {
                                return;
                            }
                        }
                    });
                }
                loop {
                    let frame = match reader.read_message::<ControlFrame>().await {
                        Ok(Some(frame)) => frame,
                        _ => return,
                    };
                    let answer = match frame {
                        ControlFrame::Request(request) => {
                            script.reads.fetch_add(1, Ordering::AcqRel);
                            let refusal = script.refuse_reads_with.lock().await.take();
                            let outcome = match refusal {
                                Some(code) => Outcome::Error(ProtocolError::new(code, "refused")),
                                None => Outcome::Ok(
                                    ParamsValue::from_typed(&SessionList { count: 2 })
                                        .expect("a result"),
                                ),
                            };
                            ControlFrame::Response(Response {
                                request_id: request.request_id,
                                outcome,
                            })
                        }
                        ControlFrame::Mutation(mutation) => {
                            script.actions.lock().await.push(mutation.action_id);
                            if let Some(code) = *script.refuse_mutations_with.lock().await {
                                let answer = ControlFrame::Response(Response {
                                    request_id: mutation.request_id,
                                    outcome: Outcome::Error(ProtocolError::new(code, "refused")),
                                });
                                if writer.lock().await.write_message(&answer).await.is_err() {
                                    return;
                                }
                                continue;
                            }
                            script
                                .windows
                                .lock()
                                .await
                                .push(mutation.action_window_id.to_string());
                            ControlFrame::Receipt(Box::new(kr_protocol::receipt::ReceiptResponse {
                                request_id: mutation.request_id,
                                receipt: Receipt {
                                    action_id: mutation.action_id,
                                    actor_id: kr_protocol::ids::ActorId::new("device:test")
                                        .expect("a principal"),
                                    method: mutation.method.clone(),
                                    method_version: mutation.method_version,
                                    revision: U64::new(1),
                                    state: ReceiptState::Accepted,
                                    reason: Nullable::null(),
                                    payload_digest: Digest256::from_bytes([0; 32]),
                                    accepted_deadline_ms: Nullable::null(),
                                    error: Nullable::null(),
                                    updated_at_ms: TimestampMs::new(0),
                                },
                            }))
                        }
                        _ => continue,
                    };
                    if writer.lock().await.write_message(&answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    })
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct SessionList {
    count: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Empty {}

async fn connect(client: &Side, host: &Side) -> Session {
    let transport = NetworkTransport::connect(
        &client.endpoint,
        direct_addr(host),
        &client.identity,
        &host.record,
        SendLimits::default(),
    )
    .await
    .expect("an authorised connection");
    Session::start(Arc::new(transport)).expect("a session")
}

#[tokio::test]
async fn one_connection_carries_one_session() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let serving = spawn_host(&host, client.record, Arc::new(HostScript::default()), None);

    let transport: Arc<dyn kr_client::transport::ControlTransport> = Arc::new(
        NetworkTransport::connect(
            &client.endpoint,
            direct_addr(&host),
            &client.identity,
            &host.record,
            SendLimits::default(),
        )
        .await
        .expect("an authorised connection"),
    );
    let session = Session::start(Arc::clone(&transport)).expect("a session");
    // Two sessions on one control stream would divide its frames between them.
    assert!(
        Session::start(Arc::clone(&transport)).is_err(),
        "a connection carries one session"
    );

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_read_returns_a_typed_result_and_a_mutation_returns_what_settled_it() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    let listing: SessionList = session
        .read(Method::SessionList, &Empty {})
        .await
        .expect("a listing");
    assert_eq!(listing, SessionList { count: 2 });

    let settled = session
        .mutate(
            Method::SessionCreate,
            ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16]))),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect("a settlement");
    let receipt = settled.receipt().expect("this host answers with a receipt");
    assert_eq!(receipt.state, ReceiptState::Accepted);

    // The action identifier is the client's own, is a version 4 UUID, and the mutation carried the
    // connection's action window.
    let actions = script.actions.lock().await;
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0], receipt.action_id);
    assert_eq!(actions[0].get().version(), 4);
    let windows = script.windows.lock().await;
    assert_eq!(
        windows[0],
        session.action_window().await.action_window_id.to_string()
    );

    // The receipt is tracked and is not terminal, so a reconnecting client would report it.
    let receipts = session.receipts().await;
    assert_eq!(receipts.unresolved(), vec![receipt.action_id]);

    session.close();
    serving.abort();
}

#[tokio::test]
async fn the_registry_decides_the_shape_of_a_call() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let serving = spawn_host(&host, client.record, Arc::new(HostScript::default()), None);
    let session = connect(&client, &host).await;

    // session.create is a mutation, so it cannot be read.
    let error = session
        .read::<_, SessionList>(Method::SessionCreate, &Empty {})
        .await
        .expect_err("a refusal");
    assert!(matches!(
        error,
        ClientError::WrongEffect {
            method: Method::SessionCreate,
            ..
        }
    ));

    // session.list is a read, so it cannot be submitted as a mutation.
    let error = session
        .mutate(
            Method::SessionList,
            ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16]))),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect_err("a refusal");
    assert!(matches!(
        error,
        ClientError::WrongEffect {
            method: Method::SessionList,
            ..
        }
    ));

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_resynchronisation_requirement_is_its_own_error() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    *script.refuse_reads_with.lock().await = Some(ErrorCode::ResyncRequired);
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    let error = session
        .read::<_, SessionList>(Method::EventsSubscribe, &Empty {})
        .await
        .expect_err("a refusal");
    assert!(matches!(error, ClientError::ResyncRequired));
    assert_eq!(error.code(), ErrorCode::ResyncRequired);

    // The next read succeeds, which is what installing a fresh snapshot looks like from here.
    let listing: SessionList = session
        .read(Method::EventsSnapshot, &Empty {})
        .await
        .expect("a snapshot");
    assert_eq!(listing.count, 2);

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_reconnect_subscribes_from_its_cursor_before_installing_a_snapshot() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let (pushes, receiver) = tokio::sync::mpsc::channel(8);
    let serving = spawn_host(
        &host,
        client.record,
        Arc::new(HostScript::default()),
        Some(receiver),
    );
    let session = connect(&client, &host).await;

    // Nothing has been seen yet, so the first restoration starts from the beginning.
    let stream_id = StreamId::new("session:1").expect("a stream identifier");
    let first = Restoration::start(stream_id.clone(), &session.cursors().await);
    assert_eq!(first.step(), RestorationStep::SubscribeFromStart);

    // The host delivers two events. Receiving them is not applying them: until the consumer says
    // it folded them into its state, a reconnect has to ask for them again.
    deliver(&pushes, &session, &stream_id, &[1, 2]).await;
    assert_eq!(
        session.cursors().await.applied_cursor(&stream_id),
        None,
        "a received event establishes no position on its own"
    );
    session.applied(&stream_id, EventSequence::new(2)).await;
    session.applied_content(&stream_id, U64::new(4_096)).await;

    let carried = kr_client::reconnect::ClientState::from_session(&session, None).await;
    // The sequences belonged to the connection that produced them and are gone; the content
    // position is what the next subscription resumes from.
    assert_eq!(carried.cursors.received(&stream_id), None);
    assert_eq!(
        carried.cursors.applied_cursor(&stream_id),
        Some(U64::new(4_096))
    );
    let mut second = Restoration::start(stream_id.clone(), &carried.cursors);
    assert_eq!(
        second.step(),
        RestorationStep::SubscribeFrom(U64::new(4_096)),
        "a reconnect subscribes from the cursor"
    );
    // And the request it builds names exactly that cursor, in the protocol's own parameter type.
    let params = second
        .subscribe_params(
            SessionId::new(Uuid::from_bytes([7; 16])),
            AttachmentId::new(Uuid::from_bytes([8; 16])),
            &[EventStream::Output],
        )
        .expect("the stream is waiting to subscribe");
    assert_eq!(params.from_cursor, Nullable::some(U64::new(4_096)));
    assert!(
        second.installed().is_err(),
        "a snapshot cannot be installed before the subscription"
    );
    second.subscribed().expect("the subscription succeeded");
    assert_eq!(
        second.step(),
        RestorationStep::InstallSnapshot,
        "and only then installs the snapshot"
    );

    session.close();
    serving.abort();
}

/// Sends events to the client from a second connection the host opens for the purpose.
///
/// The test host answers requests on the control stream; this pushes notifications onto the same
/// stream from the client's own side of the loop, which is enough to move the cursor.
async fn deliver(
    pushes: &tokio::sync::mpsc::Sender<ControlFrame>,
    session: &Session,
    stream_id: &StreamId,
    sequences: &[u64],
) {
    let mut events = session.events();
    for sequence in sequences {
        pushes
            .send(ControlFrame::Notification(Notification {
                stream_id: stream_id.clone(),
                sequence: EventSequence::new(*sequence),
                event_type: EventType::new("terminal.output").expect("an event type"),
                payload: ParamsValue::empty(),
            }))
            .await
            .expect("the host accepted the event");
    }
    for _ in sequences {
        tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("an event arrived")
            .expect("the channel is open");
    }
}

#[tokio::test]
async fn an_action_window_renewal_replaces_the_current_one() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let (pushes, receiver) = tokio::sync::mpsc::channel(8);
    let serving = spawn_host(
        &host,
        client.record,
        Arc::new(HostScript::default()),
        Some(receiver),
    );
    let session = connect(&client, &host).await;

    let first = session.action_window().await;
    let renewed = kr_protocol::hello::ActionWindow {
        action_window_id: kr_protocol::ids::ActionWindowId::new("renewed").expect("an identifier"),
        connection_id: first.connection_id,
        boot_epoch: first.boot_epoch,
        issued_at_ms: TimestampMs::new(1),
        valid_for_ms: DurationMs::new(300_000),
    };
    pushes
        .send(ControlFrame::Event(ControlEvent::ActionWindowRenewed(
            renewed,
        )))
        .await
        .expect("the host accepted the renewal");

    // The renewal is a control frame like any other, so the test waits for the client to apply it.
    let applied = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if session.action_window().await.action_window_id.as_str() == "renewed" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(applied.is_ok(), "the renewed window replaced the first one");

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_client_with_no_managed_service_reports_it() {
    assert!(ServiceClients::none().is_empty());
    let request = kr_client::services::LeaseRequest {
        source: EndpointKey::from_bytes([1; 32]),
        destination: EndpointKey::from_bytes([2; 32]),
        direction: kr_client::services::RelayDirection::Bidirectional,
        byte_ceiling: 8 * 1024 * 1024,
        duration_seconds: 300,
        region_preference: None,
        payer: None,
        lease_id: None,
    };
    let error = NullService
        .issue(&request)
        .await
        .expect_err("nothing is configured");
    assert_eq!(error.code(), ErrorCode::HostNotConfigured);
}

#[tokio::test]
async fn a_mutation_refused_by_the_host_is_not_a_lost_connection() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    *script.refuse_mutations_with.lock().await = Some(ErrorCode::PermissionDenied);
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    let error = session
        .mutate(
            Method::SessionCreate,
            ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16]))),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect_err("a refusal");
    assert_eq!(
        error.code(),
        ErrorCode::PermissionDenied,
        "the host's own code survives, rather than becoming a connection failure"
    );

    // The connection is still usable, which is what the distinction is for.
    let listing: SessionList = session
        .read(Method::SessionList, &Empty {})
        .await
        .expect("a listing");
    assert_eq!(listing.count, 2);

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_gap_in_the_event_sequence_does_not_stop_the_connection() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let (pushes, receiver) = tokio::sync::mpsc::channel(8);
    let serving = spawn_host(
        &host,
        client.record,
        Arc::new(HostScript::default()),
        Some(receiver),
    );
    let session = connect(&client, &host).await;
    let stream_id = StreamId::new("session:1").expect("a stream identifier");
    let mut events = session.events();

    // One event, then one that skips ahead. The gap discards this client's cursor for the stream.
    for sequence in [1u64, 5] {
        pushes
            .send(ControlFrame::Notification(Notification {
                stream_id: stream_id.clone(),
                sequence: EventSequence::new(sequence),
                event_type: EventType::new("terminal.output").expect("an event type"),
                payload: ParamsValue::empty(),
            }))
            .await
            .expect("the host accepted the event");
    }
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("an event arrived")
            .expect("the channel is open");
    }
    assert_eq!(
        session.cursors().await.position(&stream_id),
        None,
        "a gap discards the partial state for that stream"
    );

    // The reader is still routing, which is the point: a gap must not deadlock the connection.
    let listing: SessionList = tokio::time::timeout(
        Duration::from_secs(5),
        session.read(Method::SessionList, &Empty {}),
    )
    .await
    .expect("the read was answered")
    .expect("a listing");
    assert_eq!(listing.count, 2);

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_cancelled_mutation_returns_its_place_in_the_outstanding_bound() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    // A host that never answers, so every mutation stays outstanding until it is cancelled.
    let script = Arc::new(HostScript::default());
    *script.refuse_mutations_with.lock().await = None;
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    // Eight is the negotiated bound. Cancelling that many calls must not spend it permanently.
    for _ in 0..16 {
        let mutation = session.mutate(
            Method::InputInterrupt,
            ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16]))),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        );
        // Dropping the future before it resolves is a cancellation.
        let cancelled = tokio::time::timeout(Duration::from_millis(1), mutation).await;
        assert!(cancelled.is_err() || cancelled.expect("a result").is_ok());
    }

    // The connection still admits a mutation, which it could not if the bound had leaked.
    let settled = tokio::time::timeout(
        Duration::from_secs(5),
        session.mutate(
            Method::SessionCreate,
            ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16]))),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        ),
    )
    .await
    .expect("the mutation was answered")
    .expect("a settlement");
    assert_eq!(
        settled
            .receipt()
            .expect("this host answers with a receipt")
            .state,
        ReceiptState::Accepted
    );

    session.close();
    serving.abort();
}

#[tokio::test]
async fn an_unsettled_submission_carries_the_intent_it_was_made_for() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    let settled = session
        .mutate(
            Method::SessionCreate,
            ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16]))),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect("a settlement");
    let receipt = settled.receipt().expect("this host answers with a receipt");

    // The receipt was `accepted`, which is not terminal, so the action is still unsettled and the
    // record says which operation it was rather than only which identifier.
    let submitted = session.submitted_actions().await;
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].action_id, receipt.action_id);
    assert_eq!(submitted[0].method, Method::SessionCreate);
    assert_eq!(
        submitted[0].target.environment_id,
        EnvironmentId::new(Uuid::from_bytes([9; 16]))
    );

    let carried = kr_client::reconnect::ClientState::from_session(&session, None).await;
    assert_eq!(carried.unresolved_actions(), vec![receipt.action_id]);

    session.close();
    serving.abort();
}
