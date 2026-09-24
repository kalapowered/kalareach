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
use kr_client::drafts::{
    Associations, Draft, DraftSealer, DraftStore, DraftSync, DraftTarget, Published,
    SyncCheckpoint, draft_collection,
};
use kr_client::error::ClientError;
use kr_client::retry::{Recovery, RequestClass, UserAction};
use kr_client::services::{
    ManagedService, NullService, RelayLeaseService, ServiceClients, SyncBackupService,
    SyncExchanged, SyncPosition, SyncRequestFence, SyncRequestStatus, SyncRevision,
};
use kr_client::sync::SyncStore;

/// The position a service reports for the nth write of a collection.
fn at(write_sequence: u64) -> SyncPosition {
    SyncPosition::at(
        write_sequence,
        SyncRevision::new(Uuid::from_bytes([write_sequence as u8; 16])),
    )
}
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_crypto::connect::{ChallengeLedger, PairedPeer};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, Notification, Outcome, ParamsValue, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, AttachmentId, BootEpoch, BuildId, ClockEpoch,
    DeviceId, DeviceKeyRevision, DraftId, DraftRevision, EnvironmentId, EventSequence, EventType,
    SessionId, StreamId, SyncConflictId,
};
use kr_protocol::method::Method;
use kr_protocol::receipt::{Receipt, ReceiptState};
use kr_protocol::recovery::EventStream;
use kr_protocol::scalars::{Digest256, DurationMs, EndpointKey, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::transfer::DraftState;
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
    /// Answer this many of the next reads with this error instead of a result.
    refuse_reads_with: Mutex<Option<(ErrorCode, u32)>>,
    /// Answer every mutation with a correlated protocol error instead of a receipt.
    refuse_mutations_with: Mutex<Option<ErrorCode>>,
    /// Answer this many of the next mutations with the method's own result instead of a receipt.
    ///
    /// That is what a host does when it will not act until it has more: it answers the request it
    /// was sent with what it still needs, rather than with a receipt for work it has accepted.
    answer_mutations_with_result: Mutex<u32>,
    /// Answer nothing at all to this many of the next mutations.
    ///
    /// A host that took the frame and said nothing is what leaves an action whose outcome nobody
    /// knows, which is the state section 9 forbids forgetting.
    swallow_mutations: Mutex<u32>,
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
                            let refusal = {
                                let mut held = script.refuse_reads_with.lock().await;
                                match held.as_mut() {
                                    Some((code, left)) if *left > 0 => {
                                        *left -= 1;
                                        Some(*code)
                                    }
                                    _ => None,
                                }
                            };
                            let outcome = match refusal {
                                Some(code) => Outcome::Error(ProtocolError::new(code, "refused")),
                                None => Outcome::Ok(answer_read(&request)),
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
                            {
                                let mut swallow = script.swallow_mutations.lock().await;
                                if *swallow > 0 {
                                    *swallow -= 1;
                                    continue;
                                }
                            }
                            {
                                let mut left = script.answer_mutations_with_result.lock().await;
                                if *left > 0 {
                                    *left -= 1;
                                    drop(left);
                                    let answer = ControlFrame::Response(Response {
                                        request_id: mutation.request_id,
                                        outcome: Outcome::Ok(
                                            ParamsValue::from_typed(&Empty {})
                                                .expect("an empty result"),
                                        ),
                                    });
                                    if writer.lock().await.write_message(&answer).await.is_err() {
                                        return;
                                    }
                                    continue;
                                }
                            }
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

/// What the host answers one read with.
///
/// A restoration asks for a subscription before it installs anything, so that one answer is the
/// protocol's own; everything else in these tests is a listing.
fn answer_read(request: &kr_protocol::envelope::Request) -> ParamsValue {
    if request.method.as_str() == kr_protocol::method::Method::EventsSubscribe.entry().name {
        return ParamsValue::from_typed(&kr_protocol::recovery::EventsSubscribeResult {
            stream_id: StreamId::new("session:1").expect("a stream identifier"),
            from_cursor: U64::ZERO,
            oldest_retained_cursor: U64::ZERO,
            gap: Nullable::null(),
            agent_resources: kr_protocol::projection::AgentResourceSnapshot {
                snapshot_id: U64::ZERO,
                stream_generation: U64::new(1),
                cursor: U64::ZERO,
                resources: Vec::new(),
                continue_after: Nullable::null(),
            },
        })
        .expect("a result");
    }
    ParamsValue::from_typed(&SessionList { count: 2 }).expect("a result")
}

#[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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

/// KR-REQ-10.01: the native client library connects to a host over iroh in Rust.
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
async fn evidence_a_host_asked_for_comes_back_as_the_action_it_asked_about() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    // The first mutation is answered the way a host answers when it will not act yet: with what it
    // still needs, correlated to the request, rather than with a receipt.
    *script.answer_mutations_with_result.lock().await = 1;
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    let target = ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16])));
    let asked = session
        .mutate(
            Method::SessionCreate,
            target.clone(),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect("a settlement");
    assert!(
        asked.result().is_some(),
        "this host answered by asking for more, not with a receipt"
    );
    let asked_about = script.actions.lock().await[0];

    // The evidence comes back as the action the host asked about, so the host finds the request it
    // challenged rather than a second intent.
    let continued = session
        .mutate_continuing(
            asked_about,
            Method::SessionCreate,
            target.clone(),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect("a settlement");
    assert_eq!(
        continued
            .receipt()
            .expect("this host answers with a receipt")
            .action_id,
        asked_about
    );

    // That action now has a receipt, and a receipt is something this client must go on reporting.
    // Continuing it again would replace the record that names it.
    let replaced = session
        .mutate_continuing(
            asked_about,
            Method::SessionCreate,
            target.clone(),
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await;
    assert!(
        matches!(replaced, Err(ClientError::Host(_))),
        "an action with a receipt cannot carry another request"
    );

    // Anything that is not a continuation is still a separate intent with its own identity.
    let separate = session
        .mutate(
            Method::SessionCreate,
            target,
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await
        .expect("a settlement")
        .receipt()
        .expect("this host answers with a receipt")
        .action_id;
    assert_ne!(separate, asked_about);

    let actions = script.actions.lock().await;
    assert_eq!(actions.as_slice(), [asked_about, asked_about, separate]);

    session.close();
    serving.abort();
}

#[tokio::test]
async fn an_action_whose_outcome_is_unknown_cannot_carry_another_request() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    // A host that takes the frame and says nothing, so the action stays on the unresolved list.
    let script = Arc::new(HostScript::default());
    *script.swallow_mutations.lock().await = 1;
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    let target = ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([9; 16])));
    let mutation = session.mutate(
        Method::InputInterrupt,
        target.clone(),
        None,
        &Empty {},
        &Empty {},
        DurationMs::new(120_000),
    );
    // Dropping the future before it resolves leaves the action submitted and unanswered, which is
    // exactly the state a person has to be able to ask about.
    let cancelled = tokio::time::timeout(Duration::from_millis(50), mutation).await;
    assert!(cancelled.is_err(), "the host answers nothing here");

    let submitted = session.submitted_actions().await;
    assert_eq!(submitted.len(), 1);
    let unknown = submitted[0].action_id;

    // Continuing it would overwrite the intent that names it and leave two requests settling one
    // action, so it is refused before anything reaches the wire.
    let replaced = session
        .mutate_continuing(
            unknown,
            Method::SessionCreate,
            target,
            None,
            &Empty {},
            &Empty {},
            DurationMs::new(120_000),
        )
        .await;
    assert!(
        matches!(replaced, Err(ClientError::Host(_))),
        "an action whose outcome is unknown cannot carry another request"
    );
    assert_eq!(session.submitted_actions().await.len(), 1);
    assert_eq!(script.actions.lock().await.len(), 1);

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
    *script.refuse_reads_with.lock().await = Some((ErrorCode::ResyncRequired, 1));
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

#[tokio::test]
async fn a_transient_refusal_of_an_idempotent_read_is_sent_again_and_never_reaches_the_caller() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    // The host refuses the first read with a transient code and answers the next one.
    *script.refuse_reads_with.lock().await = Some((ErrorCode::ResourceUnavailable, 1));
    let listing: SessionList = session
        .read(Method::SessionList, &Empty {})
        .await
        .expect("the retry succeeded within the bound");
    assert_eq!(listing, SessionList { count: 2 });
    assert_eq!(
        script.reads.load(Ordering::Acquire),
        2,
        "the read was sent exactly once more"
    );

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_refusal_that_a_retry_cannot_change_comes_straight_back_with_its_action() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    // A configuration failure. Sending it again cannot change the answer, so the library does not,
    // even though the host would have answered the second attempt.
    *script.refuse_reads_with.lock().await = Some((ErrorCode::PermissionDenied, 1));
    let error = session
        .read::<_, SessionList>(Method::SessionList, &Empty {})
        .await
        .expect_err("a refusal");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(script.reads.load(Ordering::Acquire), 1);
    assert_eq!(error.user_action(), UserAction::FixConfiguration);
    let decision = error.decision(RequestClass::IdempotentRead);
    assert_eq!(decision.recovery, Recovery::Stop);
    assert!(!decision.retries_automatically());

    session.close();
    serving.abort();
}

#[tokio::test]
async fn a_mutation_is_never_sent_again_by_the_library() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    // A transient code, which is the one case an automatic retry would be legal for a read. A
    // mutation may already have been dispatched, so the library hands the decision back instead.
    *script.refuse_mutations_with.lock().await = Some(ErrorCode::ResourceUnavailable);
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
    assert_eq!(error.code(), ErrorCode::ResourceUnavailable);
    assert_eq!(
        script.actions.lock().await.len(),
        1,
        "one intent reached the host once"
    );
    assert!(
        !error
            .decision(RequestClass::Dispatchable)
            .retries_automatically()
    );

    session.close();
    serving.abort();
}

#[tokio::test]
async fn an_unknown_outcome_is_never_retried_and_names_the_action_to_ask_about() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
    let session = connect(&client, &host).await;

    *script.refuse_mutations_with.lock().await = Some(ErrorCode::OutcomeUnknown);
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
        .expect_err("an uncertain outcome");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(script.actions.lock().await.len(), 1);
    let decision = error.decision(RequestClass::Dispatchable);
    assert_eq!(decision.recovery, Recovery::QueryOutcome);
    assert_eq!(error.user_action(), UserAction::CheckTheOutcome);

    // The action stays on the unresolved list, because nothing decided what became of it.
    let submitted = session.submitted_actions().await;
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].action_id, script.actions.lock().await[0]);

    session.close();
    serving.abort();
}

/// A synchronisation service that holds one generation and one object per collection.
///
/// It is the service's half of section 20's compare and swap and of section 9's receipt: it stores
/// opaque bytes, refuses a write whose expected generation is not the one it holds, never decides
/// which of two writers was right, and records the reply it gave each request identity so it can
/// be asked about that request afterwards.
#[derive(Debug, Default)]
struct RemoteObjects {
    objects: Mutex<std::collections::HashMap<String, (SyncPosition, Vec<u8>)>>,
    /// What each request identity was answered, including the fences. One map under one lock,
    /// because a fence and an exchange decide the same thing about the same identity: two locks
    /// would let an exchange pass a check a fence took a moment later and then run anyway.
    receipts: Mutex<std::collections::HashMap<(String, Uuid), RequestReceipt>>,
    /// The copies it kept of refused writes, until the person chooses about them.
    copies: Mutex<std::collections::HashSet<SyncConflictId>>,
    /// Whether the next exchange is applied and its answer lost on the way back.
    lose_the_next_answer: Mutex<bool>,
}

/// What every fence this suite's service records says about the past.
///
/// One answer, because this suite never asks what a fence establishes about the past: it asks
/// whether the barrier releases, which a fence does whichever way that answer falls.
const FENCE_FOUND_NO_RUN: bool = true;

/// The object a comparison names, which is the only part of a position the wire carries.
fn expected_object(expected: Option<SyncPosition>) -> Option<SyncRevision> {
    expected.and_then(|position| position.revision.0)
}

/// The reply one request was given, kept under the identity that request presented.
#[derive(Clone, Debug)]
struct RequestReceipt {
    /// The request the reply answered, as the wire carried it: the revision the comparison named
    /// and the bytes. The deployed service records a digest of those fields, and its own order is
    /// not one of them. A fence answers no request, so it holds none.
    request: Option<(Option<SyncRevision>, Vec<u8>)>,
    /// The reply itself, or nothing for an identity a fence ended before anything ran under it.
    answered: Option<SyncExchanged>,
}

impl kr_client::services::SyncBackupService for RemoteObjects {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        _signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> kr_client::services::ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            let key = (collection.to_owned(), request_id);
            // The comparison the wire carries is the object the caller expects, not the order
            // beside it, and a position whose revision is null names no object exactly as no
            // position at all does.
            let request = (expected_object(expected), ciphertext.to_vec());
            // One hold decides the identity: what a fence recorded is in the same map, so an
            // exchange cannot pass a check a fence takes a moment later and run anyway.
            let mut receipts = self.receipts.lock().await;
            if let Some(receipt) = receipts.get(&key) {
                // An identity a fence ended runs nothing afterwards, whatever it carries.
                let Some(answered) = receipt.answered else {
                    return Err(ClientError::Host(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "that request was fenced",
                    )));
                };
                // An exact retry is answered from the receipt and applied no second time; the same
                // identity carrying different content is a second request wearing the first's name.
                if receipt.request.as_ref() != Some(&request) {
                    return Err(ClientError::Host(ProtocolError::new(
                        ErrorCode::IdConflict,
                        "that identity already answered a different request",
                    )));
                }
                return Ok(answered);
            }
            let mut objects = self.objects.lock().await;
            let current = objects.get(collection).map(|(position, _)| *position);
            // The comparison is against the revision the caller named, which is the only part of a
            // position the exchange carries.
            let answered =
                if current.and_then(|position| position.revision.0) == expected_object(expected) {
                    // The service's own order: each applied write of an object takes the next place.
                    let next = at(current.map_or(1, |position| position.write_sequence + 1));
                    objects.insert(collection.to_owned(), (next, ciphertext.to_vec()));
                    SyncExchanged::Applied { position: next }
                } else {
                    // The service keeps the rejected write as a copy of its own, and names it here.
                    let kept = SyncConflictId::new(
                        kr_transport::random::fresh_uuid_v4().expect("a fresh identity"),
                    );
                    self.copies.lock().await.insert(kept);
                    SyncExchanged::Refused {
                        retained: Some(kept),
                    }
                };
            receipts.insert(
                key,
                RequestReceipt {
                    request: Some(request),
                    answered: Some(answered),
                },
            );
            if std::mem::take(&mut *self.lose_the_next_answer.lock().await) {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::UpstreamUnavailable,
                    "the answer never came back",
                )));
            }
            Ok(answered)
        })
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> kr_client::services::ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async move {
            Ok(
                match self
                    .receipts
                    .lock()
                    .await
                    .get(&(collection.to_owned(), request_id))
                    .map(|receipt| receipt.answered)
                {
                    Some(Some(SyncExchanged::Applied { position })) => {
                        SyncRequestStatus::Applied { position }
                    }
                    Some(Some(SyncExchanged::Refused { retained })) => {
                        SyncRequestStatus::Refused { retained }
                    }
                    // A receipt that holds no reply is the one a fence wrote, and it carries what
                    // that fence established about the past.
                    Some(None) => SyncRequestStatus::Fenced {
                        never_ran: FENCE_FOUND_NO_RUN,
                    },
                    None => SyncRequestStatus::Unknown,
                },
            )
        })
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> kr_client::services::ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move {
            // A request the service has already decided keeps its outcome; one it has not is
            // fenced, and nothing runs under that identity afterwards. The fence is recorded under
            // the same lock an exchange decides under, so one of the two happens and not both.
            let mut receipts = self.receipts.lock().await;
            let recorded = receipts
                .entry((collection.to_owned(), request_id))
                .or_insert(RequestReceipt {
                    request: None,
                    answered: None,
                })
                .answered;
            Ok(match recorded {
                Some(SyncExchanged::Applied { position }) => SyncRequestFence::Applied { position },
                Some(SyncExchanged::Refused { retained }) => SyncRequestFence::Refused { retained },
                None => SyncRequestFence::Fenced {
                    never_ran: FENCE_FOUND_NO_RUN,
                },
            })
        })
    }

    fn fetch<'a>(
        &'a self,
        collection: &'a str,
    ) -> kr_client::services::ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
        Box::pin(async move {
            self.objects
                .lock()
                .await
                .get(collection)
                .map(|(position, ciphertext)| (*position, ciphertext.clone()))
                .ok_or_else(|| {
                    ClientError::Host(ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        "no such object",
                    ))
                })
        })
    }

    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        retained: SyncConflictId,
    ) -> kr_client::services::ServiceFuture<'a, bool> {
        Box::pin(async move { Ok(self.copies.lock().await.remove(&retained)) })
    }
}

/// A stand-in for a device's own sealing, so the test exercises the seam rather than a cipher.
///
/// It is not encryption and does not pretend to be: what it establishes is that the service only
/// ever sees bytes this device transformed, and that the same device reads them back.
#[derive(Debug)]
struct ReversingSealer;

impl DraftSealer for ReversingSealer {
    fn seal(&self, plaintext: &[u8]) -> kr_client::Result<Vec<u8>> {
        Ok(plaintext.iter().rev().copied().collect())
    }

    fn open(&self, ciphertext: &[u8]) -> kr_client::Result<Vec<u8>> {
        Ok(ciphertext.iter().rev().copied().collect())
    }
}

#[tokio::test]
async fn a_draft_outlives_its_attachment_its_connection_and_another_devices_write() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let script = Arc::new(HostScript::default());
    let serving = spawn_host(&host, client.record, Arc::clone(&script), None);

    let directory = tempfile::tempdir().expect("a directory");
    let device = DeviceId::new(Uuid::from_bytes([2; 16]));
    let store = DraftStore::open(directory.path().join("mine"), device).expect("a store");
    let session_id = SessionId::new(Uuid::from_bytes([3; 16]));
    let target = DraftTarget::session(session_id).in_application(
        ApplicationInstanceId::new(Uuid::from_bytes([4; 16])),
        AgentBindingRevision::new(1),
    );
    let draft = store
        .create(
            target.clone(),
            "the message I have not sent".to_owned(),
            TimestampMs::new(1),
        )
        .expect("a draft");

    // A connection, and an attachment presenting the draft.
    let session = connect(&client, &host).await;
    let mut associations = Associations::new();
    let first = AttachmentId::new(Uuid::from_bytes([11; 16]));
    associations.bind(draft.draft_id, first);

    // The attachment is replaced. The association moves; the draft does not.
    let second = AttachmentId::new(Uuid::from_bytes([12; 16]));
    assert_eq!(associations.bind(draft.draft_id, second), Some(first));
    assert_eq!(store.load(draft.draft_id).expect("the draft"), draft);

    // The connection goes. Every association goes with it, and the draft is untouched on disk.
    session.close();
    associations.connection_lost();
    assert!(associations.is_empty());
    assert_eq!(store.load(draft.draft_id).expect("the draft"), draft);

    // The same device reconnects and binds the draft to a new attachment. Nothing is submitted.
    let session = connect(&client, &host).await;
    let third = AttachmentId::new(Uuid::from_bytes([13; 16]));
    assert_eq!(associations.bind(draft.draft_id, third), None);
    let mut rebound = store.load(draft.draft_id).expect("the draft");
    assert_eq!(rebound.rebind(Some(&target)), DraftState::Open);
    assert_eq!(rebound, draft, "a rebind changes nothing about the draft");
    // A round trip first, so the host has answered everything this connection sent before the
    // count is read: an empty list on a connection the host had not reached yet would pass for the
    // wrong reason.
    let _: SessionList = session
        .read(Method::SessionList, &Empty {})
        .await
        .expect("a listing");
    assert!(
        script.actions.lock().await.is_empty(),
        "no action reached the host: a draft is submitted by a person, not by a reconnect"
    );

    // Another device wrote to the shared object first. One collection holds one draft, so what it
    // holds is this draft under that device's own revision and text.
    let theirs = Draft {
        device_id: DeviceId::new(Uuid::from_bytes([9; 16])),
        revision: DraftRevision::new(3),
        text: "what the other device had".to_owned(),
        updated_at_ms: TimestampMs::new(2),
        ..draft.clone()
    };
    let service = Arc::new(RemoteObjects::default());
    let sealer = ReversingSealer;
    let sealed = sealer
        .seal(&DraftStore::encode_payload(&theirs).expect("canonical bytes"))
        .expect("sealed");
    service
        .compare_exchange(
            &draft_collection(draft.draft_id),
            kr_transport::random::fresh_uuid_v4().expect("an identity"),
            1,
            None,
            &sealed,
        )
        .await
        .expect("the other device's write");

    // The device's synchronisation store, where each publication keeps its one record.
    let sync = DraftSync::new(
        Arc::clone(&service) as Arc<_>,
        Arc::new(ReversingSealer),
        SyncStore::open(directory.path().join("sync")).expect("a sync store"),
    );
    let published = sync
        .publish(&store, draft.draft_id, draft.revision, TimestampMs::new(3))
        .await
        .expect("an answer");
    let Published::Conflicted {
        copy,
        remote_revision,
        position,
    } = published
    else {
        panic!("this device was overtaken: {published:?}");
    };
    assert_eq!(
        position,
        at(1),
        "the note now names where the object stands"
    );
    assert_eq!(
        remote_revision, theirs.revision,
        "the revision reported is the other device's, not the copy's"
    );

    // The person's own draft is exactly as it was, and the other device's content is beside it.
    assert_eq!(store.load(draft.draft_id).expect("the draft"), draft);
    let kept = store.load(copy).expect("the copy");
    assert_eq!(kept.text, "what the other device had");
    assert_eq!(kept.conflict_of, Nullable::some(draft.draft_id));
    assert_ne!(kept.draft_id, draft.draft_id);
    let listing = store.list().expect("a listing");
    assert!(listing.unreadable.is_empty());
    assert_eq!(listing.drafts.len(), 2);

    // An object that opens to a different draft is not this draft's, whatever opened it.
    let misfiled = sealer
        .seal(
            &DraftStore::encode_payload(&Draft {
                draft_id: DraftId::new(Uuid::from_bytes([200; 16])),
                ..theirs.clone()
            })
            .expect("canonical bytes"),
        )
        .expect("sealed");
    service
        .compare_exchange(
            &draft_collection(draft.draft_id),
            kr_transport::random::fresh_uuid_v4().expect("an identity"),
            2,
            Some(at(1)),
            &misfiled,
        )
        .await
        .expect("a misfiled write");
    let error = sync
        .fetch_beside(&store, draft.draft_id, TimestampMs::new(4))
        .await
        .expect_err("a misfiled object");
    assert!(error.to_string().contains("could not be read"), "{error}");
    assert_eq!(
        store.list().expect("a listing").drafts.len(),
        2,
        "nothing was kept from an object that is not this draft's"
    );

    // A draft this device edited offline is published against the generation this device last saw,
    // which is none: its own revision counter has nothing to do with the service's.
    let fresh = store
        .create(
            target.clone(),
            "a second draft".to_owned(),
            TimestampMs::new(4),
        )
        .expect("a draft");
    let fresh = store
        .update(
            &Draft {
                text: "a second draft, edited".to_owned(),
                ..fresh
            },
            TimestampMs::new(5),
        )
        .expect("an edit");
    assert_eq!(fresh.revision, DraftRevision::new(2));
    assert_eq!(
        sync.publish(&store, fresh.draft_id, fresh.revision, TimestampMs::new(6))
            .await
            .expect("an answer"),
        Published::Accepted { position: at(1) }
    );
    // The note records where it reached, so the next publication names that generation.
    assert_eq!(
        store
            .checkpoint(fresh.draft_id)
            .expect("a note")
            .expect("published once"),
        SyncCheckpoint {
            position: at(1),
            published_revision: Nullable::some(fresh.revision),
        }
    );
    assert_eq!(
        sync.publish(&store, fresh.draft_id, fresh.revision, TimestampMs::new(7))
            .await
            .expect("an answer"),
        Published::Accepted { position: at(2) }
    );

    // An older revision of this device's own draft is refused rather than sent. The service would
    // take it, because its generation is right and a draft revision means nothing to it, and the
    // newest text would be gone from the object every other device reads. What decides it is the
    // store's own record.
    let error = sync
        .publish(
            &store,
            fresh.draft_id,
            DraftRevision::new(1),
            TimestampMs::new(8),
        )
        .await
        .expect_err("an older revision");
    assert!(
        error.to_string().contains("is not what this device holds"),
        "{error}"
    );

    // A store opened for another device does not publish this one's drafts, the way it does not
    // change or remove them.
    let other_device = DraftStore::open(
        directory.path().join("mine"),
        DeviceId::new(Uuid::from_bytes([9; 16])),
    )
    .expect("a store");
    let error = sync
        .publish(
            &other_device,
            fresh.draft_id,
            fresh.revision,
            TimestampMs::new(8),
        )
        .await
        .expect_err("another device's draft");
    assert!(error.to_string().contains("belongs to device"), "{error}");

    // A device that lost its note compares against nothing, is overtaken by what is already there,
    // keeps that content beside its own and learns the generation. The next publication works.
    store
        .forget_checkpoint(fresh.draft_id)
        .expect("the note is gone");
    let published = sync
        .publish(&store, fresh.draft_id, fresh.revision, TimestampMs::new(9))
        .await
        .expect("an answer");
    assert!(
        matches!(published, Published::Conflicted { position, .. } if position == at(2)),
        "{published:?}"
    );
    // The local draft is exactly as it was. What came down is beside it.
    assert_eq!(
        store.load(fresh.draft_id).expect("the draft").text,
        "a second draft, edited"
    );
    // The fetch cleared the revision on the note, and the older revision is still refused: what
    // decides that is the stored draft rather than the note.
    let error = sync
        .publish(
            &store,
            fresh.draft_id,
            DraftRevision::new(1),
            TimestampMs::new(9),
        )
        .await
        .expect_err("an older revision, after a fetch");
    assert!(
        error.to_string().contains("is not what this device holds"),
        "{error}"
    );
    assert_eq!(
        store
            .checkpoint(fresh.draft_id)
            .expect("a note")
            .expect("a fetch wrote one")
            .published_revision,
        Nullable::null(),
        "the note names no revision of this device's after a fetch"
    );
    assert_eq!(
        sync.publish(&store, fresh.draft_id, fresh.revision, TimestampMs::new(10))
            .await
            .expect("an answer"),
        Published::Accepted { position: at(3) },
        "the note the fetch wrote is what the next comparison names"
    );

    // A publication whose answer is lost is settled by asking the service about the request, with
    // the host still connected. The draft comes out of it exactly as it went in, and settling it is
    // not a way towards a submission either.
    let third = store
        .create(target, "a third draft".to_owned(), TimestampMs::new(11))
        .expect("a draft");
    *service.lose_the_next_answer.lock().await = true;
    sync.publish(&store, third.draft_id, third.revision, TimestampMs::new(12))
        .await
        .expect_err("the answer never came back");
    let reconciled = sync
        .reconcile_unsettled(&store, TimestampMs::new(13))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(
        store
            .checkpoint(third.draft_id)
            .expect("a note")
            .expect("the settlement wrote one"),
        SyncCheckpoint {
            position: at(1),
            published_revision: Nullable::some(third.revision),
        }
    );
    assert_eq!(store.load(third.draft_id).expect("the draft"), third);

    // The whole exercise, with the host still there: a draft was written, presented, re-presented,
    // carried across a reconnect, overtaken, synchronised and settled after a lost answer, and
    // nothing was ever submitted.
    let _: SessionList = session
        .read(Method::SessionList, &Empty {})
        .await
        .expect("a listing");
    assert!(script.actions.lock().await.is_empty());
    session.close();
    serving.abort();
}

/// A host on this machine: a local socket that answers the opening exchange and then control
/// frames, which is all a local endpoint is.
///
/// Section 23 puts local endpoints and network connections on the same typed frames, with local
/// peer authentication instead of a device proof. This is the local half of that, small on purpose:
/// what the tests below check is that everything above the transport is the same either way.
fn spawn_local_host(
    listener: kr_ipc::endpoint::Listener,
    script: Arc<HostScript>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((connection, peer)) = listener.accept().await else {
                return;
            };
            let script = Arc::clone(&script);
            tokio::spawn(async move {
                let (mut reader, mut writer) =
                    kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await
                else {
                    return;
                };
                let connection_id = kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([42; 16]));
                let acknowledgement = kr_protocol::local::LocalHelloAck {
                    selected_version: kr_protocol::hello::PROTOCOL_VERSION,
                    role: kr_protocol::local::LocalRole::Controller,
                    connection_id,
                    environment_id: EnvironmentId::new(Uuid::from_bytes([5; 16])),
                    boot_identity: kr_protocol::identity::BootIdentity {
                        source: kr_protocol::identity::BootIdentitySource::BootTime,
                        value: kr_protocol::scalars::Bytes::new(vec![1, 2, 3, 4]),
                    },
                    peer: kr_protocol::local::LocalPeer {
                        uid: U64::new(u64::from(peer.uid)),
                        gid: U64::new(u64::from(peer.gid)),
                        pid: Nullable::null(),
                    },
                    action_window: kr_protocol::hello::ActionWindow {
                        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                            .expect("a literal window identifier"),
                        connection_id,
                        boot_epoch: BootEpoch::new(1),
                        issued_at_ms: TimestampMs::new(0),
                        valid_for_ms: DurationMs::new(60_000),
                    },
                    capabilities: kr_protocol::scalars::CanonicalSet::new(),
                    max_receive: hello.max_receive,
                };
                if writer
                    .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    let Ok(frame) = reader.read_message::<ControlFrame>().await else {
                        return;
                    };
                    let answer = match frame {
                        ControlFrame::Request(request) => {
                            script.reads.fetch_add(1, Ordering::AcqRel);
                            ControlFrame::Response(Response {
                                request_id: request.request_id,
                                outcome: Outcome::Ok(
                                    ParamsValue::from_typed(&SessionList { count: 2 })
                                        .expect("a result"),
                                ),
                            })
                        }
                        ControlFrame::Mutation(mutation) => {
                            script.actions.lock().await.push(mutation.action_id);
                            script
                                .windows
                                .lock()
                                .await
                                .push(mutation.action_window_id.to_string());
                            ControlFrame::Receipt(Box::new(kr_protocol::receipt::ReceiptResponse {
                                request_id: mutation.request_id,
                                receipt: Receipt {
                                    action_id: mutation.action_id,
                                    actor_id: kr_protocol::ids::ActorId::new("device:local")
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
                    if writer.write_message(&answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    })
}

#[tokio::test]
async fn the_local_path_is_a_socket_and_the_remote_path_is_iroh_behind_one_seam() {
    // The local path. A command line on this machine reaches its host through kr-ipc: a socket or
    // a named pipe, peer authentication instead of a device proof, and the host's own stamp of the
    // connection's freshness context.
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .paths()
        .environment(tree.environment_id())
        .controller_endpoint()
        .expect("a controller endpoint");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("a local endpoint");
    let local_script = Arc::new(HostScript::default());
    let serving_locally = spawn_local_host(listener, Arc::clone(&local_script));

    let local = kr_client::ipc::IpcTransport::connect(&endpoint, kr_cli_build_id())
        .await
        .expect("a local connection");
    assert_eq!(
        local.context().role,
        kr_protocol::local::LocalRole::Controller
    );
    assert_eq!(
        local.context().peer.uid.get(),
        u64::from(kr_ipc::paths::current_uid()),
        "the host authenticated the operating-system caller rather than a device"
    );
    let local: Arc<dyn kr_client::transport::ControlTransport> = local.shared();

    // The remote path. A device off this machine reaches the same host through kr-client over
    // iroh: the same typed frames, with the connection proofs a network peer owes.
    let host = side(1, true).await;
    let client = side(2, false).await;
    let network_script = Arc::new(HostScript::default());
    let serving_remotely = spawn_host(&host, client.record, Arc::clone(&network_script), None);
    let remote: Arc<dyn kr_client::transport::ControlTransport> = Arc::new(
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

    // One seam. The session is written against `ControlTransport` and nothing else, so the same
    // calls produce the same answers whichever way the client connected.
    for (name, transport, script) in [
        ("the local socket", local, Arc::clone(&local_script)),
        ("iroh", remote, Arc::clone(&network_script)),
    ] {
        let session = Session::start(transport).expect("a session");
        let listing: SessionList = session
            .read(Method::SessionList, &Empty {})
            .await
            .unwrap_or_else(|error| panic!("a listing over {name}: {error}"));
        assert_eq!(listing, SessionList { count: 2 }, "over {name}");
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
            .unwrap_or_else(|error| panic!("a settlement over {name}: {error}"));
        let receipt = settled.receipt().expect("a receipt");
        assert_eq!(receipt.state, ReceiptState::Accepted, "over {name}");
        // The client generated the action identifier and presented the window the host issued on
        // this connection, whichever transport carried it.
        let actions = script.actions.lock().await;
        assert_eq!(actions.len(), 1, "over {name}");
        assert_eq!(actions[0].get().version(), 4, "over {name}");
        drop(actions);
        assert_eq!(
            script.windows.lock().await[0],
            session.action_window().await.action_window_id.to_string(),
            "over {name}"
        );
        session.close();
    }

    serving_locally.abort();
    serving_remotely.abort();
}

/// The build identity a command line presents. It is a client build, not a host's.
fn kr_cli_build_id() -> BuildId {
    BuildId::new("kr/0.1.0+test").expect("a build identity")
}

#[tokio::test]
async fn a_session_a_draft_and_a_control_need_no_managed_service_and_do_not_change_with_one() {
    let host = side(1, true).await;
    let client = side(2, false).await;
    let directory = tempfile::tempdir().expect("a directory");
    let device = DeviceId::new(Uuid::from_bytes([2; 16]));

    // The same work, twice: once with nothing configured, once with every service replaced by a
    // client that answers nothing. Section 17 says the local product is complete without any of
    // them, so what a session, a draft store and a control decide has to be the same both times.
    // None of these paths reaches a service at all, which is the claim: not that every observable
    // in the library is unchanged, but that this work never asks.
    let mut observed = Vec::new();
    for (round, clients) in [
        ("nothing configured", ServiceClients::none()),
        (
            "every service replaced",
            ServiceClients {
                account: Some(Arc::new(NullService)),
                relay_leases: Some(Arc::new(NullService)),
                push: Some(Arc::new(NullService)),
                sync_backup: Some(Arc::new(NullService)),
                managed_inference: Some(Arc::new(NullService)),
            },
        ),
    ] {
        let script = Arc::new(HostScript::default());
        let serving = spawn_host(&host, client.record, Arc::clone(&script), None);
        let session = connect(&client, &host).await;

        // A read and a mutation against the host.
        let listing: SessionList = session
            .read(Method::SessionList, &Empty {})
            .await
            .unwrap_or_else(|error| panic!("a listing with {round}: {error}"));
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
            .unwrap_or_else(|error| panic!("a settlement with {round}: {error}"));

        // A draft on this device, which needs no service at all.
        let store = DraftStore::open(directory.path().join(round.replace(' ', "-")), device)
            .expect("a store");
        let draft = store
            .create(
                DraftTarget::session(SessionId::new(Uuid::from_bytes([3; 16]))),
                "written with nothing managed".to_owned(),
                TimestampMs::new(1),
            )
            .expect("a draft");
        let edited = store
            .update(
                &Draft {
                    text: "and edited".to_owned(),
                    ..draft
                },
                TimestampMs::new(2),
            )
            .expect("an edit");

        // A control, decided from what this client knows.
        let shown = kr_client::controls::evaluate(
            &kr_plugin_sdk::predicate::Predicate::Flag {
                flag: kr_plugin_sdk::predicate::PresentationFlag::DraftNotEmpty,
            },
            &kr_client::controls::ControlState::new().with_flag(
                kr_plugin_sdk::predicate::PresentationFlag::DraftNotEmpty,
                true,
            ),
        );

        observed.push((
            listing,
            settled.receipt().expect("a receipt").state,
            edited.text.clone(),
            edited.revision,
            shown.is_shown(),
            clients.is_empty(),
        ));

        // Availability is explained service by service, in one shape, and every explanation names
        // its service. It explains; nothing above consulted it before doing any of the work here.
        let availability = clients.availability();
        assert_eq!(availability.len(), ManagedService::ALL.len(), "{round}");
        for report in &availability {
            assert_eq!(
                report.configured,
                clients.holds(report.service),
                "{round}: {report:?}"
            );
            assert!(
                report.explanation.contains(report.service.as_str()),
                "{round}: an explanation that does not name its service: {report:?}"
            );
        }
        if clients.is_empty() {
            // Nothing configured: each report says so and says what to do instead.
            assert!(
                availability.iter().all(|report| !report.configured),
                "{round}"
            );
            assert!(
                availability
                    .iter()
                    .all(|report| report.explanation.contains("You can")),
                "{round}"
            );
        } else {
            // A service replaced by one that answers nothing is configured, and says which service
            // it is refusing for when it is called. Neither is a claim that anything is entitled.
            assert!(
                availability.iter().all(|report| report.configured),
                "{round}"
            );
            let refusal = clients
                .account
                .as_ref()
                .expect("an account client")
                .revoke(
                    &kr_client::services::account::RefreshToken::new("a-refresh-token")
                        .expect("a token"),
                )
                .await
                .expect_err("a service that answers nothing");
            assert_eq!(refusal.code(), ErrorCode::HostNotConfigured);
            assert!(
                refusal
                    .to_string()
                    .contains(ManagedService::AccountLogin.as_str()),
                "{refusal}"
            );
            assert_eq!(refusal.user_action(), UserAction::FixConfiguration);
        }

        session.close();
        serving.abort();
    }

    let (first, second) = (&observed[0], &observed[1]);
    assert_eq!(first.0, second.0, "the listing differed");
    assert_eq!(first.1, second.1, "the receipt differed");
    assert_eq!(first.2, second.2, "the draft differed");
    assert_eq!(first.3, second.3, "the draft revision differed");
    assert_eq!(first.4, second.4, "the control decision differed");
    // The one thing that does differ is whether anything is configured, which is the point.
    assert!(first.5 && !second.5);
}

/// The canonical size KR-PERF-006 names.
const PERF_ROWS: u64 = 40;
const PERF_COLUMNS: u64 = 120;

/// The state half of a projected screen of that size.
fn perf_snapshot() -> Box<kr_protocol::projection::ProjectionSnapshot> {
    use kr_protocol::projection::{
        CharsetState, KittyKeyboardState, MarginState, PaletteProvenance, PaletteState,
        ProjectedBuffer, ProjectedCursor, ProjectedKeyboard, ProjectedMode, ProjectedModeKind,
        ProjectedTitle, ProjectedViewport, ProjectionSnapshot, Rgb,
    };

    let colour = Rgb {
        red: 1,
        green: 2,
        blue: 3,
    };
    Box::new(ProjectionSnapshot {
        projection_generation: U64::new(1),
        output_cursor: U64::new(1),
        active_buffer: ProjectedBuffer::Primary,
        dimensions: kr_protocol::session::Dimensions::new(PERF_COLUMNS, PERF_ROWS),
        viewport: ProjectedViewport {
            screen_top_row: U64::ZERO,
            top_row: U64::ZERO,
            rows: U64::new(PERF_ROWS),
            left_column: U64::ZERO,
            columns: U64::new(PERF_COLUMNS),
        },
        cursor: ProjectedCursor {
            column: U64::ZERO,
            row: U64::ZERO,
            visible: true,
            style: U64::new(1),
            pending_wrap: false,
        },
        saved_cursors: Vec::new(),
        margins: MarginState {
            top: U64::ZERO,
            bottom: U64::new(PERF_ROWS - 1),
            left: U64::ZERO,
            right: U64::new(PERF_COLUMNS - 1),
        },
        rendition: kr_protocol::projection::CellRendition::PLAIN,
        tab_stops: vec![U64::ZERO],
        charsets: CharsetState {
            g0: "Ascii".to_owned(),
            g1: "Ascii".to_owned(),
            shift_out: false,
        },
        modes: vec![ProjectedMode {
            kind: ProjectedModeKind::Dec,
            mode: U64::new(7),
            enabled: true,
        }],
        keypad_application: false,
        keyboard: ProjectedKeyboard {
            modify_other_keys: U64::ZERO,
            primary: KittyKeyboardState {
                flags: Nullable::null(),
                stack: Vec::new(),
            },
            alternate: KittyKeyboardState {
                flags: Nullable::null(),
                stack: Vec::new(),
            },
        },
        title: ProjectedTitle::default(),
        title_stack: Vec::new(),
        hyperlink: Nullable::null(),
        palette: PaletteState {
            source: PaletteProvenance::DarkPreset,
            foreground: colour,
            background: colour,
            cursor: colour,
            pointer_foreground: colour,
            pointer_background: colour,
            selection_background: colour,
            selection_foreground: colour,
            overrides: Vec::new(),
        },
        oldest_retained_row: U64::ZERO,
        evicted: false,
        degraded: false,
    })
}

/// Every row of that screen, full width.
fn perf_rows() -> kr_protocol::projection::ProjectionRowPage {
    use kr_protocol::projection::{
        CellRendition, CellRun, ProjectedBuffer, ProjectedRow, ProjectionRowPage,
    };

    let rows = (0..PERF_ROWS)
        .map(|row| ProjectedRow {
            row: U64::new(row),
            soft_wrapped: false,
            truncated: false,
            runs: vec![CellRun {
                column: U64::ZERO,
                cells: U64::new(PERF_COLUMNS),
                text: "x".repeat(usize::try_from(PERF_COLUMNS).expect("a column count")),
                rendition: CellRendition::PLAIN,
                hyperlink: Nullable::null(),
            }],
        })
        .collect();
    ProjectionRowPage {
        projection_generation: U64::new(1),
        output_cursor: U64::new(1),
        buffer: ProjectedBuffer::Primary,
        rows,
        oldest_retained_row: U64::ZERO,
        evicted: false,
        more: false,
    }
}

/// Sends one projection event as the notification a host publishes it as.
async fn push_projection(
    pushes: &tokio::sync::mpsc::Sender<ControlFrame>,
    stream_id: &StreamId,
    sequence: u64,
    event: &kr_protocol::projection::ProjectionEvent,
) {
    let payload = match event {
        kr_protocol::projection::ProjectionEvent::Snapshot(snapshot) => {
            ParamsValue::from_typed(snapshot.as_ref()).expect("a snapshot")
        }
        kr_protocol::projection::ProjectionEvent::Rows(page) => {
            ParamsValue::from_typed(page).expect("a page")
        }
        _ => unreachable!("these tests publish a snapshot and its rows"),
    };
    pushes
        .send(ControlFrame::Notification(Notification {
            stream_id: stream_id.clone(),
            sequence: EventSequence::new(sequence),
            event_type: EventType::new(event.event_type()).expect("an event type"),
            payload,
        }))
        .await
        .expect("the host accepted the event");
}

/// Restores a projected screen the way a reconnecting client does, and returns how long it took.
///
/// The clock starts where KR-PERF-006 starts it: the transport has returned, and nothing has been
/// asked for yet. It stops when there is a screen a terminal can draw.
async fn restore_a_screen(
    session: &Session,
    pushes: &tokio::sync::mpsc::Sender<ControlFrame>,
    stream_id: &StreamId,
) -> (Duration, usize) {
    use kr_client::projection::paint::{Keyboard, Window};
    use kr_client::projection::{Applied, Projection};
    use kr_protocol::projection::ProjectionEvent;

    let mut events = session.events();
    let started = std::time::Instant::now();

    // Subscribe from the cursor, before anything is installed.
    let mut restoration = Restoration::start(stream_id.clone(), &session.cursors().await);
    let params = restoration
        .subscribe_params(
            SessionId::new(Uuid::from_bytes([7; 16])),
            AttachmentId::new(Uuid::from_bytes([8; 16])),
            &[EventStream::Output],
        )
        .expect("the stream is waiting to subscribe");
    let subscribed = session
        .subscribe_events(&params)
        .await
        .expect("the subscription succeeded");
    assert_eq!(subscribed.stream_id, *stream_id);
    restoration
        .subscribed()
        .expect("the subscription succeeded");

    // The host publishes the screen it holds, and the client folds it in.
    push_projection(
        pushes,
        stream_id,
        1,
        &ProjectionEvent::Snapshot(perf_snapshot()),
    )
    .await;
    push_projection(pushes, stream_id, 2, &ProjectionEvent::Rows(perf_rows())).await;

    let mut projection = Projection::new();
    let mut installed = false;
    while !installed {
        let notification = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("an event arrived")
            .expect("the channel is open");
        let Some(event) =
            kr_client::projection::decode(notification.event_type.as_str(), &notification.payload)
        else {
            continue;
        };
        installed = matches!(projection.apply(event), Applied::Installed);
    }
    restoration.installed().expect("the snapshot is installed");

    // And there is a screen to draw.
    let screen = projection.screen().expect("a screen");
    assert_eq!(screen.dimensions.rows.get(), PERF_ROWS);
    assert_eq!(screen.dimensions.columns.get(), PERF_COLUMNS);
    let painted =
        kr_client::projection::paint::install(screen, Window::of(screen), Keyboard::EVERYTHING);
    let elapsed = started.elapsed();

    // Every row of the screen is in what a terminal would be sent, which is what "usable state"
    // means: not that bytes were produced, but that the screen is in them.
    let drawn = String::from_utf8(painted.bytes).expect("the paint is text and escapes");
    let row = "x".repeat(usize::try_from(PERF_COLUMNS).expect("a column count"));
    (elapsed, drawn.matches(&row).count())
}

#[tokio::test]
async fn a_reconnect_reaches_a_screen_a_terminal_can_draw_inside_the_budget() {
    // KR-PERF-006: usable state within two seconds for a 120x40 screen, measured from where the
    // transport returns. What is measured here is the client's own half against a host that answers
    // at once: the round trip it makes, the retry policy that goes through, folding the screen in
    // and painting every row of it. What a real host spends answering, and the attach that precedes
    // a subscription, are not in this figure, so passing it is a necessary condition for the row
    // rather than the row's own measurement.
    let client = side(2, false).await;
    let stream_id = StreamId::new("session:1").expect("a stream identifier");

    // One host answers at once.
    let first_host = side(1, true).await;
    let (pushes, receiver) = tokio::sync::mpsc::channel(8);
    let first_serving = spawn_host(
        &first_host,
        client.record,
        Arc::new(HostScript::default()),
        Some(receiver),
    );
    let session = connect(&client, &first_host).await;
    let (elapsed, rows_drawn) = restore_a_screen(&session, &pushes, &stream_id).await;
    assert_eq!(
        u64::try_from(rows_drawn).expect("a row count"),
        PERF_ROWS,
        "every row of the screen is in what a terminal would be sent"
    );
    assert!(
        elapsed < kr_client::retry::RECONNECT_BUDGET,
        "a restoration took {elapsed:?}, over the {:?} budget",
        kr_client::retry::RECONNECT_BUDGET
    );
    session.close();
    first_serving.abort();

    // Another refuses the restoration's read once, so the policy's own delay is inside the
    // measurement rather than beside it.
    let second_host = side(3, true).await;
    let script = Arc::new(HostScript::default());
    *script.refuse_reads_with.lock().await = Some((ErrorCode::ResourceUnavailable, 1));
    let (pushes, receiver) = tokio::sync::mpsc::channel(8);
    let second_serving = spawn_host(
        &second_host,
        client.record,
        Arc::clone(&script),
        Some(receiver),
    );
    let session = connect(&client, &second_host).await;
    let (with_retries, rows_drawn) = restore_a_screen(&session, &pushes, &stream_id).await;
    assert_eq!(u64::try_from(rows_drawn).expect("a row count"), PERF_ROWS);
    assert_eq!(
        script.reads.load(Ordering::Acquire),
        2,
        "the read was refused once and sent again"
    );
    assert!(
        with_retries >= kr_client::retry::RETRY_BACKOFF_MIN,
        "the refusal and its delay were not in the measurement: {with_retries:?}"
    );
    assert!(
        with_retries < kr_client::retry::RECONNECT_BUDGET,
        "a restoration that retried took {with_retries:?}, over the {:?} budget",
        kr_client::retry::RECONNECT_BUDGET
    );

    session.close();
    second_serving.abort();
}
