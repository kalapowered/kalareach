//! Remote input is prioritised over a bulk transfer.
//!
//! KR-PERF-005 puts a figure on this: application scheduling adds less than 25 ms p95 above the
//! measured path round trip while a transfer runs. A figure needs the host section 27 describes,
//! and `tests/perf.rs` is where it is taken. What is asserted here is the property behind the
//! figure, through the mechanism that produces it, and nothing here reads a clock. So it holds on
//! a shared runner, on a loaded laptop and in an unoptimised build, which is what a property of
//! the design should do.
//!
//! There is one deadline in the file, and it decides nothing about the property: it turns a host
//! or a peer that has stopped answering into a named failure rather than a job that runs until CI
//! kills it. It is twenty seconds against work that takes a fifth of a second.
//!
//! The mechanism has two halves and both are observable.
//!
//! The first is admission. Every data-stream write is charged against the whole send budget the
//! peer declared, and a bulk write is charged again against a lower ceiling, so a transfer can
//! never occupy the last mebibyte of what the application hands the connection. A keystroke is
//! still admitted with a transfer holding everything it is allowed to hold.
//!
//! The second is the connection itself. The input stream and the transfer are separate QUIC
//! streams with the input stream's priority above the transfer's, so a keystroke goes out ahead of
//! queued transfer bytes while the connection has capacity. What is asserted is the priority the
//! connection is actually using, read back from the connection on both sides of it, rather than
//! the number the scheduler would have chosen: a stream whose priority was never applied answers
//! the connection's default of zero and fails here.
//!
//! Beside those two, the end-to-end consequence: every keystroke is answered, each echo carries
//! what was sent, and the transfer moves a further chunk at the far end after they began. That one
//! is a progress check rather than an ordering one. On loopback the receiver keeps up, so the
//! standing backlog a keystroke could overtake is small, and stalling the receiver instead would
//! exhaust the connection's flow-control window, which no stream priority reaches past.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_cbor::CanonicalValue;
use kr_protocol::envelope::ParamsValue;
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::hello::ALPN;
use kr_protocol::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionId, TransferId};
use kr_protocol::scalars::{Nullable, Uuid};
use kr_transport::clock::ManualClock;
use kr_transport::error::TransportError;
use kr_transport::handshake::{self, Admitted, PairedDirectory};
use kr_transport::scheduler::{
    CONTROL_RESERVE_BYTES, SendLimits, StreamBudget, StreamClass, class_of, priority_of,
};
use kr_transport::streams::{DataStream, StreamRegistry};
use support::{OneDevice, Side, direct_addr, epochs, ledger, paired_pair, windows};

/// How many keystrokes are sent while the transfer runs.
const KEYSTROKES: usize = 32;

/// One chunk of the transfer. Large enough to fill the connection, small enough that an
/// unoptimised build is not slow about it.
const CHUNK_BYTES: usize = 256 * 1024;

/// How many chunks the host has to have taken before the keystrokes begin, so what they are
/// measured against is a transfer at steady state rather than one that is still opening.
const CHUNKS_BEFORE: usize = 4;

/// How long the test waits for a peer that should have answered by now.
///
/// A liveness bound rather than a measurement: the work inside it takes a fifth of a second, and
/// nothing about the property depends on how long it took. Without it a peer that stopped
/// answering leaves the test waiting rather than failing.
const DEADLINE: Duration = Duration::from_secs(20);

/// Wraps raw bytes as the byte string a frame carries.
fn payload(bytes: &[u8]) -> ParamsValue {
    ParamsValue::new(CanonicalValue::bytes(bytes))
}

/// Returns the bytes a frame carried.
fn bytes_of(value: &ParamsValue) -> &[u8] {
    match value.as_value() {
        CanonicalValue::Bytes(bytes) => bytes,
        other => panic!("a frame carried {other:?} rather than a byte string"),
    }
}

fn one_device(client: &Side) -> Arc<dyn PairedDirectory> {
    Arc::new(OneDevice {
        endpoint_id: client.record.endpoint_id,
        record: client.record,
    })
}

fn registry(connection_id: ConnectionId) -> Arc<StreamRegistry> {
    Arc::new(StreamRegistry::new(
        connection_id,
        Arc::new(StreamBudget::new(SendLimits::default())),
        None,
    ))
}

fn input_header(connection_id: ConnectionId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::TerminalInput,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([8; 16]))),
            attachment_id: Nullable::some(AttachmentId::new(Uuid::from_bytes([7; 16]))),
            transfer_id: Nullable::null(),
        },
    }
}

fn attachment_header(connection_id: ConnectionId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::AttachmentChunks,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: Nullable::some(TransferId::new(Uuid::from_bytes([6; 16]))),
        },
    }
}

/// KR-PERF-005 and KR-REQ-23.21, as the admission rule the connection's own limits produce.
///
/// A transfer holding every byte its ceiling allows still leaves the control reserve, so a
/// keystroke is admitted and one more transfer frame is not. At the connection's own default
/// limits, which is what a host and a client actually run with.
#[test]
fn a_transfer_never_takes_the_room_a_keystroke_needs() {
    let limits = SendLimits::default();
    let budget = Arc::new(StreamBudget::new(limits));

    let transfer = budget
        .reserve(StreamClass::Bulk, limits.max_bulk_queued_bytes)
        .expect("a transfer may hold its whole ceiling");
    assert_eq!(budget.bulk_queued_bytes(), limits.max_bulk_queued_bytes);

    assert!(
        matches!(
            budget.reserve(StreamClass::Bulk, 1),
            Err(TransportError::LimitExceeded {
                what: "queued bulk bytes",
                ..
            })
        ),
        "a transfer was admitted past its ceiling"
    );

    let keystroke = budget
        .reserve(StreamClass::Interactive, CONTROL_RESERVE_BYTES)
        .expect("the control reserve is still there with a transfer at its ceiling");
    assert_eq!(budget.queued_bytes(), limits.max_queued_bytes);

    drop(keystroke);
    drop(transfer);
    assert_eq!(budget.queued_bytes(), 0);
    assert_eq!(budget.bulk_queued_bytes(), 0);
}

/// A header for any kind, with the resource each kind's validation requires.
fn header_for(kind: StreamKind, connection_id: ConnectionId) -> StreamHeader {
    let session = Nullable::some(SessionId::new(Uuid::from_bytes([8; 16])));
    let attachment = Nullable::some(AttachmentId::new(Uuid::from_bytes([7; 16])));
    let transfer = Nullable::some(TransferId::new(Uuid::from_bytes([6; 16])));
    let resource = match kind {
        StreamKind::Control => StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: Nullable::null(),
        },
        StreamKind::TerminalInput | StreamKind::TerminalOutput => StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: session,
            attachment_id: attachment,
            transfer_id: Nullable::null(),
        },
        StreamKind::SemanticUpdates => StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: session,
            attachment_id: Nullable::null(),
            transfer_id: Nullable::null(),
        },
        StreamKind::AttachmentChunks => StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: transfer,
        },
    };
    StreamHeader {
        kind,
        connection_id,
        stream_id: Nullable::null(),
        resource,
    }
}

/// Every kind this version defines, control and receipts included.
const EVERY_KIND: [StreamKind; 5] = [
    StreamKind::Control,
    StreamKind::TerminalInput,
    StreamKind::TerminalOutput,
    StreamKind::SemanticUpdates,
    StreamKind::AttachmentChunks,
];

/// KR-PERF-005 and KR-REQ-23.21: the priority the connection is using, read back from it.
///
/// This is the observation the figure rests on. Both sides of every kind are checked, because the
/// opening side and the accepting side install it separately, and a stream whose priority never
/// reached the connection answers the default of zero rather than the class's number. Control and
/// the receipts it carries are covered here as well as terminal input, because section 23 names
/// both ahead of a transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_uses_the_priority_each_kind_is_scheduled_at() {
    let (host, client) = paired_pair().await;
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory = one_device(&client);

    let (installed, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    let (control, host_control) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async move {
        let connection = endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection");
        let clock = ManualClock::new();
        let challenges = ledger();
        let issuer = windows(&clock);
        let Admitted::Authorised(authorised) = handshake::accept(
            &connection,
            &identity,
            epochs(),
            directory.as_ref(),
            &challenges,
            &issuer,
        )
        .await
        .expect("an admitted connection") else {
            panic!("a paired endpoint is authorised");
        };
        // The connection's own control stream, which the handshake opened rather than the
        // registry, and which the host keeps for the life of the connection.
        if control.send(authorised.control_writer.priority()).is_err() {
            return;
        }
        let streams = registry(authorised.connection_id);
        // Each accepted stream is held for the life of the test, because a closed stream has no
        // priority left to report.
        let mut open = Vec::new();
        while let Ok(stream) = streams.accept(&connection).await {
            if installed.send((stream.kind(), stream.priority())).is_err() {
                return;
            }
            open.push(stream);
        }
    });

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");

    // The connection's own control stream first, on both sides of it. The handshake installs its
    // priority itself, so nothing the registry does can stand in for this.
    let control_priority = authorised.control_writer.priority();
    assert_eq!(
        control_priority,
        Some(priority_of(StreamKind::Control)),
        "the connection is not using the control stream's priority on the client's side"
    );
    let host_control_priority = tokio::time::timeout(DEADLINE, host_control)
        .await
        .expect("the host completed its handshake")
        .expect("the host reported its control stream");
    assert_eq!(
        host_control_priority,
        Some(priority_of(StreamKind::Control)),
        "the connection is not using the control stream's priority on the host's side"
    );

    let streams = registry(authorised.connection_id);

    let mut open = Vec::new();
    for kind in EVERY_KIND {
        let stream = streams
            .open(&connection, header_for(kind, authorised.connection_id))
            .await
            .unwrap_or_else(|error| panic!("a {kind:?} stream: {error}"));
        assert_eq!(
            stream.priority(),
            Some(priority_of(kind)),
            "the connection is not using the priority {kind:?} is scheduled at"
        );
        open.push(stream);
    }

    for _ in EVERY_KIND {
        let (kind, priority) = tokio::time::timeout(DEADLINE, accepted.recv())
            .await
            .expect("the host accepted every stream")
            .expect("the host is still accepting");
        assert_eq!(
            priority,
            Some(priority_of(kind)),
            "the accepting side is not using the priority {kind:?} is scheduled at"
        );
    }

    // The order the numbers have to be in, read off the connection rather than off the table.
    let installed = |kind: StreamKind| {
        open.iter()
            .find(|stream| stream.kind() == kind)
            .and_then(DataStream::priority)
            .unwrap_or_else(|| panic!("a {kind:?} stream with a priority"))
    };
    assert!(
        installed(StreamKind::Control) > installed(StreamKind::TerminalOutput),
        "control does not outrank live output on the connection"
    );
    assert!(
        installed(StreamKind::TerminalInput) > installed(StreamKind::AttachmentChunks),
        "a keystroke does not outrank a transfer on the connection"
    );
    assert!(
        installed(StreamKind::TerminalOutput) > installed(StreamKind::AttachmentChunks),
        "live output does not outrank a transfer on the connection"
    );

    connection.close(0u32.into(), b"done");
    serving.abort();
}

/// KR-PERF-005 and KR-REQ-23.21, over a real connection.
///
/// Every keystroke is answered, in order, while a transfer that never ends keeps moving through
/// the same connection. Nothing is timed: what is asserted is that each echo carried the keystroke
/// that was sent, that the transfer was still writing when the keystrokes were done, and that a
/// further chunk of it reached the far end after they began. A connection whose transfer had taken
/// the link could not do all three.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_keystroke_is_answered_while_a_transfer_runs() {
    let (host, client) = paired_pair().await;
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory = one_device(&client);

    // What the host took from the transfer, and one message a chunk so the keystrokes can wait for
    // the transfer to reach steady state without waiting on a clock.
    let taken = Arc::new(AtomicUsize::new(0));
    let (chunks, mut chunk_arrived) = tokio::sync::mpsc::unbounded_channel();

    let host_taken = Arc::clone(&taken);
    let serving = tokio::spawn(async move {
        let connection = endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection");
        let clock = ManualClock::new();
        let challenges = ledger();
        let issuer = windows(&clock);
        let admitted = handshake::accept(
            &connection,
            &identity,
            epochs(),
            directory.as_ref(),
            &challenges,
            &issuer,
        )
        .await
        .expect("an admitted connection");
        let Admitted::Authorised(authorised) = admitted else {
            panic!("a paired endpoint is authorised");
        };
        let streams = registry(authorised.connection_id);
        loop {
            let Ok(mut stream) = streams.accept(&connection).await else {
                return;
            };
            let kind = stream.kind();
            let taken = Arc::clone(&host_taken);
            let chunks = chunks.clone();
            tokio::spawn(async move {
                loop {
                    let frame = match stream.read_payload().await {
                        Ok(Some(frame)) => frame,
                        _ => return,
                    };
                    match kind {
                        // Echoing is what makes a keystroke's answer observable at all.
                        StreamKind::TerminalInput => {
                            if stream.write_payload(&frame).await.is_err() {
                                return;
                            }
                        }
                        // The transfer is drained and discarded. A receiver that stopped reading
                        // would fill the connection's flow-control window, which no priority can
                        // reach past, and that is a different case from this one.
                        StreamKind::AttachmentChunks => {
                            taken.fetch_add(1, Ordering::Relaxed);
                            let _ = chunks.send(());
                        }
                        _ => {}
                    }
                }
            });
        }
    });

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let streams = registry(authorised.connection_id);

    let mut input = streams
        .open(&connection, input_header(authorised.connection_id))
        .await
        .expect("an input stream");
    assert_eq!(
        class_of(input.kind()),
        StreamClass::Interactive,
        "a keystroke is not on an interactive stream"
    );

    let bulk_connection = connection.clone();
    let bulk_streams = Arc::clone(&streams);
    let bulk_connection_id = authorised.connection_id;
    let bulk: tokio::task::JoinHandle<Result<(), TransportError>> = tokio::spawn(async move {
        let mut stream = bulk_streams
            .open(&bulk_connection, attachment_header(bulk_connection_id))
            .await
            .expect("a transfer stream");
        assert_eq!(
            class_of(stream.kind()),
            StreamClass::Bulk,
            "a transfer is not on a bulk stream"
        );
        let chunk = payload(&vec![0u8; CHUNK_BYTES]);
        // Until the test aborts it. A transfer that stopped on its own would leave the keystrokes
        // measured against nothing, so the error that stopped it is what this task returns: the
        // assertion below reports the write that failed rather than reporting that a task ended.
        loop {
            stream.write_message(&chunk).await?;
        }
    });

    for chunk in 0..CHUNKS_BEFORE {
        tokio::time::timeout(DEADLINE, chunk_arrived.recv())
            .await
            .unwrap_or_else(|_| panic!("chunk {chunk} of the transfer never reached the host"))
            .expect("the transfer reached the host");
    }

    // Every chunk the host has already taken. What is left to arrive is what arrives from here on,
    // so the wait after the keystrokes cannot be satisfied by a chunk from before them.
    while chunk_arrived.try_recv().is_ok() {}
    let before = taken.load(Ordering::Relaxed);

    for keystroke in 0..KEYSTROKES {
        let bytes = format!("\x1b[{keystroke}A");
        let echoed = tokio::time::timeout(DEADLINE, async {
            input
                .write_message(&payload(bytes.as_bytes()))
                .await
                .expect("the keystroke was admitted and sent");
            input
                .read_message::<ParamsValue>()
                .await
                .expect("an echo")
                .expect("the stream did not end")
        })
        .await
        .unwrap_or_else(|_| panic!("keystroke {keystroke} was never answered"));
        assert_eq!(
            bytes_of(&echoed),
            bytes.as_bytes(),
            "keystroke {keystroke} came back as something else"
        );
    }

    // The transfer never ends, so a further chunk has to reach the far end. Waiting for one is
    // deterministic where comparing two counters is a race: a keystroke round trip is smaller than
    // a chunk, so every keystroke can finish inside one chunk's flight and the chunk arrive after
    // them. What this establishes is that the transfer went on moving from the moment the
    // keystrokes began, not that a chunk landed between two of them.
    tokio::time::timeout(DEADLINE, chunk_arrived.recv())
        .await
        .expect("a further chunk of the transfer reached the host after the keystrokes began")
        .expect("the transfer reached the host");
    let after = taken.load(Ordering::Relaxed);

    if bulk.is_finished() {
        // It only ends by failing: nothing else leaves that loop. Awaiting it names the write that
        // failed, or the panic, rather than saying that a task ended.
        match bulk.await {
            Ok(Err(error)) => panic!("the transfer stopped while the keystrokes ran: {error}"),
            Err(join) => panic!("the transfer's task ended while the keystrokes ran: {join}"),
            Ok(Ok(())) => unreachable!("the transfer's loop has no successful exit"),
        }
    }
    println!(
        "KR-PERF-005 property keystrokes={KEYSTROKES} chunks_during={} chunk_bytes={CHUNK_BYTES}",
        after - before
    );

    bulk.abort();
    connection.close(0u32.into(), b"done");
    serving.abort();
}
