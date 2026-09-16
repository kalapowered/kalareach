//! Remote input is prioritised over a bulk transfer.
//!
//! KR-PERF-005 puts a figure on this: application scheduling adds less than 25 ms p95 above the
//! measured path round trip while a transfer runs. A figure needs the host section 27 describes,
//! and `tests/perf.rs` is where it is taken. What is asserted here is the property behind the
//! figure, through the mechanism that produces it, and nothing here reads a clock. So it holds on
//! a shared runner, on a loaded laptop and in an unoptimised build, which is what a property of
//! the design should do.
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
//! queued transfer bytes while the connection has capacity. What that comes to end to end is
//! progress: every keystroke is answered, in order, while the transfer keeps moving.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    CONTROL_RESERVE_BYTES, SendLimits, StreamBudget, StreamClass, class_of,
};
use kr_transport::streams::StreamRegistry;
use support::{OneDevice, Side, direct_addr, epochs, ledger, paired_pair, windows};

/// How many keystrokes are sent while the transfer runs.
const KEYSTROKES: usize = 32;

/// One chunk of the transfer. Large enough to fill the connection, small enough that an
/// unoptimised build is not slow about it.
const CHUNK_BYTES: usize = 256 * 1024;

/// How many chunks the host has to have taken before the keystrokes begin, so what they are
/// measured against is a transfer at steady state rather than one that is still opening.
const CHUNKS_BEFORE: usize = 4;

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

/// KR-PERF-005 and KR-REQ-23.21, over a real connection.
///
/// Every keystroke is answered, in order, while a transfer that never ends keeps moving through
/// the same connection. No wall clock: what is asserted is that both sides made progress and that
/// each echo carried the keystroke that was sent, which a connection whose transfer had taken the
/// link could not do.
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
    let sent = Arc::new(AtomicUsize::new(0));
    let bulk_sent = Arc::clone(&sent);
    let bulk = tokio::spawn(async move {
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
        loop {
            // Every chunk is charged against the connection's queued-bytes ceiling before it is
            // handed over, which is the admission half of the mechanism.
            if stream.write_message(&chunk).await.is_err() {
                return;
            }
            bulk_sent.fetch_add(1, Ordering::Relaxed);
        }
    });

    for _ in 0..CHUNKS_BEFORE {
        chunk_arrived
            .recv()
            .await
            .expect("the transfer reached the host");
    }

    let before = taken.load(Ordering::Relaxed);
    for keystroke in 0..KEYSTROKES {
        let bytes = format!("\x1b[{keystroke}A");
        input
            .write_message(&payload(bytes.as_bytes()))
            .await
            .expect("the keystroke was admitted and sent");
        let echoed = input
            .read_message::<ParamsValue>()
            .await
            .expect("an echo")
            .expect("the stream did not end");
        assert_eq!(
            bytes_of(&echoed),
            bytes.as_bytes(),
            "keystroke {keystroke} came back as something else"
        );
    }
    let after = taken.load(Ordering::Relaxed);

    assert!(
        after > before,
        "the transfer moved nothing while the keystrokes went through, so they were not measured \
         against one: {before} chunks before, {after} after"
    );
    assert!(
        sent.load(Ordering::Relaxed) >= CHUNKS_BEFORE,
        "the transfer stopped before the keystrokes began"
    );
    println!(
        "KR-PERF-005 property keystrokes={KEYSTROKES} chunks_during={} chunk_bytes={CHUNK_BYTES}",
        after - before
    );

    bulk.abort();
    connection.close(0u32.into(), b"done");
    serving.abort();
}
