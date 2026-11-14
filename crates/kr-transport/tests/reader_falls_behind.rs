//! A connection survives a reader that falls behind.
//!
//! A reader that is only slow, and a peer that sends nothing wrong, must not cost the connection.
//! The QUIC library keeps the data of a stream that the application has not read as a queue of
//! chunks, one for each frame that carried it, and it ends the connection when that queue grows
//! past a fixed number of chunks. The number counts chunks, not bytes. The stream's receive window
//! bounds how many bytes a sender may be ahead of its reader, so large frames, which fill whole
//! packets, reach the window with a short queue; small frames, one to a packet, can make a long
//! queue inside the window. This case holds a reader still while a sender writes each of the two
//! kinds, over the product's own endpoints and frame codec on loopback with no relay and no
//! discovery, and then lets the reader read everything.
//!
//! Nothing here waits for a time. The reader reads one frame and then waits for a count: the
//! sender's own count of the frames it has written, or, for large frames, the bytes the
//! receiving connection reports it has taken. The sender writes the next small frame only when
//! the connection reports that the last one has left as a STREAM frame, so each frame travels in
//! a packet of its own; the receiving connection's datagram count is checked against that. The
//! runtime has one thread, so a frame's length prefix and its payload, written one after the
//! other, reach the connection together. The one deadline in the file decides nothing about the
//! property: it turns a connection that stopped answering into a named failure.

mod support;

use std::time::Duration;

use iroh::endpoint::Connection;
use kr_protocol::frame::StreamKind;
use kr_transport::ALPN;
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::endpoint::connect;
use support::{direct_addr, paired_pair};
use tokio::sync::watch;

/// How long the whole case may take. A case that runs into it has a connection that stopped.
const DEADLINE: Duration = Duration::from_secs(120);

/// A small frame's payload, in bytes. With its prefix it fills most of a packet that carries
/// nothing else.
const SMALL_FRAME: usize = 200;

/// How many small frames the reader lets pile up before it reads again: past the limit on queued
/// chunks that the library has, which no bytes-based window reaches at this size.
const SMALL_FRAMES_BEHIND: usize = 2_100;

/// How many small frames the sender writes in all.
const SMALL_FRAMES: usize = 2_400;

/// A large frame's payload, in bytes: many full packets.
const LARGE_FRAME: usize = 1_000_000;

/// How many large frames the sender writes in all.
const LARGE_FRAMES: usize = 4;

/// The library's default receive window for one stream, in bytes, which the product keeps. A
/// receiving connection that has taken this many bytes of datagrams holds about 1.2 MB of stream
/// data that nobody has read.
const STREAM_WINDOW: u64 = 1_250_000;

/// What the reader waits for after its first frame.
#[derive(Clone, Copy)]
enum Behind {
    /// The sender has written this many frames, and the receiving connection has taken them.
    Frames(usize),
    /// The receiving connection has taken this many bytes of datagrams.
    Bytes(u64),
}

/// The frames of one case.
#[derive(Clone, Copy)]
struct Shape {
    payload: usize,
    frames: usize,
    behind: Behind,
}

/// Polls `condition` until it holds, giving the other tasks of the runtime the thread between
/// looks. Returns whether it held, and false when the connection ended first.
async fn until(connection: &Connection, condition: impl Fn() -> bool) -> bool {
    while !condition() {
        if connection.close_reason().is_some() {
            return false;
        }
        tokio::task::yield_now().await;
    }
    true
}

/// Runs one case: a sender writes `shape.frames` frames of `shape.payload` bytes, a reader reads
/// one and waits until it is `shape.behind`, and then reads to the end.
async fn a_reader_falls_behind(shape: Shape) {
    let (host, client) = paired_pair().await;
    let accepting = {
        let endpoint = host.endpoint.clone();
        tokio::spawn(async move {
            endpoint
                .accept()
                .await
                .expect("an incoming connection")
                .await
                .expect("a connection")
        })
    };
    let dialled = connect(&client.endpoint, direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let accepted = accepting.await.expect("the accepting task");

    let (written_tx, mut written_rx) = watch::channel(0_usize);

    // The reader is the host's side of the connection.
    let reader_connection = accepted.clone();
    let reader = tokio::spawn(async move {
        let (_send, recv) = reader_connection.accept_bi().await.expect("a stream");
        let mut reader = FrameReader::new(recv, StreamKind::TerminalOutput);
        let mut read = 0_usize;
        match reader.read_payload().await {
            Ok(Some(_)) => read += 1,
            other => return (read, format!("the first frame did not come: {other:?}")),
        }
        // Behind: nothing is read until the count that the case waits for holds, or the
        // connection ends.
        match shape.behind {
            Behind::Frames(behind) => {
                let sent = written_rx.wait_for(|written| *written >= behind);
                let sender_got_there = tokio::select! {
                    sent = sent => sent.is_ok(),
                    _ended = reader_connection.closed() => false,
                };
                if sender_got_there {
                    let taken = until(&reader_connection, || {
                        reader_connection.stats().frame_rx.stream >= behind as u64
                    })
                    .await;
                    let datagrams = reader_connection.stats().udp_rx.datagrams;
                    if taken {
                        assert!(
                            datagrams >= behind as u64,
                            "the receiving connection took {datagrams} datagrams for {behind} \
                             frames: the frames did not travel one to a packet, so the case \
                             would not hold the queue it is meant to hold"
                        );
                    }
                }
            }
            Behind::Bytes(bytes) => {
                until(&reader_connection, || {
                    reader_connection.stats().udp_rx.bytes >= bytes
                })
                .await;
            }
        }
        loop {
            match reader.read_payload().await {
                Ok(Some(_)) => read += 1,
                Ok(None) => return (read, "the stream ended cleanly".to_owned()),
                Err(error) => return (read, format!("the read failed: {error}")),
            }
        }
    });

    // The sender is the client's side. It hands the connection back so that it stays open until
    // the reader has read the end.
    let sender = tokio::spawn(async move {
        let outcome = async {
            let (send, _recv) = dialled.open_bi().await.map_err(|error| error.to_string())?;
            let mut writer = FrameWriter::new(send, StreamKind::TerminalOutput);
            let payload = vec![0x5a_u8; shape.payload];
            for written in 1..=shape.frames {
                let before = dialled.stats().frame_tx.stream;
                writer
                    .write_payload(&payload)
                    .await
                    .map_err(|error| format!("the write of frame {written} failed: {error}"))?;
                // The next frame waits until the connection reports that this one has left.
                until(&dialled, || dialled.stats().frame_tx.stream > before).await;
                let _ = written_tx.send(written);
            }
            writer.finish().map_err(|error| error.to_string())
        }
        .await
        .map_err(|error| {
            format!(
                "{error}; the connection's close: {:?}",
                dialled.close_reason()
            )
        });
        (dialled, outcome)
    });

    let (read, reader_end) = reader.await.expect("the reader task");
    let (_dialled, sender_end) = sender.await.expect("the sender task");
    assert!(
        read == shape.frames && reader_end == "the stream ended cleanly" && sender_end.is_ok(),
        "the connection did not survive a reader that fell behind: the reader read {read} of {} \
         frames and then: {reader_end}; the sender: {sender_end:?}",
        shape.frames
    );
}

/// Frames of a few hundred bytes, one to a packet: the queue of chunks gets long inside the
/// window.
#[tokio::test]
async fn a_reader_behind_by_many_small_frames_keeps_its_connection() {
    tokio::time::timeout(
        DEADLINE,
        a_reader_falls_behind(Shape {
            payload: SMALL_FRAME,
            frames: SMALL_FRAMES,
            behind: Behind::Frames(SMALL_FRAMES_BEHIND),
        }),
    )
    .await
    .expect("the case finishes within its deadline");
}

/// Frames of a megabyte: the window, not the queue, bounds how far behind the reader gets, and the
/// reader catches up when it reads.
#[tokio::test]
async fn a_reader_behind_by_a_window_of_large_frames_keeps_its_connection() {
    tokio::time::timeout(
        DEADLINE,
        a_reader_falls_behind(Shape {
            payload: LARGE_FRAME,
            frames: LARGE_FRAMES,
            behind: Behind::Bytes(STREAM_WINDOW),
        }),
    )
    .await
    .expect("the case finishes within its deadline");
}
