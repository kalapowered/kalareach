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
//! Nothing here waits for a time. The reader reads one frame and then waits for a count that its
//! own connection reports: the STREAM frames it has taken, or, for large frames, the bytes of
//! datagrams. The sender writes the next small frame only when the receiving connection reports
//! that the last one has arrived, so each frame travels in a packet of its own; the case then
//! checks, from both connections' counts, that each frame was one STREAM frame and that the
//! datagrams were at least as many as the frames, so a sender that merged frames cannot make the
//! case pass without the long queue. The runtime has one thread, so a frame's length prefix and
//! its payload, written one after the other, reach the connection together.
//!
//! The case passes only when the reader gets every frame with its own content and in order, the
//! stream ends cleanly, and the connection then carries one more exchange on a new stream. A
//! connection that the library closes ends every wait at once, and the case reports the close.
//! The one deadline in the file decides nothing about the property: it turns a connection that
//! stopped answering into a named failure.

mod support;

use std::time::Duration;

use iroh::endpoint::Connection;
use kr_protocol::frame::StreamKind;
use kr_transport::ALPN;
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::endpoint::connect;
use support::{allow_streams, direct_addr, paired_pair};

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

/// What the reader says when the stream and the exchange after it went right.
const CLEAN: &str = "the stream ended cleanly and the further exchange went through";

/// What the reader waits for after its first frame.
#[derive(Clone, Copy)]
enum Behind {
    /// The receiving connection has taken this many STREAM frames since the case began.
    Frames(u64),
    /// The receiving connection has taken this many bytes of datagrams since the case began.
    Bytes(u64),
}

/// The frames of one case.
#[derive(Clone, Copy)]
struct Shape {
    payload: usize,
    frames: usize,
    behind: Behind,
    /// Whether the sender holds each frame back until the receiving connection has it, so that
    /// each travels in a packet of its own.
    one_to_a_packet: bool,
}

/// The counts of a connection that the case compares before and after.
#[derive(Clone, Copy)]
struct Counts {
    stream_frames_received: u64,
    stream_frames_sent: u64,
    datagrams_received: u64,
    bytes_received: u64,
}

impl Counts {
    fn of(connection: &Connection) -> Self {
        let stats = connection.stats();
        Self {
            stream_frames_received: stats.frame_rx.stream,
            stream_frames_sent: stats.frame_tx.stream,
            datagrams_received: stats.udp_rx.datagrams,
            bytes_received: stats.udp_rx.bytes,
        }
    }
}

/// What the reader reports: the frames it took, and how it ended.
struct ReaderEnd {
    read: usize,
    end: String,
}

/// The payload of frame `index`: its number first, then bytes that differ from frame to frame.
fn payload(index: usize, len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..len).map(|at| ((index + at) % 251) as u8).collect();
    bytes[..4].copy_from_slice(&(index as u32).to_be_bytes());
    bytes
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

/// Reads frame `index` and checks it. Returns false at the clean end of the stream.
async fn take(reader: &mut FrameReader, shape: Shape, index: usize) -> Result<bool, String> {
    match reader.read_payload().await {
        Ok(Some(frame)) if frame == payload(index, shape.payload) => Ok(true),
        Ok(Some(_)) => Err(format!(
            "frame {index} has the wrong content or is out of order"
        )),
        Ok(None) => Ok(false),
        Err(error) => Err(format!("the read after {index} frames failed: {error}")),
    }
}

/// Runs one case: a sender writes `shape.frames` frames of `shape.payload` bytes, a reader reads
/// one and waits until it is `shape.behind`, reads to the end, and the connection then carries
/// one more exchange.
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
    allow_streams(&accepted);
    let start = Counts::of(&accepted);
    let sent_at_start = Counts::of(&dialled).stream_frames_sent;

    // The reader is the host's side of the connection.
    let reader_connection = accepted.clone();
    let reader = tokio::spawn(async move {
        let (_send, recv) = reader_connection.accept_bi().await.expect("a stream");
        let mut reader = FrameReader::new(recv, StreamKind::TerminalOutput);
        let mut read = 0_usize;
        let ended = |read: usize, end: String| ReaderEnd { read, end };
        match take(&mut reader, shape, read).await {
            Ok(true) => read += 1,
            Ok(false) => return ended(read, "the stream held no frame".to_owned()),
            Err(error) => return ended(read, error),
        }
        // Behind: nothing is read until the count that the case waits for holds, or the
        // connection ends.
        match shape.behind {
            Behind::Frames(behind) => {
                until(&reader_connection, || {
                    Counts::of(&reader_connection).stream_frames_received
                        - start.stream_frames_received
                        >= behind
                })
                .await;
                let now = Counts::of(&reader_connection);
                if reader_connection.close_reason().is_none() {
                    let datagrams = now.datagrams_received - start.datagrams_received;
                    assert!(
                        datagrams >= behind,
                        "the receiving connection took {datagrams} datagrams for {behind} \
                         frames: the frames did not travel one to a packet, so the case \
                         would not hold the queue it is meant to hold"
                    );
                }
            }
            Behind::Bytes(bytes) => {
                until(&reader_connection, || {
                    Counts::of(&reader_connection).bytes_received - start.bytes_received >= bytes
                })
                .await;
            }
        }
        loop {
            match take(&mut reader, shape, read).await {
                Ok(true) => read += 1,
                Ok(false) => break,
                Err(error) => return ended(read, error),
            }
        }
        // One more exchange on the same connection, now that the reader has caught up.
        let exchange = async {
            let (send, recv) = reader_connection
                .accept_bi()
                .await
                .map_err(|error| format!("no second stream: {error}"))?;
            let mut asked = FrameReader::new(recv, StreamKind::Control);
            let mut answering = FrameWriter::new(send, StreamKind::Control);
            let mut question = asked
                .read_payload()
                .await
                .map_err(|error| format!("no question: {error}"))?
                .ok_or_else(|| "the second stream ended without a question".to_owned())?;
            question.reverse();
            answering
                .write_payload(&question)
                .await
                .map_err(|error| format!("no answer: {error}"))?;
            answering.finish().map_err(|error| error.to_string())
        }
        .await;
        match exchange {
            Ok(()) => ended(read, CLEAN.to_owned()),
            Err(error) => ended(
                read,
                format!("the stream ended cleanly, but the further exchange failed: {error}"),
            ),
        }
    });

    // The sender is the client's side. It hands the connection back so that it stays open until
    // the reader has finished.
    let paced_by = accepted.clone();
    let sender = tokio::spawn(async move {
        let outcome: Result<(u64, u64), String> = async {
            let (send, _recv) = dialled.open_bi().await.map_err(|error| error.to_string())?;
            let mut writer = FrameWriter::new(send, StreamKind::TerminalOutput);
            for index in 0..shape.frames {
                writer
                    .write_payload(&payload(index, shape.payload))
                    .await
                    .map_err(|error| format!("the write of frame {index} failed: {error}"))?;
                if shape.one_to_a_packet {
                    // The next frame waits until the receiving connection reports this one.
                    let wanted = start.stream_frames_received + index as u64 + 1;
                    let arrived = until(&paced_by, || {
                        Counts::of(&paced_by).stream_frames_received >= wanted
                    })
                    .await;
                    if !arrived {
                        return Err(format!("the connection ended after frame {index}"));
                    }
                }
            }
            writer.finish().map_err(|error| error.to_string())?;
            // The STREAM frames that the sender has sent and that the receiving connection has
            // taken, counted before the second stream adds its own.
            let sent = Counts::of(&dialled).stream_frames_sent - sent_at_start;
            let taken = Counts::of(&paced_by).stream_frames_received - start.stream_frames_received;
            // One more exchange on the same connection, on a new stream.
            let (send, recv) = dialled.open_bi().await.map_err(|error| error.to_string())?;
            let mut asking = FrameWriter::new(send, StreamKind::Control);
            let mut answered = FrameReader::new(recv, StreamKind::Control);
            let question = payload(7, 64);
            asking
                .write_payload(&question)
                .await
                .map_err(|error| format!("the question failed: {error}"))?;
            let answer = answered
                .read_payload()
                .await
                .map_err(|error| format!("no answer came: {error}"))?
                .ok_or_else(|| "the answer stream ended empty".to_owned())?;
            let mut expected = question;
            expected.reverse();
            if answer != expected {
                return Err("the answer is not the question reversed".to_owned());
            }
            Ok((sent, taken))
        }
        .await
        .map_err(|error| {
            format!(
                "{error}; the sender's connection closed with {:?}, the receiving one with {:?}",
                dialled.close_reason(),
                paced_by.close_reason()
            )
        });
        (dialled, outcome)
    });

    let reader_end = reader.await.expect("the reader task");
    let (_dialled, sender_end) = sender.await.expect("the sender task");
    assert!(
        reader_end.read == shape.frames && reader_end.end == CLEAN && sender_end.is_ok(),
        "the connection did not survive a reader that fell behind: the reader read {} of {} \
         frames and then: {}; the sender: {sender_end:?}",
        reader_end.read,
        shape.frames,
        reader_end.end,
    );
    if shape.one_to_a_packet {
        // Each frame went out, and came in, as one STREAM frame; the end of the stream may add
        // one more.
        let frames = shape.frames as u64;
        let (sent, taken) = *sender_end.as_ref().expect("the sender's counts");
        assert!(
            (frames..=frames + 1).contains(&sent) && (frames..=frames + 1).contains(&taken),
            "{frames} frames went out as {sent} STREAM frames and came in as {taken}: they were merged"
        );
    }
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
            behind: Behind::Frames(SMALL_FRAMES_BEHIND as u64),
            one_to_a_packet: true,
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
            one_to_a_packet: false,
        }),
    )
    .await
    .expect("the case finishes within its deadline");
}
