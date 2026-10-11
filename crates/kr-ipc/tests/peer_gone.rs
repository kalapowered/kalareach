//! What a connection's writer can say, at once, of its peer: that it has gone, that it has sent
//! bytes nobody has read, or that it is there and quiet.
//!
//! A runtime learns that a peer closed only when it next turns its reactor, so a reader polled in
//! between says nothing. The writer asks the operating system instead, and these tests drive a real
//! connection to show what it says whatever the peer has sent, and that a caller told how much is
//! waiting can read exactly that.

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::{FrameReader, FrameWriter, PeerState, split};
use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::frame::StreamKind;

/// A connection over a real local endpoint, as its two ends hold it.
struct Pair {
    _tree: kr_ipc::testing::TempHost,
    server: (FrameReader, FrameWriter),
    client: (FrameReader, FrameWriter),
}

async fn pair() -> Pair {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint path");
    let listener = Listener::bind(&endpoint).expect("a local endpoint");
    let accepting = tokio::spawn(async move {
        let (connection, _peer) = listener.accept().await.expect("accepts the client");
        connection
    });
    let client = Connection::connect(&endpoint).await.expect("connects");
    let server = accepting.await.expect("the accepting task finishes");
    Pair {
        _tree: tree,
        server: split(server, StreamKind::Control),
        client: split(client, StreamKind::Control),
    }
}

/// Sends one whole frame from `writer`, and returns how many bytes it is on the wire.
#[cfg(unix)]
fn send(writer: &mut FrameWriter) -> usize {
    let sent = FrameWriter::encode(
        StreamKind::Control,
        &ControlFrame::Event(ControlEvent::Keepalive),
    )
    .expect("encodes");
    assert!(
        matches!(
            writer.begin_frame(&sent),
            Ok(kr_ipc::framed::Wrote::Complete)
        ),
        "the frame goes whole"
    );
    sent.len()
}

#[tokio::test]
async fn a_peer_that_is_there_and_has_said_nothing_is_quiet() {
    let pair = pair().await;
    assert_eq!(pair.server.1.peer_state(), PeerState::Quiet);
}

/// A peer that has closed is gone. A Windows pipe's handle is released when its runtime next turns,
/// so there the answer is waited for, to a bound; on Unix it is the system's own at once.
#[tokio::test]
async fn a_peer_that_has_closed_is_gone_whether_or_not_the_runtime_has_been_told() {
    let pair = pair().await;
    let Pair {
        _tree,
        server,
        client,
    } = pair;
    drop(client);
    // Nothing has polled the server's reader, so the runtime has not been told.
    #[cfg(unix)]
    assert_eq!(server.1.peer_state(), PeerState::Gone);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while server.1.peer_state() != PeerState::Gone {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer closed and the system never said so"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_peer_that_has_ended_what_it_sends_is_gone_though_it_still_reads() {
    let pair = pair().await;
    pair.client
        .1
        .shut_down(std::net::Shutdown::Write)
        .expect("ends what the client sends");
    assert_eq!(pair.server.1.peer_state(), PeerState::Gone);
}

/// Bytes the peer has sent and nobody has read are not a peer that has gone, however it ended
/// after them: the system reports the end only behind them. Reading what was said to be waiting
/// is what lets the end be found.
#[cfg(unix)]
#[tokio::test]
async fn a_peer_that_sent_a_frame_and_went_is_gone_once_the_frame_is_read() {
    let mut pair = pair().await;
    let length = send(&mut pair.client.1);
    pair.client
        .1
        .shut_down(std::net::Shutdown::Write)
        .expect("ends what the client sends");
    assert_eq!(pair.server.1.peer_state(), PeerState::Unread(length));

    let mut waiting = length;
    let frame = pair
        .server
        .0
        .read_message_within::<ControlFrame>(&mut waiting)
        .await
        .expect("reads the frame that was waiting");
    assert!(matches!(
        frame,
        Some(ControlFrame::Event(ControlEvent::Keepalive))
    ));
    assert_eq!(waiting, 0);
    assert_eq!(pair.server.1.peer_state(), PeerState::Gone);
}

/// A read bounded by what was waiting returns the frames that are whole in it, leaves the one it
/// only begins to the next read, and never waits for the peer to send the rest.
#[cfg(unix)]
#[tokio::test]
async fn a_read_within_what_was_waiting_leaves_a_frame_it_only_begins() {
    let mut pair = pair().await;
    let length = send(&mut pair.client.1);
    send(&mut pair.client.1);
    let PeerState::Unread(waiting) = pair.server.1.peer_state() else {
        panic!("two frames are waiting");
    };
    assert_eq!(waiting, 2 * length);

    // Everything but the last three bytes of the second frame.
    let mut budget = waiting - 3;
    let first = pair
        .server
        .0
        .read_message_within::<ControlFrame>(&mut budget)
        .await
        .expect("reads the first frame");
    assert!(first.is_some(), "the first frame is whole in the budget");
    let second = pair
        .server
        .0
        .read_message_within::<ControlFrame>(&mut budget)
        .await
        .expect("stops at the end of the budget");
    assert!(second.is_none(), "the second frame is only begun");
    assert_eq!(budget, 0);

    // The next read, with no bound, continues it.
    let rest = pair
        .server
        .0
        .read_message::<ControlFrame>()
        .await
        .expect("finishes the second frame");
    assert!(matches!(rest, ControlFrame::Event(ControlEvent::Keepalive)));
}

/// A length the reader refuses leaves the frame unread, and a later read is refused for it again
/// instead of finding nothing left in its budget to read and coming back for more. The reads run
/// on a worker of their own and the wait for them is bounded, so a read that never came back would
/// fail the test where the bound ends, though the runtime would hold the test until the harness
/// ended it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_length_is_refused_each_time_it_is_read() {
    let mut pair = pair().await;
    // A frame that declares no payload at all.
    assert!(matches!(
        pair.client.1.begin_frame(&[0, 0, 0, 0]),
        Ok(kr_ipc::framed::Wrote::Complete)
    ));
    let mut reader = pair.server.0;
    let reading = tokio::spawn(async move {
        let first = reader.read_payload().await;
        let again = reader.read_payload().await;
        (first, again)
    });
    let (first, again) = tokio::time::timeout(std::time::Duration::from_secs(30), reading)
        .await
        .expect("a refused length is refused again and not waited out")
        .expect("the reading task finishes");
    for refused in [first, again] {
        assert!(
            matches!(
                refused,
                Err(kr_ipc::error::IpcError::Frame(
                    kr_protocol::frame::FrameError::EmptyPayload
                ))
            ),
            "{refused:?}"
        );
    }
}

/// A peer that has sent more than a runtime holds for itself leaves bytes in the connection, and
/// the system counts them. A Windows pipe's runtime keeps a read of its own posted into a buffer of
/// a few kilobytes, so the peer sends enough to fill it and more, and the writer waits to a bound
/// for the count. A read within that count then returns, whichever frames it finds, and does not
/// wait for the peer to send anything more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_has_sent_more_than_the_runtime_holds_is_counted_and_the_count_can_be_read() {
    let pair = pair().await;
    let Pair {
        _tree,
        server,
        client,
    } = pair;
    let (mut reader, writer) = server;
    let (_client_reader, mut client_writer) = client;
    // Some tens of kilobytes of whole frames, written by a task of its own: a connection that holds
    // less keeps the task waiting for the reader, which does no harm here. A frame that cannot be
    // written is recorded, and fails the test below.
    let send_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let failed = std::sync::Arc::clone(&send_failed);
    let sending = tokio::spawn(async move {
        let frame = ControlFrame::Event(ControlEvent::Keepalive);
        for _ in 0..4000 {
            if client_writer.write_message(&frame).await.is_err() {
                failed.store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }
        }
        client_writer
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let counted = loop {
        if let PeerState::Unread(counted) = writer.peer_state() {
            break counted;
        }
        assert!(
            !send_failed.load(std::sync::atomic::Ordering::SeqCst),
            "a frame the peer sent could not be written"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer sent frames and the system never counted any"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    let mut budget = counted;
    let read = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match reader
                .read_message_within::<ControlFrame>(&mut budget)
                .await
            {
                Ok(Some(_)) => {}
                other => break other,
            }
        }
    })
    .await
    .expect("a read within the count does not wait for the peer to send more");
    assert!(read.is_ok(), "{read:?}");
    // The sender is ended first, with this end of the connection still open, and the flag is read
    // once it has stopped: a write that failed while it ran is then in the flag.
    sending.abort();
    if let Err(ended) = sending.await {
        assert!(ended.is_cancelled(), "the sending task panicked: {ended:?}");
    }
    assert!(
        !send_failed.load(std::sync::atomic::Ordering::SeqCst),
        "a frame the peer sent could not be written"
    );
}
