//! Whether a connection's writer can say, at once, that its peer has gone.
//!
//! A runtime learns that a peer closed only when it next turns its reactor, so a reader polled in
//! between says nothing. The writer asks the operating system instead, and these tests drive a real
//! connection to show that it says nothing of a peer that is there, whatever that peer has sent,
//! and that it says so as soon as the peer has gone.

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::{FrameReader, FrameWriter, split};
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

#[tokio::test]
async fn a_peer_that_is_there_is_not_gone() {
    let pair = pair().await;
    assert!(
        !pair.server.1.peer_is_gone(),
        "a peer that has said nothing"
    );
}

/// A frame the peer has sent and nobody has read is a peer that is there, not one that has gone.
#[cfg(unix)]
#[tokio::test]
async fn a_peer_with_a_frame_nobody_has_read_is_not_gone() {
    let mut pair = pair().await;
    let sent = FrameWriter::encode(
        StreamKind::Control,
        &kr_protocol::envelope::ControlFrame::Event(kr_protocol::envelope::ControlEvent::Keepalive),
    )
    .expect("encodes");
    assert!(
        matches!(
            pair.client.1.begin_frame(&sent),
            Ok(kr_ipc::framed::Wrote::Complete)
        ),
        "the client sends a frame"
    );
    assert!(!pair.server.1.peer_is_gone());
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
    assert!(server.1.peer_is_gone());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !server.1.peer_is_gone() {
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
    assert!(pair.server.1.peer_is_gone());
}
