//! A bulk transfer between two endpoints is carried in single datagrams, never in segmented batches.
//!
//! Some kernels refuse a segmented send on a device with no transmit checksum offload (Linux
//! before 6.11; the Android emulator's Wi-Fi interface is one). The socket layer then stops batching
//! on that socket, but a connection that was already open keeps asking for batches, every one of
//! them is refused, and its stream data stalls while single datagrams still pass. A device that
//! refuses a batch cannot be made in a process, and the endpoint does not hand out its socket, so
//! this watches the other end of the same fact: when a sender hands the kernel a batch, the Linux
//! loopback delivers it to the receiving socket as one coalesced read, which the receiving endpoint
//! counts. A transfer with no coalesced read was sent as single datagrams.
//!
//! The count is zero on every operating system whose sockets do not coalesce, so on those this
//! checks that the transfer arrived and nothing more; the leg that has something to show runs on
//! Linux.

mod support;

use kr_transport::endpoint::connect;
use support::{direct_addr, paired_pair};

/// One mebibyte is about 720 datagrams at the 1,452 bytes a loopback connection settles on, far more
/// than the few the handshake and its acknowledgements need.
const TRANSFER: usize = 1 << 20;

/// A transfer that needs many datagrams in a row is exactly where a batch would be offered, and
/// none is: every datagram is sent on its own.
#[tokio::test]
async fn a_bulk_transfer_is_carried_in_single_datagrams() {
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
    let connection = connect(&client.endpoint, direct_addr(&host), kr_transport::ALPN)
        .await
        .expect("a connection");
    let (mut send, _reply) = connection.open_bi().await.expect("a stream");
    let payload = vec![0x5a_u8; TRANSFER];
    send.write_all(&payload).await.expect("the payload written");
    send.finish().expect("the stream finished");

    let accepted = accepting.await.expect("the accepting task");
    let (_answer, mut receive) = accepted.accept_bi().await.expect("the stream");
    let received = receive
        .read_to_end(2 * TRANSFER)
        .await
        .expect("the payload read");
    assert_eq!(received.len(), TRANSFER, "the whole payload arrived");

    let socket = &host.endpoint.metrics().socket;
    assert!(
        socket.recv_datagrams.get() >= 500,
        "the transfer crossed the socket as datagrams, {} of them",
        socket.recv_datagrams.get()
    );
    assert_eq!(
        socket.recv_gro_datagrams.get(),
        0,
        "no datagram reached the receiving socket in a coalesced batch"
    );
    connection.close(0_u32.into(), b"done");
    client.endpoint.close().await;
    host.endpoint.close().await;
}
