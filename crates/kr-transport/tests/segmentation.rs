//! A bulk transfer between two endpoints is carried in single datagrams, never in segmented batches,
//! in each direction.
//!
//! Some kernels refuse a segmented send on a device with no transmit checksum offload (Linux
//! before 6.11; the Android emulator's Wi-Fi interface is one). The socket layer then stops batching
//! on that socket, but a connection that was already open keeps asking for batches, every one of
//! them is refused, and whenever it has more than one datagram to send at a time its stream data can
//! stall while single datagrams still pass. A device that refuses a batch cannot be made in a
//! process, and the endpoint does not hand out its socket, so this watches the other end of the same
//! fact: when a sender hands the kernel a batch, the Linux loopback delivers it to a receiving socket
//! that asked for coalesced reads as one coalesced read, which the receiving endpoint counts. A
//! transfer with no coalesced read was sent as single datagrams.
//!
//! That inference needs a Linux kernel with UDP segmentation offload and a receiving socket on which
//! `UDP_GRO` took, both of which the socket layer treats as optional. Where either is missing the
//! count is zero whatever is sent, as it is on every operating system whose sockets do not coalesce,
//! and the case then checks only that each transfer arrived. A Linux run that fails when the setting
//! is taken away is the evidence that the leg has something to show.

mod support;

use kr_transport::endpoint::connect;
use support::{Side, direct_addr, paired_pair};

/// One mebibyte is about 720 datagrams at the 1,452 bytes a loopback connection settles on, far more
/// than the few the handshake and its acknowledgements need.
const TRANSFER: usize = 1 << 20;

/// The datagrams a receiving endpoint counted: all of them, and those that arrived coalesced.
fn counted(side: &Side) -> (u64, u64) {
    let socket = &side.endpoint.metrics().socket;
    (socket.recv_datagrams.get(), socket.recv_gro_datagrams.get())
}

/// A transfer that needs many datagrams in a row is exactly where a batch would be offered, and none
/// is: every datagram is sent on its own, by the dialling side and by the accepting side alike.
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
    let (mut send, mut reply) = connection.open_bi().await.expect("a stream");
    let payload = vec![0x5a_u8; TRANSFER];

    // The dialling side sends, written and read together so that no window can hold the write.
    let upload = async {
        send.write_all(&payload).await.expect("the payload written");
        send.finish().expect("the stream finished");
    };
    let accepted = accepting.await.expect("the accepting task");
    let download = async {
        let (answer, mut receive) = accepted.accept_bi().await.expect("the stream");
        let received = receive
            .read_to_end(2 * TRANSFER)
            .await
            .expect("the payload read");
        (answer, received)
    };
    let ((), (mut answer, received)) = tokio::join!(upload, download);
    assert_eq!(received.len(), TRANSFER, "the whole payload arrived");

    // The accepting side sends it back.
    let answering = async {
        answer
            .write_all(&payload)
            .await
            .expect("the answer written");
        answer.finish().expect("the answer finished");
    };
    let returning = async {
        reply
            .read_to_end(2 * TRANSFER)
            .await
            .expect("the answer read")
    };
    let ((), returned) = tokio::join!(answering, returning);
    assert_eq!(returned.len(), TRANSFER, "the whole answer arrived");

    let (host_datagrams, host_coalesced) = counted(&host);
    let (client_datagrams, client_coalesced) = counted(&client);
    assert!(
        host_datagrams >= 500 && client_datagrams >= 500,
        "each transfer crossed a socket as datagrams, {host_datagrams} to the host and \
         {client_datagrams} to the client"
    );
    assert_eq!(
        (host_coalesced, client_coalesced),
        (0, 0),
        "no datagram reached a receiving socket in a coalesced batch, to the host or to the client"
    );
    connection.close(0_u32.into(), b"done");
    client.endpoint.close().await;
    host.endpoint.close().await;
}
