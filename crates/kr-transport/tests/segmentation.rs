//! A bulk transfer between two endpoints is carried in single datagrams, never in segmented
//! batches, in each direction, and a control connection on the same pair shows that the case is
//! able to see a batch.
//!
//! Some kernels refuse a segmented send on some devices and routes, for example Linux before 6.11
//! on a device with no transmit checksum offload (the Android emulator's Wi-Fi interface is one),
//! Linux on an IPsec policy route, and Windows, whose own refusal the socket layer treats the same
//! way. The socket layer then stops batching on that socket, but a connection that was already
//! open keeps asking for batches, every one of them is refused, and whenever it has more than one
//! datagram to send at a time its stream data can stall while single datagrams still pass. A
//! device that refuses a batch cannot be made in a process, and the endpoint does not hand out its
//! socket, so this watches the other end of the same fact: when a sender hands the kernel a batch,
//! the Linux loopback delivers it to a receiving socket that asked for coalesced reads as one
//! coalesced read, which the receiving endpoint counts. A transfer with no coalesced read was sent
//! as single datagrams.
//!
//! A count of zero says nothing where the host cannot show a batch at all: a kernel without UDP
//! segmentation offload, a loopback that splits a batch itself, a receiving socket on which
//! `UDP_GRO` did not take, or an operating system whose sockets do not coalesce. So the case also
//! opens a control connection on the same pair with iroh's default transport configuration at both
//! ends, which keeps segmentation offload on, and moves the same payload over it. Where the
//! control's batches arrive coalesced, the product connection's zero is a difference the setting
//! makes. Where they do not, the host cannot show the property: the case says so and passes, and a
//! run that sets `KR_REQUIRE_SEGMENTATION` fails instead, as the Linux job of the landing workflow
//! does.

mod support;

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{ConnectOptions, Connection, QuicTransportConfig};
use kr_transport::ALPN;
use kr_transport::endpoint::connect;
use support::{Side, direct_addr, paired_pair};

/// One mebibyte is about 720 datagrams at the 1,452 bytes a loopback connection settles on, far
/// more than the few the handshake and its acknowledgements need.
const TRANSFER: usize = 1 << 20;

/// What a transfer may take before the case fails instead of waiting for ever: a transfer over
/// loopback is a few milliseconds, so this only turns a connection that stalls into a failure.
const DEADLINE: Duration = Duration::from_secs(60);

/// Set by a run that has to show the property, as the Linux job of the landing workflow does, so a
/// host that cannot show it fails the case instead of passing without having looked.
const REQUIRE: &str = "KR_REQUIRE_SEGMENTATION";

/// The reads a receiving endpoint counted: datagrams, and reads that arrived coalesced.
fn counted(side: &Side) -> (u64, u64) {
    let socket = &side.endpoint.metrics().socket;
    (socket.recv_datagrams.get(), socket.recv_gro_datagrams.get())
}

/// A connection the way the product opens one: dialled through the crate's own `connect` and
/// accepted as the endpoint accepts it, so both ends use the endpoint's transport configuration.
/// Returns the dialling end and the accepting end.
async fn product_connection(host: &Side, client: &Side) -> (Connection, Connection) {
    let accepting = async {
        host.endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection")
    };
    let dialling = async {
        connect(&client.endpoint, direct_addr(host), ALPN)
            .await
            .expect("a connection")
    };
    let (accepted, dialled) = tokio::join!(accepting, dialling);
    (dialled, accepted)
}

/// A connection between the same two endpoints that uses iroh's default transport configuration at
/// both ends, which keeps segmentation offload on. Returns the dialling end and the accepting end.
async fn control_connection(host: &Side, client: &Side) -> (Connection, Connection) {
    let defaults = QuicTransportConfig::default();
    let server = Arc::new(
        host.endpoint
            .create_server_config_builder(vec![ALPN.to_vec()])
            .set_transport_config(defaults.clone())
            .build(),
    );
    let accepting = async {
        host.endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .accept_with(server)
            .expect("the connection accepted")
            .await
            .expect("a connection")
    };
    let dialling = async {
        client
            .endpoint
            .connect_with_opts(
                direct_addr(host),
                ALPN,
                ConnectOptions::new().with_transport_config(defaults),
            )
            .await
            .expect("the connection requested")
            .await
            .expect("a connection")
    };
    let (accepted, dialled) = tokio::join!(accepting, dialling);
    (dialled, accepted)
}

/// Moves the payload from the dialling end to the accepting end and the same payload back, each
/// way written and read together so that no window can hold the write. A transfer is exactly where
/// a batch would be offered: it needs many datagrams in a row, by the dialling side and by the
/// accepting side alike.
async fn exchange(dialled: &Connection, accepted: &Connection) {
    let transfer = async {
        let (mut send, mut reply) = dialled.open_bi().await.expect("a stream");
        let payload = vec![0x5a_u8; TRANSFER];

        // The dialling side sends.
        let upload = async {
            send.write_all(&payload).await.expect("the payload written");
            send.finish().expect("the stream finished");
        };
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
    };
    tokio::time::timeout(DEADLINE, transfer)
        .await
        .expect("the transfer finished before the deadline");
}

/// The product's connection sends every datagram on its own, and a control connection on the same
/// pair, with segmentation offload on, shows where the host is able to see a batch.
#[tokio::test]
async fn a_bulk_transfer_is_carried_in_single_datagrams() {
    let (host, client) = paired_pair().await;

    let (dialled, accepted) = product_connection(&host, &client).await;
    exchange(&dialled, &accepted).await;
    let (host_datagrams, host_coalesced) = counted(&host);
    let (client_datagrams, client_coalesced) = counted(&client);

    let (control_dialled, control_accepted) = control_connection(&host, &client).await;
    exchange(&control_dialled, &control_accepted).await;
    let control_to_host = counted(&host).1 - host_coalesced;
    let control_to_client = counted(&client).1 - client_coalesced;

    dialled.close(0_u32.into(), b"done");
    control_dialled.close(0_u32.into(), b"done");
    client.endpoint.close().await;
    host.endpoint.close().await;

    eprintln!(
        "coalesced reads: the product connection {host_coalesced} to the host and \
         {client_coalesced} to the client, the control connection {control_to_host} to the host \
         and {control_to_client} to the client"
    );
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
    if control_to_host == 0 || control_to_client == 0 {
        assert!(
            std::env::var_os(REQUIRE).is_none(),
            "{REQUIRE} is set, and with segmentation offload on this host delivered \
             {control_to_host} coalesced reads to the host and {control_to_client} to the client"
        );
        eprintln!(
            "this host cannot show a segmented batch, so the zero above says nothing here: the \
             check passed without proving that the setting is in effect"
        );
    }
}
