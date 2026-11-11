//! A paired device's attachment-chunk stream over real paired connections.
//!
//! A device sends an upload's chunks on a data stream of its own, never on the control stream, and
//! asks the host which streams it takes before it begins an upload. The streams are real: a paired
//! device opens them on its authorised connection, and the host reads their headers, admits them
//! under the device's own principal and answers each chunk on the stream it came on.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::method::Method;
use kr_protocol::transfer::{TransferStreamsParams, TransferStreamsResult};
use net_support::{Device, Host, RawDevice};

/// A method name the registry does not list, as an older host would meet a method it has not heard of.
const A_METHOD_THE_HOST_DOES_NOT_LIST: &str = "transfer.stream_kinds";

/// KR-REQ-23.21: a paired device that holds no right at all is told which streams the host takes,
/// so that a device decides before it reserves anything whether its chunks have a stream to travel
/// on. The control is a method the host does not list: it is refused as a host older than the
/// method refuses it, `PERMISSION_DENIED` with the registry's own words, which is how a client
/// tells a host that cannot take the form from one that refused for another reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_no_rights_is_told_which_streams_the_host_takes() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = net_support::pair_with(&host, &device, &owner, net_support::proposal(&[])).await;
    let raw = RawDevice::connect(&host, &device, &record).await;
    raw.claim();

    let answered: TransferStreamsResult = raw
        .read(Method::TransferStreams, &TransferStreamsParams {})
        .await
        .expect("a device with no rights is told")
        .to_typed()
        .expect("a result of the declared shape");
    assert_eq!(
        answered.accepted_streams,
        vec![StreamKind::AttachmentChunks]
    );

    let unlisted = raw
        .read_named(A_METHOD_THE_HOST_DOES_NOT_LIST, &TransferStreamsParams {})
        .await
        .expect_err("a method the registry does not list");
    assert_eq!(unlisted.code, ErrorCode::PermissionDenied, "{unlisted:?}");
    assert_eq!(
        unlisted.message,
        kr_transport::actor::METHOD_NOT_AVAILABLE,
        "the registry's own words, which a client reads as a host that does not list the method"
    );
    raw.close();
    host.stop().await;
}
