//! What the door does with a paired device's uploads: `upload.begin`, `upload.finish`,
//! `upload.cancel` and `upload.status`, and the chunk that travels on a stream of its own.
//!
//! The transfer service performs each under the device's own principal. The chunk is served on an
//! attachment-chunk stream and refused by name on the control stream, and every other upload method
//! is served on the control stream.

use kr_protocol::method::Method;

use super::routes::DeviceRead;
use super::writes::DeviceWrite;

/// KR-REQ-23.21 and KR-REQ-23.41: the routing of the walk lists every upload method as served. The
/// four methods of an upload and the read that tells a device which streams the host takes each
/// have a route that performs them, and the chunk is served only through the stream door. None is
/// refused by name for lack of a part of the host.
#[test]
fn the_walk_serves_the_upload_methods_and_the_reads_that_go_with_them() {
    for method in [
        Method::UploadBegin,
        Method::UploadFinish,
        Method::UploadCancel,
    ] {
        let route = DeviceWrite::of(method);
        assert!(
            matches!(route, Some(route) if !matches!(route, DeviceWrite::Refused(_))),
            "{method:?} is served to a paired device: {route:?}"
        );
    }
    assert_eq!(
        DeviceWrite::of(Method::UploadChunk),
        Some(DeviceWrite::Chunk),
        "a chunk is served on a stream"
    );
    for method in [Method::UploadStatus, Method::TransferStreams] {
        let route = DeviceRead::of(method);
        assert!(
            matches!(route, Some(route) if !matches!(route, DeviceRead::Refused(_))),
            "{method:?} is served to a paired device: {route:?}"
        );
    }
}
