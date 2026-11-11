//! The data streams a paired device sends an upload's chunks on.

use kr_protocol::frame::StreamKind;

/// The stream kinds this host takes from a paired device, besides the control stream.
///
/// The one list both the listener's configuration and the answer to `transfer.streams` are built
/// from, so a host never says it takes a stream its listener resets.
pub(crate) const ACCEPTED_STREAMS: [StreamKind; 1] = [StreamKind::AttachmentChunks];
