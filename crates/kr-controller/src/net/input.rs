//! Terminal input on a stream of its own: the host's door for it.
//!
//! A device sends typing on a stream that carries nothing else, so a key never waits behind a
//! control request and a control request never waits behind a key.

#[cfg(feature = "testing")]
use std::sync::Mutex;

/// The streams of typing this host serves, and what each one has been given.
#[derive(Debug, Default)]
pub(super) struct InputStreams {
    /// Where a suite has this host connect its input lanes, instead of the worker's own endpoint.
    #[cfg(feature = "testing")]
    pub(super) lane_endpoint: Mutex<Option<kr_ipc::paths::Endpoint>>,
}
