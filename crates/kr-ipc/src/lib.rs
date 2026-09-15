//! Local typed-frame inter-process communication for the KalaReach host.
//!
//! Everything a KalaReach host does locally passes through here: the `kr` command line reaching
//! the control daemon, the control daemon reaching a session worker, and a worker reporting itself
//! at startup. The network transport is a separate crate; what this one owns is the part where the
//! operating system, rather than a cryptographic handshake, says who is calling.
//!
//! # What it provides
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`paths`] | The owner-only runtime and state directories, endpoint names and atomic file publication |
//! | [`identity`] | The host's boot identity and a process's start identity, read from the kernel |
//! | [`peer`] | Peer-credential authentication of a local caller |
//! | [`endpoint`] | Binding, connecting and accepting, over Unix sockets or Windows named pipes |
//! | [`framed`] | The length-delimited KR-CBOR-1 frame codec on a connection |
//! | [`client`] | Connecting, negotiating, verifying a worker and calling a method |
//! | [`descriptor`] | Atomic publication, reading and retirement of worker descriptors |
//! | [`verify`] | The rendezvous, the challenge answer and the controller generation token |
//! | [`error`] | The failures above, each mapped to one stable protocol error code |
//!
//! The `testing` feature adds [`testing::TempHost`], a disposable host tree the other host
//! crates build their tests on.
//!
//! # What authenticates what
//!
//! Three separate things are checked, and none of them substitutes for another:
//!
//! * The **runtime directory** is owner-only, so another user cannot reach the sockets at all.
//! * **Peer credentials** identify the calling process's user, which the listener checks before it
//!   reads a frame. That proves an operating-system identity, not human intent.
//! * The **boot and process-start identities** bind a running worker to the session a controller
//!   reserved. A filename, a process identifier and a descriptor on disk are hints; only the
//!   kernel's own record settles whether this is the same boot and the same process.
//!
//! # Example
//!
//! ```no_run
//! use kr_ipc::endpoint::{Connection, Listener};
//! use kr_ipc::framed::split;
//! use kr_ipc::paths::HostPaths;
//! use kr_protocol::frame::StreamKind;
//!
//! # async fn example() -> kr_ipc::Result<()> {
//! let paths = HostPaths::discover()?;
//! let environment = paths.environment(paths.open_environment_id()?);
//! environment.create()?;
//!
//! let listener = Listener::bind(&environment.controller_endpoint()?)?;
//! let (connection, peer) = listener.accept().await?;
//! println!("user {} process {:?}", peer.uid, peer.pid);
//! let (mut reader, mut writer) = split(connection, StreamKind::Control);
//! # let _ = (&mut reader, &mut writer);
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod descriptor;
pub mod endpoint;
pub mod error;
pub mod framed;
pub mod identity;
pub mod paths;
pub mod peer;
#[cfg(feature = "testing")]
pub mod testing;
pub mod verify;

pub use crate::error::{IpcError, Result};

/// Generates a fresh random identifier.
///
/// Section 9 requires a cryptographically generated UUIDv4 with 122 random bits. The bits come
/// from the operating system's random generator; nothing here derives an identifier from a
/// counter, a clock or a hardware address.
#[must_use]
pub fn new_uuid() -> kr_protocol::scalars::Uuid {
    kr_protocol::scalars::Uuid::from_bytes(*uuid::Uuid::new_v4().as_bytes())
}

/// Returns the current UTC time in milliseconds.
///
/// This is the wall clock, used for timestamps a person reads and for the trusted deadlines of
/// cross-reboot objects. Expiry within one boot is measured on the suspend-aware continuous clock
/// instead, because a wall clock that moves backwards must never extend authority.
#[must_use]
pub fn now_ms() -> kr_protocol::scalars::TimestampMs {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    kr_protocol::scalars::TimestampMs::new(u64::try_from(millis).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_version_four_and_distinct() {
        let first = new_uuid();
        let second = new_uuid();
        assert_eq!(first.version(), 4);
        assert_ne!(first, second);
    }
}
