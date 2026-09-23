//! Peer-credential authentication.
//!
//! A local connection is authenticated by asking the kernel who is on the other end, never by
//! trusting anything the caller sends. On Unix that is `SO_PEERCRED` on Linux and `LOCAL_PEEREPID`
//! with `getpeereid` on macOS; on Windows the named pipe reports the client's process.
//!
//! What this proves is an operating-system identity, not human intent. Section 2 is explicit
//! about the difference: a rights-enlarging owner operation still needs the owner-confirmation
//! contract, because code already running under the user's account can open this socket too.

use kr_protocol::local::LocalPeer;
use kr_protocol::scalars::{Nullable, U64};

use crate::error::{IpcError, Result};

/// The operating-system caller on the other end of a local connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The caller's effective user.
    pub uid: u32,
    /// The caller's effective group.
    pub gid: u32,
    /// The caller's process, where the platform reports one.
    pub pid: Option<u32>,
}

impl PeerIdentity {
    /// Rejects a caller that is not the user this endpoint belongs to.
    ///
    /// The runtime directory is already owner-only, so this check is the second of two: the
    /// filesystem keeps other users away from the socket, and this keeps a socket that somehow
    /// became reachable from serving them.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PeerRejected`] when the users differ.
    pub const fn authorise(&self, owner_uid: u32) -> Result<()> {
        if self.uid != owner_uid {
            return Err(IpcError::PeerRejected {
                peer_uid: self.uid,
                owner_uid,
            });
        }
        Ok(())
    }

    /// Renders the identity for the handshake acknowledgement.
    #[must_use]
    pub fn to_wire(self) -> LocalPeer {
        LocalPeer {
            uid: U64::new(u64::from(self.uid)),
            gid: U64::new(u64::from(self.gid)),
            pid: Nullable(self.pid.map(|pid| U64::new(u64::from(pid)))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-23.10: a local peer running as another user is refused.
    #[test]
    fn another_user_is_refused() {
        let peer = PeerIdentity {
            uid: 501,
            gid: 20,
            pid: Some(42),
        };
        assert!(peer.authorise(501).is_ok());
        assert!(matches!(
            peer.authorise(502),
            Err(IpcError::PeerRejected {
                peer_uid: 501,
                owner_uid: 502
            })
        ));
    }
}
