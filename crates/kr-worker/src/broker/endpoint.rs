//! The bound local endpoint: the socket a launched agent's bridge actually connects to.
//!
//! [`listener`](crate::broker::listener) decides what an endpoint must be. This binds one, and the
//! difference is the whole point of it: peer ownership and process identity come from the kernel
//! here, not from what the connecting side says about itself. A bridge that lies about its process
//! is refused by the same check that would refuse a stranger.
//!
//! Three properties are established at bind time rather than assumed.
//!
//! * **The directory answers first.** A private socket lives inside the owner-only runtime
//!   directory, and the directory's ownership and mode are read before the socket is created.
//! * **The socket itself is owner-only.** The permissions are set on the bound path, so a socket
//!   whose directory protection were ever relaxed is still not one another user may connect to.
//! * **The address is local.** An address something other than this machine could reach is refused
//!   before it is published; section 12 never exposes this listener through iroh.
//!
//! Windows has no Unix socket, so its endpoint is a named pipe that carries its owner's own access
//! list: another account is refused when it opens the pipe, and the kernel names the process on the
//! other end, exactly as on a private socket. The two platforms differ only in the transport. A
//! connection whose peer the kernel will not name is refused on both, so no admission rests on an
//! identity the connecting side presented.

use kr_protocol::identity::ProcessStartIdentity;

use crate::broker::error::{BrokerError, Result};
use crate::broker::listener::ListenerAddress;

/// Who the kernel says is on the other end of one accepted connection.
///
/// It is built by accepting a connection on a bound endpoint and nowhere else, which is what makes
/// it evidence rather than a claim. A caller cannot construct one to assert its own identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    process: ProcessStartIdentity,
    owner: bool,
}

impl PeerIdentity {
    /// The identity the kernel reported for one connection.
    ///
    /// Only [`BoundEndpoint::accept`] produces one in the product. It is visible to this crate's
    /// own tests, and to the integration suites through the `testing` feature, so a test can state
    /// which process the kernel named, or that the peer was another user, without binding an
    /// endpoint. No shipped build compiles it.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn from_kernel(process: ProcessStartIdentity, owner: bool) -> Self {
        Self { process, owner }
    }

    /// Returns the process the kernel named on this connection.
    #[must_use]
    pub const fn process(&self) -> &ProcessStartIdentity {
        &self.process
    }

    /// Returns true when the connecting user owns this session.
    #[must_use]
    pub const fn is_owner(&self) -> bool {
        self.owner
    }
}

/// A connection accepted on the bound endpoint, with the identity the kernel gave it.
#[derive(Debug)]
pub struct Accepted {
    /// Who is on the other end.
    pub peer: PeerIdentity,
    /// The stream itself.
    pub stream: Stream,
}

/// One accepted byte stream.
#[derive(Debug)]
pub enum Stream {
    /// A private socket inside the owner-only runtime directory.
    #[cfg(unix)]
    Socket(tokio::net::UnixStream),
    /// A named pipe that carries its owner's access list.
    #[cfg(windows)]
    Pipe(kr_ipc::endpoint::Connection),
}

/// The endpoint a launched agent's bridge connects to.
#[derive(Debug)]
pub struct BoundEndpoint {
    address: ListenerAddress,
    listener: Bound,
}

#[derive(Debug)]
enum Bound {
    #[cfg(unix)]
    Socket(tokio::net::UnixListener),
    #[cfg(windows)]
    Pipe(kr_ipc::endpoint::Listener),
}

impl BoundEndpoint {
    /// Binds the endpoint this platform uses for one launch.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the address is not local,
    /// [`BrokerError::LedgerUnavailable`] when the runtime directory is not private or the
    /// endpoint cannot be created, and [`BrokerError::UnsupportedCapability`] for an address this
    /// platform does not bind.
    pub fn bind(runtime_directory: &std::path::Path) -> Result<Self> {
        let address = ListenerAddress::for_launch(runtime_directory)?;
        address.require_local()?;
        match &address {
            #[cfg(unix)]
            ListenerAddress::PrivateSocket(path) => {
                // The directory is read again here rather than trusted from a moment ago: a
                // directory whose mode changed between choosing the address and binding it is one
                // this socket must not be created in.
                let parent = path.parent().ok_or_else(|| {
                    BrokerError::invalid("a private socket lives inside a directory")
                })?;
                crate::broker::process::check_private_directory(parent)?;
                let listener = tokio::net::UnixListener::bind(path).map_err(|error| {
                    BrokerError::ledger(format!(
                        "could not bind {} ({} bytes): {error}",
                        path.display(),
                        path.as_os_str().len()
                    ))
                })?;
                // And the socket itself is owner-only, so the filesystem answers "who may
                // connect" before any byte is read.
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                        .map_err(|error| {
                            BrokerError::ledger(format!(
                                "could not make {} owner-only: {error}",
                                path.display()
                            ))
                        })?;
                }
                Ok(Self {
                    address,
                    listener: Bound::Socket(listener),
                })
            }
            #[cfg(not(unix))]
            ListenerAddress::PrivateSocket(_) => Err(BrokerError::UnsupportedCapability {
                detail: "this platform has no private socket".to_owned(),
            }),
            #[cfg(windows)]
            ListenerAddress::NamedPipe(name) => {
                // The directory holds the registration and the credential, so it is read again
                // here rather than trusted from a moment ago.
                crate::broker::process::check_private_directory(runtime_directory)?;
                let endpoint =
                    kr_ipc::paths::Endpoint::from_name(name.clone()).map_err(|error| {
                        BrokerError::ledger(format!("the pipe name {name} is not usable: {error}"))
                    })?;
                // The pipe's own list is its owner's, and the first instance is created
                // exclusively, so a name another account made first is refused.
                let listener = kr_ipc::endpoint::Listener::bind(&endpoint).map_err(|error| {
                    BrokerError::ledger(format!(
                        "could not bind {}: {error}",
                        address.for_diagnostics()
                    ))
                })?;
                Ok(Self {
                    address,
                    listener: Bound::Pipe(listener),
                })
            }
            #[cfg(not(windows))]
            ListenerAddress::NamedPipe(_) => Err(BrokerError::UnsupportedCapability {
                detail: "this platform has no named pipe".to_owned(),
            }),
        }
    }

    /// Returns the address a launched process is told to connect to.
    #[must_use]
    pub const fn address(&self) -> &ListenerAddress {
        &self.address
    }

    /// Accepts one connection and reads who made it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the accept fails, and
    /// [`BrokerError::PermissionDenied`] when the kernel will not name the connecting process on a
    /// platform where it should.
    pub async fn accept(&self) -> Result<Accepted> {
        match &self.listener {
            #[cfg(unix)]
            Bound::Socket(listener) => {
                let (stream, _) = listener.accept().await.map_err(|error| {
                    BrokerError::ledger(format!("the endpoint could not accept: {error}"))
                })?;
                let credentials = stream.peer_cred().map_err(|error| {
                    BrokerError::denied(format!(
                        "the operating system would not name the connecting process: {error}"
                    ))
                })?;
                let pid = credentials.pid().ok_or_else(|| {
                    BrokerError::denied(
                        "the operating system named no process on this connection, so nothing \
                         about it can be bound to a launch",
                    )
                })?;
                #[expect(
                    clippy::cast_sign_loss,
                    reason = "a process identifier the kernel reported is not negative"
                )]
                let process =
                    kr_ipc::identity::process_start_identity(pid as u32).map_err(|error| {
                        BrokerError::denied(format!(
                            "the connecting process could not be identified: {error}"
                        ))
                    })?;
                Ok(Accepted {
                    peer: PeerIdentity {
                        process,
                        owner: credentials.uid() == kr_ipc::paths::current_uid(),
                    },
                    stream: Stream::Socket(stream),
                })
            }
            #[cfg(windows)]
            Bound::Pipe(listener) => {
                // The caller's account is proved at the connection's first read, before any byte
                // reaches a reader, and another account is refused when it opens the pipe.
                let (connection, peer) = listener.accept().await.map_err(|error| {
                    BrokerError::ledger(format!("the endpoint could not accept: {error}"))
                })?;
                let pid = peer.pid.ok_or_else(|| {
                    BrokerError::denied(
                        "the operating system named no process on this connection, so nothing \
                         about it can be bound to a launch",
                    )
                })?;
                let process = kr_ipc::identity::process_start_identity(pid).map_err(|error| {
                    BrokerError::denied(format!(
                        "the connecting process could not be identified: {error}"
                    ))
                })?;
                Ok(Accepted {
                    peer: PeerIdentity {
                        process,
                        owner: true,
                    },
                    stream: Stream::Pipe(connection),
                })
            }
        }
    }
}

impl Drop for BoundEndpoint {
    fn drop(&mut self) {
        // A socket file outlives the process that bound it, and a stale one would make the next
        // launch refuse to bind. Removing it is the endpoint's own business, because it is the
        // only thing that knows it created it.
        if let ListenerAddress::PrivateSocket(path) = &self.address {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A short private directory, because a socket path has a small bound on every Unix.
    #[cfg(unix)]
    fn short_directory() -> std::path::PathBuf {
        let name: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        std::env::temp_dir().join(format!("kr-e-{name}"))
    }

    // Unix only: a socket file's mode and a kernel-named peer exist only on a private socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_bound_socket_is_owner_only_and_names_the_process_that_connects() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = short_directory();
        std::fs::create_dir_all(&directory).expect("the directory is created");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made private");
        let endpoint = BoundEndpoint::bind(&directory).expect("the endpoint binds");
        let ListenerAddress::PrivateSocket(path) = endpoint.address().clone() else {
            panic!("this platform prefers a private socket");
        };
        let mode = std::fs::metadata(&path)
            .expect("the socket exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o077, 0, "nobody else may connect to it");

        let connect = tokio::spawn(async move {
            tokio::net::UnixStream::connect(&path)
                .await
                .expect("the bridge connects")
        });
        let accepted = endpoint.accept().await.expect("the connection is accepted");
        assert!(accepted.peer.is_owner());
        assert_eq!(
            accepted.peer.process().pid.get(),
            u64::from(std::process::id()),
            "the identity is the kernel's reading of the connecting process"
        );
        drop(connect.await.expect("the connecting task finishes"));
        drop(endpoint);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// On Windows the endpoint is a named pipe: reachable from this machine only, named by the
    /// kernel's own reading of the process that connects, and bound only in a private directory.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_bound_pipe_names_the_process_that_connects() {
        use tokio::io::AsyncWriteExt as _;
        let directory = std::env::temp_dir().join(format!("kr-e-{}", kr_ipc::new_uuid()));
        kr_ipc::paths::create_private_directory(&directory).expect("a private directory is made");
        let endpoint = BoundEndpoint::bind(&directory).expect("the endpoint binds");
        let ListenerAddress::NamedPipe(name) = endpoint.address().clone() else {
            panic!("this platform binds a named pipe");
        };
        assert!(endpoint.address().is_local());

        let connect = tokio::spawn(async move {
            let address = kr_ipc::paths::Endpoint::from_name(name).expect("a usable name");
            let mut connection = kr_ipc::endpoint::Connection::connect(&address)
                .await
                .expect("the bridge connects");
            // The caller's account is proved at its first read, so it speaks first.
            connection
                .write_all(b"hello\n")
                .await
                .expect("the bridge writes");
            connection
        });
        let accepted = endpoint.accept().await.expect("the connection is accepted");
        assert!(accepted.peer.is_owner());
        assert_eq!(
            accepted.peer.process().pid.get(),
            u64::from(std::process::id()),
            "the identity is the kernel's reading of the connecting process"
        );
        drop(connect.await.expect("the connecting task finishes"));
        drop(endpoint);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A runtime directory that is not private binds nothing, where the list says so: an ordinary
    /// directory under the temporary one carries the profile's own inherited entries.
    #[cfg(windows)]
    #[test]
    fn a_directory_that_is_not_private_binds_nothing() {
        let directory = std::env::temp_dir().join(format!("kr-e-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        assert!(BoundEndpoint::bind(&directory).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }

    // Unix only: the directory decides who may connect only where the endpoint is a socket in it.
    #[cfg(unix)]
    #[test]
    fn a_directory_other_users_can_read_binds_nothing() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = short_directory();
        std::fs::create_dir_all(&directory).expect("the directory is created");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("the directory is made readable by others");
        assert!(BoundEndpoint::bind(&directory).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
