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
//! Where the platform has no Unix socket the endpoint is loopback with a random per-launch
//! credential. The kernel names no peer there, so the credential is the whole authentication and
//! the process identity is the one the bridge presents, checked against the launch this host made.
//! That difference is stated rather than hidden: [`PeerIdentity::from_operating_system`] says
//! which of the two a given admission came from.

use kr_protocol::identity::ProcessStartIdentity;

use crate::broker::error::{BrokerError, Result};
use crate::broker::listener::ListenerAddress;

/// Who the kernel says is on the other end of one accepted connection.
///
/// It is built by accepting a connection on a bound endpoint and nowhere else, which is what makes
/// it evidence rather than a claim. A caller cannot construct one to assert its own identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    process: Option<ProcessStartIdentity>,
    owner: bool,
    from_operating_system: bool,
}

impl PeerIdentity {
    /// The identity a bridge presented, where the kernel names no peer.
    ///
    /// This is the loopback case and nothing else. [`Registration::authenticate`] refuses one of
    /// these wherever the platform binds a private socket, so it cannot be used to put a presented
    /// identity in front of a kernel that would have named the real one.
    ///
    /// [`Registration::authenticate`]: crate::broker::listener::Registration::authenticate
    #[must_use]
    pub const fn presented(process: Option<ProcessStartIdentity>, owner: bool) -> Self {
        Self {
            process,
            owner,
            from_operating_system: false,
        }
    }

    /// The identity the kernel reported for one connection.
    ///
    /// Only [`BoundEndpoint::accept`] produces one in the product; it is visible inside this crate
    /// so a unit test can state which process the kernel named without binding a socket.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_kernel(process: ProcessStartIdentity, owner: bool) -> Self {
        Self {
            process: Some(process),
            owner,
            from_operating_system: true,
        }
    }

    /// Returns the process the kernel named on this connection, where it named one.
    #[must_use]
    pub const fn process(&self) -> Option<&ProcessStartIdentity> {
        self.process.as_ref()
    }

    /// Returns true when the connecting user owns this session.
    #[must_use]
    pub const fn is_owner(&self) -> bool {
        self.owner
    }

    /// Returns true when the identity came from the kernel rather than from the bridge.
    ///
    /// A private socket always answers true. Loopback answers false, because the kernel names no
    /// peer on a stream socket and the credential is what decides there.
    #[must_use]
    pub const fn from_operating_system(&self) -> bool {
        self.from_operating_system
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
    /// Loopback, where the platform has no private socket.
    Loopback(tokio::net::TcpStream),
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
    Loopback(tokio::net::TcpListener),
}

impl BoundEndpoint {
    /// Binds the endpoint this platform uses for one launch.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the runtime directory is not owner-only or
    /// the resulting address is not local, and [`BrokerError::LedgerUnavailable`] when the socket
    /// cannot be created.
    pub fn bind(runtime_directory: &std::path::Path) -> Result<Self> {
        let address = ListenerAddress::for_launch(runtime_directory, 0)?;
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
            ListenerAddress::Loopback { address: host, .. } => {
                let listener = std::net::TcpListener::bind((*host, 0)).map_err(|error| {
                    BrokerError::ledger(format!("could not bind {host}: {error}"))
                })?;
                listener.set_nonblocking(true).map_err(|error| {
                    BrokerError::ledger(format!("could not prepare the endpoint: {error}"))
                })?;
                let port = listener
                    .local_addr()
                    .map_err(|error| {
                        BrokerError::ledger(format!("the endpoint has no address: {error}"))
                    })?
                    .port();
                let listener = tokio::net::TcpListener::from_std(listener).map_err(|error| {
                    BrokerError::ledger(format!("could not prepare the endpoint: {error}"))
                })?;
                let address = ListenerAddress::Loopback {
                    address: *host,
                    port,
                };
                address.require_local()?;
                Ok(Self {
                    address,
                    listener: Bound::Loopback(listener),
                })
            }
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
                        process: Some(process),
                        owner: credentials.uid() == kr_ipc::paths::current_uid(),
                        from_operating_system: true,
                    },
                    stream: Stream::Socket(stream),
                })
            }
            Bound::Loopback(listener) => {
                let (stream, _) = listener.accept().await.map_err(|error| {
                    BrokerError::ledger(format!("the endpoint could not accept: {error}"))
                })?;
                Ok(Accepted {
                    peer: PeerIdentity {
                        // The kernel names no peer on a loopback stream. The credential is what
                        // decides there, and the identity the bridge presents is compared with
                        // the launch this host made rather than believed on its own.
                        process: None,
                        owner: true,
                        from_operating_system: false,
                    },
                    stream: Stream::Loopback(stream),
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
        assert!(accepted.peer.from_operating_system());
        assert!(accepted.peer.is_owner());
        assert_eq!(
            accepted
                .peer
                .process()
                .expect("the kernel named the connecting process")
                .pid
                .get(),
            u64::from(std::process::id()),
            "the identity is the kernel's reading of the connecting process"
        );
        drop(connect.await.expect("the connecting task finishes"));
        drop(endpoint);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Where the platform has no private socket, the endpoint is loopback: reachable from this
    /// machine only, and naming no process, because the kernel names none on a loopback stream.
    /// What decides there is the per-launch credential, not anything this endpoint reports.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn a_loopback_endpoint_is_local_and_names_no_process() {
        let endpoint = BoundEndpoint::bind(&std::env::temp_dir()).expect("the endpoint binds");
        let ListenerAddress::Loopback { address, port } = endpoint.address().clone() else {
            panic!("this platform has no private socket");
        };
        assert!(
            address.is_loopback(),
            "nothing off this machine can reach it"
        );
        assert_ne!(port, 0, "the address is the port the listener holds");

        let connect = tokio::spawn(async move {
            tokio::net::TcpStream::connect((address, port))
                .await
                .expect("the bridge connects")
        });
        let accepted = endpoint.accept().await.expect("the connection is accepted");
        assert!(
            !accepted.peer.from_operating_system(),
            "the kernel names nobody on a loopback stream"
        );
        assert!(
            accepted.peer.process().is_none(),
            "so no process is claimed for the connection"
        );
        drop(connect.await.expect("the connecting task finishes"));
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
