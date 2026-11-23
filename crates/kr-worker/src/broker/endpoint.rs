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
//! Windows has two kinds. A launch's bridge connects to a named pipe that carries its owner's own
//! access list: another account is refused when it opens the pipe, and the kernel names the process
//! on the other end, exactly as on a private socket. The gateway's agent program connects to a
//! Unix-domain socket inside the owner-only directory, which Windows also has. What an admission
//! rests on there is the peer check: the kernel names the process on the other end and that
//! process's own token names its account, both before a byte of what the peer sent is read. The
//! socket's file also carries a protected list that names its owner only, as defence in depth: no
//! admission relies on it. A build that cannot name the process on the other end of a socket binds
//! none, and says so before any launch is committed. A connection whose peer the kernel will not
//! name is refused on every kind, so no admission rests on an identity the connecting side
//! presented.

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
    /// A Unix-domain socket inside the owner-only runtime directory.
    #[cfg(windows)]
    Uds(crate::windows::uds::Stream),
}

/// The device and inode of a socket file.
#[cfg(unix)]
pub(crate) type SocketIdentity = (u64, u64);

/// The volume and file id of a socket file.
#[cfg(windows)]
pub(crate) type SocketIdentity = crate::windows::file::Object;

/// The identity of the socket that stands at `path` now, or none where nothing does or something
/// else does.
#[cfg(unix)]
pub(crate) fn socket_identity(path: &std::path::Path) -> Option<SocketIdentity> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let metadata = std::fs::symlink_metadata(path).ok()?;
    metadata
        .file_type()
        .is_socket()
        .then(|| (metadata.dev(), metadata.ino()))
}

/// The identity of the socket that stands at `path` now, or none where nothing does or something
/// else does.
#[cfg(windows)]
pub(crate) fn socket_identity(path: &std::path::Path) -> Option<SocketIdentity> {
    crate::windows::uds::socket_object(path)
}

/// Removes what stands at `path` only when it is the socket whose identity `made` is: a path that
/// names another socket, a file or nothing is left as it is, because it is not what a bind made.
#[cfg(unix)]
pub(crate) fn remove_socket_made(path: &std::path::Path, made: SocketIdentity) {
    if socket_identity(path) == Some(made) {
        let _ = std::fs::remove_file(path);
    }
}

/// Removes what stands at `path` only when it is the socket whose identity `made` is, as the handle
/// that removes it reads it.
#[cfg(windows)]
pub(crate) fn remove_socket_made(path: &std::path::Path, made: SocketIdentity) {
    crate::windows::uds::remove_socket_made(path, made);
}

/// The longest path a socket this host binds has on Windows.
///
/// Windows holds a socket's path in the 108 bytes of `sun_path`, and the last is the terminator.
/// `kr_ipc::paths::MAX_SOCKET_PATH_LEN` is the bound of a pipe's name there and is not this.
#[cfg(any(windows, test))]
pub(crate) const WINDOWS_SOCKET_PATH_LIMIT: usize = 107;

/// Refuses a socket path longer than `limit` bytes, one that is not text and one with a NUL in it,
/// by name.
///
/// The address is a path, and the platform bounds it, so a runtime directory that is most of the
/// bound leaves no room for the file name below it. The refusal says how long the path is and how
/// long it may be, and how to leave room.
#[cfg(any(windows, test))]
pub(crate) fn require_room_for_a_socket_path(path: &std::path::Path, limit: usize) -> Result<()> {
    let Some(text) = path.to_str() else {
        return Err(BrokerError::invalid(format!(
            "the socket path {} is not text, and a socket's address is",
            path.display()
        )));
    };
    if text.contains('\0') {
        return Err(BrokerError::invalid(format!(
            "the socket path {} has a NUL in it, and a socket's address ends at one",
            text.escape_debug()
        )));
    }
    let length = text.len();
    if length > limit {
        return Err(BrokerError::invalid(format!(
            "the socket path {text} is {length} bytes, and a socket's path is at most {limit} on \
             this platform; a shorter runtime directory ({}) leaves room",
            kr_ipc::paths::RUNTIME_DIR_VARIABLE
        )));
    }
    Ok(())
}

/// The endpoint a launched agent's bridge connects to.
#[derive(Debug)]
pub struct BoundEndpoint {
    address: ListenerAddress,
    listener: Bound,
    /// The identity of the socket file this endpoint made, read as soon as its bind succeeded: what
    /// its end removes, and nothing else.
    #[cfg(unix)]
    made: SocketIdentity,
}

#[derive(Debug)]
enum Bound {
    #[cfg(unix)]
    Socket(tokio::net::UnixListener),
    #[cfg(windows)]
    Pipe(kr_ipc::endpoint::Listener),
    /// A Unix-domain socket and the identity of its file, read as soon as its bind succeeded: what
    /// its end removes, and nothing else.
    #[cfg(windows)]
    Uds {
        listener: crate::windows::uds::Listener,
        made: SocketIdentity,
    },
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
        Self::bind_address(address, runtime_directory)
    }

    /// Binds a private socket of the given file name in `runtime_directory`, for an address the
    /// caller has already told a process of.
    ///
    /// # Errors
    ///
    /// Returns what [`BoundEndpoint::bind`] does.
    #[cfg(any(unix, windows))]
    pub fn bind_named(runtime_directory: &std::path::Path, name: &str) -> Result<Self> {
        if !runtime_directory.is_absolute() {
            return Err(BrokerError::invalid(
                "a launch's runtime directory is an absolute path",
            ));
        }
        Self::bind_address(
            ListenerAddress::PrivateSocket(runtime_directory.join(name)),
            runtime_directory,
        )
    }

    fn bind_address(
        address: ListenerAddress,
        #[cfg_attr(
            not(windows),
            expect(
                unused_variables,
                reason = "a pipe's directory is read to be checked private, and a socket's is its path's parent"
            )
        )]
        runtime_directory: &std::path::Path,
    ) -> Result<Self> {
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
                let listener = tokio::net::UnixListener::bind(path)
                    .map_err(|error| bind_refusal(path, &error))?;
                // What the bind made is read before anything else is done to it, so a step that
                // fails after it removes that socket and nothing else.
                let Some(made) = socket_identity(path) else {
                    return Err(BrokerError::Listen {
                        endpoint: path.to_string_lossy().into_owned(),
                        refusal: kr_ipc::listen::ListenRefusal::Other {
                            operation: kr_ipc::listen::ListenStep::Inspect,
                            os: None,
                        },
                    });
                };
                // And the socket itself is owner-only, so the filesystem answers "who may
                // connect" before any byte is read.
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                        .map_err(|error| {
                            remove_socket_made(path, made);
                            BrokerError::Listen {
                                endpoint: path.to_string_lossy().into_owned(),
                                refusal: kr_ipc::listen::ListenRefusal::Other {
                                    operation: kr_ipc::listen::ListenStep::Permissions,
                                    os: error.raw_os_error(),
                                },
                            }
                        })?;
                }
                Ok(Self {
                    address,
                    listener: Bound::Socket(listener),
                    made,
                })
            }
            #[cfg(windows)]
            ListenerAddress::PrivateSocket(path) => {
                require_room_for_a_socket_path(path, WINDOWS_SOCKET_PATH_LIMIT)?;
                // The directory is read again here, as for a socket on Unix: a directory whose
                // list changed between choosing the address and binding it is one this socket
                // must not be created in.
                let parent = path.parent().ok_or_else(|| {
                    BrokerError::invalid("a private socket lives inside a directory")
                })?;
                crate::broker::process::check_private_directory(parent)?;
                // The bind proves the build names its peers, makes the socket's file, gives it
                // the owner-only list through the handle it opened and reads that list back from
                // the same handle, and returns the identity of the file it made.
                let (listener, made) =
                    crate::windows::uds::Listener::bind(path).map_err(|failure| match failure {
                        crate::windows::uds::BindFailure::Bind(error) => bind_refusal(path, &error),
                        // The build cannot name the process that connects, so nothing bound here
                        // could be told who connected to it: the launch is refused by name and the
                        // program runs as typed.
                        crate::windows::uds::BindFailure::NoPeerProcess(detail) => {
                            BrokerError::UnsupportedCapability { detail }
                        }
                        crate::windows::uds::BindFailure::Unprotected(detail) => {
                            BrokerError::ledger(detail)
                        }
                    })?;
                Ok(Self {
                    address,
                    listener: Bound::Uds { listener, made },
                })
            }
            #[cfg(not(any(unix, windows)))]
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
                let listener =
                    kr_ipc::endpoint::Listener::bind(&endpoint).map_err(|error| match error {
                        kr_ipc::IpcError::Listen { endpoint, refusal } => {
                            BrokerError::Listen { endpoint, refusal }
                        }
                        other => BrokerError::ledger(format!(
                            "could not bind {}: {other}",
                            address.for_diagnostics()
                        )),
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
            #[cfg(windows)]
            Bound::Uds { listener, .. } => {
                let stream = listener.accept().await.map_err(|error| {
                    BrokerError::ledger(format!("the endpoint could not accept: {error}"))
                })?;
                // The kernel names the process, and its own token says whose it is: nothing the
                // connecting side wrote is read.
                let pid = stream.peer_process().map_err(|error| {
                    BrokerError::denied(format!(
                        "the operating system would not name the connecting process: {error}"
                    ))
                })?;
                let process = kr_ipc::identity::process_start_identity(pid).map_err(|error| {
                    BrokerError::denied(format!(
                        "the connecting process could not be identified: {error}"
                    ))
                })?;
                let owner = crate::windows::uds::process_is_this_account(pid).map_err(|error| {
                    BrokerError::denied(format!(
                        "the account of the connecting process could not be read: {error}"
                    ))
                })?;
                Ok(Accepted {
                    peer: PeerIdentity { process, owner },
                    stream: Stream::Uds(stream),
                })
            }
        }
    }
}

impl BoundEndpoint {
    /// The identity of the socket file this endpoint made.
    #[cfg(unix)]
    pub(crate) const fn made(&self) -> SocketIdentity {
        self.made
    }

    /// Removes the socket file this endpoint made, if it still stands at its address and is that
    /// socket.
    #[cfg(unix)]
    pub(crate) fn remove_its_socket(&self) {
        if let ListenerAddress::PrivateSocket(path) = &self.address {
            remove_socket_made(path, self.made);
        }
    }

    /// Removes the socket file this endpoint made, if it still stands at its address and is that
    /// socket.
    #[cfg(windows)]
    pub(crate) fn remove_its_socket(&self) {
        if let (ListenerAddress::PrivateSocket(path), Bound::Uds { made, .. }) =
            (&self.address, &self.listener)
        {
            remove_socket_made(path, *made);
        }
    }
}

impl Drop for BoundEndpoint {
    fn drop(&mut self) {
        // A socket file outlives the process that bound it, and a stale one would make the next
        // launch refuse to bind. Removing it is the endpoint's own business, because it is the
        // only thing that knows it created it, and it removes that socket and nothing else: a
        // path that names another socket by now is another program's.
        #[cfg(any(unix, windows))]
        self.remove_its_socket();
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

    /// KR-REQ-12.07: an endpoint removes the socket file it made and no other: a path that names
    /// another socket, or a file, by the time the endpoint ends is not its own and stays, and the
    /// socket it made is removed where nothing has replaced it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_path_replaced_after_a_successful_bind_is_not_removed_when_the_endpoint_ends() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = short_directory();
        std::fs::create_dir_all(&directory).expect("the directory is created");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made private");
        let path_of = |endpoint: &BoundEndpoint| {
            let ListenerAddress::PrivateSocket(path) = endpoint.address().clone() else {
                panic!("this platform prefers a private socket");
            };
            path
        };

        let untouched = BoundEndpoint::bind(&directory).expect("the endpoint binds");
        let path = path_of(&untouched);
        assert_eq!(socket_identity(&path), Some(untouched.made()));
        drop(untouched);
        assert!(!path.exists(), "the socket the endpoint made is removed");

        let replaced = BoundEndpoint::bind(&directory).expect("the endpoint binds");
        let path = path_of(&replaced);
        std::fs::remove_file(&path).expect("another program takes the path");
        let other = std::os::unix::net::UnixListener::bind(&path).expect("another socket");
        drop(replaced);
        assert!(
            std::os::unix::net::UnixStream::connect(&path).is_ok(),
            "the other program's socket was not removed"
        );
        drop(other);
        std::fs::remove_file(&path).expect("the other program's socket is cleared");

        let overwritten = BoundEndpoint::bind(&directory).expect("the endpoint binds");
        let path = path_of(&overwritten);
        std::fs::remove_file(&path).expect("something takes the path");
        std::fs::write(&path, b"a file").expect("a file stands there");
        drop(overwritten);
        assert_eq!(
            std::fs::read(&path).expect("the file was not removed"),
            b"a file"
        );
        let _ = std::fs::remove_dir_all(&directory);
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

    /// A private directory under the temporary one, which a socket's path stays short in.
    #[cfg(windows)]
    fn private_directory() -> std::path::PathBuf {
        let name: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let directory = std::env::temp_dir().join(format!("kr-e-{name}"));
        kr_ipc::paths::create_private_directory(&directory).expect("a private directory is made");
        directory
    }

    /// KR-REQ-07.45: on Windows a gateway's socket is a Unix-domain socket in the owner-only
    /// directory, reachable from this machine only, and named by the kernel's own reading of the
    /// process that connects and by that process's own token.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_bound_socket_names_the_process_that_connects() {
        let directory = private_directory();
        let endpoint =
            BoundEndpoint::bind_named(&directory, "gw.sock").expect("the endpoint binds");
        let ListenerAddress::PrivateSocket(path) = endpoint.address().clone() else {
            panic!("a named bind on this platform is a private socket");
        };
        assert_eq!(path, directory.join("gw.sock"));
        assert!(endpoint.address().is_local());

        let connect = tokio::spawn(async move {
            crate::windows::uds::Stream::connect(&path).expect("the program connects")
        });
        let accepted = endpoint.accept().await.expect("the connection is accepted");
        assert!(accepted.peer.is_owner());
        assert_eq!(
            accepted.peer.process().pid.get(),
            u64::from(std::process::id()),
            "the identity is the kernel's reading of the connecting process"
        );
        assert!(matches!(accepted.stream, Stream::Uds(_)));
        drop(connect.await.expect("the connecting task finishes"));
        drop(endpoint);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// KR-REQ-07.45: a socket is never created in a directory that is not private: an ordinary
    /// directory under the temporary one carries the profile's own inherited entries.
    #[cfg(windows)]
    #[test]
    fn a_socket_in_a_directory_that_is_not_private_binds_nothing() {
        let directory = std::env::temp_dir().join(format!("kr-e-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        assert!(BoundEndpoint::bind_named(&directory, "gw.sock").is_err());
        assert!(
            std::fs::symlink_metadata(directory.join("gw.sock")).is_err(),
            "no socket was made"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// KR-REQ-12.07: a path that is not text is refused by name, and a path of two-byte characters is
    /// measured in bytes, not in characters.
    #[cfg(windows)]
    #[test]
    fn a_socket_path_is_measured_in_utf8_bytes_and_must_be_text() {
        use std::os::windows::ffi::OsStringExt as _;
        let not_text = std::path::PathBuf::from(std::ffi::OsString::from_wide(&[
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            0xD800,
        ]));
        let refusal = require_room_for_a_socket_path(&not_text, WINDOWS_SOCKET_PATH_LIMIT)
            .expect_err("an unpaired surrogate is no text");
        assert!(refusal.to_string().contains("not text"), "{refusal}");

        // Fifty-four characters of two bytes each fit a limit of 107 bytes by characters and not by
        // bytes.
        let wide = std::path::PathBuf::from(format!("C:\\{}", "\u{e9}".repeat(54)));
        assert!(
            wide.to_str()
                .is_some_and(|text| text.chars().count() < WINDOWS_SOCKET_PATH_LIMIT)
        );
        assert!(require_room_for_a_socket_path(&wide, WINDOWS_SOCKET_PATH_LIMIT).is_err());
    }

    /// KR-REQ-07.45: the socket's own list is protected, so widening what its directory passes down
    /// after the bind does not reach it: it still names its owner only, read from its own handle,
    /// while the directory itself no longer counts as private.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_socket_stays_owner_only_when_its_directory_s_inheritable_list_widens() {
        let directory = private_directory();
        let endpoint =
            BoundEndpoint::bind_named(&directory, "gw.sock").expect("the endpoint binds");
        let path = directory.join("gw.sock");
        crate::windows::uds::check_access_list(&path, true).expect("protected at the bind");
        // Everyone may read what the directory holds and what is made in it from now on, and the
        // change is carried to everything below that inherits.
        let widened = std::process::Command::new("icacls")
            .arg(&directory)
            .args(["/grant", "*S-1-1-0:(OI)(CI)(R)"])
            .output()
            .expect("icacls runs");
        assert!(widened.status.success(), "the entry is added: {widened:?}");
        assert!(
            crate::broker::process::check_private_directory(&directory).is_err(),
            "the widened directory is no longer private"
        );
        crate::windows::uds::check_access_list(&path, true)
            .expect("the socket's own list is still protected and names no other account");
        drop(endpoint);
        assert_eq!(socket_identity(&path), None, "its end still removes it");
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// KR-REQ-12.07: a path over the limit is refused by name and makes nothing, and a path of
    /// exactly the limit binds.
    #[cfg(windows)]
    #[test]
    fn a_socket_path_over_the_limit_binds_nothing() {
        let directory = private_directory();
        let base = directory.to_str().expect("a text path").len() + 1;
        let fits = "s".repeat(WINDOWS_SOCKET_PATH_LIMIT - base);
        let bound =
            BoundEndpoint::bind_named(&directory, &fits).expect("a path at the limit binds");
        drop(bound);

        let too_long = "s".repeat(WINDOWS_SOCKET_PATH_LIMIT - base + 1);
        let refusal = BoundEndpoint::bind_named(&directory, &too_long)
            .map(|_| ())
            .expect_err("a path over the limit is refused");
        assert!(
            matches!(refusal, BrokerError::InvalidArgument(_)),
            "{refusal:?}"
        );
        assert!(refusal.to_string().contains("at most 107"), "{refusal}");
        assert!(
            std::fs::symlink_metadata(directory.join(&too_long)).is_err(),
            "no socket was made"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// KR-REQ-12.07: an endpoint removes the socket file it made and no other: a path that names
    /// another socket, or a file, by the time the endpoint ends is not its own and stays, and the
    /// socket it made is removed where nothing has replaced it.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_socket_is_removed_only_when_it_is_the_one_made() {
        let directory = private_directory();
        let path = directory.join("gw.sock");

        let untouched = BoundEndpoint::bind_named(&directory, "gw.sock").expect("it binds");
        let Bound::Uds { made, .. } = &untouched.listener else {
            panic!("a named bind on this platform is a socket");
        };
        assert_eq!(socket_identity(&path), Some(*made));
        drop(untouched);
        assert_eq!(
            socket_identity(&path),
            None,
            "the socket it made is removed"
        );

        let replaced = BoundEndpoint::bind_named(&directory, "gw.sock").expect("it binds");
        std::fs::remove_file(&path).expect("another program takes the path");
        let other = uds_windows::UnixListener::bind(&path).expect("another socket");
        drop(replaced);
        assert!(
            uds_windows::UnixStream::connect(&path).is_ok(),
            "the other program's socket was not removed"
        );
        drop(other);
        std::fs::remove_file(&path).expect("the other program's socket is cleared");

        let overwritten = BoundEndpoint::bind_named(&directory, "gw.sock").expect("it binds");
        std::fs::remove_file(&path).expect("something takes the path");
        std::fs::write(&path, b"a file").expect("a file stands there");
        drop(overwritten);
        assert_eq!(
            std::fs::read(&path).expect("the file was not removed"),
            b"a file"
        );
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

    /// KR-REQ-12.07: a socket path with no room is refused by name, once, with the length it has and
    /// the length it may have: a path of exactly the limit is not refused, and one byte more is.
    #[test]
    fn a_path_over_the_limit_is_refused_by_name() {
        assert_eq!(
            WINDOWS_SOCKET_PATH_LIMIT, 107,
            "a socket's path is held in the 108 bytes of `sun_path`, and one is the terminator"
        );
        let limit = WINDOWS_SOCKET_PATH_LIMIT;
        let at_the_limit = std::path::PathBuf::from(format!("/{}", "x".repeat(limit - 1)));
        assert_eq!(at_the_limit.as_os_str().len(), limit);
        require_room_for_a_socket_path(&at_the_limit, limit).expect("a path at the limit has room");

        let over = std::path::PathBuf::from(format!("/{}", "x".repeat(limit)));
        let refusal = require_room_for_a_socket_path(&over, limit).expect_err("one byte too many");
        assert!(matches!(refusal, BrokerError::InvalidArgument(_)));
        let said = refusal.to_string();
        assert!(said.contains(&format!("is {} bytes", limit + 1)), "{said}");
        assert!(said.contains(&format!("at most {limit}")), "{said}");
        assert!(said.contains(kr_ipc::paths::RUNTIME_DIR_VARIABLE), "{said}");

        let with_a_nul = std::path::PathBuf::from("/a\0b");
        let refusal = require_room_for_a_socket_path(&with_a_nul, limit)
            .expect_err("an address ends at a NUL");
        assert!(refusal.to_string().contains("NUL"), "{refusal}");
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

/// What a failed bind of a launch's socket says, read from what stands at the address at that
/// moment: something that is not a socket is named for what it is, a socket is said to occupy the
/// address (the launch's directory is new, so nothing there is the broker's to replace, and no
/// claim about whether its listener runs is made), and any other failure is the bind step's own.
#[cfg(any(unix, windows))]
fn bind_refusal(path: &std::path::Path, error: &std::io::Error) -> BrokerError {
    use kr_ipc::listen::{ListenRefusal, ListenStep, ObjectKind};

    #[cfg(unix)]
    let is_a_socket = |metadata: &std::fs::Metadata| {
        use std::os::unix::fs::FileTypeExt as _;
        metadata.file_type().is_socket()
    };
    #[cfg(windows)]
    let is_a_socket = |_: &std::fs::Metadata| socket_identity(path).is_some();

    let refusal = match std::fs::symlink_metadata(path) {
        Ok(metadata) if is_a_socket(&metadata) => ListenRefusal::Occupied,
        Ok(metadata) => ListenRefusal::NotASocket {
            object: ObjectKind::of(metadata.file_type()),
        },
        Err(_) => ListenRefusal::Other {
            operation: ListenStep::Bind,
            os: error.raw_os_error(),
        },
    };
    BrokerError::Listen {
        endpoint: path.to_string_lossy().into_owned(),
        refusal,
    }
}

#[cfg(all(test, unix))]
mod bind_tests {
    use super::*;
    use kr_ipc::listen::{ListenRefusal, ObjectKind};

    /// A launch's socket that cannot be bound is named for what stands at its address: a file, a
    /// directory or a socket, each left alone.
    #[tokio::test]
    async fn a_broker_bind_names_what_stands_at_the_path() {
        let folder = kr_ipc::testing::PrivateTempDir::create();
        let file = folder.path().join("file.sock");
        std::fs::write(&file, b"mine").expect("a file");
        let directory = folder.path().join("directory.sock");
        std::fs::create_dir(&directory).expect("a directory");
        let socket = folder.path().join("socket.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("a socket");
        for (name, expected) in [
            (
                "file.sock",
                ListenRefusal::NotASocket {
                    object: ObjectKind::File,
                },
            ),
            (
                "directory.sock",
                ListenRefusal::NotASocket {
                    object: ObjectKind::Directory,
                },
            ),
            ("socket.sock", ListenRefusal::Occupied),
        ] {
            let error = BoundEndpoint::bind_named(folder.path(), name)
                .map(|_| ())
                .expect_err("the address is taken");
            match error {
                BrokerError::Listen { endpoint, refusal } => {
                    assert_eq!(refusal, expected, "{name}");
                    assert_eq!(endpoint, folder.path().join(name).to_string_lossy());
                }
                other => panic!("a listen refusal, not {other:?}"),
            }
        }
        assert_eq!(std::fs::read(&file).expect("the file"), b"mine");
        assert!(directory.is_dir() && socket.exists());
    }
}

#[cfg(all(test, windows))]
mod windows_bind_tests {
    use super::*;
    use kr_ipc::listen::{ListenRefusal, ObjectKind};

    /// A launch's socket that cannot be bound is named for what stands at its address: a file, a
    /// directory or a socket, each left alone.
    #[tokio::test]
    async fn a_broker_bind_names_what_stands_at_the_path() {
        let name: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let folder = std::env::temp_dir().join(format!("kr-e-{name}"));
        kr_ipc::paths::create_private_directory(&folder).expect("a private directory is made");
        let file = folder.join("file.sock");
        std::fs::write(&file, b"mine").expect("a file");
        let directory = folder.join("directory.sock");
        std::fs::create_dir(&directory).expect("a directory");
        let socket = folder.join("socket.sock");
        let _listener = uds_windows::UnixListener::bind(&socket).expect("a socket");
        for (name, expected) in [
            (
                "file.sock",
                ListenRefusal::NotASocket {
                    object: ObjectKind::File,
                },
            ),
            (
                "directory.sock",
                ListenRefusal::NotASocket {
                    object: ObjectKind::Directory,
                },
            ),
            ("socket.sock", ListenRefusal::Occupied),
        ] {
            let error = BoundEndpoint::bind_named(&folder, name)
                .map(|_| ())
                .expect_err("the address is taken");
            match error {
                BrokerError::Listen { endpoint, refusal } => {
                    assert_eq!(refusal, expected, "{name}");
                    assert_eq!(endpoint, folder.join(name).to_string_lossy());
                }
                other => panic!("a listen refusal, not {other:?}"),
            }
        }
        assert_eq!(std::fs::read(&file).expect("the file"), b"mine");
        assert!(directory.is_dir() && socket_identity(&socket).is_some());
        let _ = std::fs::remove_dir_all(&folder);
    }
}
