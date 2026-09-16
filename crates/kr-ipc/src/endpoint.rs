//! Binding, connecting and accepting on a local endpoint.
//!
//! One API, two implementations. On Unix the endpoint is a socket file inside the owner-only
//! runtime directory; the file is replaced on bind, because a socket file left behind by a process
//! that died is not evidence that anything is listening. On Windows it is a named pipe carrying an
//! owner-only access-control list, since the pipe namespace has no directory permissions to
//! inherit.
//!
//! Both report the peer's credentials, and both refuse a peer that is not the owning user.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{IpcError, Result};
use crate::paths::Endpoint;
use crate::peer::PeerIdentity;

/// A bound local endpoint.
#[derive(Debug)]
pub struct Listener {
    inner: platform::Listener,
    endpoint: Endpoint,
    owner_uid: u32,
}

impl Listener {
    /// Binds the endpoint, replacing a socket left by a process that is gone.
    ///
    /// # Errors
    ///
    /// Returns an error when the address is in use by a live listener, or when the endpoint
    /// cannot be created.
    pub fn bind(endpoint: &Endpoint) -> Result<Self> {
        let inner = platform::Listener::bind(endpoint)?;
        Ok(Self {
            inner,
            endpoint: endpoint.clone(),
            owner_uid: crate::paths::current_uid(),
        })
    }

    /// Returns the address this listener is bound to.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Accepts one connection and authenticates its caller.
    ///
    /// A caller that is not the owning user is refused here, before any frame is read.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails, when the platform does not report the peer's
    /// credentials, or when the peer is another user.
    pub async fn accept(&self) -> Result<(Connection, PeerIdentity)> {
        loop {
            let accepted = self.inner.accept().await;
            let (connection, peer) = match accepted {
                Ok(accepted) => accepted,
                // A caller whose credentials the kernel will not report cannot be authenticated,
                // whatever is still sitting in its receive buffer. Some platforms report that as
                // "not connected" the moment the caller closes its end. Dropping the connection
                // and waiting for the next caller is the safe answer; it is not a reason for the
                // listener to stop serving the owner, which is why neither failure escapes here.
                Err(IpcError::PeerClosed | IpcError::PeerUnknown { .. }) => continue,
                Err(error) => return Err(error),
            };
            match peer.authorise(self.owner_uid) {
                Ok(()) => return Ok((connection, peer)),
                // Refusing one caller is not a reason to stop serving the owner.
                Err(IpcError::PeerRejected { .. }) => drop(connection),
                Err(error) => return Err(error),
            }
        }
    }
}

/// One local connection.
#[derive(Debug)]
pub struct Connection(platform::Connection);

impl Connection {
    /// Connects to an endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when nothing is listening or the connection is refused.
    pub async fn connect(endpoint: &Endpoint) -> Result<Self> {
        platform::Connection::connect(endpoint).await.map(Self)
    }

    /// Returns the credentials of the process on the other end.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::PeerUnknown`] when the platform does not answer.
    pub fn peer(&self) -> Result<PeerIdentity> {
        self.0.peer()
    }

    /// Returns a handle on this connection's writability.
    ///
    /// Waiting for a socket to have room and writing to it are two different things, and the
    /// difference is what lets a caller wait outside the boundary that decides whether the bytes
    /// may still be sent. This is the waiting half, and it borrows nothing the writer holds.
    #[cfg(unix)]
    pub(crate) fn writability(&self) -> Result<std::os::fd::OwnedFd> {
        use std::os::fd::AsFd as _;

        rustix::io::fcntl_dupfd_cloexec(self.0.as_fd(), 0)
            .map_err(|error| IpcError::socket("duplicate the connection", error.into()))
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, buffer)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(context)
    }
}

#[cfg(unix)]
mod platform {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use std::os::unix::fs::FileTypeExt as _;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use tokio::net::{UnixListener, UnixStream};

    use crate::error::{IpcError, Result};
    use crate::paths::Endpoint;
    use crate::peer::PeerIdentity;

    #[derive(Debug)]
    pub(super) struct Listener {
        inner: UnixListener,
        path: std::path::PathBuf,
        identity: (u64, u64),
    }

    impl Listener {
        pub(super) fn bind(endpoint: &Endpoint) -> Result<Self> {
            let path = endpoint.as_path().to_path_buf();
            // The guard covers the change and nothing else. Probing an address, unlinking it and
            // binding it are three steps, and two processes interleaving them would leave one of
            // them bound to an address the other had already unlinked. Holding it for the
            // listener's whole life would instead make a second bind wait for the first listener
            // to end, which is not the answer either: that bind should be told the address is
            // taken.
            let guard = EndpointGuard::take(&path)?;
            replace_stale_socket(&path)?;
            let inner =
                UnixListener::bind(&path).map_err(|error| IpcError::socket("bind", error))?;
            set_owner_only(&path)?;
            let identity = socket_identity(&path)?;
            drop(guard);
            Ok(Self {
                inner,
                path,
                identity,
            })
        }

        pub(super) async fn accept(&self) -> Result<(super::Connection, PeerIdentity)> {
            let (stream, _) = self
                .inner
                .accept()
                .await
                .map_err(|error| IpcError::socket("accept", error))?;
            let connection = Connection(stream);
            let peer = connection.peer()?;
            Ok((super::Connection(connection), peer))
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            // The address stays reserved until the file is gone, and leaving it behind makes the
            // next bind decide whether a live process owns it. Remove it only while it is still
            // the same socket this listener bound: another process may already have replaced it,
            // and deleting a working endpoint out from under it would be worse than leaving a
            // stale file.
            // Removal takes the guard as well, so it cannot interleave with another process's
            // probe. A guard that cannot be taken leaves the file alone: a stale socket file is a
            // smaller problem than deleting a working endpoint.
            let Ok(_guard) = EndpointGuard::take(&self.path) else {
                return;
            };
            if socket_identity(&self.path).is_ok_and(|identity| identity == self.identity) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    /// Removes a socket file only when nothing is listening on it.
    ///
    /// A socket file is not a lock, so its presence proves nothing on its own. A connection that
    /// is refused proves the previous owner is gone. Any other failure — a permission error, an
    /// exhausted descriptor table, a full backlog — proves nothing at all, and unlinking on those
    /// would let one process delete another's live endpoint.
    fn replace_stale_socket(path: &std::path::Path) -> Result<()> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(IpcError::io("inspect", path, error)),
        };
        if !metadata.file_type().is_socket() {
            return Err(IpcError::UntrustedFile {
                path: path.to_path_buf(),
                reason: "an endpoint address is occupied by something that is not a socket",
            });
        }
        match probe(path)? {
            // Something answered, or its backlog was full, which only a live listener has. Either
            // way the address belongs to a running process.
            Probe::Listening => Err(IpcError::socket(
                "bind",
                std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "another process is listening on this endpoint",
                ),
            )),
            Probe::Abandoned => {
                std::fs::remove_file(path).map_err(|error| IpcError::io("replace", path, error))
            }
        }
    }

    enum Probe {
        Listening,
        Abandoned,
    }

    /// Asks whether anything is listening, without waiting for it.
    ///
    /// The connection is made on a non-blocking socket, so a listener whose backlog is full
    /// answers immediately instead of holding this call. For a Unix socket that is the whole
    /// bound: there is no network round trip to time out.
    fn probe(path: &std::path::Path) -> Result<Probe> {
        use rustix::net::{AddressFamily, SocketType};

        let socket = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)
            .map_err(|error| IpcError::socket("probe", std::io::Error::from(error)))?;
        // `SOCK_NONBLOCK` is a Linux extension, so the mode is set on the descriptor instead.
        rustix::io::ioctl_fionbio(&socket, true)
            .map_err(|error| IpcError::socket("probe", std::io::Error::from(error)))?;
        let address = rustix::net::SocketAddrUnix::new(path)
            .map_err(|error| IpcError::socket("probe", std::io::Error::from(error)))?;
        match rustix::net::connect(&socket, &address) {
            // Connected, or the handshake is still in progress against a listener that exists.
            Ok(()) | Err(rustix::io::Errno::INPROGRESS) => Ok(Probe::Listening),
            // A full backlog is a live listener that is busy, never an abandoned address.
            Err(rustix::io::Errno::AGAIN) => Ok(Probe::Listening),
            // Refused means the socket file outlived the process that bound it.
            Err(rustix::io::Errno::CONNREFUSED) => Ok(Probe::Abandoned),
            // Anything else proves nothing, and unlinking on it would let one process delete
            // another's live endpoint.
            Err(error) => Err(IpcError::socket("probe", std::io::Error::from(error))),
        }
    }

    /// The exclusive right to change one endpoint address.
    ///
    /// Probing an address, unlinking it and binding it are three steps. Without a lock two
    /// processes can interleave them: both probe a refused socket, both unlink, both bind, and the
    /// one that bound first ends up with an address that no longer names its socket.
    #[derive(Debug)]
    pub(super) struct EndpointGuard {
        _file: std::fs::File,
    }

    /// How long a guard waits for the other holder to finish its change.
    ///
    /// The work under the guard is three filesystem calls. A holder that takes longer than this is
    /// not making progress, and waiting further would turn a busy address into a hang.
    const GUARD_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

    impl EndpointGuard {
        fn take(path: &std::path::Path) -> Result<Self> {
            use rustix::fs::{FlockOperation, flock};

            let lock_path = lock_path(path);
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&lock_path)
                .map_err(|error| IpcError::io("open the endpoint lock", &lock_path, error))?;
            // Bounded, because the guard protects three filesystem calls. A bind that loses the
            // race waits for the other process to finish them and then discovers the address is in
            // use; a bind that waits on a process which has stopped making progress is told so
            // instead of hanging.
            let deadline = std::time::Instant::now() + GUARD_WAIT;
            loop {
                match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => return Ok(Self { _file: file }),
                    Err(rustix::io::Errno::WOULDBLOCK) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => {
                        return Err(IpcError::io(
                            "lock the endpoint",
                            &lock_path,
                            std::io::Error::from(error),
                        ));
                    }
                }
            }
        }
    }

    fn lock_path(path: &std::path::Path) -> std::path::PathBuf {
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        std::path::PathBuf::from(name)
    }

    fn socket_identity(path: &std::path::Path) -> Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| IpcError::io("inspect", path, error))?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn set_owner_only(path: &std::path::Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(crate::paths::OWNER_ONLY_FILE_MODE),
        )
        .map_err(|error| IpcError::io("restrict", path, error))
    }

    #[derive(Debug)]
    pub(super) struct Connection(UnixStream);

    impl std::os::fd::AsFd for Connection {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    impl Connection {
        pub(super) async fn connect(endpoint: &Endpoint) -> Result<Self> {
            let connection = UnixStream::connect(endpoint.as_path())
                .await
                .map(Self)
                .map_err(|error| IpcError::socket("connect", error))?;
            // The listener authenticates its callers; a caller authenticates the listener the same
            // way. An endpoint inside an owner-only directory should not be answered by another
            // user's process, and if one ever is, the client stops there rather than beginning a
            // handshake with it.
            connection.peer()?.authorise(crate::paths::current_uid())?;
            Ok(connection)
        }

        pub(super) fn peer(&self) -> Result<PeerIdentity> {
            let credentials = self.0.peer_cred().map_err(|source| {
                // A peer that closed before the kernel was asked is gone, not unidentifiable.
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) {
                    IpcError::PeerClosed
                } else {
                    IpcError::PeerUnknown { source }
                }
            })?;
            Ok(PeerIdentity {
                uid: credentials.uid(),
                gid: credentials.gid(),
                pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
            })
        }
    }

    impl AsyncRead for Connection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for Connection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(context, bytes)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use interprocess::local_socket::tokio::prelude::*;
    use interprocess::local_socket::{GenericNamespaced, ListenerOptions, ToNsName};
    use interprocess::os::windows::local_socket::ListenerOptionsExt as _;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use crate::error::{IpcError, Result};
    use crate::paths::Endpoint;
    use crate::peer::PeerIdentity;

    /// The object's owner only, with inheritance blocked.
    ///
    /// `D:P` makes the list protected, so no inherited entry widens it. `OW` is the OWNER RIGHTS
    /// identifier, which resolves to whoever owns the object: the process that created the pipe,
    /// which is this user. The CREATOR OWNER identifier would be wrong here, because it is a
    /// placeholder that only means anything in an inheritable entry.
    const OWNER_ONLY_DESCRIPTOR: &str = "D:P(A;;GA;;;OW)";

    #[derive(Debug)]
    pub(super) struct Listener {
        inner: interprocess::local_socket::tokio::Listener,
    }

    impl Listener {
        pub(super) fn bind(endpoint: &Endpoint) -> Result<Self> {
            let name = endpoint
                .as_text()
                .to_ns_name::<GenericNamespaced>()
                .map_err(|error| IpcError::socket("bind", error))?;
            let descriptor = SecurityDescriptor::deserialize(
                &widestring::U16CString::from_str(OWNER_ONLY_DESCRIPTOR).map_err(|_| {
                    IpcError::socket(
                        "bind",
                        std::io::Error::other("the access-control list is not valid text"),
                    )
                })?,
            )
            .map_err(|error| IpcError::socket("bind", error))?;
            let inner = ListenerOptions::new()
                .name(name)
                .security_descriptor(descriptor)
                .create_tokio()
                .map_err(|error| IpcError::socket("bind", error))?;
            Ok(Self { inner })
        }

        pub(super) async fn accept(&self) -> Result<(super::Connection, PeerIdentity)> {
            let stream = self
                .inner
                .accept()
                .await
                .map_err(|error| IpcError::socket("accept", error))?;
            let connection = Connection(stream);
            let peer = connection.peer()?;
            Ok((super::Connection(connection), peer))
        }
    }

    #[derive(Debug)]
    pub(super) struct Connection(interprocess::local_socket::tokio::Stream);

    impl Connection {
        pub(super) async fn connect(endpoint: &Endpoint) -> Result<Self> {
            let name = endpoint
                .as_text()
                .to_ns_name::<GenericNamespaced>()
                .map_err(|error| IpcError::socket("connect", error))?;
            interprocess::local_socket::tokio::Stream::connect(name)
                .await
                .map(Self)
                .map_err(|error| IpcError::socket("connect", error))
        }

        pub(super) fn peer(&self) -> Result<PeerIdentity> {
            let credentials = self
                .0
                .peer_creds()
                .map_err(|source| IpcError::PeerUnknown { source })?;
            // Windows reports the peer's process, not a numeric user. The access-control list on
            // the pipe is what keeps another user out, so the identity carried here is the process
            // and the owning user this endpoint belongs to.
            Ok(PeerIdentity {
                uid: crate::paths::current_uid(),
                gid: 0,
                pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
            })
        }
    }

    impl AsyncRead for Connection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for Connection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(context, bytes)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }
}
