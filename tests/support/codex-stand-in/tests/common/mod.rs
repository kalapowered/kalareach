//! What the cases of both platforms share: the socket a gateway binds, the processes of a command
//! and the removal of a folder.

// Each test program that includes this module uses some of it.
#![allow(
    dead_code,
    reason = "each test program that includes this module uses some of it"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(windows)]
pub mod windows;

/// A socket in a directory of its own that only this account reaches, and what removes both.
pub struct Gateway {
    directory: PathBuf,
    socket: PathBuf,
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    /// The bound endpoint, until the folder is removed: it closes first.
    #[cfg(windows)]
    endpoint: Option<kr_worker::broker::BoundEndpoint>,
}

/// The connection a program made to the socket, and the process the kernel names at its other end.
pub struct Connected<S> {
    pub stream: S,
    pub pid: u64,
}

impl Gateway {
    /// Binds a socket in a new private directory under the system's temporary one. The names stay
    /// short, because a socket's path is bounded.
    pub fn bind(name: &str) -> Self {
        static BOUND: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "kr-sm-{}-{}-{name}",
            std::process::id(),
            BOUND.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        remove_tree(&directory);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::create_dir_all(&directory).expect("a directory");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("a private directory");
            let socket = directory.join("gw.sock");
            let listener = tokio::net::UnixListener::bind(&socket).expect("a socket");
            Self {
                directory,
                socket,
                listener,
            }
        }
        #[cfg(windows)]
        {
            kr_ipc::paths::create_private_directory(&directory).expect("a private directory");
            let endpoint = kr_worker::broker::BoundEndpoint::bind_named(&directory, "gw.sock")
                .expect("the socket binds");
            let kr_worker::broker::ListenerAddress::PrivateSocket(socket) =
                endpoint.address().clone()
            else {
                panic!("a named bind on this platform is a socket");
            };
            Self {
                directory,
                socket,
                endpoint: Some(endpoint),
            }
        }
    }

    /// The socket's path, as text.
    pub fn socket(&self) -> String {
        self.socket
            .to_str()
            .expect("a path that is text")
            .to_owned()
    }

    #[cfg(unix)]
    pub async fn accept(&self) -> Connected<tokio::net::UnixStream> {
        let (stream, _) = self.listener.accept().await.expect("accepted");
        let pid = stream
            .peer_cred()
            .expect("the kernel names the peer")
            .pid()
            .expect("it names a process");
        Connected {
            stream,
            pid: u64::try_from(pid).expect("a process number"),
        }
    }

    #[cfg(windows)]
    pub async fn accept(&self) -> Connected<kr_worker::windows::uds::Stream> {
        let accepted = self
            .endpoint
            .as_ref()
            .expect("the endpoint is bound until the gateway goes")
            .accept()
            .await
            .expect("the connection is accepted and its peer named");
        let kr_worker::broker::Stream::Uds(stream) = accepted.stream else {
            panic!("the accepted stream is a Unix-domain socket's");
        };
        Connected {
            stream,
            pid: accepted.peer.process().pid.get(),
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        // The listener closes before its folder goes, so that no handle of this process holds it.
        #[cfg(windows)]
        drop(self.endpoint.take());
        remove_tree(&self.directory);
    }
}

/// How long a removal that a program's open handle holds up is tried again.
const REMOVAL: Duration = Duration::from_secs(20);

/// Removes a folder and what it holds, and says nothing if it is not there. On Windows a handle
/// that a program has not closed yet (a process that was ended a moment ago, a socket that is
/// closing) refuses the removal with a sharing violation, and the removal is tried again for a
/// bounded time.
pub fn remove_tree(path: &Path) {
    let end = Instant::now() + REMOVAL;
    loop {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) if Instant::now() >= end => {
                eprintln!("{} is not removed: {error}", path.display());
                return;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}
