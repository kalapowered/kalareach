//! A relay in front of the control daemon's socket that loses one answer.
//!
//! What a person's `kr` does when the answer to a request is lost is the part of a command that no
//! success path reaches: the daemon has carried the request out, and the connection that would have
//! told `kr` so ends. The relay makes that happen with the daemon and `kr` as they are. It takes the
//! daemon's socket name, passes every frame in both directions unchanged, and when the answer to
//! the first request for a chosen method comes back it drops that answer and ends both connections,
//! as a connection does that the person's computer lost. The daemon went on to carry the request
//! out first, because the answer is what it sends afterwards.
//!
//! A relay can instead lose the answer to every request for the method, which is a host that
//! carries its requests out and never says so: what a command does then is read the host's state.
//!
//! The daemon keeps listening where it is: its socket file is moved aside, not closed, and moved
//! back when the relay is removed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::RequestId;
use kr_protocol::method::Method;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use crate::host::Host;

/// The name the daemon's own socket is moved to, beside where it was.
const ASIDE: &str = "k";

/// The most a frame's payload may be, which the relay reads whole.
const MAX_FRAME: usize = 1 << 21;

/// What the relay watches for, and what it did.
struct Plan {
    /// The method whose first request's answer is lost.
    method: &'static str,
    /// Whether every request for the method loses its answer, and not the first alone.
    every: bool,
    /// Whether the first request has not been seen yet, on any connection.
    armed: AtomicBool,
    /// Whether an answer was dropped.
    lost: AtomicBool,
}

/// The request whose answer is to be dropped, once it has been seen. Request identifiers belong to
/// one connection, so it is kept with the connection that sent it.
type Watching = Arc<Mutex<Option<RequestId>>>;

/// A relay on the control socket of a running host.
#[derive(Debug)]
pub struct Relay {
    accepting: tokio::task::JoinHandle<()>,
    plan: Arc<Plan>,
    socket: PathBuf,
    aside: PathBuf,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Plan")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl Relay {
    /// Puts a relay in front of the control socket of `host`, which loses the answer to the first
    /// `method` request that goes through it.
    ///
    /// # Panics
    ///
    /// Panics when the socket cannot be moved aside or bound again.
    #[must_use]
    pub fn losing_the_answer_to(
        host: &Host<'_>,
        runtime: &tokio::runtime::Runtime,
        method: Method,
    ) -> Self {
        Self::in_front_of(host, runtime, method, false)
    }

    /// Puts a relay in front of the control socket of `host`, which loses the answer to every
    /// `method` request that goes through it.
    ///
    /// # Panics
    ///
    /// As [`Self::losing_the_answer_to`].
    #[must_use]
    pub fn losing_every_answer_to(
        host: &Host<'_>,
        runtime: &tokio::runtime::Runtime,
        method: Method,
    ) -> Self {
        Self::in_front_of(host, runtime, method, true)
    }

    fn in_front_of(
        host: &Host<'_>,
        runtime: &tokio::runtime::Runtime,
        method: Method,
        every: bool,
    ) -> Self {
        let socket = host
            .environment()
            .controller_endpoint()
            .expect("the control endpoint")
            .as_path()
            .to_path_buf();
        let aside = socket.with_file_name(ASIDE);
        std::fs::rename(&socket, &aside).expect("the daemon's socket is moved aside");
        let plan = Arc::new(Plan {
            method: method.entry().name,
            every,
            armed: AtomicBool::new(true),
            lost: AtomicBool::new(false),
        });
        let listener = {
            let _guard = runtime.enter();
            UnixListener::bind(&socket).expect("the relay binds the daemon's socket name")
        };
        restrict(&socket);
        let accepting = {
            let (plan, aside) = (Arc::clone(&plan), aside.clone());
            runtime.spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let (plan, aside) = (Arc::clone(&plan), aside.clone());
                    tokio::spawn(async move {
                        if let Ok(daemon) = UnixStream::connect(&aside).await {
                            relay(client, daemon, plan).await;
                        }
                    });
                }
            })
        };
        Self {
            accepting,
            plan,
            socket,
            aside,
        }
    }

    /// Whether an answer was lost.
    #[must_use]
    pub fn lost(&self) -> bool {
        self.plan.lost.load(Ordering::SeqCst)
    }

    /// Takes the relay away and gives the daemon its socket name back.
    ///
    /// # Panics
    ///
    /// Panics when the socket cannot be moved back.
    pub fn remove(self) {
        self.accepting.abort();
        std::fs::rename(&self.aside, &self.socket).expect("the daemon's socket is moved back");
    }
}

/// Makes the relay's socket as private as the daemon's, which a client checks.
fn restrict(socket: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .expect("the relay's socket is private");
}

/// Passes frames between one client and the daemon until either ends, or the answer to the watched
/// request comes back, when it is dropped and both ends are closed.
async fn relay(client: UnixStream, daemon: UnixStream, plan: Arc<Plan>) {
    let (from_client, to_client) = client.into_split();
    let (from_daemon, to_daemon) = daemon.into_split();
    let watching = Watching::default();
    let mut requests = {
        let (plan, watching) = (Arc::clone(&plan), Arc::clone(&watching));
        tokio::spawn(async move { requests(from_client, to_daemon, &plan, &watching).await })
    };
    let mut answers =
        tokio::spawn(async move { answers(from_daemon, to_client, &plan, &watching).await });
    futures_util::future::select(&mut requests, &mut answers).await;
    // Ending both tasks drops the halves of both connections, which ends them.
    requests.abort();
    answers.abort();
}

/// The client's frames to the daemon. The first request for the watched method is noted.
async fn requests(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    plan: &Plan,
    watching: &Watching,
) {
    while let Some(frame) = read_frame(&mut from).await {
        if let Ok(ControlFrame::Mutation(request)) = decode(&frame)
            && request.method.as_str() == plan.method
            && (plan.armed.swap(false, Ordering::SeqCst) || plan.every)
        {
            *watching.lock().unwrap_or_else(PoisonError::into_inner) = Some(request.request_id);
        }
        if write_frame(&mut to, &frame).await.is_err() {
            return;
        }
    }
}

/// The daemon's frames to the client. The answer to the noted request is read and dropped.
async fn answers(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    plan: &Plan,
    watching: &Watching,
) {
    while let Some(frame) = read_frame(&mut from).await {
        if let Ok(ControlFrame::Response(response)) = decode(&frame) {
            let mut watching = watching.lock().unwrap_or_else(PoisonError::into_inner);
            if *watching == Some(response.request_id) {
                watching.take();
                plan.lost.store(true, Ordering::SeqCst);
                return;
            }
        }
        if write_frame(&mut to, &frame).await.is_err() {
            return;
        }
    }
}

fn decode(payload: &[u8]) -> Result<ControlFrame, kr_cbor::CborError> {
    kr_cbor::from_canonical_slice(payload, &kr_cbor::Limits::DEFAULT)
}

/// One frame's payload: a four-byte big-endian length, then that many bytes.
async fn read_frame(from: &mut OwnedReadHalf) -> Option<Vec<u8>> {
    let mut length = [0_u8; 4];
    from.read_exact(&mut length).await.ok()?;
    let length = usize::try_from(u32::from_be_bytes(length)).ok()?;
    if length > MAX_FRAME {
        return None;
    }
    let mut payload = vec![0_u8; length];
    from.read_exact(&mut payload).await.ok()?;
    Some(payload)
}

async fn write_frame(to: &mut OwnedWriteHalf, payload: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    to.write_all(&frame).await
}
