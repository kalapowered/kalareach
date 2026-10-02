//! `kr bridge --stdio`: the destination half of a local process bridge.
//!
//! The helper is started inside the environment it serves, by `wsl.exe --exec` for a WSL
//! distribution or by the container runtime's exec for an enrolled container. It reads the
//! invoker's opening frame, decides whether this bridge may carry the request at all, connects to
//! its own environment's control daemon or session worker through local IPC, and then relays
//! protocol frames in both directions until either side goes away.
//!
//! Three rules decide the admission, and each is refused by name:
//!
//! * **The original ingress must be a locally authenticated one.** Section 3 restricts the
//!   process bridges to locally authenticated command-line invocations and forbids relabelling a
//!   network actor as a local owner on the far side. A remote client reaches this environment
//!   through that environment's own paired endpoint instead.
//! * **A request crosses at most one bridge.** A federated proxy is outside version 1, so a
//!   handshake that says the request has already been bridged is refused rather than chained, and
//!   so is a carried request that would open a bridge of its own. The destination cannot enforce
//!   that second rule for itself: what arrives over this helper's local connection looks like any
//!   other local request, and nothing in it says a bridge was crossed to get there.
//! * **The protocol major must match**, because the frames are carried unchanged.
//!
//! What the helper never does is decide authority. The destination authenticates it by its own
//! operating-system credentials, exactly as it authenticates any other local caller, and the
//! actor envelope the destination builds records that local ingress. Nothing on standard input
//! can widen it, and no environment variable is read for it.

use kr_client::shown;
use kr_client::shown::{Said, Shown};
use std::io::{Read, Write};

use kr_ipc::paths::HostPaths;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    BridgeFrame, BridgeHello, BridgeHelloAck, BridgeTarget, DESTINATION_BASE_VARIABLES,
    DestinationBase,
};
use kr_protocol::scalars::U64;

use crate::bridge::pipe::{self, PipeError};
use crate::error::{CliError, Result};
use crate::resolve;

/// Why a bridge handshake was refused.
///
/// Each becomes one `BridgeFrame::Refused` on standard output and one diagnostic line on standard
/// error. The two carry the same reason, so a log and a caller never disagree about what happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The first frame was not an opening frame.
    NotAHandshake,
    /// The invoker speaks a protocol major this helper does not.
    ProtocolMajor,
    /// The request did not originally arrive on a locally authenticated ingress.
    RemoteOrigin,
    /// The request has already crossed a bridge.
    AlreadyBridged,
    /// The session target has closed.
    SessionClosed,
    /// A frame to be carried says hello again.
    ///
    /// A connection says hello once. The destination admits a connection under what its hello
    /// declared, so a second one carried over an open bridge would be a way to admit it again
    /// under something else.
    SecondHello,
}

impl Refusal {
    /// Returns the message sent to the invoker and written to standard error.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotAHandshake => "a bridge begins with its opening frame",
            Self::ProtocolMajor => "this helper does not speak that protocol major",
            Self::RemoteOrigin => {
                "a process bridge carries locally authenticated invocations only; reach this \
                 environment through its own paired endpoint"
            }
            Self::AlreadyBridged => "a request crosses at most one process bridge",
            Self::SessionClosed => "that session is closed",
            Self::SecondHello => "a bridge says hello once, and a second one is not carried",
        }
    }

    /// Returns the protocol error this refusal is sent as.
    #[must_use]
    pub fn as_error(self) -> ProtocolError {
        let code = match self {
            // A shape this helper cannot read and a version it does not implement are schema
            // failures. The two admission rules are authority failures, and both say the same
            // thing, because the difference between them tells a caller nothing it may act on.
            Self::NotAHandshake | Self::ProtocolMajor => ErrorCode::UnsupportedSchema,
            Self::RemoteOrigin | Self::AlreadyBridged | Self::SecondHello => {
                ErrorCode::PermissionDenied
            }
            Self::SessionClosed => ErrorCode::SessionClosed,
        };
        kr_client::error::refusal(code, Shown::said(self.message()))
    }
}

/// Decides whether this bridge may carry what the opening frame describes.
///
/// # Errors
///
/// Returns the [`Refusal`] to send back, without connecting to anything.
pub fn admit(hello: &BridgeHello) -> std::result::Result<(), Refusal> {
    if hello.protocol_version.major != PROTOCOL_VERSION.major {
        return Err(Refusal::ProtocolMajor);
    }
    if !hello.origin_ingress.may_cross_process_bridge() {
        return Err(Refusal::RemoteOrigin);
    }
    if hello.already_bridged {
        return Err(Refusal::AlreadyBridged);
    }
    Ok(())
}

/// Runs the helper until either side closes.
///
/// `environment` names the environment to serve; without it this installation's own is served. The
/// streams are this process's standard input and output, and diagnostics go to standard error.
///
/// # Errors
///
/// Returns [`CliError::Refused`] when the handshake was refused, and a transport failure when a
/// stream or the local connection fails.
pub async fn run(environment: Option<&str>) -> Result<()> {
    serve(
        std::io::stdin(),
        &mut crate::output::protocol_stream().blocking(),
        environment,
    )
    .await
}

/// Runs one bridge over the streams given, which is what a test drives.
///
/// The reading side owns its stream because it is read on a thread of its own: standard input is a
/// blocking stream, and reading it on this task would stop the answers coming back from the
/// destination from being written.
///
/// # Errors
///
/// As [`run`].
pub async fn serve(
    input: impl Read + Send + 'static,
    output: &mut impl Write,
    environment: Option<&str>,
) -> Result<()> {
    // One frame at a time, so the reading thread stops at the frame after the one this bridge is
    // still carrying rather than drawing the whole of standard input into memory.
    let (to_relay, mut incoming) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let (wake, mut woken) = tokio::sync::mpsc::channel::<()>(2);
    let reading = std::thread::spawn(move || read_frames(input, &to_relay, &wake));

    let outcome = relay(&mut incoming, &mut woken, output, environment).await;
    // The reading thread holds the input stream. Drop both receivers first: a thread that is
    // handing a frame over waits on one of them, and dropping them unblocks it.
    drop(incoming);
    drop(woken);
    // If the reading thread has already finished (or finishes promptly on EOF), collect its status.
    // If standard input remains open, do not wait indefinitely: dropped receivers mean nothing more
    // will be relayed, and an indefinite join would leave this helper stuck in a blocking read.
    if !reading.is_finished() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let stream = if reading.is_finished() {
        match reading.join() {
            Ok(Ok(()) | Err(PipeError::Closed)) => Ok(()),
            Ok(Err(error)) => Err(transport(&error)),
            Err(_) => Err(CliError::Other(Shown::said(
                "the bridge's reading thread stopped unexpectedly",
            ))),
        }
    } else {
        Ok(())
    };
    match (outcome, stream) {
        (Err(error), _) => Err(error),
        (Ok(()), stream) => stream,
    }
}

/// Reads frames from the invoker until the stream ends or the relay stops.
///
/// The payload is handed on exactly as it arrived. A frame this side cannot read is a refusal, and
/// it ends the bridge rather than being skipped: skipping one would leave the destination reading
/// the middle of a message.
fn read_frames(
    mut input: impl Read,
    to_relay: &std::sync::mpsc::SyncSender<Vec<u8>>,
    wake: &tokio::sync::mpsc::Sender<()>,
) -> std::result::Result<(), PipeError> {
    loop {
        let payload = pipe::read_payload(&mut input)?;
        if to_relay.send(payload).is_err() {
            // The relay has stopped. Nothing else will read this stream.
            return Ok(());
        }
        // The relay waits on this rather than polling the blocking channel.
        if wake.blocking_send(()).is_err() {
            return Ok(());
        }
    }
}

/// Connects to the destination and carries frames both ways until either side goes away.
async fn relay(
    incoming: &mut std::sync::mpsc::Receiver<Vec<u8>>,
    woken: &mut tokio::sync::mpsc::Receiver<()>,
    output: &mut impl Write,
    environment: Option<&str>,
) -> Result<()> {
    let hello = match first_frame(incoming, woken).await {
        Some(payload) => match decode_hello(&payload) {
            Ok(hello) => hello,
            Err(refusal) => return refuse(output, refusal),
        },
        // Nothing arrived. An invoker that opens a bridge and closes it has done nothing wrong.
        None => return Ok(()),
    };
    if let Err(refusal) = admit(&hello) {
        return refuse(output, refusal);
    }

    let (client, role) = match reach(&hello, environment).await {
        Ok(reached) => reached,
        // Everything that stops the helper before it can acknowledge is said to the invoker as a
        // refusal. An invoker that read only the end of the stream could name nothing, and the
        // person would be told that a bridge failed when what failed is a daemon that is not
        // there, or a session that is not.
        Err(Unreached::Refusal(refusal)) => return refuse(output, refusal),
        Err(Unreached::Error(error)) => return refuse_with(output, &error),
    };
    let (mut reader, mut writer, acknowledgement) = client.into_halves();

    // The acknowledgement carries the destination's own identity, never the invoker's. A caller
    // reading it learns which environment answered, which is the fact a grouped interface has to
    // present beside every action.
    pipe::write_frame(
        output,
        &BridgeFrame::HelloAck(Box::new(BridgeHelloAck {
            protocol_version: acknowledgement.selected_version,
            environment_id: acknowledgement.environment_id,
            os_user: account().name,
            role,
            connection_id: acknowledgement.connection_id,
            boot_identity: acknowledgement.boot_identity.clone(),
            max_frame_len: U64::new(pipe::max_frame_len() as u64),
            action_window: acknowledgement.action_window,
            build: acknowledgement.build.clone(),
            base: base(),
        })),
    )
    .map_err(|error| transport(&error))?;

    loop {
        tokio::select! {
            arrival = woken.recv() => {
                if arrival.is_none() {
                    // The invoker went away, or its stream failed. Either way this bridge is over.
                    return Ok(());
                }
                let Ok(payload) = incoming.try_recv() else {
                    return Ok(());
                };
                let frame: BridgeFrame = decode_frame(&payload)?;
                match frame {
                    // Carried unchanged: the bytes are what a payload digest was taken over, and
                    // re-encoding them would risk changing what the caller signed for.
                    BridgeFrame::Control(carried) => {
                        if matches!(*carried, kr_protocol::envelope::ControlFrame::Hello(_)) {
                            return refuse(output, Refusal::SecondHello);
                        }
                        // Except for one thing this side has to decide: a request crosses at most
                        // one bridge. The destination will serve what arrives here as an ordinary
                        // local request, so a method that opens a bridge of its own would chain one
                        // behind this helper's back. It is refused here, where the hop is known.
                        if let Some(method) = crosses_again(&carried) {
                            crate::report::say(&shown!(
                                "kr bridge: {} opens a bridge of its own",
                                method.as_str()
                            ));
                            return refuse(output, Refusal::AlreadyBridged);
                        }
                        writer.write_message(&*carried).await.map_err(CliError::Ipc)?;
                    }
                    // A second handshake, an acknowledgement or a refusal on this side of the
                    // bridge is a frame this role does not serve.
                    _ => return refuse(output, Refusal::NotAHandshake),
                }
            }
            answer = reader.read_payload() => match answer {
                Ok(payload) => pipe::write_carried_payload(output, &payload)
                    .map_err(|error| transport(&error))?,
                Err(kr_ipc::IpcError::PeerClosed) => return Ok(()),
                Err(error) => return Err(CliError::Ipc(error)),
            },
        }
    }
}

/// What stopped the helper before it could acknowledge.
enum Unreached {
    /// One of the helper's own admission rules.
    Refusal(Refusal),
    /// A failure to reach the destination's daemon or worker, in the command's own terms.
    Error(CliError),
}

impl From<CliError> for Unreached {
    fn from(error: CliError) -> Self {
        Self::Error(error)
    }
}

/// Connects to what the opening asked for inside this environment.
///
/// A destination that was just started has no control daemon yet. An opening that may start what
/// it needs reaches the daemon the way `kr new` does, through this environment's own configured
/// startup, so a destination with none configured says what to set up rather than being started
/// in a way its owner did not choose. An opening that may not start anything finds the daemon
/// running or says that it is not.
async fn reach(
    hello: &BridgeHello,
    environment: Option<&str>,
) -> std::result::Result<(kr_ipc::client::LocalClient, kr_protocol::local::LocalRole), Unreached> {
    let paths = HostPaths::discover().map_err(CliError::from)?;
    let known = resolve::select(&paths, environment)?;
    // What the destination is told of where this invocation began: the invoker's own declaration,
    // which the destination checks again for itself and never takes for authority.
    let origin = kr_protocol::local::BridgeOrigin {
        environment_id: hello.origin_environment_id,
        ingress: hello.origin_ingress,
    };
    let (client, role) = match hello.target {
        BridgeTarget::Controller => (
            match controller(&paths, &known, hello.start, origin).await {
                Ok(client) => client,
                Err(error) => {
                    let endpoint = known.paths.controller_endpoint().ok();
                    return Err(explained(Peer::Daemon, endpoint, error).await);
                }
            },
            kr_protocol::local::LocalRole::Controller,
        ),
        BridgeTarget::Session { session_id } => {
            match resolve::find(
                &paths,
                &resolve::SessionSelector::Identifier(session_id),
                Some(known.environment_id),
            ) {
                Ok((_, descriptor)) => (
                    match resolve::open_worker_for(&descriptor, crate::build_id(), Some(origin))
                        .await
                    {
                        Ok(client) => client,
                        Err(error) => {
                            let endpoint =
                                kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).ok();
                            return Err(explained(Peer::Worker, endpoint, error).await);
                        }
                    },
                    kr_protocol::local::LocalRole::Worker,
                ),
                Err(CliError::UnknownSession(_)) => {
                    // No worker publishes a descriptor for it, so the daemon's retained record is
                    // what says whether it closed. After a stop of the whole environment that
                    // daemon has to be started to be asked, which an attach is allowed to do.
                    if is_destination_session_closed(
                        &paths,
                        &known,
                        session_id,
                        hello.start,
                        origin,
                    )
                    .await
                    {
                        return Err(Unreached::Refusal(Refusal::SessionClosed));
                    }
                    return Err(CliError::UnknownSession(shown!("{}", session_id)).into());
                }
                Err(other) => return Err(other.into()),
            }
        }
    };
    // The destination authenticates this helper by its operating-system credentials, and says
    // which user it saw. A socket forwarded from somewhere else is authenticated as whoever
    // forwarded it, so a daemon that did not see this helper's own user is not this
    // environment's: socket forwarding alone does not install the integration.
    let own = u64::from(kr_ipc::paths::current_uid());
    if client.acknowledgement().peer.uid.get() != own {
        return Err(Unreached::Error(CliError::Refused(
            kr_client::error::refusal(
                ErrorCode::PermissionDenied,
                Shown::said(
                    "the daemon behind this endpoint did not authenticate this helper as the \
                     user it runs as, so it is not this environment's own",
                ),
            ),
        )));
    }
    Ok((client, role))
}

/// What a bridge's helper reaches inside its environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Peer {
    /// The environment's control daemon.
    Daemon,
    /// A session's worker.
    Worker,
}

impl Peer {
    const fn name(self) -> &'static str {
        match self {
            Self::Daemon => "control daemon",
            Self::Worker => "session worker",
        }
    }

    /// What a person does about one of an earlier build that will not take a bridge's connection.
    const fn action(self) -> &'static str {
        match self {
            Self::Daemon => "restart it, so that it runs this release",
            Self::Worker => {
                "attach to the session from a shell inside this environment, with the kr of its \
                 own build"
            }
        }
    }
}

/// Turns the failure to open a connection that says where the invocation began into what is said
/// of it.
///
/// A daemon or worker of a build before that declaration existed ends the connection that carries
/// it, so what the connection reports is that the peer went away, which reads like a daemon that is
/// not running. One that answers an ordinary connection is running, though, so it is asked who it is
/// and the failure is said to be this one: the peer's build and this helper's, and what to do. A
/// failure of any other kind, and a peer that answers nothing, are reported as they were.
async fn explained(
    peer: Peer,
    endpoint: Option<kr_ipc::paths::Endpoint>,
    error: CliError,
) -> Unreached {
    if !matches!(error, CliError::HostUnavailable(_)) {
        return Unreached::Error(error);
    }
    let Some(endpoint) = endpoint else {
        return Unreached::Error(error);
    };
    let answered = tokio::time::timeout(
        crate::startup::ANSWER_BOUND,
        kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            crate::build_id(),
        ),
    )
    .await;
    match answered {
        Ok(Ok(ordinary)) => Unreached::Error(refused_by_a_peer_that_answers(
            peer,
            ordinary.acknowledgement().build.as_ref(),
        )),
        _ => Unreached::Error(error),
    }
}

/// The refusal a caller is given when the peer in `peer` answers an ordinary connection, states
/// `theirs` as its build, and did not take the connection a bridge makes.
fn refused_by_a_peer_that_answers(
    peer: Peer,
    theirs: Option<&kr_protocol::local::LocalBuild>,
) -> CliError {
    let own = kr_protocol::local::LocalBuild::this(crate::build_id());
    let version = |build: &kr_protocol::local::LocalBuild| {
        shown!(
            "{}.{}.{}",
            build.protocol_version.major,
            build.protocol_version.minor,
            build.protocol_version.patch
        )
    };
    let theirs = match theirs {
        Some(build) => shown!(
            "{} with protocol {}",
            crate::shown::build_name(&build.build_id),
            version(build)
        ),
        None => Shown::said("a build that does not state its build or its protocol version"),
    };
    CliError::Refused(kr_client::error::refusal(
        ErrorCode::UnsupportedSchema,
        shown!(
            "the {} in this environment answers an ordinary connection and not the one a process \
             bridge makes. It is {}, and this helper is {} with protocol {}: a {} of an earlier \
             build does not take a connection that says where an invocation began. To go on, {}",
            peer.name(),
            theirs,
            crate::shown::build_name(&own.build_id),
            version(&own),
            peer.name(),
            peer.action()
        ),
    ))
}

/// Reaches the control daemon, starting it only where the opening may.
async fn controller(
    paths: &HostPaths,
    known: &resolve::KnownEnvironment,
    start: bool,
    origin: kr_protocol::local::BridgeOrigin,
) -> Result<kr_ipc::client::LocalClient> {
    if start {
        // The daemon is reached the way `kr new` reaches it, starting it where this environment
        // has chosen to. That connection is a plain one, made only to be sure a daemon is there;
        // the one this bridge carries is made after it, and says where the invocation began.
        let (reached, started) = crate::startup::open_or_start(paths, known).await?;
        drop(reached);
        if let Some(started) = started {
            // Diagnostic output, which is where a person reading the log looks for what a helper
            // did.
            crate::report::say(&shown!("kr: {}", started.describe(known.environment_id)));
        }
    }
    resolve::open_controller_for(&known.paths, crate::build_id(), Some(origin)).await
}

/// What this helper's user is called, and where its home is, as the destination's account records
/// them.
struct Account {
    name: String,
    home: Option<String>,
}

/// Reads the account this process runs as.
///
/// The name is the account's own and not a variable a caller could have set: `USER` and `LOGNAME`
/// are whatever the process that started the helper put there. A destination that records no
/// account for the user is said by its number.
fn account() -> Account {
    let uid = kr_ipc::paths::current_uid();
    #[cfg(unix)]
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 6 && fields[2].parse::<u32>().ok() == Some(uid) {
                return Account {
                    name: fields[0].to_owned(),
                    home: Some(fields[5].to_owned()).filter(|home| !home.is_empty()),
                };
            }
        }
    }
    // A destination whose accounts are not in that file (a directory service) answers `id`, which
    // asks the system's own database for the name of this process's user.
    #[cfg(unix)]
    if let Ok(named) = std::process::Command::new("/usr/bin/id")
        .arg("-un")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        && named.status.success()
        && let Ok(name) = String::from_utf8(named.stdout)
        && !name.trim().is_empty()
    {
        return Account {
            name: name.trim().to_owned(),
            home: None,
        };
    }
    Account {
        name: format!("uid {uid}"),
        home: None,
    }
}

/// Where a session created through this bridge starts, and with what, as this helper's own
/// environment states it.
///
/// What a `kr new` run here would have sent, and nothing from the host the bridge was opened from.
/// A destination that has no home to offer starts a session at its root.
fn base() -> DestinationBase {
    // The home the user's login gave this process, which `wsl.exe --user` and a container
    // runtime's exec set for the user they run it as, and else the account's own record of it.
    let home = std::env::var("HOME")
        .ok()
        .filter(|home| home.starts_with('/'))
        .or_else(|| account().home)
        .filter(|home| home.starts_with('/'))
        .unwrap_or_else(|| "/".to_owned());
    // The session's `HOME` is the directory it starts in. A login that gave this process none, or
    // one that is not an absolute path, leaves the shell with the account's home as its directory
    // and no `HOME`, or with a relative one, so the resolved home is what the snapshot carries.
    let variables = DESTINATION_BASE_VARIABLES
        .iter()
        .filter_map(|name| {
            let value = if *name == "HOME" {
                home.clone()
            } else {
                std::env::var(name).ok()?
            };
            Some(kr_protocol::session::EnvironmentVariable {
                name: (*name).to_owned(),
                value,
            })
        })
        .filter(|variable| {
            variable.value.len() <= kr_protocol::identity::DESTINATION_BASE_VALUE_LIMIT
        })
        .collect();
    DestinationBase { home, variables }
}

/// Waits for the invoker's first frame.
async fn first_frame(
    incoming: &mut std::sync::mpsc::Receiver<Vec<u8>>,
    woken: &mut tokio::sync::mpsc::Receiver<()>,
) -> Option<Vec<u8>> {
    woken.recv().await?;
    incoming.try_recv().ok()
}

/// Returns the method a carried frame would run that opens a bridge of its own.
///
/// Section 3 allows a request to cross at most one process bridge, and a federated proxy is outside
/// this version. The destination cannot enforce that for itself: what reaches it over this helper's
/// local connection looks like any other local request, and nothing in it says a bridge was already
/// crossed. So the rule is kept here, at the hop that knows.
fn crosses_again(
    carried: &kr_protocol::envelope::ControlFrame,
) -> Option<kr_protocol::method::Method> {
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::method::Method;

    let name = match carried {
        ControlFrame::Request(request) => request.method.as_str(),
        ControlFrame::Mutation(mutation) => mutation.method.as_str(),
        _ => return None,
    };
    let method = Method::from_wire(name)?;
    // A refresh of an enrolled environment opens a process bridge to it. Enrolling, forgetting and
    // listing change or read a record and open nothing.
    matches!(method, Method::EnvironmentRefresh).then_some(method)
}

/// Decodes one bridge frame from a payload the reader already bounded.
fn decode_frame(payload: &[u8]) -> Result<BridgeFrame> {
    kr_protocol::wire::decode(payload, &StreamKind::Control.cbor_limits()).map_err(|error| {
        CliError::Other(shown!(
            "the bridge stream carried a frame this helper cannot read: {}",
            Shown::cbor(&error)
        ))
    })
}

/// Decodes the opening frame, refusing anything else.
fn decode_hello(payload: &[u8]) -> std::result::Result<BridgeHello, Refusal> {
    match kr_protocol::wire::decode(payload, &StreamKind::Control.cbor_limits()) {
        Ok(BridgeFrame::Hello(hello)) => Ok(*hello),
        Ok(_) | Err(_) => Err(Refusal::NotAHandshake),
    }
}

/// Turns a stream failure into the command's own error.
fn transport(error: &PipeError) -> CliError {
    CliError::Other(shown!("the bridge stream failed: {}", *error))
}

/// Writes a refusal and reports it.
fn refuse(output: &mut impl Write, refusal: Refusal) -> Result<()> {
    let error = refusal.as_error();
    // Standard error stays diagnostic: the refusal a caller acts on is the frame, and this line is
    // for whoever reads the log.
    crate::report::say(&shown!("kr bridge: {}", refusal.message()));
    pipe::write_frame(output, &BridgeFrame::Refused(error.clone()))
        .map_err(|failure| transport(&failure))?;
    Err(CliError::Refused(error))
}

/// Writes a refusal that is the command's own failure to reach the destination, and reports it.
fn refuse_with(output: &mut impl Write, error: &CliError) -> Result<()> {
    let refusal = match error {
        CliError::Refused(refused) | CliError::ServiceRefused { error: refused, .. } => {
            refused.clone()
        }
        CliError::Unfinished { code, message } => kr_client::error::refusal(*code, message.clone()),
        CliError::UnknownSession(said) => {
            kr_client::error::refusal(ErrorCode::UnknownSession, said.clone())
        }
        other => kr_client::error::refusal(ErrorCode::EnvironmentUnavailable, other.said()),
    };
    crate::report::say(&shown!("kr bridge: {}", Shown::protocol(&refusal)));
    pipe::write_frame(output, &BridgeFrame::Refused(refusal.clone()))
        .map_err(|failure| transport(&failure))?;
    Err(CliError::Refused(refusal))
}

/// Asks the destination environment whether one session has closed.
///
/// Section 3: an old closed session still answers `SESSION_CLOSED`. The only thing that establishes
/// that is the destination's own retained closure record, which its control daemon answers with, so
/// this asks the daemon and reports what it said.
///
/// What is deliberately not evidence is a file on disk. A worker writes a journal for a session
/// while that session is live, so a journal that exists says a session ran here and nothing about
/// whether it ended. Treating one as closure would answer `SESSION_CLOSED` for a session that is
/// still running, which is worse than saying the session is not known: a daemon that cannot be
/// reached has not told this helper anything, and the caller is told exactly that.
async fn is_destination_session_closed(
    paths: &HostPaths,
    known: &resolve::KnownEnvironment,
    session_id: kr_protocol::ids::SessionId,
    start: bool,
    origin: kr_protocol::local::BridgeOrigin,
) -> bool {
    let Ok(mut client) = controller(paths, known, start, origin).await else {
        return false;
    };
    let params = kr_protocol::session::SessionReadParams { session_id };
    match client
        .request(kr_protocol::method::Method::SessionRead, &params)
        .await
    {
        // The record the daemon holds carries the closure when there is one.
        Ok(Ok(payload)) => payload
            .to_typed::<kr_protocol::session::SessionReadResult>()
            .is_ok_and(|result| result.session.closure.is_present()),
        // Or the daemon answers the read with the closure itself.
        Ok(Err(error)) => error.code == ErrorCode::SessionClosed,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::ids::{BuildId, EnvironmentId};
    use kr_protocol::scalars::Uuid;

    fn hello(ingress: ActorIngress) -> BridgeHello {
        BridgeHello {
            protocol_version: PROTOCOL_VERSION,
            build_id: BuildId::new("kr/0.1.0").expect("a build"),
            origin_environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            origin_ingress: ingress,
            already_bridged: false,
            start: false,
            target: BridgeTarget::Controller,
        }
    }

    #[test]
    fn a_locally_authenticated_invocation_is_admitted() {
        admit(&hello(ActorIngress::LocalIpc)).expect("admitted");
    }

    #[test]
    fn every_other_ingress_is_refused_before_anything_is_connected() {
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            assert_eq!(
                admit(&hello(ingress)),
                Err(Refusal::RemoteOrigin),
                "{}",
                ingress.as_str()
            );
        }
        assert_eq!(
            Refusal::RemoteOrigin.as_error().code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn a_second_hop_is_refused_rather_than_chained() {
        let mut chained = hello(ActorIngress::LocalIpc);
        chained.already_bridged = true;
        assert_eq!(admit(&chained), Err(Refusal::AlreadyBridged));
    }

    /// What a caller is told when the daemon or worker that answers an ordinary connection took no
    /// bridge's: both builds, and the thing to do for that kind of peer.
    #[test]
    fn a_peer_of_an_earlier_build_is_named_with_what_to_do_about_that_kind_of_peer() {
        let earlier = kr_protocol::local::LocalBuild {
            build_id: BuildId::new("kr-worker/0.0.9").expect("a build"),
            protocol_version: kr_protocol::hello::PackageVersion::new(0, 0, 9),
        };
        let said = |peer, build: Option<&kr_protocol::local::LocalBuild>| {
            let CliError::Refused(error) = refused_by_a_peer_that_answers(peer, build) else {
                panic!("a refusal");
            };
            assert_eq!(error.code, ErrorCode::UnsupportedSchema);
            error.message
        };
        let daemon = said(Peer::Daemon, Some(&earlier));
        assert!(
            daemon.contains("the control daemon")
                && daemon.contains("kr-worker/0.0.9 with protocol 0.0.9")
                && daemon.contains("this helper is kr/")
                && daemon.contains("restart it"),
            "{daemon}"
        );
        let worker = said(Peer::Worker, None);
        assert!(
            worker.contains("the session worker")
                && worker.contains("a build that does not state its build")
                && worker.contains("attach to the session from a shell inside this environment"),
            "{worker}"
        );
    }

    #[test]
    fn a_protocol_major_this_helper_does_not_speak_is_refused() {
        let mut other = hello(ActorIngress::LocalIpc);
        other.protocol_version = kr_protocol::hello::ProtocolVersion {
            major: PROTOCOL_VERSION.major + 1,
            minor: 0,
        };
        assert_eq!(admit(&other), Err(Refusal::ProtocolMajor));
        assert_eq!(
            Refusal::ProtocolMajor.as_error().code,
            ErrorCode::UnsupportedSchema
        );
    }
}
