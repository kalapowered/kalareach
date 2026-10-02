//! Opening a bridge: what may cross it, what is refused before a process starts, and the frames
//! the invoking side carries once one is open.
//!
//! This is the gate section 3 puts on the near side. The process bridges serve locally
//! authenticated command-line invocations only, and **a Windows controller must not route a
//! network actor through one and relabel it a Linux local owner**. A remote client reaches the
//! destination environment through that environment's own paired endpoint, which it has, because
//! each Windows, WSL and enrolled container installation is an independent environment authority.
//!
//! The refusal happens here, before an argument vector is built and before a process exists. The
//! helper on the far side refuses the same handshake again, and neither check makes the other
//! redundant: this one is what a correct invoker does, and that one is what a destination
//! environment can enforce for itself.
//!
//! **Ingress is carried, not recomputed.** The opening frame states the ingress the request
//! originally arrived on. It is always [`ActorIngress::LocalIpc`] once this gate has passed, which
//! is exactly the point: the record on the far side then names where the request entered rather
//! than the local IPC hop the helper made, and there is no arrangement of hops that turns a
//! network device into a local owner.
//!
//! **The environment that answers is the one that was enrolled.** An opening carries the identity
//! the record names, and the acknowledgement is compared against it before a single request
//! crosses. A distribution reinstalled under the same name, or a container recreated under a name
//! that was reused, answers with a different identity and is refused rather than inheriting the
//! enrolment.
//!
//! **Every length is bounded before it is allocated.** Section 9 sets the control-frame maximum
//! and requires large messages to be rejected before allocation. Both directions here take that
//! bound from the frame codec, so a destination cannot make this host reserve memory by declaring
//! a large frame, and an oversized frame ends the bridge rather than being truncated.

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::envelope::{ControlEvent, ControlFrame, MutationRequest, Request, Response};
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, FrameCodec, StreamKind};
use kr_protocol::hello::{ActionWindow, PACKAGE_VERSION, ProtocolVersion};
use kr_protocol::identity::EnvironmentEnrolment;
use kr_protocol::identity::{BridgeFrame, BridgeHello, BridgeHelloAck, BridgeTarget};
use kr_protocol::ids::{BuildId, EnvironmentId, RequestId};
use kr_protocol::local::{LocalBuild, LocalRole};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bridge::launch::{self, BridgeCommand, LaunchError};

/// How long this host waits for a destination to say anything before it gives up on the bridge.
///
/// A helper that stopped answering would otherwise hold the caller, and the daemon's own task, for
/// as long as it stayed silent. Every wait below is bounded by this, and the helper is ended with
/// the bridge, so a destination that goes quiet costs one refusal rather than a stuck refresh.
pub const SILENCE_LIMIT: std::time::Duration = std::time::Duration::from_secs(20);

/// How long this host waits for the first acknowledgement of an opening that may start what it
/// needs.
///
/// Starting a stopped distribution and then the control daemon inside it takes longer than a
/// destination that is already serving: a distribution's boot, then the destination's own start
/// bound for its daemon. The wait is for something this host asked to be started, so it is longer
/// than [`SILENCE_LIMIT`] and is still a bound.
pub const START_LIMIT: std::time::Duration = std::time::Duration::from_secs(90);

/// How long this host waits for the answer to one mutation.
///
/// A create waits for its worker for up to thirty seconds inside the destination's daemon, which
/// says nothing until it has the answer. This is the bound the network door puts on the same wait.
pub const MUTATION_LIMIT: std::time::Duration = std::time::Duration::from_secs(45);

/// How long an attached stream may go without any frame at all, a keepalive included.
///
/// The destination's daemon and workers send a keepalive every few seconds, so a stream that says
/// nothing for this long is not an idle session but a frozen bridge, and it ends.
pub const STREAM_SILENCE_LIMIT: std::time::Duration = std::time::Duration::from_secs(45);

/// What a helper of a release before the opening's `start` member says when it refuses an opening it
/// cannot read.
///
/// The sentence is fixed in every such release, and a destination keeps the helper it was installed
/// with until somebody updates it, so this host recognises it. Remove it once no release that says
/// it can still be installed in a destination.
const EARLIER_HELPER_CANNOT_READ_OPENING: &str = "a bridge begins with its opening frame";

/// How much of a helper's standard error is kept, from the end.
const DIAGNOSTIC_TAIL: usize = 4096;

/// How long a closing waits, after the helper has gone, for what it wrote last to be read.
///
/// The end of a pipe follows the end of its writer at once, so this is spent only when something
/// else that the helper started still holds the pipe open, and then the reader is ended rather than
/// waited for.
const DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_millis(250);

/// How long this host waits for a helper to go once it has killed it.
///
/// Ending a process is ordinarily immediate. One that outlives its kill (a Windows process whose
/// termination waits on I/O that cannot be cancelled, or a Unix process in uninterruptible sleep)
/// would otherwise hold the caller for as long as it lasted, so past this the helper is reported by
/// name and let go.
pub const KILL_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why this host will not open a bridge for a request, or will not go on using one.
///
/// Each variant is one cause, and each says what happened. A person reading a connection
/// diagnostic has to be able to tell a helper that never started from one that answered as the
/// wrong environment, so no two causes share a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request did not arrive on a locally authenticated ingress.
    ///
    /// It carries the ingress it did arrive on, so a receipt and a log can say what was refused.
    NetworkActor {
        /// Where the request entered this host.
        ingress: ActorIngress,
    },
    /// The request has already crossed a bridge. A federated proxy is outside version 1.
    AlreadyBridged,
    /// The enrolment is not reached by a process bridge, or is incomplete.
    Launch(LaunchError),
    /// The helper could not be started at all.
    NotStarted {
        /// The program this host tried to run.
        program: String,
        /// What the operating system said.
        detail: String,
    },
    /// A stream to or from the helper failed part way through.
    Stream {
        /// What the stream said.
        detail: String,
    },
    /// The helper wrote something this invoker cannot read: a frame past the bound, or one that is
    /// not a canonical bridge frame.
    Unreadable {
        /// What the codec said.
        detail: String,
    },
    /// The helper's first frame was not an acknowledgement.
    NotAnAcknowledgement,
    /// The destination speaks a protocol major this host does not.
    ProtocolMajor {
        /// The major the destination answered with.
        destination: u16,
        /// The major this host speaks.
        invoker: u16,
    },
    /// The destination answered in a role the opening did not ask for.
    WrongRole {
        /// The role the opening asked for.
        expected: LocalRole,
        /// The role that answered.
        answered: LocalRole,
    },
    /// The environment that answered is not the one the enrolment names.
    IdentityMismatch {
        /// The identity the enrolment records.
        enrolled: EnvironmentId,
        /// The identity that answered.
        answered: EnvironmentId,
    },
    /// The destination refused the bridge, in its own words.
    Destination(ProtocolError),
    /// The targeted session has closed.
    SessionClosed,
    /// The destination said nothing for long enough that this host gave up.
    Silent {
        /// How long it was given.
        waited: std::time::Duration,
    },
    /// The helper ran as another user than the record names.
    UserMismatch {
        /// The user the enrolment records.
        enrolled: String,
        /// The user the helper said it ran as.
        answered: String,
    },
    /// The destination answered as one of this host's own environments, which a socket forwarded
    /// from here would, so it registers nothing about the host that was asked.
    OwnEnvironment,
    /// The destination's build does not share this host's compatibility level, so the frames that
    /// follow could not be read by one side.
    Level {
        /// The build the destination stated, or none when it is of a build before the statement.
        destination: Option<LocalBuild>,
    },
    /// The destination sent more than this host will hold for a caller that has not read it.
    Backlog {
        /// The bound, in bytes.
        limit: usize,
    },
    /// A helper this host started could not be ended, and may still be running.
    ///
    /// Section 7's supervision asks for what survived to be named rather than claimed ended. This
    /// host has let go of the helper, its streams and the caller, and no longer waits for it.
    Unkillable {
        /// The program this host started.
        program: String,
        /// Its process identifier, where the platform gave one.
        pid: Option<u32>,
        /// What happened when it was killed.
        detail: String,
    },
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkActor { ingress } => write!(
                formatter,
                "a process bridge carries locally authenticated invocations only, and this request \
                 arrived as {}; reach that environment through its own paired endpoint",
                ingress.as_str()
            ),
            Self::AlreadyBridged => {
                formatter.write_str("a request crosses at most one process bridge")
            }
            Self::Launch(error) => write!(formatter, "{error}"),
            Self::NotStarted { program, detail } => {
                write!(formatter, "{program} could not be started: {detail}")
            }
            Self::Stream { detail } => write!(formatter, "the bridge stream failed: {detail}"),
            Self::Unreadable { detail } => write!(
                formatter,
                "the destination wrote a frame this host cannot read: {detail}"
            ),
            Self::NotAnAcknowledgement => formatter
                .write_str("the destination answered the opening frame with something else"),
            Self::ProtocolMajor {
                destination,
                invoker,
            } => write!(
                formatter,
                "the destination speaks protocol major {destination} and this host speaks {invoker}"
            ),
            Self::WrongRole { expected, answered } => write!(
                formatter,
                "the opening asked for the {} and the {} answered",
                expected.as_str(),
                answered.as_str()
            ),
            Self::IdentityMismatch { enrolled, answered } => write!(
                formatter,
                "the enrolment names environment {enrolled} and {answered} answered; enrol the \
                 environment that is installed there rather than reusing this record"
            ),
            Self::Destination(error) => write!(
                formatter,
                "the destination refused the bridge: {}",
                error.message
            ),
            Self::SessionClosed => formatter.write_str("that session is closed"),
            Self::Silent { waited } => write!(
                formatter,
                "the destination said nothing for {} seconds",
                waited.as_secs()
            ),
            Self::UserMismatch { enrolled, answered } => write!(
                formatter,
                "the enrolment names user {enrolled} and the helper ran as {answered}"
            ),
            Self::OwnEnvironment => formatter.write_str(
                "the destination answered as this host's own environment, so it is not another \
                 one: a socket forwarded from here does not register an environment",
            ),
            Self::Level { destination } => match destination {
                Some(build) => write!(
                    formatter,
                    "the destination runs {} with protocol {}.{}.{} and this host speaks protocol \
                     {}.{}.{}: update kr in the destination or here so both are of one release",
                    build.build_id,
                    build.protocol_version.major,
                    build.protocol_version.minor,
                    build.protocol_version.patch,
                    PACKAGE_VERSION.major,
                    PACKAGE_VERSION.minor,
                    PACKAGE_VERSION.patch,
                ),
                None => write!(
                    formatter,
                    "the destination is of a build that states no protocol version, and this host \
                     speaks protocol {}.{}.{}: update kr in the destination",
                    PACKAGE_VERSION.major, PACKAGE_VERSION.minor, PACKAGE_VERSION.patch,
                ),
            },
            Self::Backlog { limit } => write!(
                formatter,
                "the destination sent more than {limit} bytes this host had not yet been asked \
                 for, so the bridge was ended"
            ),
            Self::Unkillable {
                program,
                pid,
                detail,
            } => match pid {
                Some(pid) => write!(
                    formatter,
                    "{program} (process {pid}) could not be ended: {detail}; it may still be \
                     running, and this host no longer waits for it"
                ),
                None => write!(
                    formatter,
                    "{program} could not be ended: {detail}; it may still be running, and this \
                     host no longer waits for it"
                ),
            },
        }
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for crate::error::ControllerError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            // The admission refusals are permission failures, and so is a destination that refused
            // the handshake: in each case the answer is that this request may not cross.
            Refusal::NetworkActor { .. }
            | Refusal::AlreadyBridged
            | Refusal::Destination(_)
            | Refusal::UserMismatch { .. }
            | Refusal::OwnEnvironment
            | Refusal::IdentityMismatch { .. } => Self::PermissionDenied {
                detail: refusal.to_string(),
            },
            Refusal::SessionClosed => Self::SessionClosed {
                session: "the bridged session".to_owned(),
            },
            // An incomplete enrolment is the caller's own record being wrong.
            Refusal::Launch(_) => Self::InvalidArgument(refusal.to_string()),
            // The rest are this host failing to reach a destination it was told to reach.
            Refusal::NotStarted { .. }
            | Refusal::Stream { .. }
            | Refusal::Unreadable { .. }
            | Refusal::NotAnAcknowledgement
            | Refusal::ProtocolMajor { .. }
            | Refusal::WrongRole { .. }
            | Refusal::Silent { .. }
            | Refusal::Level { .. }
            | Refusal::Backlog { .. }
            | Refusal::Unkillable { .. } => Self::supervision(refusal.to_string()),
        }
    }
}

/// One bridge this host is ready to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The command the helper is started with.
    pub command: BridgeCommand,
    /// The identity the enrolment names. The destination has to answer with it.
    pub environment_id: EnvironmentId,
    /// The opening frame written to its standard input.
    pub hello: BridgeHello,
}

/// A bridge that is open: the helper is running and has acknowledged the opening frame.
#[derive(Debug)]
pub struct Invocation {
    /// The program the helper was started with, which names it if it cannot be ended.
    program: String,
    /// The running helper.
    child: tokio::process::Child,
    /// The helper's standard input, which carries frames to the destination.
    stdin: tokio::process::ChildStdin,
    /// The helper's standard output, which carries the destination's answers back.
    stdout: tokio::process::ChildStdout,
    /// What the destination acknowledged: its identity, its user, its role and its bounds.
    acknowledgement: BridgeHelloAck,
    /// What the helper wrote to its standard error, from the end.
    diagnostics: Diagnostics,
    /// The task that reads it, which ends with this invocation.
    stderr: Reader,
}

/// The end of what a helper wrote to its standard error.
///
/// Standard error is diagnostic output that belongs to whoever ran the command, and a helper that
/// writes a line there while a terminal shows a projection of a session would damage the screen it
/// is describing. So it is read here, kept to its last [`DIAGNOSTIC_TAIL`] bytes, and left for the
/// caller to say once it is able to.
#[derive(Clone, Debug, Default)]
pub struct Diagnostics(Arc<Mutex<DiagnosticTail>>);

#[derive(Debug, Default)]
struct DiagnosticTail {
    /// The last bytes written, at most [`DIAGNOSTIC_TAIL`] of them.
    kept: Vec<u8>,
    /// How many bytes were written in all.
    total: u64,
}

impl Diagnostics {
    /// How many bytes the helper has written to its standard error.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).total
    }

    fn keep(&self, bytes: &[u8]) {
        let mut tail = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        tail.total = tail.total.saturating_add(bytes.len() as u64);
        tail.kept.extend_from_slice(bytes);
        let excess = tail.kept.len().saturating_sub(DIAGNOSTIC_TAIL);
        if excess > 0 {
            tail.kept.drain(..excess);
        }
    }
}

/// A task that reads one of a helper's pipes, and ends with whoever owns it.
///
/// Dropping a task's handle detaches the task, which then lives until what it reads closes, and a
/// process the helper started and left running holds a pipe open for as long as it lives. So the
/// handle is owned here, and what drops it ends the task, whichever way the bridge ended: closed
/// in order, given up on, or never opened.
#[derive(Debug)]
struct Reader(tokio::task::JoinHandle<()>);

impl Reader {
    /// Waits for the task to end by itself, no longer than `limit`.
    async fn ended_within(&mut self, limit: std::time::Duration) {
        let _ = tokio::time::timeout(limit, &mut self.0).await;
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Reads a helper's standard error until it ends, so a helper that writes a great deal never
/// blocks on a full pipe.
fn drain(stderr: tokio::process::ChildStderr, into: Diagnostics) -> Reader {
    Reader(tokio::spawn(async move {
        let mut stderr = stderr;
        let mut buffer = [0_u8; 1024];
        loop {
            match stderr.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => into.keep(&buffer[..read]),
            }
        }
    }))
}

impl Opening {
    /// Starts the helper, exchanges the opening frames and checks what answered.
    ///
    /// The acknowledgement is accepted only when the destination speaks this protocol major,
    /// answers in the role the opening asked for, and names the environment the enrolment records.
    /// The helper is ended when any of those fails, so a refused opening leaves no process behind.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] naming what stopped the bridge: the helper not starting, a stream
    /// failing, a frame this host cannot read, a protocol major, a role, an identity that is not
    /// the enrolled one, or the destination's own refusal, including a closed session.
    pub async fn launch(self) -> Result<Invocation, Refusal> {
        let Started {
            child,
            stdin,
            stdout,
            acknowledgement,
            diagnostics,
            stderr,
        } = start_and_acknowledge(&self.command, &self.hello).await?;
        // The enrolment is a record of one installation. An environment that answers with another
        // identity is another installation, whatever name it was reached by: a distribution
        // registered again under the name it had, or a container recreated under a reused one.
        if acknowledgement.environment_id != self.environment_id {
            return Err(Refusal::IdentityMismatch {
                enrolled: self.environment_id,
                answered: acknowledgement.environment_id,
            });
        }
        Ok(Invocation {
            program: self.command.program,
            child,
            stdin,
            stdout,
            acknowledgement,
            diagnostics,
            stderr,
        })
    }
}

/// Asks the helper an enrolled environment names, once, who it is, and checks the answer against
/// the record. `local_environments` is every environment this installation holds: a socket
/// forwarded from here answers as one of them.
///
/// This is how a host reached by SSH registers its identity and the channel its helper holds, and
/// it is the only thing ssh is used for: the helper answers the opening and is ended, and no
/// request ever crosses. The answer has to be the environment the record names, run as the user it
/// names, and not one of this host's own environments, which a socket forwarded from here is.
///
/// # Errors
///
/// As [`open`] for the gate, as [`discover`] for the helper, and [`Refusal::IdentityMismatch`],
/// [`Refusal::UserMismatch`] or [`Refusal::OwnEnvironment`] for an answer that is not the record's.
pub async fn identify(
    actor: &ActorEnvelope,
    already_bridged: bool,
    enrolment: &EnvironmentEnrolment,
    origin_environment_id: EnvironmentId,
    local_environments: &[EnvironmentId],
    build_id: BuildId,
) -> Result<BridgeHelloAck, Refusal> {
    if !actor.ingress.may_cross_process_bridge() {
        return Err(Refusal::NetworkActor {
            ingress: actor.ingress,
        });
    }
    if already_bridged {
        return Err(Refusal::AlreadyBridged);
    }
    let command = launch::identity_command(
        enrolment.access,
        &enrolment.target,
        &enrolment.os_user,
        &enrolment.helper_path,
    )
    .map_err(Refusal::Launch)?;
    let hello = BridgeHello {
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        build_id,
        origin_environment_id,
        origin_ingress: ActorIngress::LocalIpc,
        already_bridged: false,
        start: false,
        target: BridgeTarget::Controller,
    };
    let acknowledgement = discover(&command, &hello).await?;
    if acknowledgement.environment_id == origin_environment_id
        || local_environments.contains(&acknowledgement.environment_id)
    {
        return Err(Refusal::OwnEnvironment);
    }
    if acknowledgement.environment_id != enrolment.environment_id {
        return Err(Refusal::IdentityMismatch {
            enrolled: enrolment.environment_id,
            answered: acknowledgement.environment_id,
        });
    }
    if acknowledgement.os_user != enrolment.os_user {
        return Err(Refusal::UserMismatch {
            enrolled: enrolment.os_user.clone(),
            answered: acknowledgement.os_user,
        });
    }
    Ok(acknowledgement)
}

/// Asks a destination which environment it is, before there is a record naming it.
///
/// Enrolment is the one caller: the identity is exactly what it is learning, so there is nothing
/// yet to compare the acknowledgement against. Everything else is still checked, and the helper is
/// ended as soon as it has answered, because discovery carries no request.
///
/// # Errors
///
/// As [`Opening::launch`], less the identity check, and [`Refusal::Unkillable`] for a helper that
/// answered and then could not be ended.
pub async fn discover(
    command: &BridgeCommand,
    hello: &BridgeHello,
) -> Result<BridgeHelloAck, Refusal> {
    let Started {
        child,
        stdin,
        stdout,
        acknowledgement,
        // Nothing here reads what the helper wrote to standard error, and its reader ends with
        // this function.
        stderr: _stderr,
        ..
    } = start_and_acknowledge(command, hello).await?;
    drop(stdin);
    drop(stdout);
    // Discovery carries no request, so the helper is ended as soon as it has answered, and waited
    // for here so the runtime is not left to collect it after this function has returned.
    end(child, &command.program, KILL_LIMIT).await?;
    Ok(acknowledgement)
}

/// Kills a helper this host started, and waits no longer than `limit` for it to go.
///
/// Section 7's supervision is the rule: what this host ended it may report as ended, and what it
/// could not end it names rather than claims. Past the bound the helper's handle is dropped, and
/// nothing here holds it, its streams or the caller any longer: on Unix the runtime reaps the
/// process if it ever ends, and on Windows closing the handle is all that is left to do. Dropping
/// the handle asks for the kill again only where the first request failed, because the runtime
/// stops asking once one has been sent.
async fn end(
    mut child: tokio::process::Child,
    program: &str,
    limit: std::time::Duration,
) -> Result<(), Refusal> {
    let pid = child.id();
    ended_within(child.kill(), limit)
        .await
        .map_err(|detail| Refusal::Unkillable {
            program: program.to_owned(),
            pid,
            detail,
        })
}

/// Waits for an ending that has been asked for, no longer than `limit`, and says why it did not
/// come.
///
/// This is the whole of the decision apart from the process, so a test can hand it an ending that
/// never comes: no process a test can start outlives its kill.
async fn ended_within<F>(ending: F, limit: std::time::Duration) -> Result<(), String>
where
    F: core::future::Future<Output = std::io::Result<()>>,
{
    match tokio::time::timeout(limit, ending).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("killing it failed: {error}")),
        Err(_elapsed) => Err(format!(
            "it had not gone {} seconds after it was killed",
            limit.as_secs()
        )),
    }
}

/// A helper that has started and acknowledged the opening, and what this host holds of it.
struct Started {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    acknowledgement: BridgeHelloAck,
    diagnostics: Diagnostics,
    stderr: Reader,
}

/// Starts the helper, exchanges the opening frames, and checks the version and the role.
async fn start_and_acknowledge(
    command: &BridgeCommand,
    hello: &BridgeHello,
) -> Result<Started, Refusal> {
    let mut process = tokio::process::Command::new(&command.program);
    process
        .args(&command.arguments)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // Section 3 keeps standard error diagnostic. It is read here and kept to its end, so it
        // never reaches a terminal this host is showing something else on.
        .stderr(std::process::Stdio::piped())
        // A handshake this host refuses ends the helper with it rather than leaving a distribution
        // or a container process running behind a failed connection.
        .kill_on_drop(true);
    // A console's interrupt goes to every process attached to it. The helper has its own group, so
    // an interrupt aimed at the person's command does not also end the bridge it is using.
    #[cfg(windows)]
    {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        process.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = process.spawn().map_err(|error| Refusal::NotStarted {
        program: command.program.clone(),
        detail: error.to_string(),
    })?;

    let mut stdin = child.stdin.take().ok_or_else(|| Refusal::NotStarted {
        program: command.program.clone(),
        detail: "its standard input is not a pipe".to_owned(),
    })?;
    let mut stdout = child.stdout.take().ok_or_else(|| Refusal::NotStarted {
        program: command.program.clone(),
        detail: "its standard output is not a pipe".to_owned(),
    })?;
    let diagnostics = Diagnostics::default();
    // Held until the helper is, so a handshake that fails below ends the reader with it.
    let stderr = child
        .stderr
        .take()
        .map(|stderr| drain(stderr, diagnostics.clone()))
        .ok_or_else(|| Refusal::NotStarted {
            program: command.program.clone(),
            detail: "its standard error is not a pipe".to_owned(),
        })?;

    write_frame(&mut stdin, &BridgeFrame::Hello(Box::new(hello.clone()))).await?;
    // A helper that was asked to start what it needs is waited for as long as that takes.
    let limit = if hello.start {
        START_LIMIT
    } else {
        SILENCE_LIMIT
    };
    let opening = read_frame_within(&mut stdout, limit)
        .await
        .map_err(|refusal| match refusal {
            // The first frame is what a helper of another release, or a login that wrote to
            // standard output before it, gets wrong.
            Refusal::Unreadable { detail } => Refusal::Unreadable {
                detail: format!(
                    "{detail}; the helper may be of another release, or the login it runs under \
                     may write to standard output"
                ),
            },
            other => other,
        })?
        .0;
    let acknowledgement = match opening {
        BridgeFrame::HelloAck(acknowledgement) => *acknowledgement,
        BridgeFrame::Refused(error) => {
            return Err(
                if error.code == kr_protocol::error::ErrorCode::SessionClosed {
                    Refusal::SessionClosed
                } else if error.code == kr_protocol::error::ErrorCode::UnsupportedSchema
                    && error.message == EARLIER_HELPER_CANNOT_READ_OPENING
                {
                    // A helper of an earlier release, which a distribution keeps until somebody
                    // updates it, refuses an opening it cannot read with this sentence. It says
                    // what to do, which the sentence does not.
                    Refusal::Level { destination: None }
                } else {
                    Refusal::Destination(error)
                },
            );
        }
        _ => return Err(Refusal::NotAnAcknowledgement),
    };

    let invoker = hello.protocol_version.major;
    if acknowledgement.protocol_version.major != invoker {
        return Err(Refusal::ProtocolMajor {
            destination: acknowledgement.protocol_version.major,
            invoker,
        });
    }
    // The frames that follow are closed schemas, and below 1.0.0 the package's minor number is the
    // level they are written at. A destination of another level is refused before a request is
    // sent, and so is one that states none.
    match acknowledgement.build.as_ref() {
        Some(build) if build.protocol_version.shares_frames_with(PACKAGE_VERSION) => {}
        stated => {
            return Err(Refusal::Level {
                destination: stated.cloned(),
            });
        }
    }
    acknowledgement
        .base
        .validate()
        .map_err(|detail| Refusal::Unreadable {
            detail: detail.to_owned(),
        })?;
    let expected = match hello.target {
        BridgeTarget::Controller => LocalRole::Controller,
        BridgeTarget::Session { .. } => LocalRole::Worker,
    };
    if acknowledgement.role != expected {
        return Err(Refusal::WrongRole {
            expected,
            answered: acknowledgement.role,
        });
    }
    Ok(Started {
        child,
        stdin,
        stdout,
        acknowledgement,
        diagnostics,
        stderr,
    })
}

impl Invocation {
    /// What the destination acknowledged.
    #[must_use]
    pub const fn acknowledgement(&self) -> &BridgeHelloAck {
        &self.acknowledgement
    }

    /// Carries one request to the destination and returns the answer it gave.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] naming the stream, frame or destination failure. A method that the
    /// destination answered with an error is an [`Response`] carrying that error, not a refusal:
    /// the bridge carried it unchanged.
    pub async fn request(&mut self, request: Request) -> Result<Response, Refusal> {
        let request_id = request.request_id;
        self.exchange(
            BridgeFrame::Control(Box::new(ControlFrame::Request(request))),
            request_id,
            SILENCE_LIMIT,
        )
        .await
    }

    /// Carries one mutation to the destination and returns the answer it gave.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub async fn mutate(&mut self, mutation: MutationRequest) -> Result<Response, Refusal> {
        let request_id = mutation.request_id;
        // A mutation can be the creation of a session, which the destination's daemon does not
        // answer, or say anything about, until its worker is up.
        self.exchange(
            BridgeFrame::Control(Box::new(ControlFrame::Mutation(Box::new(mutation)))),
            request_id,
            MUTATION_LIMIT,
        )
        .await
    }

    /// Ends the bridge: the helper's input is closed and the helper is waited for.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Stream`] when the helper could not be waited for, [`Refusal::Silent`]
    /// when it did not end on its own and was ended, and [`Refusal::Unkillable`] when it could not
    /// be ended either.
    pub async fn close(self) -> Result<(), Refusal> {
        self.close_within(SILENCE_LIMIT, KILL_LIMIT).await
    }

    /// [`Self::close`], with the two bounds named.
    async fn close_within(
        mut self,
        silence: std::time::Duration,
        kill_limit: std::time::Duration,
    ) -> Result<(), Refusal> {
        drop(self.stdin);
        match tokio::time::timeout(silence, self.child.wait()).await {
            Ok(Ok(_status)) => {
                // What the helper wrote last is read before this says it has ended.
                self.stderr.ended_within(DRAIN_LIMIT).await;
                Ok(())
            }
            Ok(Err(error)) => Err(Refusal::Stream {
                detail: error.to_string(),
            }),
            // A helper that will not end on its own is ended here rather than left running: the
            // caller asked for one exchange, and it is over. One that will not end at the kill
            // either is named and let go rather than waited for.
            Err(_elapsed) => {
                end(self.child, &self.program, kill_limit).await?;
                Err(Refusal::Silent { waited: silence })
            }
        }
    }

    /// Writes one frame and reads until the answer to `request_id` arrives.
    ///
    /// Anything else the destination sends in the meantime — an event, a keepalive — is carried
    /// past rather than mistaken for the answer.
    async fn exchange(
        &mut self,
        frame: BridgeFrame,
        request_id: RequestId,
        limit: std::time::Duration,
    ) -> Result<Response, Refusal> {
        write_frame(&mut self.stdin, &frame).await?;
        loop {
            match read_frame_within(&mut self.stdout, limit).await?.0 {
                BridgeFrame::Control(carried) => match *carried {
                    ControlFrame::Response(response) if response.request_id == request_id => {
                        return Ok(response);
                    }
                    _ => continue,
                },
                BridgeFrame::Refused(error) => {
                    return Err(
                        if error.code == kr_protocol::error::ErrorCode::SessionClosed {
                            Refusal::SessionClosed
                        } else {
                            Refusal::Destination(error)
                        },
                    );
                }
                _ => return Err(Refusal::NotAnAcknowledgement),
            }
        }
    }
}

/// What the reader of a stream hands to the caller of it.
#[derive(Debug)]
struct Pending {
    /// The frames that have arrived and not been taken, oldest first, each with what it occupied.
    frames: VecDeque<(ControlFrame, usize)>,
    /// What those frames occupy together.
    bytes: usize,
    /// The action window the destination last issued, which a renewal replaces.
    window: ActionWindow,
    /// When the destination last sent anything at all, a keepalive included.
    last_heard: tokio::time::Instant,
    /// How the stream ended, once it has. What arrived before the end is still delivered first.
    ended: Option<Refusal>,
}

/// What the reader and the caller of a stream share.
#[derive(Debug)]
struct Shared {
    pending: Mutex<Pending>,
    arrived: tokio::sync::Notify,
    /// How long the stream may go without any frame before it ends.
    silence: std::time::Duration,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A bridge that is open and carries a conversation: output, input and answers in any order.
///
/// An [`Invocation`] carries one exchange at a time. A terminal attached to a session in another
/// environment needs more: the destination pushes output while the person types, and neither waits
/// for the other. So the stream has a reader of its own, which takes frames off the helper's
/// standard output as they arrive and keeps them, in order, for whoever asks. Four rules hold it.
///
/// * **The reader never waits for its caller.** What has arrived and not been taken is held up to
///   [`kr_protocol::limits::MAX_SEND_QUEUE_BYTES`], the most the destination would queue for a peer
///   that stopped reading. Past it the output and screen frames held are replaced by one
///   `session.resync` marker, which is what a worker on this host does to a client that falls
///   behind, and the caller takes the screen again; a stream that holds nothing it could drop ends
///   with [`Refusal::Backlog`]. A reader that waited for a full queue to drain, while its caller
///   waited to write to a helper that was waiting to write to the reader, would hold all three for
///   good.
/// * **Reading is cancellable.** [`Self::recv`] waits on that queue and nothing else, so a caller
///   that drops it in a `select!` loses nothing.
/// * **The connection's own traffic is not the caller's.** A renewed action window replaces the
///   one the stream quotes, and a keepalive is not returned; both count as the destination being
///   heard from, and a stream that is not heard from for [`STREAM_SILENCE_LIMIT`] ends with
///   [`Refusal::Silent`].
/// * **What the helper writes to its standard error is kept, not shown.** It is read from the same
///   place as the rest of a helper's diagnostics, and [`Self::diagnostics`] says how much there was.
#[derive(Debug)]
pub struct BridgeStream {
    program: String,
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    /// The task that reads the helper's standard output, which ends with this stream.
    reader: Reader,
    shared: Arc<Shared>,
    acknowledgement: BridgeHelloAck,
    diagnostics: Diagnostics,
    /// The task that reads the helper's standard error, which ends with this stream.
    stderr: Reader,
}

impl Invocation {
    /// Turns this invocation into a stream that carries a conversation.
    ///
    /// Frames the invocation had not yet taken are not lost: nothing has been read from the
    /// helper beyond its acknowledgement.
    #[must_use]
    pub fn into_stream(self) -> BridgeStream {
        self.into_stream_within(
            STREAM_SILENCE_LIMIT,
            kr_protocol::limits::MAX_SEND_QUEUE_BYTES,
        )
    }

    /// [`Self::into_stream`], with the two bounds named.
    fn into_stream_within(self, silence: std::time::Duration, ceiling: usize) -> BridgeStream {
        let shared = Arc::new(Shared {
            pending: Mutex::new(Pending {
                frames: VecDeque::new(),
                bytes: 0,
                window: self.acknowledgement.action_window.clone(),
                last_heard: tokio::time::Instant::now(),
                ended: None,
            }),
            arrived: tokio::sync::Notify::new(),
            silence,
        });
        let reader = Reader(tokio::spawn(read_stream(
            self.stdout,
            Arc::clone(&shared),
            ceiling,
        )));
        BridgeStream {
            program: self.program,
            child: self.child,
            stdin: self.stdin,
            reader,
            shared,
            acknowledgement: self.acknowledgement,
            diagnostics: self.diagnostics,
            stderr: self.stderr,
        }
    }
}

/// Whether a notification is part of what a terminal draws: the session's output and the canonical
/// screen's rendering. These are the deliveries a worker charges to a subscriber's queue, and the
/// ones it replaces with a marker when the subscriber falls behind. The rest, the answers and the
/// events that carry no bytes, are never dropped.
fn is_a_view(event_type: &str) -> bool {
    event_type == "session.output"
        || event_type == "session.gap"
        || event_type.starts_with("session.projection.")
}

/// Whether a frame opens a subscription's stream: the first of the notifications a subscription
/// sends, which restart their sequence at zero.
///
/// A caller that asked for a new subscription ignores everything of the old stream and waits for
/// this one, and knows nothing of the new stream until it arrives. Dropping it leaves the caller
/// waiting for good, so it is never dropped.
fn opens_a_stream(notification: &kr_protocol::envelope::Notification) -> bool {
    notification.sequence.get() == 0
}

/// Whether a frame that opens a stream is among the frames held.
fn holds_an_opening(pending: &Pending) -> bool {
    pending.frames.iter().any(|(frame, _)| {
        matches!(
            frame,
            ControlFrame::Notification(notification)
                if is_a_view(notification.event_type.as_str()) && opens_a_stream(notification)
        )
    })
}

/// Drops what the caller holds of the view, and leaves a marker that says to take it again.
///
/// A client of a worker on this host that stops reading backs the socket up, and the worker replaces
/// what it would have queued with `session.resync`. A bridge's reader never waits for its caller,
/// because a caller waiting to write to a helper that waits to write to the reader would hold all
/// three for good, so it is here that the same thing is done: past the bound, the output and screen
/// frames held are dropped, one marker takes their place, and the caller asks for the screen
/// again. Answers and the events that carry no bytes stay, and so does the frame that opens a
/// stream, because a caller that asked for a new one cannot tell the stream has begun without it.
/// Where nothing can be dropped the caller is not left without a marker: [`ensure_a_marker`] puts
/// one where the frame that does not fit would have been.
fn shed_a_view(pending: &mut Pending) {
    // The last view frame dropped since the last frame that opens a stream. What was dropped
    // before an opening belongs to a stream the caller has already asked to replace.
    let mut last: Option<(kr_protocol::ids::StreamId, u64)> = None;
    let mut kept = VecDeque::with_capacity(pending.frames.len());
    let mut bytes = 0;
    for (frame, charged) in std::mem::take(&mut pending.frames) {
        if let ControlFrame::Notification(notification) = &frame
            && is_a_view(notification.event_type.as_str())
        {
            if !opens_a_stream(notification) {
                last = Some((notification.stream_id.clone(), notification.sequence.get()));
                continue;
            }
            last = None;
        }
        bytes += charged;
        kept.push_back((frame, charged));
    }
    pending.frames = kept;
    pending.bytes = bytes;
    if let Some((stream_id, sequence)) = last {
        ensure_a_marker(pending, stream_id, sequence);
    }
}

/// Leaves the caller a marker that says to take the view again, unless one is already held for
/// the stream the frames after it belong to.
///
/// A marker held before the frame that opens a stream says something about the stream before it:
/// a caller that has asked for a new subscription passes it over. So only a marker after the last
/// opening held counts, and where frames of the new stream are dropped, the marker that says so
/// follows the opening.
///
/// `sequence` is the sequence of the frame the marker stands in for, which a marker is never
/// below the first of: a client reads sequence zero as a new subscription beginning.
fn ensure_a_marker(pending: &mut Pending, stream_id: kr_protocol::ids::StreamId, sequence: u64) {
    let mut held = false;
    for (frame, _) in &pending.frames {
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        if notification.event_type.as_str() == "session.resync" {
            held = true;
        } else if is_a_view(notification.event_type.as_str()) && opens_a_stream(notification) {
            held = false;
        }
    }
    if held {
        return;
    }
    let marker = kr_protocol::recovery::ResyncRequired {
        reason: kr_protocol::recovery::ResyncReason::SendQueueFull,
        cursor: kr_protocol::scalars::U64::new(0),
        oldest_retained_cursor: kr_protocol::scalars::U64::new(0),
    };
    let (Ok(event_type), Ok(payload)) = (
        kr_protocol::ids::EventType::new("session.resync"),
        kr_protocol::envelope::ParamsValue::from_typed(&marker),
    ) else {
        return;
    };
    let frame = ControlFrame::Notification(kr_protocol::envelope::Notification {
        stream_id,
        sequence: kr_protocol::ids::EventSequence::new(sequence.max(1)),
        event_type,
        payload,
    });
    // What a frame read from the helper is charged: its length prefix and its payload.
    let charged = FrameCodec::new(StreamKind::Control)
        .encode_message(&BridgeFrame::Control(Box::new(frame.clone())))
        .map_or(0, |bytes| bytes.len());
    pending.bytes += charged;
    pending.frames.push_back((frame, charged));
}

/// Takes frames off the helper's standard output until it ends, keeping each for the stream's
/// caller.
async fn read_stream(mut stdout: tokio::process::ChildStdout, shared: Arc<Shared>, ceiling: usize) {
    loop {
        let read = read_frame_unbounded(&mut stdout).await;
        let mut pending = shared.lock();
        pending.last_heard = tokio::time::Instant::now();
        match read {
            Ok((BridgeFrame::Control(frame), charged)) => match *frame {
                ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
                    pending.window = window;
                }
                ControlFrame::Event(ControlEvent::Keepalive) => {}
                other => {
                    // A caller that cannot keep up is told to take the view again, as a client of a
                    // worker on this host is when its socket backs up. What it held of the view is
                    // dropped, and a marker stands where it was.
                    if pending.bytes.saturating_add(charged) > ceiling {
                        shed_a_view(&mut pending);
                    }
                    if pending.bytes.saturating_add(charged) > ceiling {
                        match &other {
                            // The frame that opens a stream is what a caller waits for after it
                            // has asked for a new one, and it is one frame: it is held past the
                            // bound rather than dropped. A second one while another is held is
                            // more than a caller that asks for one stream at a time is owed, and a
                            // destination that sends them has nothing this host should keep.
                            ControlFrame::Notification(held)
                                if is_a_view(held.event_type.as_str())
                                    && opens_a_stream(held)
                                    && !holds_an_opening(&pending) => {}
                            // A view frame that still does not fit is replaced by a marker, which
                            // is left where it would have been if none is held: the caller is
                            // never left without one that says it has missed something.
                            ControlFrame::Notification(held)
                                if is_a_view(held.event_type.as_str()) =>
                            {
                                ensure_a_marker(
                                    &mut pending,
                                    held.stream_id.clone(),
                                    held.sequence.get(),
                                );
                                drop(pending);
                                shared.arrived.notify_waiters();
                                continue;
                            }
                            // Anything else is something the caller is owed.
                            _ => {
                                pending.ended = Some(Refusal::Backlog { limit: ceiling });
                                drop(pending);
                                shared.arrived.notify_waiters();
                                return;
                            }
                        }
                    }
                    pending.bytes += charged;
                    pending.frames.push_back((other, charged));
                }
            },
            Ok((BridgeFrame::Refused(error), _)) => {
                pending.ended = Some(
                    if error.code == kr_protocol::error::ErrorCode::SessionClosed {
                        Refusal::SessionClosed
                    } else {
                        Refusal::Destination(error)
                    },
                );
                drop(pending);
                shared.arrived.notify_waiters();
                return;
            }
            // A second acknowledgement or an opening frame is not something a destination sends in
            // the middle of a conversation.
            Ok(_) => {
                pending.ended = Some(Refusal::NotAnAcknowledgement);
                drop(pending);
                shared.arrived.notify_waiters();
                return;
            }
            Err(refusal) => {
                pending.ended = Some(refusal);
                drop(pending);
                shared.arrived.notify_waiters();
                return;
            }
        }
        drop(pending);
        shared.arrived.notify_waiters();
    }
}

impl BridgeStream {
    /// What the destination acknowledged.
    #[must_use]
    pub const fn acknowledgement(&self) -> &BridgeHelloAck {
        &self.acknowledgement
    }

    /// The action window the destination last issued on this connection.
    ///
    /// A mutation quotes the window in force when it is built, so this is read at that moment and
    /// never kept.
    #[must_use]
    pub fn action_window(&self) -> ActionWindow {
        self.shared.lock().window.clone()
    }

    /// How many bytes the helper has written to its standard error.
    #[must_use]
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }

    /// Writes one frame to the destination.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Silent`] when the helper does not take it within [`SILENCE_LIMIT`],
    /// [`Refusal::Stream`] when the stream fails, and [`Refusal::Unreadable`] for a frame past the
    /// control bound, which is refused rather than truncated.
    pub async fn send(&mut self, frame: ControlFrame) -> Result<(), Refusal> {
        write_frame(&mut self.stdin, &BridgeFrame::Control(Box::new(frame))).await
    }

    /// Takes the oldest frame the destination sent that has not been taken, waiting for one.
    ///
    /// Cancelling this loses nothing: what it was waiting for stays where it is. When the stream
    /// has ended, everything that arrived before the end is returned first, and then the reason.
    ///
    /// # Errors
    ///
    /// Returns what ended the stream: the destination's own refusal, a stream or frame failure,
    /// [`Refusal::Backlog`], or [`Refusal::Silent`] when it was not heard from for
    /// [`STREAM_SILENCE_LIMIT`].
    pub async fn recv(&mut self) -> Result<ControlFrame, Refusal> {
        self.take(|_| true, None).await
    }

    /// Takes the answer to one request, leaving everything else for [`Self::recv`], in order.
    ///
    /// # Errors
    ///
    /// As [`Self::recv`], and [`Refusal::Silent`] when no answer came within `limit`.
    pub async fn response(
        &mut self,
        request_id: RequestId,
        limit: std::time::Duration,
    ) -> Result<Response, Refusal> {
        let frame = self
            .take(
                |frame| matches!(frame, ControlFrame::Response(response) if response.request_id == request_id),
                Some(limit),
            )
            .await?;
        match frame {
            ControlFrame::Response(response) => Ok(response),
            _ => Err(Refusal::NotAnAcknowledgement),
        }
    }

    /// Waits for the first held frame `wanted` accepts, and takes it out of the queue.
    async fn take(
        &self,
        wanted: impl Fn(&ControlFrame) -> bool,
        limit: Option<std::time::Duration>,
    ) -> Result<ControlFrame, Refusal> {
        let asked = tokio::time::Instant::now();
        loop {
            let arrived = self.shared.arrived.notified();
            tokio::pin!(arrived);
            // Registered before the queue is read, so a frame that arrives in between wakes this.
            arrived.as_mut().enable();
            let deadline = {
                let mut pending = self.shared.lock();
                if let Some(index) = pending.frames.iter().position(|(frame, _)| wanted(frame)) {
                    let (frame, charged) = pending
                        .frames
                        .remove(index)
                        .expect("the position was just found");
                    pending.bytes = pending.bytes.saturating_sub(charged);
                    return Ok(frame);
                }
                if let Some(ended) = pending.ended.clone() {
                    return Err(ended);
                }
                let heard = pending.last_heard + self.shared.silence;
                match limit {
                    Some(limit) => heard.min(asked + limit),
                    None => heard,
                }
            };
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                let pending = self.shared.lock();
                let silent_since = pending.last_heard + self.shared.silence;
                if tokio::time::Instant::now() >= silent_since {
                    return Err(Refusal::Silent {
                        waited: self.shared.silence,
                    });
                }
                if let Some(limit) = limit
                    && tokio::time::Instant::now() >= asked + limit
                {
                    return Err(Refusal::Silent { waited: limit });
                }
            }
        }
    }

    /// Ends the stream: the helper's input is closed and the helper is waited for.
    ///
    /// # Errors
    ///
    /// As [`Invocation::close`].
    pub async fn close(self) -> Result<(), Refusal> {
        self.close_within(SILENCE_LIMIT, KILL_LIMIT).await
    }

    async fn close_within(
        mut self,
        silence: std::time::Duration,
        kill_limit: std::time::Duration,
    ) -> Result<(), Refusal> {
        drop(self.stdin);
        let waited = tokio::time::timeout(silence, self.child.wait()).await;
        // Nothing more is wanted of the frames, and a closing that is given up on from here ends
        // the readers with the stream rather than leaving them to their pipes.
        drop(self.reader);
        match waited {
            Ok(Ok(_status)) => {
                // What the helper wrote last is read before this says it has ended.
                self.stderr.ended_within(DRAIN_LIMIT).await;
                Ok(())
            }
            Ok(Err(error)) => Err(Refusal::Stream {
                detail: error.to_string(),
            }),
            Err(_elapsed) => {
                end(self.child, &self.program, kill_limit).await?;
                Err(Refusal::Silent { waited: silence })
            }
        }
    }
}

/// Writes one bridge frame and flushes it.
///
/// The codec refuses to encode a frame past the control bound, so an oversized frame never reaches
/// the stream.
async fn write_frame<W: AsyncWrite + Unpin>(
    sink: &mut W,
    frame: &BridgeFrame,
) -> Result<(), Refusal> {
    tokio::time::timeout(SILENCE_LIMIT, write_frame_unbounded(sink, frame))
        .await
        .unwrap_or(Err(Refusal::Silent {
            waited: SILENCE_LIMIT,
        }))
}

/// Writes one bridge frame, waiting as long as the stream takes.
///
/// Every caller reaches this through [`write_frame`], which bounds the wait: a destination that
/// never reads would otherwise hold this host as surely as one that never answers.
async fn write_frame_unbounded<W: AsyncWrite + Unpin>(
    sink: &mut W,
    frame: &BridgeFrame,
) -> Result<(), Refusal> {
    let bytes = FrameCodec::new(StreamKind::Control)
        .encode_message(frame)
        .map_err(|error| Refusal::Unreadable {
            detail: error.to_string(),
        })?;
    sink.write_all(&bytes)
        .await
        .map_err(|error| Refusal::Stream {
            detail: error.to_string(),
        })?;
    sink.flush().await.map_err(|error| Refusal::Stream {
        detail: error.to_string(),
    })
}

/// Reads one bridge frame, waiting no longer than [`SILENCE_LIMIT`].
///
/// The declared length is checked against section 9's control-frame bound *before* a payload
/// buffer exists, so a destination that declares a large frame is refused rather than served with
/// the memory it asked for.
#[cfg(test)]
async fn read_frame<R: AsyncRead + Unpin>(source: &mut R) -> Result<BridgeFrame, Refusal> {
    Ok(read_frame_within(source, SILENCE_LIMIT).await?.0)
}

/// Reads one bridge frame, waiting no longer than `limit` for it, and says what it occupied.
async fn read_frame_within<R: AsyncRead + Unpin>(
    source: &mut R,
    limit: std::time::Duration,
) -> Result<(BridgeFrame, usize), Refusal> {
    tokio::time::timeout(limit, read_frame_unbounded(source))
        .await
        .unwrap_or(Err(Refusal::Silent { waited: limit }))
}

/// Reads one bridge frame, waiting as long as the stream takes, and says what it occupied on the
/// wire, its length prefix included.
///
/// Every caller reaches this through [`read_frame_within`], which bounds the wait, or through the
/// reader of a stream, whose wait is bounded by the silence of the whole stream.
async fn read_frame_unbounded<R: AsyncRead + Unpin>(
    source: &mut R,
) -> Result<(BridgeFrame, usize), Refusal> {
    let mut prefix = [0_u8; FRAME_LENGTH_PREFIX_LEN];
    source
        .read_exact(&mut prefix)
        .await
        .map_err(|error| Refusal::Stream {
            detail: error.to_string(),
        })?;
    let declared = FrameCodec::new(StreamKind::Control)
        .decode_length(prefix)
        .map_err(|error| Refusal::Unreadable {
            detail: error.to_string(),
        })?;
    let mut payload = vec![0_u8; declared];
    source
        .read_exact(&mut payload)
        .await
        .map_err(|error| Refusal::Stream {
            detail: error.to_string(),
        })?;
    let frame = kr_protocol::wire::decode(&payload, &StreamKind::Control.cbor_limits()).map_err(
        |error| Refusal::Unreadable {
            detail: error.to_string(),
        },
    )?;
    Ok((frame, FRAME_LENGTH_PREFIX_LEN + declared))
}

/// Decides whether a request may cross a bridge, and builds what opens it.
///
/// `actor` is the envelope this host constructed for the request. Nothing the caller supplied is
/// read here: the ingress comes from that envelope, which the host built from the connection.
/// `start` is whether the opening may start what it needs inside the destination: a refresh,
/// enrolment or verification says `false`.
///
/// # Errors
///
/// Returns [`Refusal::NetworkActor`] for a request that did not arrive on a locally authenticated
/// ingress, [`Refusal::AlreadyBridged`] for one that has already crossed a bridge, and
/// [`Refusal::Launch`] when the enrolment names no process bridge or is incomplete.
pub fn open(
    actor: &ActorEnvelope,
    already_bridged: bool,
    enrolment: &EnvironmentEnrolment,
    origin_environment_id: EnvironmentId,
    build_id: BuildId,
    target: BridgeTarget,
    start: bool,
) -> Result<Opening, Refusal> {
    if !actor.ingress.may_cross_process_bridge() {
        return Err(Refusal::NetworkActor {
            ingress: actor.ingress,
        });
    }
    if already_bridged {
        return Err(Refusal::AlreadyBridged);
    }
    opening(enrolment, origin_environment_id, build_id, target, start)
}

/// Builds what opens a bridge for a person at this host's own command line.
///
/// The command line is the invoker here, not the control daemon acting for a connection, so there
/// is no envelope to read an ingress from: a person running `kr` at this host is a locally
/// authenticated invocation by construction, and nothing has crossed a bridge before it. A request
/// that arrived any other way never reaches this function, because only the command line calls it.
///
/// # Errors
///
/// Returns [`Refusal::Launch`] when the enrolment names no process bridge or is incomplete.
pub fn open_for_person(
    enrolment: &EnvironmentEnrolment,
    origin_environment_id: EnvironmentId,
    build_id: BuildId,
    target: BridgeTarget,
    start: bool,
) -> Result<Opening, Refusal> {
    opening(enrolment, origin_environment_id, build_id, target, start)
}

fn opening(
    enrolment: &EnvironmentEnrolment,
    origin_environment_id: EnvironmentId,
    build_id: BuildId,
    target: BridgeTarget,
    start: bool,
) -> Result<Opening, Refusal> {
    let command = launch::command(enrolment).map_err(Refusal::Launch)?;
    Ok(Opening {
        command,
        environment_id: enrolment.environment_id,
        hello: BridgeHello {
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            build_id,
            origin_environment_id,
            // Carried, not recomputed: both entrances above are locally authenticated, which is
            // the only ingress a bridge carries.
            origin_ingress: ActorIngress::LocalIpc,
            already_bridged: false,
            start,
            target,
        },
    })
}

/// The protocol version this host opens bridges with.
#[must_use]
pub const fn invoker_version() -> ProtocolVersion {
    kr_protocol::hello::PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::frame::FrameError;
    use kr_protocol::identity::EnvironmentAccess;
    use kr_protocol::ids::{ActorId, ConnectionId, ControllerGeneration, DeviceId};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    fn enrolment() -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
            access: EnvironmentAccess::WslDistribution,
            label: "ubuntu".to_owned(),
            target: "Ubuntu-24.04".to_owned(),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }

    fn actor(ingress: ActorIngress) -> ActorEnvelope {
        ActorEnvelope {
            actor_id: ActorId::new("device:1").expect("a principal"),
            ingress,
            device_id: if ingress == ActorIngress::PairedDevice {
                Nullable::some(DeviceId::new(Uuid::from_bytes([5; 16])))
            } else {
                Nullable::null()
            },
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(3),
            connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
        }
    }

    fn here() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([1; 16]))
    }

    fn build() -> BuildId {
        BuildId::new("kr/0.1.0").expect("a build")
    }

    #[test]
    fn a_local_invocation_opens_a_bridge_that_carries_its_own_ingress() {
        let opening = open(
            &actor(ActorIngress::LocalIpc),
            false,
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
            false,
        )
        .expect("opened");
        assert_eq!(opening.hello.origin_ingress, ActorIngress::LocalIpc);
        assert_eq!(opening.hello.origin_environment_id, here());
        assert!(!opening.hello.already_bridged);
        assert_eq!(opening.command.program, "wsl.exe");
        // The identity the destination will have to answer with comes from the record, never from
        // the caller.
        assert_eq!(opening.environment_id, enrolment().environment_id);
    }

    #[test]
    fn a_network_actor_never_reaches_a_bridge() {
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            let refusal = open(
                &actor(ingress),
                false,
                &enrolment(),
                here(),
                build(),
                BridgeTarget::Controller,
                false,
            )
            .expect_err("a refusal");
            assert_eq!(refusal, Refusal::NetworkActor { ingress });
            assert!(
                refusal.to_string().contains(ingress.as_str()),
                "the refusal names what arrived: {refusal}"
            );
        }
    }

    #[test]
    fn a_paired_device_is_refused_before_an_argument_vector_exists() {
        // The refusal comes before the enrolment is even read, so a device cannot reach a bridge
        // by naming a record this host would otherwise have started.
        let mut unusable = enrolment();
        unusable.helper_path = String::new();
        let refusal = open(
            &actor(ActorIngress::PairedDevice),
            false,
            &unusable,
            here(),
            build(),
            BridgeTarget::Controller,
            false,
        )
        .expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::NetworkActor {
                ingress: ActorIngress::PairedDevice
            }
        );
    }

    #[test]
    fn a_request_that_already_crossed_a_bridge_is_not_chained() {
        let refusal = open(
            &actor(ActorIngress::LocalIpc),
            true,
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
            false,
        )
        .expect_err("a refusal");
        assert_eq!(refusal, Refusal::AlreadyBridged);
    }

    #[test]
    fn an_ssh_environment_is_refused_as_a_bridge_rather_than_started() {
        let mut ssh = enrolment();
        ssh.access = EnvironmentAccess::SshHost;
        let refusal = open(
            &actor(ActorIngress::LocalIpc),
            false,
            &ssh,
            here(),
            build(),
            BridgeTarget::Controller,
            false,
        )
        .expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::Launch(LaunchError::NotAProcessBridge {
                access: EnvironmentAccess::SshHost
            })
        );
    }

    #[tokio::test]
    async fn a_declared_length_past_the_bound_is_refused_before_a_buffer_exists() {
        // One byte past the control-frame payload maximum, and nothing behind it. A reader that
        // allocated first would reserve the memory the destination asked for and then wait for
        // bytes that are not coming.
        for declared in [
            u32::try_from(StreamKind::Control.max_payload_len() + 1).expect("fits"),
            u32::MAX,
        ] {
            let stream = declared.to_be_bytes().to_vec();
            let refusal = read_frame(&mut stream.as_slice())
                .await
                .expect_err("a refusal");
            assert!(
                matches!(&refusal, Refusal::Unreadable { detail }
                    if detail.contains(&StreamKind::Control.max_payload_len().to_string())),
                "{refusal}"
            );
        }
    }

    #[tokio::test]
    async fn a_frame_at_the_bound_is_read_rather_than_refused() {
        // The bound itself is allowed: the refusal is for what exceeds it, not for what reaches it.
        let codec = FrameCodec::new(StreamKind::Control);
        let length = codec
            .decode_length(
                u32::try_from(StreamKind::Control.max_payload_len())
                    .expect("fits")
                    .to_be_bytes(),
            )
            .expect("the maximum is within the bound");
        assert_eq!(length, StreamKind::Control.max_payload_len());
    }

    #[tokio::test]
    async fn a_stream_that_ends_inside_a_frame_is_a_stream_failure_rather_than_a_short_frame() {
        let mut stream = 8_u32.to_be_bytes().to_vec();
        stream.extend_from_slice(&[1, 2, 3]);
        let refusal = read_frame(&mut stream.as_slice())
            .await
            .expect_err("a refusal");
        assert!(matches!(refusal, Refusal::Stream { .. }), "{refusal}");
    }

    #[tokio::test]
    async fn a_zero_length_frame_is_refused() {
        let stream = 0_u32.to_be_bytes().to_vec();
        let refusal = read_frame(&mut stream.as_slice())
            .await
            .expect_err("a refusal");
        assert!(
            matches!(&refusal, Refusal::Unreadable { detail }
                if detail == &FrameError::EmptyPayload.to_string()),
            "{refusal}"
        );
    }

    #[tokio::test]
    async fn a_frame_written_here_is_read_back_whole() {
        let original = BridgeFrame::Refused(ProtocolError::new(ErrorCode::PermissionDenied, "no"));
        let mut buffer: Vec<u8> = Vec::new();
        write_frame(&mut buffer, &original).await.expect("written");
        let read = read_frame(&mut buffer.as_slice()).await.expect("read back");
        assert_eq!(read, original);
    }

    #[tokio::test(start_paused = true)]
    #[cfg(unix)]
    async fn a_helper_that_says_nothing_is_given_up_on_rather_than_waited_for() {
        // `sleep` stands in for a helper that started and then went quiet. The bridge ends on the
        // silence bound, and the process ends with it.
        let opening = Opening {
            command: BridgeCommand {
                program: "/bin/sleep".to_owned(),
                arguments: vec!["600".to_owned()],
            },
            environment_id: here(),
            hello: BridgeHello {
                protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
                build_id: build(),
                origin_environment_id: here(),
                origin_ingress: ActorIngress::LocalIpc,
                already_bridged: false,
                start: false,
                target: BridgeTarget::Controller,
            },
        };
        // Nothing is read from a sleeping child, so the wait ends on the bound rather than on a
        // stream failure. The clock is the test's own, so this costs no real time.
        let refusal = opening.launch().await.expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::Silent {
                waited: SILENCE_LIMIT
            },
            "{refusal}"
        );
    }

    /// The opening frame a local invocation writes.
    #[cfg(unix)]
    fn hello() -> BridgeHello {
        BridgeHello {
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            build_id: build(),
            origin_environment_id: here(),
            origin_ingress: ActorIngress::LocalIpc,
            already_bridged: false,
            start: false,
            target: BridgeTarget::Controller,
        }
    }

    /// The acknowledgement a destination daemon gives, as the environment [`here`] names.
    #[cfg(unix)]
    fn acknowledgement() -> BridgeHelloAck {
        let connection_id = ConnectionId::new(Uuid::from_bytes([7; 16]));
        BridgeHelloAck {
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            build: Some(kr_protocol::local::LocalBuild::this(
                kr_protocol::ids::BuildId::new("kr/0.1.0").expect("a build"),
            )),
            base: kr_protocol::identity::DestinationBase {
                home: "/home/kala".to_owned(),
                variables: Vec::new(),
            },
            environment_id: here(),
            os_user: "kala".to_owned(),
            role: LocalRole::Controller,
            connection_id,
            boot_identity: kr_protocol::identity::BootIdentity {
                source: kr_protocol::identity::BootIdentitySource::LinuxBootId,
                value: kr_protocol::scalars::Bytes::new(b"boot".to_vec()),
            },
            max_frame_len: kr_protocol::scalars::U64::new(65_536),
            action_window: kr_protocol::hello::ActionWindow {
                action_window_id: kr_protocol::ids::ActionWindowId::new("w-bridge")
                    .expect("a window"),
                connection_id,
                boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(100),
                valid_for_ms: kr_protocol::scalars::DurationMs::new(120_000),
            },
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_helper_that_outlives_its_kill_is_named_and_let_go_rather_than_waited_for() {
        // No process a test can start outlives its kill. One that does is in uninterruptible
        // sleep, or is a Windows process whose termination waits on I/O that cannot be cancelled,
        // and from here either is an ending that never comes. The clock is the test's own, so the
        // bound costs no real time; the outer one is how a wait with no end shows as a failure.
        let started = tokio::time::Instant::now();
        let detail = tokio::time::timeout(
            KILL_LIMIT * 4,
            ended_within(std::future::pending(), KILL_LIMIT),
        )
        .await
        .expect("the helper is let go at the kill bound rather than waited for")
        .expect_err("an ending that never came is not reported as one");
        let waited = started.elapsed();
        assert!(
            waited >= KILL_LIMIT && waited < KILL_LIMIT * 2,
            "let go after {waited:?}"
        );
        assert!(
            detail.contains(&format!(
                "{} seconds after it was killed",
                KILL_LIMIT.as_secs()
            )),
            "{detail}"
        );
    }

    #[tokio::test]
    async fn a_kill_that_could_not_be_made_is_reported_rather_than_taken_as_an_ending() {
        let detail = ended_within(
            async { Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)) },
            KILL_LIMIT,
        )
        .await
        .expect_err("a helper that was not killed is not reported as ended");
        assert!(detail.starts_with("killing it failed"), "{detail}");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn a_helper_that_goes_at_the_kill_is_ended_and_nothing_is_reported() {
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("600")
            .kill_on_drop(true)
            .spawn()
            .expect("sleep starts");
        end(child, "/bin/sleep", KILL_LIMIT)
            .await
            .expect("a helper that goes at the kill is ended, and nothing is reported");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn a_helper_that_ignores_its_closed_input_is_ended_at_the_silence_bound_as_before() {
        // The helper answers the opening frame and then waits on something other than its input,
        // so closing that input does not end it. The bridge waits out the silence bound, kills it
        // and says it was silent: a helper that goes at the kill is ended as it always was. The
        // bound is short and the clock is real, because the ending is a real process's.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let answer = directory.path().join("answer");
        std::fs::write(
            &answer,
            FrameCodec::new(StreamKind::Control)
                .encode_message(&BridgeFrame::HelloAck(Box::new(acknowledgement())))
                .expect("the acknowledgement encodes"),
        )
        .expect("the answer is written");
        let opening = Opening {
            command: BridgeCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "cat \"$1\"; exec sleep 600".to_owned(),
                    "sh".to_owned(),
                    answer
                        .to_str()
                        .expect("a temporary path is text")
                        .to_owned(),
                ],
            },
            environment_id: here(),
            hello: hello(),
        };
        let invocation = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment");
        let silence = std::time::Duration::from_millis(200);
        assert_eq!(
            invocation.close_within(silence, KILL_LIMIT).await,
            Err(Refusal::Silent { waited: silence })
        );
    }

    #[test]
    fn every_failure_class_says_something_different() {
        // A diagnostic that named two causes the same way would send whoever reads it to the wrong
        // place. Section 18 asks for connection diagnostics; this is what makes them worth reading.
        let refusals = [
            Refusal::NetworkActor {
                ingress: ActorIngress::PairedDevice,
            },
            Refusal::AlreadyBridged,
            Refusal::Launch(LaunchError::NotAProcessBridge {
                access: EnvironmentAccess::SshHost,
            }),
            Refusal::NotStarted {
                program: "wsl.exe".to_owned(),
                detail: "no such file".to_owned(),
            },
            Refusal::Stream {
                detail: "broken pipe".to_owned(),
            },
            Refusal::Unreadable {
                detail: "not canonical".to_owned(),
            },
            Refusal::NotAnAcknowledgement,
            Refusal::ProtocolMajor {
                destination: 9,
                invoker: invoker_version().major,
            },
            Refusal::WrongRole {
                expected: LocalRole::Controller,
                answered: LocalRole::Worker,
            },
            Refusal::IdentityMismatch {
                enrolled: here(),
                answered: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            },
            Refusal::Destination(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the destination said no",
            )),
            Refusal::SessionClosed,
            Refusal::Silent {
                waited: SILENCE_LIMIT,
            },
            Refusal::UserMismatch {
                enrolled: "kala".to_owned(),
                answered: "root".to_owned(),
            },
            Refusal::OwnEnvironment,
            Refusal::Level { destination: None },
            Refusal::Backlog { limit: 1 },
            Refusal::Unkillable {
                program: "wsl.exe".to_owned(),
                pid: Some(4242),
                detail: "it had not gone 5 seconds after it was killed".to_owned(),
            },
        ];
        let mut messages: Vec<String> = refusals.iter().map(ToString::to_string).collect();
        messages.sort();
        let count = messages.len();
        messages.dedup();
        assert_eq!(messages.len(), count, "two refusals read the same");
    }

    #[test]
    fn a_failure_to_reach_a_destination_is_not_reported_as_a_permission_refusal() {
        // A helper that did not start is this host's own failure. Reporting it as a permission
        // refusal would send a person looking for a grant that was never the problem.
        let unreachable: crate::error::ControllerError = Refusal::NotStarted {
            program: "wsl.exe".to_owned(),
            detail: "no such file".to_owned(),
        }
        .into();
        assert!(
            matches!(
                unreachable,
                crate::error::ControllerError::Supervision { .. }
            ),
            "{unreachable:?}"
        );
        let mismatched: crate::error::ControllerError = Refusal::IdentityMismatch {
            enrolled: here(),
            answered: EnvironmentId::new(Uuid::from_bytes([9; 16])),
        }
        .into();
        assert!(
            matches!(
                mismatched,
                crate::error::ControllerError::PermissionDenied { .. }
            ),
            "{mismatched:?}"
        );
        let closed: crate::error::ControllerError = Refusal::SessionClosed.into();
        assert!(
            matches!(closed, crate::error::ControllerError::SessionClosed { .. }),
            "{closed:?}"
        );
        // A helper this host could not end is this host's supervision failing, and the message
        // names the process so a person can find it.
        let unended: crate::error::ControllerError = Refusal::Unkillable {
            program: "wsl.exe".to_owned(),
            pid: Some(4242),
            detail: "it had not gone 5 seconds after it was killed".to_owned(),
        }
        .into();
        assert!(
            matches!(&unended, crate::error::ControllerError::Supervision { .. }),
            "{unended:?}"
        );
        assert!(unended.to_string().contains("process 4242"), "{unended}");
    }

    /// A helper that writes `frames`, one after another, and then waits for its input to close, which
    /// is what a destination that has nothing more to say looks like from here.
    #[cfg(unix)]
    fn writing(frames: &[BridgeFrame], then: &str) -> (tempfile::TempDir, Opening) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let answer = directory.path().join("answer");
        let mut bytes = Vec::new();
        for frame in frames {
            bytes.extend(
                FrameCodec::new(StreamKind::Control)
                    .encode_message(frame)
                    .expect("the frame encodes"),
            );
        }
        std::fs::write(&answer, bytes).expect("the frames are written");
        let opening = Opening {
            command: BridgeCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    format!("head -c 4 >/dev/null; cat \"$1\"; {then}"),
                    "sh".to_owned(),
                    answer
                        .to_str()
                        .expect("a temporary path is text")
                        .to_owned(),
                ],
            },
            environment_id: here(),
            hello: hello(),
        };
        (directory, opening)
    }

    #[cfg(unix)]
    fn notification(sequence: u64) -> BridgeFrame {
        BridgeFrame::Control(Box::new(ControlFrame::Notification(
            kr_protocol::envelope::Notification {
                stream_id: kr_protocol::ids::StreamId::new("s1").expect("a stream"),
                sequence: kr_protocol::ids::EventSequence::new(sequence),
                event_type: kr_protocol::ids::EventType::new("session.output")
                    .expect("an event type"),
                payload: kr_protocol::envelope::ParamsValue::empty(),
            },
        )))
    }

    #[cfg(unix)]
    fn answer_to(request_id: u64) -> BridgeFrame {
        BridgeFrame::Control(Box::new(ControlFrame::Response(Response {
            request_id: RequestId::new(request_id),
            outcome: kr_protocol::envelope::Outcome::Ok(kr_protocol::envelope::ParamsValue::empty()),
        })))
    }

    #[cfg(unix)]
    fn event(event: ControlEvent) -> BridgeFrame {
        BridgeFrame::Control(Box::new(ControlFrame::Event(event)))
    }

    #[cfg(unix)]
    fn renewed(id: &str) -> BridgeFrame {
        let mut window = acknowledgement().action_window;
        window.action_window_id = kr_protocol::ids::ActionWindowId::new(id).expect("a window");
        event(ControlEvent::ActionWindowRenewed(window))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_stream_applies_a_renewed_window_skips_keepalives_and_holds_what_arrives_first() {
        let (_directory, opening) = writing(
            &[
                BridgeFrame::HelloAck(Box::new(acknowledgement())),
                event(ControlEvent::Keepalive),
                renewed("w-second"),
                notification(1),
                notification(2),
                answer_to(1),
                notification(3),
            ],
            "exec sleep 600",
        );
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream();
        assert_eq!(stream.action_window().action_window_id.as_str(), "w-bridge");
        // The answer is taken from behind two notifications, which stay where they are, in order.
        let answered = stream
            .response(RequestId::new(1), SILENCE_LIMIT)
            .await
            .expect("the answer arrives");
        assert_eq!(answered.request_id, RequestId::new(1));
        // The renewal that came before the answer is applied, so a mutation built now quotes it.
        assert_eq!(stream.action_window().action_window_id.as_str(), "w-second");
        let mut sequences = Vec::new();
        for _ in 0..3 {
            match stream.recv().await.expect("a held frame") {
                ControlFrame::Notification(notification) => {
                    sequences.push(notification.sequence.get());
                }
                other => panic!("expected a notification, got {other:?}"),
            }
        }
        assert_eq!(sequences, [1, 2, 3], "what was held comes first, in order");
        stream
            .close_within(std::time::Duration::from_millis(200), KILL_LIMIT)
            .await
            .expect_err("the helper ignores its closed input and is ended");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_receive_that_is_given_up_on_loses_nothing() {
        let (_directory, opening) = writing(
            &[
                BridgeFrame::HelloAck(Box::new(acknowledgement())),
                notification(1),
            ],
            "exec sleep 600",
        );
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream();
        // Dropped by a select that another branch won, over and over, while the frame is on its way.
        // Whatever a receive that did finish returned is kept: the frame must come out exactly once.
        let mut received = Vec::new();
        for _ in 0..50 {
            tokio::select! {
                biased;
                () = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
                frame = stream.recv() => received.push(frame.expect("a frame")),
            }
        }
        if received.is_empty() {
            received.push(stream.recv().await.expect("the frame was never lost"));
        }
        assert_eq!(received.len(), 1, "the one frame came out once");
        match &received[0] {
            ControlFrame::Notification(notification) => assert_eq!(notification.sequence.get(), 1),
            other => panic!("expected a notification, got {other:?}"),
        }
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_stream_that_has_ended_hands_over_what_arrived_before_it_ended_and_then_says_how() {
        let (_directory, opening) = writing(
            &[
                BridgeFrame::HelloAck(Box::new(acknowledgement())),
                notification(1),
                BridgeFrame::Refused(ProtocolError::new(
                    ErrorCode::SessionClosed,
                    "that session is closed",
                )),
            ],
            "exit 0",
        );
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream();
        assert!(matches!(
            stream.recv().await,
            Ok(ControlFrame::Notification(_))
        ));
        assert_eq!(
            stream.recv().await.expect_err("it ended"),
            Refusal::SessionClosed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_stream_whose_helper_goes_away_ends_with_the_stream_failing_not_with_silence() {
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            "exit 0",
        );
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream();
        let ended = stream
            .recv()
            .await
            .expect_err("the end of the stream is an error");
        assert!(matches!(ended, Refusal::Stream { .. }), "{ended}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_stream_that_is_not_heard_from_ends_instead_of_holding_its_caller() {
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            "exec sleep 600",
        );
        let silence = std::time::Duration::from_millis(300);
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(silence, kr_protocol::limits::MAX_SEND_QUEUE_BYTES);
        let started = std::time::Instant::now();
        assert_eq!(
            stream.recv().await.expect_err("nothing is coming"),
            Refusal::Silent { waited: silence }
        );
        assert!(started.elapsed() < silence * 20, "{:?}", started.elapsed());
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_keepalive_counts_as_the_destination_being_heard_from() {
        // Keepalives arrive faster than the silence bound, for longer than it, and nothing else is
        // sent: the stream stays up. The helper writes one frame every 100 milliseconds.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let first = directory.path().join("first");
        let beat = directory.path().join("beat");
        let encode = |frame: &BridgeFrame| {
            FrameCodec::new(StreamKind::Control)
                .encode_message(frame)
                .expect("the frame encodes")
        };
        std::fs::write(
            &first,
            encode(&BridgeFrame::HelloAck(Box::new(acknowledgement()))),
        )
        .expect("written");
        std::fs::write(&beat, encode(&event(ControlEvent::Keepalive))).expect("written");
        let opening = Opening {
            command: BridgeCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "head -c 4 >/dev/null; cat \"$1\"; i=0; while [ $i -lt 8 ]; do sleep 0.1; cat \"$2\"; i=$((i+1)); done; \
                     cat \"$3\"; exec sleep 600"
                        .to_owned(),
                    "sh".to_owned(),
                    first.to_str().expect("text").to_owned(),
                    beat.to_str().expect("text").to_owned(),
                    {
                        let last = directory.path().join("last");
                        std::fs::write(&last, encode(&notification(9))).expect("written");
                        last.to_str().expect("text").to_owned()
                    },
                ],
            },
            environment_id: here(),
            hello: hello(),
        };
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(
                std::time::Duration::from_millis(400),
                kr_protocol::limits::MAX_SEND_QUEUE_BYTES,
            );
        let started = std::time::Instant::now();
        match stream.recv().await.expect("kept up by its keepalives") {
            ControlFrame::Notification(notification) => assert_eq!(notification.sequence.get(), 9),
            other => panic!("expected the notification, got {other:?}"),
        }
        assert!(
            started.elapsed() > std::time::Duration::from_millis(700),
            "the keepalives ran for longer than the bound: {:?}",
            started.elapsed()
        );
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    /// The size one frame is charged: its length prefix and its payload.
    #[cfg(unix)]
    fn charged(frame: &BridgeFrame) -> usize {
        FrameCodec::new(StreamKind::Control)
            .encode_message(frame)
            .expect("encodes")
            .len()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_caller_that_falls_behind_is_told_to_take_the_view_again_rather_than_ended() {
        // Four output frames and an answer between them. Room for the answer and two of them.
        let answer = answer_to(5);
        let (_directory, opening) = writing(
            &[
                BridgeFrame::HelloAck(Box::new(acknowledgement())),
                notification(1),
                answer.clone(),
                notification(2),
                notification(3),
                notification(4),
            ],
            "exec sleep 600",
        );
        let ceiling = charged(&notification(1)) * 2 + charged(&answer) + 1;
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(SILENCE_LIMIT, ceiling);
        // Nobody reads while they arrive.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            stream.shared.lock().bytes <= ceiling,
            "what is held stays within the bound"
        );
        // The answer is what the caller is owed, whatever else was dropped.
        let response = stream
            .response(RequestId::new(5), std::time::Duration::from_secs(5))
            .await
            .expect("an answer is never dropped");
        assert_eq!(response.request_id, RequestId::new(5));
        // The view is replaced by one marker, and what arrived after it is still there.
        let mut types = Vec::new();
        while let Ok(Ok(ControlFrame::Notification(held))) =
            tokio::time::timeout(std::time::Duration::from_millis(300), stream.recv()).await
        {
            types.push((held.event_type.as_str().to_owned(), held.sequence.get()));
        }
        let resyncs = types
            .iter()
            .filter(|(event, _)| event == "session.resync")
            .count();
        assert_eq!(
            resyncs, 1,
            "one marker takes the place of what was dropped: {types:?}"
        );
        assert!(
            types.iter().all(|(_, sequence)| *sequence >= 1),
            "a marker is never the first of a stream: {types:?}"
        );
        assert_eq!(
            types.first().map(|(event, _)| event.as_str()),
            Some("session.resync"),
            "the marker is what the caller reads first of the view: {types:?}"
        );
        // And the stream is alive: the caller was told to recover, not ended.
        assert!(stream.shared.lock().ended.is_none());
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    /// What a stream's caller reads of the view, as (event, sequence), until nothing more comes.
    #[cfg(unix)]
    async fn view_read(stream: &mut BridgeStream) -> Vec<(String, u64)> {
        let mut types = Vec::new();
        while let Ok(Ok(ControlFrame::Notification(held))) =
            tokio::time::timeout(std::time::Duration::from_millis(300), stream.recv()).await
        {
            types.push((held.event_type.as_str().to_owned(), held.sequence.get()));
        }
        types
    }

    /// A caller that asked for a new subscription ignores the old stream and waits for the frame
    /// that opens the new one, so that frame is what a second overflow must never drop: the output
    /// of the old stream, a new stream's opening and its first frames arrive past the bound, and
    /// the opening is still held, with a marker after it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_overflow_never_drops_the_frame_that_opens_the_new_stream() {
        let (_directory, opening) = writing(
            &[
                BridgeFrame::HelloAck(Box::new(acknowledgement())),
                notification(7),
                notification(8),
                notification(0),
                notification(1),
                notification(2),
                notification(3),
            ],
            "exec sleep 600",
        );
        let ceiling = charged(&notification(1)) * 2 + 1;
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(SILENCE_LIMIT, ceiling);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let types = view_read(&mut stream).await;
        // The caller is waiting for the new stream: what it reads of the old one, a marker among it,
        // is ignored, and the opening is what it takes for the new stream's beginning.
        assert!(
            types.iter().any(|(_, sequence)| *sequence == 0),
            "the stream's opening was dropped: {types:?}"
        );
        assert!(
            types
                .iter()
                .filter(|(event, _)| event == "session.resync")
                .all(|(_, sequence)| *sequence >= 1),
            "a marker is never the first of a stream: {types:?}"
        );
        // The marker that was held for the old stream stands ahead of the opening and says nothing
        // of the new stream: frames of the new stream were dropped after it, so the caller needs
        // one that follows the opening.
        let opening = types
            .iter()
            .position(|(_, sequence)| *sequence == 0)
            .expect("the opening is held");
        assert!(
            types[opening..]
                .iter()
                .any(|(event, _)| event == "session.resync"),
            "no marker follows the opening, so the caller never learns the new stream lost frames: \
             {types:?}"
        );
        assert!(stream.shared.lock().ended.is_none(), "and the stream lives");
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    /// A destination that sends one opening after another cannot make this host hold them all: one
    /// is held past the bound, the others are replaced by a marker, and the stream is not ended.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_destination_that_sends_openings_without_end_does_not_make_the_host_hold_them() {
        let answers: Vec<BridgeFrame> = (1..=2).map(answer_to).collect();
        let mut frames = vec![BridgeFrame::HelloAck(Box::new(acknowledgement()))];
        frames.extend(answers.clone());
        frames.extend((0..200).map(|_| notification(0)));
        let (_directory, opening) = writing(&frames, "exec sleep 600");
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(SILENCE_LIMIT, charged(&answers[0]) * 2 + 1);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let held = stream.shared.lock().frames.len();
        assert!(
            held <= 2 + 1 + 1,
            "two answers, one opening and one marker are all that are held, not {held}"
        );
        let mut taken = Vec::new();
        while let Ok(Ok(frame)) =
            tokio::time::timeout(std::time::Duration::from_millis(300), stream.recv()).await
        {
            taken.push(match frame {
                ControlFrame::Notification(held) => {
                    format!("{} {}", held.event_type.as_str(), held.sequence.get())
                }
                ControlFrame::Response(_) => "response".to_owned(),
                other => format!("{other:?}"),
            });
        }
        assert_eq!(
            taken,
            [
                "response",
                "response",
                "session.output 0",
                "session.resync 1"
            ]
        );
        assert!(stream.shared.lock().ended.is_none());
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    /// The opening of a stream is one frame, held past the bound where the bound is met by what
    /// cannot be dropped, and the stream is not ended for it.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_frame_that_opens_a_stream_is_held_past_a_bound_met_by_answers() {
        let answers: Vec<BridgeFrame> = (1..=2).map(answer_to).collect();
        let mut frames = vec![BridgeFrame::HelloAck(Box::new(acknowledgement()))];
        frames.extend(answers.clone());
        frames.push(notification(0));
        let (_directory, opening) = writing(&frames, "exec sleep 600");
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(SILENCE_LIMIT, charged(&answers[0]) * 2 + 1);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let mut taken = Vec::new();
        while let Ok(Ok(frame)) =
            tokio::time::timeout(std::time::Duration::from_millis(300), stream.recv()).await
        {
            taken.push(match frame {
                ControlFrame::Notification(held) => format!("notification {}", held.sequence.get()),
                ControlFrame::Response(_) => "response".to_owned(),
                other => format!("{other:?}"),
            });
        }
        assert_eq!(taken, ["response", "response", "notification 0"]);
        assert!(stream.shared.lock().ended.is_none());
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    /// Where the bound is met by what cannot be dropped, a view frame that does not fit is replaced
    /// by a marker rather than by nothing: the caller is told it has missed something, and the
    /// stream is not ended.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_view_frame_that_does_not_fit_beside_answers_leaves_a_marker() {
        let answers: Vec<BridgeFrame> = (1..=2).map(answer_to).collect();
        let mut frames = vec![BridgeFrame::HelloAck(Box::new(acknowledgement()))];
        frames.extend(answers.clone());
        frames.push(notification(3));
        frames.push(notification(4));
        let (_directory, opening) = writing(&frames, "exec sleep 600");
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(SILENCE_LIMIT, charged(&answers[0]) * 2 + 1);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let mut taken = Vec::new();
        while let Ok(Ok(frame)) =
            tokio::time::timeout(std::time::Duration::from_millis(300), stream.recv()).await
        {
            taken.push(match frame {
                ControlFrame::Notification(held) => {
                    format!("{} {}", held.event_type.as_str(), held.sequence.get())
                }
                ControlFrame::Response(_) => "response".to_owned(),
                other => format!("{other:?}"),
            });
        }
        assert_eq!(
            taken,
            ["response", "response", "session.resync 3"],
            "one marker stands for both frames that did not fit"
        );
        assert!(stream.shared.lock().ended.is_none());
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_destination_that_sends_more_than_the_bound_of_what_cannot_be_dropped_ends_the_stream()
     {
        // Answers and events that carry no bytes are not a view, so nothing here can be dropped to
        // make room, and the stream ends instead of filling memory.
        let answers: Vec<BridgeFrame> = (1..=3).map(answer_to).collect();
        let mut frames = vec![BridgeFrame::HelloAck(Box::new(acknowledgement()))];
        frames.extend(answers.clone());
        let (_directory, opening) = writing(&frames, "exec sleep 600");
        let mut stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream_within(SILENCE_LIMIT, charged(&answers[0]) * 2 + 1);
        let mut taken = 0;
        let ended = loop {
            match stream.recv().await {
                Ok(_) => taken += 1,
                Err(refusal) => break refusal,
            }
        };
        assert_eq!(taken, 2, "the frames that fit were delivered");
        assert!(matches!(ended, Refusal::Backlog { .. }), "{ended}");
        let _ = stream
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn what_a_helper_writes_to_standard_error_is_kept_and_counted_not_shown() {
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            "echo a diagnostic line >&2; exec sleep 600",
        );
        let invocation = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment");
        let diagnostics = invocation.diagnostics.clone();
        let started = std::time::Instant::now();
        while diagnostics.written() == 0 {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "nothing was kept"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(diagnostics.written(), "a diagnostic line\n".len() as u64);
        let _ = invocation
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    /// Whether every task this test's runtime started has ended within `within`.
    ///
    /// The tests that use it start a helper whose descendant keeps the helper's pipes open for a
    /// few seconds after the helper itself is gone. A reader that ends when its pipe does is still
    /// alive then, and one that ends with its owner is not.
    #[cfg(unix)]
    async fn readers_end_within(within: std::time::Duration) -> bool {
        let metrics = tokio::runtime::Handle::current().metrics();
        let started = std::time::Instant::now();
        while metrics.num_alive_tasks() > 0 {
            if started.elapsed() > within {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        true
    }

    /// The descendant a helper leaves behind, which keeps its standard streams open for a while.
    #[cfg(unix)]
    const HOLDING_THE_PIPES: &str = "sleep 4 &";

    #[cfg(unix)]
    #[tokio::test]
    async fn an_earlier_helper_that_cannot_read_the_opening_is_said_to_need_an_update() {
        // What a helper of a release before the opening's `start` member answers.
        let (_directory, opening) = writing(
            &[BridgeFrame::Refused(ProtocolError::new(
                ErrorCode::UnsupportedSchema,
                EARLIER_HELPER_CANNOT_READ_OPENING,
            ))],
            "exit 0",
        );
        let refusal = opening.launch().await.expect_err("a refusal");
        assert_eq!(refusal, Refusal::Level { destination: None });
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn another_refusal_of_the_same_kind_is_the_destinations_own_and_is_not_rewritten() {
        let said = ProtocolError::new(
            ErrorCode::UnsupportedSchema,
            "the daemon here is of an earlier build; restart it",
        );
        let (_directory, opening) = writing(&[BridgeFrame::Refused(said.clone())], "exit 0");
        let refusal = opening.launch().await.expect_err("a refusal");
        assert_eq!(refusal, Refusal::Destination(said));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_readers_of_a_bridge_that_failed_its_opening_end_with_it_not_with_its_pipes() {
        // The helper writes what is not a frame, so the opening fails after its readers started.
        let (_directory, opening) = writing(
            &[],
            &format!("printf 'zzzzzzzz'; {HOLDING_THE_PIPES} exec sleep 600"),
        );
        let refusal = opening
            .launch()
            .await
            .expect_err("what is not a frame is refused");
        assert!(matches!(refusal, Refusal::Unreadable { .. }), "{refusal}");
        assert!(
            readers_end_within(std::time::Duration::from_secs(2)).await,
            "a reader outlived the opening that failed"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_readers_of_a_stream_that_is_dropped_end_with_it_not_with_its_pipes() {
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            &format!("{HOLDING_THE_PIPES} exec sleep 600"),
        );
        let stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream();
        drop(stream);
        assert!(
            readers_end_within(std::time::Duration::from_secs(2)).await,
            "a reader outlived the stream that owned it"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_readers_of_a_stream_whose_closing_is_given_up_on_end_with_it() {
        // The helper does not end at its closed input, so the closing is still waiting for it when
        // its caller stops waiting for the closing.
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            &format!("{HOLDING_THE_PIPES} exec sleep 600"),
        );
        let stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream();
        let closing = stream.close_within(std::time::Duration::from_secs(30), KILL_LIMIT);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), closing)
                .await
                .is_err(),
            "the helper was still being waited for"
        );
        assert!(
            readers_end_within(std::time::Duration::from_secs(2)).await,
            "a reader outlived the closing that was cancelled"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_readers_of_an_invocation_that_is_dropped_end_with_it_not_with_its_pipes() {
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            &format!("{HOLDING_THE_PIPES} exec sleep 600"),
        );
        let invocation = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment");
        drop(invocation);
        assert!(
            readers_end_within(std::time::Duration::from_secs(2)).await,
            "a reader outlived the invocation that owned it"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn what_a_helper_wrote_to_standard_error_before_it_ended_is_kept_when_it_is_closed() {
        // Ending the readers with the stream must not cut the diagnostic a helper wrote last.
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            "echo a last line >&2; exit 0",
        );
        let stream = opening
            .launch()
            .await
            .expect("the helper answered as the enrolled environment")
            .into_stream();
        let diagnostics = stream.diagnostics().clone();
        stream
            .close_within(std::time::Duration::from_secs(10), KILL_LIMIT)
            .await
            .expect("a helper that ended at its closed input is closed");
        assert_eq!(diagnostics.written(), "a last line\n".len() as u64);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_destination_of_another_level_is_refused_before_a_request_is_sent() {
        for build in [
            None,
            Some(kr_protocol::local::LocalBuild {
                build_id: kr_protocol::ids::BuildId::new("kr/0.0.1").expect("a build"),
                protocol_version: kr_protocol::hello::PackageVersion::new(
                    PACKAGE_VERSION.major,
                    PACKAGE_VERSION.minor + 1,
                    0,
                ),
            }),
        ] {
            let mut stated = acknowledgement();
            stated.build.clone_from(&build);
            let (_directory, opening) =
                writing(&[BridgeFrame::HelloAck(Box::new(stated))], "exec sleep 600");
            let refusal = opening.launch().await.expect_err("refused");
            assert_eq!(refusal, Refusal::Level { destination: build });
            assert!(refusal.to_string().contains("update kr"), "{refusal}");
        }
        // The control: this release's own level is accepted.
        let (_directory, opening) = writing(
            &[BridgeFrame::HelloAck(Box::new(acknowledgement()))],
            "exec sleep 600",
        );
        let invocation = opening
            .launch()
            .await
            .expect("a destination of this level answers");
        let _ = invocation
            .close_within(std::time::Duration::from_millis(100), KILL_LIMIT)
            .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_base_the_protocol_does_not_allow_is_refused_before_a_create_is_built_from_it() {
        for (what, base) in [
            (
                "a variable outside the allowlist",
                kr_protocol::identity::DestinationBase {
                    home: "/home/kala".to_owned(),
                    variables: vec![kr_protocol::session::EnvironmentVariable {
                        name: "AWS_SECRET_ACCESS_KEY".to_owned(),
                        value: "x".to_owned(),
                    }],
                },
            ),
            (
                "a home that is not absolute",
                kr_protocol::identity::DestinationBase {
                    home: "home/kala".to_owned(),
                    variables: Vec::new(),
                },
            ),
            (
                "one variable twice",
                kr_protocol::identity::DestinationBase {
                    home: "/home/kala".to_owned(),
                    variables: vec![
                        kr_protocol::session::EnvironmentVariable {
                            name: "HOME".to_owned(),
                            value: "/a".to_owned(),
                        },
                        kr_protocol::session::EnvironmentVariable {
                            name: "HOME".to_owned(),
                            value: "/b".to_owned(),
                        },
                    ],
                },
            ),
        ] {
            let mut stated = acknowledgement();
            stated.base = base;
            let (_directory, opening) =
                writing(&[BridgeFrame::HelloAck(Box::new(stated))], "exec sleep 600");
            let refusal = opening.launch().await.expect_err(what);
            assert!(
                matches!(refusal, Refusal::Unreadable { .. }),
                "{what}: {refusal}"
            );
        }
    }

    #[test]
    fn an_opening_that_may_start_what_it_needs_waits_longer_for_its_first_answer_and_says_so() {
        // The two bounds are different on purpose, and ordered: a start waits for a boot and a
        // daemon, and a mutation waits for the destination's own bound on a create.
        assert!(START_LIMIT > SILENCE_LIMIT);
        assert!(MUTATION_LIMIT > SILENCE_LIMIT);
        let opening = open_for_person(
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
            true,
        )
        .expect("a person at this host opens a bridge");
        assert!(opening.hello.start);
        assert_eq!(opening.hello.origin_ingress, ActorIngress::LocalIpc);
        assert!(!opening.hello.already_bridged);
        // A refresh's opening starts nothing.
        let refresh = open(
            &actor(ActorIngress::LocalIpc),
            false,
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
            false,
        )
        .expect("opened");
        assert!(!refresh.hello.start);
    }
}
