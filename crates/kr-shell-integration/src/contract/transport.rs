//! The bridge endpoint, the bootstrap values and the `kr-shell-bridge/1` handshake.
//!
//! The worker listens on one endpoint per session inside its owner-only runtime directory, and
//! tells the shell where it is through two reserved bootstrap variables. Nothing about that
//! endpoint is discoverable: the directory keeps other users out, peer credentials keep other users
//! off the socket, and the proof over the bootstrap secret keeps a process of the same user that
//! merely guessed the path from registering as the root integration.
//!
//! # Frames
//!
//! The bridge carries the same framing as every other local endpoint: a four-byte unsigned
//! big-endian length followed by one KR-CBOR-1 object, bounded by the control stream's maximum
//! frame. [`BRIDGE_STREAM_KIND`] names that bound, and [`frame_codec`] is the codec both sides use,
//! so the bytes a shell package writes are the bytes the worker's own codec reads.
//!
//! # What a child shell inherits
//!
//! Neither an active root token nor automatic activation, and two independent rules keep it that
//! way:
//!
//! * The bootstrap variables leave the exported environment as soon as the handshake succeeds, so a
//!   child process started afterwards sees no endpoint and no secret. [`decide_activation`] is the
//!   check a starting shell makes, and with nothing exported it skips activation entirely.
//! * Even with the variables in hand, the handshake binds to the root process the worker started,
//!   and it binds it to the *kernel's* view of the connection rather than to what the hello says. A
//!   child that names its parent's identifier is refused with
//!   [`QualificationReason::ProcessMismatch`], because the process on the other end of the endpoint
//!   is not the one the worker launched.

use kr_cbor::CborError;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::root::{
    DETACH_HINT, FENCE_EXCHANGE_TIMEOUT, FencePublication, RootCommandAcceptedResult,
    RootEditorEnterResult, RootEditorLeaveResult, RootEofDetachResult,
};
use kr_protocol::scalars::{Bytes, DurationMs};
use serde::{Deserialize, Serialize};

use crate::contract::events::{BridgeEvent, EofGesture};
use crate::contract::qualification::{BridgeAbi, QualificationReason, ShellKind, qualify};
use crate::contract::requests::{
    BridgeAnswer, LaunchRejectionReason, LaunchTransactionId, WorkerRequest,
};

/// The bridge protocol both sides name in the handshake.
pub const BRIDGE_PROTOCOL: &str = "kr-shell-bridge/1";

/// The reserved variable that names the bridge endpoint.
///
/// The worker sets it when it launches the root shell and the integration removes it from the
/// exported environment after the handshake.
pub const ENDPOINT_VARIABLE: &str = "KR_SHELL_BRIDGE";

/// The reserved variable that carries the one-time bootstrap secret.
///
/// Unpadded base64url of [`BOOTSTRAP_SECRET_LEN`] random bytes. It is removed from the exported
/// environment with the endpoint and retained only in private integration state.
pub const SECRET_VARIABLE: &str = "KR_SHELL_BRIDGE_SECRET";

/// Both bootstrap variables, in the order a package reads them.
pub const BOOTSTRAP_VARIABLES: &[&str] = &[ENDPOINT_VARIABLE, SECRET_VARIABLE];

/// The length of the bootstrap secret in bytes.
pub const BOOTSTRAP_SECRET_LEN: usize = 32;

/// The length of the proof over the bootstrap secret in bytes.
pub const BOOTSTRAP_PROOF_LEN: usize = 32;

/// The basename of the endpoint inside the session's runtime directory.
pub const ENDPOINT_BASENAME: &str = "shell-bridge";

/// The prefix every Windows named pipe carries.
pub const WINDOWS_PIPE_PREFIX: &str = r"\\.\pipe\";

/// The longest endpoint path the contract accepts.
///
/// A Unix socket address is copied into a fixed array, 104 bytes on macOS and 108 on Linux, one of
/// which is the terminator. The tightest platform decides the contract, so a path that validates
/// here binds everywhere rather than on the machine it was written on.
pub const MAX_ENDPOINT_PATH_LEN: usize = 103;

/// The permission bits the endpoint's directory carries.
pub const ENDPOINT_DIRECTORY_MODE: u32 = 0o700;

/// The permission bits the endpoint itself carries.
pub const ENDPOINT_FILE_MODE: u32 = 0o600;

/// The stream kind whose bound the bridge's frames are held to.
pub const BRIDGE_STREAM_KIND: StreamKind = StreamKind::Control;

/// Returns the frame codec both sides of the bridge use.
#[must_use]
pub const fn frame_codec() -> FrameCodec {
    FrameCodec::new(BRIDGE_STREAM_KIND)
}

/// Which kind of endpoint the worker is listening on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// A Unix domain socket in the session's owner-only runtime directory.
    UnixSocket,
    /// A Windows named pipe whose security descriptor admits the owning user alone.
    WindowsNamedPipe,
}

impl EndpointKind {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnixSocket => "unix_socket",
            Self::WindowsNamedPipe => "windows_named_pipe",
        }
    }
}

/// Why an endpoint path cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EndpointFault {
    /// The path is empty.
    #[error("the bridge endpoint path is empty")]
    Empty,
    /// The path is longer than the tightest platform's address family accepts.
    #[error(
        "the bridge endpoint path is {len} bytes, more than the {limit} a socket address holds"
    )]
    TooLong {
        /// The path's length in bytes.
        len: usize,
        /// The bound.
        limit: usize,
    },
    /// A Unix socket path must be absolute, so the shell cannot resolve it against a working
    /// directory a startup file changed.
    #[error("the bridge endpoint path is relative")]
    Relative,
    /// A Windows named pipe must carry the pipe prefix.
    #[error("the bridge endpoint is not a named pipe path")]
    NotAPipe,
    /// The path contains a byte no endpoint name may hold.
    #[error("the bridge endpoint path contains a control character or a null byte")]
    IllegalByte,
}

/// Where the worker listens for its root integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEndpoint {
    /// Which kind of endpoint this is.
    pub kind: EndpointKind,
    /// The path or pipe name, exactly as the bootstrap variable carries it.
    pub path: String,
}

impl BridgeEndpoint {
    /// Names a Unix socket endpoint.
    #[must_use]
    pub fn unix(path: impl Into<String>) -> Self {
        Self {
            kind: EndpointKind::UnixSocket,
            path: path.into(),
        }
    }

    /// Names a Windows named pipe endpoint.
    #[must_use]
    pub fn windows_pipe(path: impl Into<String>) -> Self {
        Self {
            kind: EndpointKind::WindowsNamedPipe,
            path: path.into(),
        }
    }

    /// Checks the path against what the platform's address family accepts.
    ///
    /// The permissions are not checked here: the worker creates the endpoint inside a directory it
    /// has already verified is owner-only, and a shell package cannot verify that from a string.
    ///
    /// # Errors
    ///
    /// Returns the first [`EndpointFault`] the path has.
    pub fn validate(&self) -> Result<(), EndpointFault> {
        if self.path.is_empty() {
            return Err(EndpointFault::Empty);
        }
        if self.path.len() > MAX_ENDPOINT_PATH_LEN {
            return Err(EndpointFault::TooLong {
                len: self.path.len(),
                limit: MAX_ENDPOINT_PATH_LEN,
            });
        }
        if self.path.chars().any(char::is_control) {
            return Err(EndpointFault::IllegalByte);
        }
        match self.kind {
            EndpointKind::UnixSocket if !self.path.starts_with('/') => Err(EndpointFault::Relative),
            EndpointKind::WindowsNamedPipe if !self.path.starts_with(WINDOWS_PIPE_PREFIX) => {
                Err(EndpointFault::NotAPipe)
            }
            EndpointKind::UnixSocket | EndpointKind::WindowsNamedPipe => Ok(()),
        }
    }
}

/// Where the bootstrap secret is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretLocation {
    /// In the exported environment, where the shell's own startup files can read it and where a
    /// child process would inherit it. This is true only until the handshake succeeds.
    ExportedEnvironment,
    /// In private integration state: a shell-local variable the integration never exports, or the
    /// module's own memory for a compiled bridge. Nothing a child process inherits and nothing a
    /// user's startup file receives.
    PrivateIntegrationState,
}

impl SecretLocation {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExportedEnvironment => "exported_environment",
            Self::PrivateIntegrationState => "private_integration_state",
        }
    }
}

/// The bootstrap values a managed shell starts with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    /// Where the worker is listening.
    pub endpoint: BridgeEndpoint,
    /// The one-time secret the proof is taken over.
    pub secret: Bytes,
}

impl Bootstrap {
    /// Returns the variables the worker exports when it launches the root shell.
    #[must_use]
    pub fn exported_variables(&self) -> Vec<(&'static str, String)> {
        vec![
            (ENDPOINT_VARIABLE, self.endpoint.path.clone()),
            (
                SECRET_VARIABLE,
                kr_protocol::scalars::to_base64url(self.secret.as_slice()),
            ),
        ]
    }

    /// Moves the bootstrap values into private integration state.
    ///
    /// Called once, immediately after the handshake is accepted. The returned state names the
    /// variables the integration removes from the exported environment; the secret survives only
    /// where a child process and a user's startup file cannot reach it, because the integration
    /// needs it again if the reader is re-established within the same shell.
    #[must_use]
    pub fn retain_after_handshake(self) -> RetainedBootstrap {
        RetainedBootstrap {
            endpoint: self.endpoint,
            secret: self.secret,
            secret_location: SecretLocation::PrivateIntegrationState,
            unexported: unexported_variables(),
        }
    }
}

/// The bootstrap values after the handshake, and what left the environment with them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedBootstrap {
    /// Where the worker is listening.
    pub endpoint: BridgeEndpoint,
    /// The secret, now out of the exported environment.
    pub secret: Bytes,
    /// Where the secret is kept.
    pub secret_location: SecretLocation,
    /// The variables that were removed from the exported environment.
    pub unexported: Vec<String>,
}

/// What a starting shell knows when it decides whether to activate the integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationInputs {
    /// The endpoint the exported environment names, when it names one.
    pub exported_endpoint: Option<String>,
    /// Whether the exported environment carries the bootstrap secret.
    pub exported_secret: bool,
}

/// Why a shell did not activate the integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// No bridge endpoint is exported, which is every ordinary shell and every child of a managed
    /// root shell.
    NoEndpoint,
    /// An endpoint without a secret, which is what a copied or forged environment looks like.
    NoSecret,
}

impl SkipReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEndpoint => "no_endpoint",
            Self::NoSecret => "no_secret",
        }
    }
}

/// Whether a starting shell activates the integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    /// Attempt the handshake. Activation still depends on it succeeding.
    Attempt,
    /// Do not attempt it, and load no user-facing hooks.
    Skip(SkipReason),
}

/// Decides whether a starting shell attempts the handshake at all.
///
/// A guarded startup entry runs in every interactive shell of that user, including one the session's
/// own commands start. This is what keeps it inert in all of them: without both bootstrap values in
/// the exported environment there is nothing to attempt, and after the root handshake there are no
/// bootstrap values to inherit.
#[must_use]
pub const fn decide_activation(inputs: &ActivationInputs) -> Activation {
    match inputs.exported_endpoint {
        None => Activation::Skip(SkipReason::NoEndpoint),
        Some(_) if !inputs.exported_secret => Activation::Skip(SkipReason::NoSecret),
        Some(_) => Activation::Attempt,
    }
}

/// One published reader patch and the upstream revision it applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchRevision {
    /// The patch's name in the package.
    pub name: String,
    /// The upstream revision it was rebased onto.
    pub upstream_revision: String,
    /// The patch's own revision.
    pub revision: String,
}

/// One loadable module the shell will search for, with the ABI it was built against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleEntry {
    /// The module's name.
    pub name: String,
    /// Where the shell searches for it.
    pub search_path: String,
    /// The editor ABI revision it was built against.
    pub editor_abi: String,
}

/// What the bridge says it is.
///
/// All of it is recorded with the session, because a managed contract that cannot name the exact
/// binary and patches behind it is not a qualification claim, only a hope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellIdentity {
    /// Which managed shell this is.
    pub kind: ShellKind,
    /// The executable actually launched.
    pub executable: String,
    /// The upstream shell version.
    pub upstream_version: String,
    /// The editor ABI revision the bridge was built against.
    pub editor_abi: String,
    /// The integration version of the package.
    pub integration_version: String,
    /// Every published reader patch in this package.
    pub patches: Vec<PatchRevision>,
    /// The module tree the shell will load, with each module's ABI.
    pub modules: Vec<ModuleEntry>,
}

/// The first frame a bridge sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeHello {
    /// The protocol the bridge offers.
    pub protocol: String,
    /// The session the bridge believes it belongs to, read from the worker's session variable.
    ///
    /// A claim rather than authority: the endpoint already identifies the session, and this is
    /// checked against it so a shell that inherited a stale environment is refused instead of
    /// registering against the wrong session.
    pub session_id: SessionId,
    /// This shell process, with the kernel's record of when it started.
    pub shell_process: ProcessStartIdentity,
    /// What the shell is.
    pub shell: ShellIdentity,
    /// The mechanisms the bridge implements.
    pub abi: BridgeAbi,
    /// The proof over the bootstrap secret.
    pub proof: Bytes,
}

/// The connection's own identity, as the kernel reports it.
///
/// This is what the endpoint's peer credentials and the platform's process query give the worker:
/// who is actually on the other end, rather than who the first frame says is. A hello is checked
/// against this before its declaration is read at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedPeer {
    /// The caller's operating-system user.
    pub uid: u32,
    /// The caller's process and the kernel's record of when it started, where the platform reports
    /// it. `None` means the platform could not say, which is not a basis for registering a root
    /// integration.
    pub process: Option<ProcessStartIdentity>,
}

/// Whether the worker's own verification of the proof succeeded.
///
/// The comparison happens in the worker, which holds the secret and a constant-time comparison; the
/// contract takes its verdict rather than the bytes, so no part of this crate handles key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofVerdict {
    /// The proof matches the transcript under the bootstrap secret.
    Verified,
    /// It does not.
    Failed,
}

/// What the worker knows before the first frame arrives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerExpectation {
    /// The session this endpoint belongs to.
    pub session_id: SessionId,
    /// The root shell the worker launched.
    pub root_process: ProcessStartIdentity,
    /// The editor ABI revisions this build was qualified against.
    pub supported_editor_abis: Vec<String>,
    /// The integration versions this build supports.
    pub supported_integration_versions: Vec<String>,
    /// Whether a root integration is already registered for this session.
    pub already_registered: bool,
    /// The end-of-file gesture configured for this session, which the accept carries back.
    pub gesture: EofGesture,
}

/// What the worker answers an accepted bridge with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeAccepted {
    /// The protocol both sides will use.
    pub protocol: String,
    /// The session.
    pub session_id: SessionId,
    /// The editor ABI revision the worker accepted.
    pub editor_abi: String,
    /// How long the worker will hold input for a reader transition or a launch.
    pub hold_ms: DurationMs,
    /// The end-of-file gesture in force at acceptance.
    pub gesture: EofGesture,
    /// The hint an unattributable gesture prints, exactly as written.
    pub hint: String,
    /// Where the bridge must keep the bootstrap secret from now on.
    pub secret_location: SecretLocation,
    /// The variables the bridge removes from the exported environment before it returns.
    pub unexport: Vec<String>,
}

/// What the worker answers a bridge it will not register.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeRefused {
    /// Why.
    pub reason: QualificationReason,
    /// The error the session reports, with the reason's own code.
    pub error: ProtocolError,
}

impl BridgeRefused {
    /// Builds a refusal from a reason.
    #[must_use]
    pub fn new(reason: QualificationReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            error: ProtocolError::new(reason.code(), message),
        }
    }

    /// Returns the error code the refusal carries.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.error.code
    }
}

/// The worker's answer to a hello.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeOutcome {
    /// Registered as this session's root integration.
    Accepted(BridgeAccepted),
    /// Not registered, with the named reason.
    Refused(BridgeRefused),
}

impl HandshakeOutcome {
    /// Returns the refusal's reason, or `None` when the bridge was accepted.
    #[must_use]
    pub const fn refusal(&self) -> Option<QualificationReason> {
        match self {
            Self::Accepted(_) => None,
            Self::Refused(refused) => Some(refused.reason),
        }
    }
}

/// Decides a handshake.
///
/// The order is identity first, capability second. A bridge that is not this session's root shell is
/// refused before its declaration is read at all, so an unqualified mechanism is never the headline
/// for what is actually a different process.
#[must_use]
pub fn decide_handshake(
    expectation: &WorkerExpectation,
    peer: &ObservedPeer,
    hello: &BridgeHello,
    proof: ProofVerdict,
) -> HandshakeOutcome {
    use QualificationReason as Reason;

    if hello.protocol != BRIDGE_PROTOCOL {
        return refuse(
            Reason::ProtocolMismatch,
            format!(
                "the bridge offered {} and this worker speaks {BRIDGE_PROTOCOL}",
                hello.protocol
            ),
        );
    }
    if hello.session_id != expectation.session_id {
        return refuse(
            Reason::SessionMismatch,
            "the bridge named a different session from the one this endpoint belongs to",
        );
    }
    let Some(observed) = peer.process.as_ref() else {
        return refuse(
            Reason::PeerUnidentified,
            "the platform could not identify the process on the other end of the endpoint",
        );
    };
    if !observed.matches(&expectation.root_process) || !hello.shell_process.matches(observed) {
        // The kernel's view decides. A child that inherited the bootstrap values can name its
        // parent's identifier and compute the matching proof; it cannot be its parent.
        return refuse(
            Reason::ProcessMismatch,
            "the connecting process is not the root shell this session started",
        );
    }
    if proof == ProofVerdict::Failed {
        return refuse(
            Reason::ProofMismatch,
            "the proof over the bootstrap secret did not verify",
        );
    }
    if expectation.already_registered {
        return refuse(
            Reason::AlreadyRegistered,
            "this session already has a registered root integration",
        );
    }
    if let Err(reason) = qualify(hello.shell.kind, &hello.abi) {
        return refuse(reason, unqualified_message(reason, hello));
    }
    if !expectation
        .supported_integration_versions
        .contains(&hello.shell.integration_version)
    {
        return refuse(
            Reason::IntegrationVersionUnsupported,
            format!(
                "integration version {} is not one this build supports",
                hello.shell.integration_version
            ),
        );
    }
    if !expectation
        .supported_editor_abis
        .contains(&hello.shell.editor_abi)
    {
        return refuse(
            Reason::EditorAbiUnsupported,
            format!(
                "editor ABI {} is not one this build was qualified against",
                hello.shell.editor_abi
            ),
        );
    }
    if let Some(module) = hello
        .shell
        .modules
        .iter()
        .find(|module| module.editor_abi != hello.shell.editor_abi)
    {
        return refuse(
            Reason::ModuleTreeUnsupported,
            format!(
                "module {} was built against editor ABI {} and this reader is {}",
                module.name, module.editor_abi, hello.shell.editor_abi
            ),
        );
    }
    HandshakeOutcome::Accepted(BridgeAccepted {
        protocol: BRIDGE_PROTOCOL.to_owned(),
        session_id: expectation.session_id,
        editor_abi: hello.shell.editor_abi.clone(),
        hold_ms: FENCE_EXCHANGE_TIMEOUT,
        gesture: expectation.gesture.clone(),
        hint: DETACH_HINT.to_owned(),
        secret_location: SecretLocation::PrivateIntegrationState,
        unexport: unexported_variables(),
    })
}

/// Returns the bootstrap variables a completed handshake removes from the exported environment.
#[must_use]
pub fn unexported_variables() -> Vec<String> {
    BOOTSTRAP_VARIABLES
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

fn refuse(reason: QualificationReason, message: impl Into<String>) -> HandshakeOutcome {
    HandshakeOutcome::Refused(BridgeRefused::new(reason, message))
}

fn unqualified_message(reason: QualificationReason, hello: &BridgeHello) -> String {
    use QualificationReason as Reason;

    match reason {
        Reason::UnqualifiedMailbox => format!(
            "{} cannot carry a fenced request to the reader",
            hello.abi.mailbox.as_str()
        ),
        Reason::MailboxNotForShell => format!(
            "{} is another reader's mailbox; the {} package implements {}",
            hello.abi.mailbox.as_str(),
            hello.shell.kind.as_str(),
            crate::contract::qualification::MailboxMechanism::for_shell(hello.shell.kind).as_str()
        ),
        Reason::KeyBindingPreEof => {
            "the end-of-file decision must come from the reader's own hook, not a key binding"
                .to_owned()
        }
        Reason::PreEofNotForShell => format!(
            "{} is another reader's mechanism; the {} package takes the decision through {}",
            hello.abi.pre_eof.as_str(),
            hello.shell.kind.as_str(),
            crate::contract::qualification::PreEofMechanism::for_shell(hello.shell.kind).as_str()
        ),
        Reason::UnprovableFence => format!(
            "{} cannot prove a delivery fence: {}",
            hello.abi.fence_proof.as_str(),
            hello.abi.fence_proof.shortfall()
        ),
        Reason::NoCancellationPath => {
            "a takeover needs a cancellation that preserves the edit buffer".to_owned()
        }
        Reason::KeyInjectionForbidden => {
            "a launch is installed through the reader's mailbox; writing a private key into the \
             terminal is not a fallback"
                .to_owned()
        }
        _ => reason.as_str().to_owned(),
    }
}

/// The bytes a proof over the bootstrap secret covers.
///
/// `CBOR(["kr-shell-bridge/1", session_id, endpoint, shell_process, integration_version])`, and the
/// proof is HMAC-SHA-256 over it under the bootstrap secret. Binding the endpoint and the shell's
/// own process identity is what stops a proof taken in one session being replayed in another, or by
/// another process of the same user.
///
/// # Errors
///
/// Returns a [`CborError`] only when the transcript cannot be encoded canonically, which would mean
/// one of its fields is malformed rather than a runtime condition.
pub fn bootstrap_transcript(
    session_id: SessionId,
    endpoint: &BridgeEndpoint,
    shell_process: &ProcessStartIdentity,
    integration_version: &str,
) -> Result<Vec<u8>, CborError> {
    kr_cbor::to_canonical_vec(&(
        BRIDGE_PROTOCOL,
        session_id,
        &endpoint.path,
        shell_process,
        integration_version,
    ))
}

/// One frame on the bridge endpoint.
///
/// The union is closed and each side refuses the variants its role does not send: a bridge never
/// sends a [`Self::Request`], and a worker never sends a [`Self::Event`]. A frame that does not
/// belong on this endpoint ends the connection rather than being ignored, because a bridge that
/// misunderstands the direction of this contract cannot be trusted with the fence.
///
/// Every exchange is correlated by an identifier the sender allocates on its own side of the
/// connection, so an answer belongs to its question rather than to whatever is currently in flight.
/// Bridge events are answered too: a detach the worker refuses is how the bridge learns to consume
/// the gesture and print the hint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeFrame {
    /// Bridge to worker: the opening frame.
    Hello(BridgeHello),
    /// Worker to bridge: the answer to the opening frame.
    Handshake(HandshakeOutcome),
    /// Bridge to worker: something the reader did.
    Event {
        /// The bridge's own identifier for this event.
        id: RequestId,
        /// What happened.
        event: BridgeEvent,
    },
    /// Worker to bridge: the answer to one event.
    EventResult {
        /// The event being answered.
        id: RequestId,
        /// The answer.
        result: EventOutcome,
    },
    /// Worker to bridge: something the reader thread must decide.
    Request {
        /// The worker's own identifier for this request.
        id: RequestId,
        /// What to decide.
        request: WorkerRequest,
    },
    /// Bridge to worker: the reader thread's answer to one request.
    Answer {
        /// The request being answered.
        id: RequestId,
        /// The answer.
        answer: BridgeAnswer,
    },
    /// Worker to bridge: whether a fence was published, which the bridge cannot infer from having
    /// acknowledged one.
    FencePublished(FencePublication),
    /// Worker to bridge: the launch transaction is over, and nothing may be installed for it.
    ///
    /// The reader is bound by the same 250 ms as the worker, so this is a belt on top of the
    /// reader's own deadline check rather than the only thing stopping a late installation.
    LaunchRevoked {
        /// The transaction.
        transaction: LaunchTransactionId,
        /// Why it ended.
        reason: LaunchRejectionReason,
    },
}

/// What the worker answers one bridge event with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    /// The answer to `root.editor.enter`.
    EditorEntered(RootEditorEnterResult),
    /// The answer to `root.editor.leave`.
    EditorLeft(RootEditorLeaveResult),
    /// The answer to an accepted `root.eof.detach`.
    Detached(RootEofDetachResult),
    /// The answer to `root.command.accepted`.
    CommandRecorded(RootCommandAcceptedResult),
    /// The answer to `root.command.resolve`: what to run, and the backend established for it.
    CommandResolved(Box<kr_protocol::root::RootCommandResolveResult>),
    /// The answer to `root.command.block`.
    CommandBlockRecorded(kr_protocol::root::RootCommandBlockResult),
    /// The event was received and needs no answer of its own: an idle report, a gesture change or a
    /// consumed gesture.
    Received,
    /// The event was refused, with the error the session reports.
    ///
    /// A refused detach is the one every bridge must handle: the gesture has already been taken
    /// from the reader, so the bridge consumes it and prints the hint, at most once per prompt.
    Refused(ProtocolError),
}

#[cfg(test)]
mod tests {
    use kr_protocol::identity::ProcessStartSource;
    use kr_protocol::scalars::Uuid;

    use super::*;
    use crate::contract::qualification::{FenceProofMechanism, LaunchDelivery};

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([0x11; 16]))
    }

    fn root() -> ProcessStartIdentity {
        ProcessStartIdentity::new(4242, ProcessStartSource::MacosProcBsdInfo, 900)
    }

    fn expectation() -> WorkerExpectation {
        WorkerExpectation {
            session_id: session(),
            root_process: root(),
            supported_editor_abis: vec!["zle-5.9".to_owned()],
            supported_integration_versions: vec!["1".to_owned()],
            already_registered: false,
            gesture: EofGesture::default(),
        }
    }

    fn hello() -> BridgeHello {
        BridgeHello {
            protocol: BRIDGE_PROTOCOL.to_owned(),
            session_id: session(),
            shell_process: root(),
            shell: ShellIdentity {
                kind: ShellKind::Zsh,
                executable: "/opt/kalareach/shells/zsh-5.9/bin/zsh".to_owned(),
                upstream_version: "5.9".to_owned(),
                editor_abi: "zle-5.9".to_owned(),
                integration_version: "1".to_owned(),
                patches: vec![PatchRevision {
                    name: "zle-reader-mailbox".to_owned(),
                    upstream_revision: "zsh-5.9".to_owned(),
                    revision: "1".to_owned(),
                }],
                modules: vec![ModuleEntry {
                    name: "zsh/kr-bridge".to_owned(),
                    search_path: "/opt/kalareach/shells/zsh-5.9/lib/zsh/5.9".to_owned(),
                    editor_abi: "zle-5.9".to_owned(),
                }],
            },
            abi: BridgeAbi::qualified(ShellKind::Zsh),
            proof: Bytes::new(vec![7; BOOTSTRAP_PROOF_LEN]),
        }
    }

    #[test]
    fn each_shells_wire_string_is_the_one_it_serialises_as() {
        for kind in ShellKind::ALL {
            let json = serde_json::to_string(kind).expect("a shell kind serialises");
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
        }
    }

    fn peer() -> ObservedPeer {
        ObservedPeer {
            uid: 501,
            process: Some(root()),
        }
    }

    #[test]
    fn a_qualified_root_shell_is_accepted() {
        let outcome = decide_handshake(&expectation(), &peer(), &hello(), ProofVerdict::Verified);
        let HandshakeOutcome::Accepted(accepted) = outcome else {
            panic!("a qualified root shell registers");
        };
        assert_eq!(accepted.protocol, BRIDGE_PROTOCOL);
        assert_eq!(accepted.hold_ms.get(), 250);
        assert_eq!(
            accepted.secret_location,
            SecretLocation::PrivateIntegrationState
        );
        assert_eq!(
            accepted.unexport,
            vec![
                "KR_SHELL_BRIDGE".to_owned(),
                "KR_SHELL_BRIDGE_SECRET".to_owned()
            ]
        );
        assert_eq!(accepted.hint, DETACH_HINT);
    }

    #[test]
    fn a_child_shell_is_refused_before_its_declaration_is_read() {
        let child_identity =
            ProcessStartIdentity::new(4243, ProcessStartSource::MacosProcBsdInfo, 901);
        let child_peer = ObservedPeer {
            uid: 501,
            process: Some(child_identity.clone()),
        };
        let declares_itself = BridgeHello {
            shell_process: child_identity,
            abi: BridgeAbi {
                fence_proof: FenceProofMechanism::PromptHook,
                ..BridgeAbi::qualified(ShellKind::Zsh)
            },
            ..hello()
        };
        let outcome = decide_handshake(
            &expectation(),
            &child_peer,
            &declares_itself,
            ProofVerdict::Verified,
        );
        assert_eq!(
            outcome.refusal(),
            Some(QualificationReason::ProcessMismatch)
        );
        // A child that names its parent's identity and computes the matching proof is still not its
        // parent: the kernel's view of the connection decides.
        let claims_its_parent = decide_handshake(
            &expectation(),
            &child_peer,
            &hello(),
            ProofVerdict::Verified,
        );
        assert_eq!(
            claims_its_parent.refusal(),
            Some(QualificationReason::ProcessMismatch)
        );
        // A platform that cannot say who is calling is no basis for registering anything.
        let unidentified = decide_handshake(
            &expectation(),
            &ObservedPeer {
                uid: 501,
                process: None,
            },
            &hello(),
            ProofVerdict::Verified,
        );
        assert_eq!(
            unidentified.refusal(),
            Some(QualificationReason::PeerUnidentified)
        );
    }

    #[test]
    fn a_child_shell_has_nothing_to_activate_from() {
        assert_eq!(
            decide_activation(&ActivationInputs {
                exported_endpoint: None,
                exported_secret: false,
            }),
            Activation::Skip(SkipReason::NoEndpoint)
        );
        assert_eq!(
            decide_activation(&ActivationInputs {
                exported_endpoint: Some("/tmp/kalareach/s/shell-bridge".to_owned()),
                exported_secret: false,
            }),
            Activation::Skip(SkipReason::NoSecret)
        );
        assert_eq!(
            decide_activation(&ActivationInputs {
                exported_endpoint: Some("/tmp/kalareach/s/shell-bridge".to_owned()),
                exported_secret: true,
            }),
            Activation::Attempt
        );
    }

    #[test]
    fn the_secret_leaves_the_environment_with_the_endpoint() {
        let bootstrap = Bootstrap {
            endpoint: BridgeEndpoint::unix("/tmp/kalareach/s/shell-bridge"),
            secret: Bytes::new(vec![3; BOOTSTRAP_SECRET_LEN]),
        };
        let exported = bootstrap.exported_variables();
        assert_eq!(exported.len(), 2);
        assert_eq!(exported[0].0, ENDPOINT_VARIABLE);
        assert_eq!(exported[1].0, SECRET_VARIABLE);
        let retained = bootstrap.retain_after_handshake();
        assert_eq!(
            retained.secret_location,
            SecretLocation::PrivateIntegrationState
        );
        assert_eq!(retained.unexported, unexported_variables());
    }

    #[test]
    fn a_key_injecting_bridge_is_refused_rather_than_reduced() {
        let injecting = BridgeHello {
            abi: BridgeAbi {
                launch_delivery: LaunchDelivery::PseudoTerminalKeyInjection,
                ..BridgeAbi::qualified(ShellKind::Zsh)
            },
            ..hello()
        };
        let outcome = decide_handshake(&expectation(), &peer(), &injecting, ProofVerdict::Verified);
        assert_eq!(
            outcome.refusal(),
            Some(QualificationReason::KeyInjectionForbidden)
        );
        let HandshakeOutcome::Refused(refused) = outcome else {
            panic!("refused");
        };
        assert_eq!(refused.code(), ErrorCode::ShellIntegrationUnsupported);
    }

    #[test]
    fn an_endpoint_path_must_fit_the_tightest_platforms_socket_address() {
        assert_eq!(
            BridgeEndpoint::unix("/tmp/kalareach/s/shell-bridge").validate(),
            Ok(())
        );
        assert_eq!(
            BridgeEndpoint::unix("kalareach/s/shell-bridge").validate(),
            Err(EndpointFault::Relative)
        );
        assert_eq!(
            BridgeEndpoint::unix("").validate(),
            Err(EndpointFault::Empty)
        );
        let long = format!("/tmp/{}", "b".repeat(MAX_ENDPOINT_PATH_LEN));
        assert!(matches!(
            BridgeEndpoint::unix(long).validate(),
            Err(EndpointFault::TooLong { .. })
        ));
        assert_eq!(
            BridgeEndpoint::windows_pipe(r"\\.\pipe\kalareach-shell-bridge").validate(),
            Ok(())
        );
        assert_eq!(
            BridgeEndpoint::windows_pipe("kalareach-shell-bridge").validate(),
            Err(EndpointFault::NotAPipe)
        );
    }

    #[test]
    fn the_transcript_binds_the_session_the_endpoint_and_the_process() {
        let endpoint = BridgeEndpoint::unix("/tmp/kalareach/s/shell-bridge");
        let mine = bootstrap_transcript(session(), &endpoint, &root(), "1").expect("encodes");
        let other_session = bootstrap_transcript(
            SessionId::new(Uuid::from_bytes([0x22; 16])),
            &endpoint,
            &root(),
            "1",
        )
        .expect("encodes");
        let other_endpoint = bootstrap_transcript(
            session(),
            &BridgeEndpoint::unix("/tmp/kalareach/t/shell-bridge"),
            &root(),
            "1",
        )
        .expect("encodes");
        let other_process = bootstrap_transcript(
            session(),
            &endpoint,
            &ProcessStartIdentity::new(4243, ProcessStartSource::MacosProcBsdInfo, 901),
            "1",
        )
        .expect("encodes");
        assert_ne!(mine, other_session);
        assert_ne!(mine, other_endpoint);
        assert_ne!(mine, other_process);
    }

    #[test]
    fn the_bridge_frame_round_trips_through_the_canonical_encoding() {
        let frame = BridgeFrame::Hello(hello());
        let bytes = kr_cbor::to_canonical_vec(&frame).expect("encodes");
        let decoded: BridgeFrame =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(decoded, frame);
    }
}
