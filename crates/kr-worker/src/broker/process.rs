//! The processes the broker launched, their credentials and their immutable source frames.
//!
//! Section 11 gives the broker three things nothing else may hold.
//!
//! * **The processes.** A managed backend belongs to an `application_instance_id`. The broker
//!   tracks it by process identity, never by identifier alone, because a process identifier is
//!   reused within milliseconds of the original exiting.
//! * **The credentials.** "Credentials stay in the broker and never appear in component memory."
//!   [`Credential`] has no accessor that returns its bytes: it can authenticate a presented value
//!   and it can be written into an owner-only registration file, and that is all. A type that
//!   could hand its bytes to a caller would make the rule a convention.
//! * **The source frames.** A decoder reads immutable bytes with a generation and a digest. The
//!   generation advances whenever the bound execution owner changes, so a resource offered from an
//!   earlier execution's frame is refused rather than attributed to the current one.

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, SourceEventHandle, SourceGeneration};
use kr_protocol::scalars::{Digest256, TimestampMs};

use crate::broker::error::{BrokerError, Result};

/// Maximum bytes one source frame may carry.
///
/// A frame is one upstream message. Anything larger is a stream, and a stream does not become a
/// pending resource.
pub const MAX_SOURCE_FRAME_BYTES: usize = 1024 * 1024;

/// Length in bytes of a launch credential.
pub const CREDENTIAL_BYTES: usize = 32;

/// The alphabet a credential is rendered in.
const HEX: [u8; 16] = *b"0123456789abcdef";

/// A per-launch secret the broker holds.
///
/// It is generated once per launch, written into an owner-only registration file for the process
/// the broker is about to start, and used to authenticate that process when it connects.
///
/// What this type guarantees, exactly: there is no accessor that returns the bytes, `Debug`
/// redacts, the value leaves the broker only through [`ManagedProcess::write_registration`], and
/// the bytes live in the host's own zeroising secret buffer, so the wipe on drop is the one the
/// cryptography crate performs rather than ordinary stores an optimiser may remove.
pub struct Credential {
    secret: kr_crypto::secret::Secret<CREDENTIAL_BYTES>,
}

impl Credential {
    /// Generates a fresh credential.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the host has no key material, because a
    /// launch that cannot be authenticated is one the broker declines to make.
    pub fn generate() -> Result<Self> {
        let secret = kr_crypto::secret::Secret::random().map_err(|error| {
            BrokerError::ledger(format!("no key material for a launch credential: {error}"))
        })?;
        Ok(Self { secret })
    }

    /// Builds a credential from known bytes.
    ///
    /// This exists for the registration file the broker itself wrote and for tests. It is not a
    /// way to read one back out: the value goes in and nothing comes out.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CREDENTIAL_BYTES]) -> Self {
        Self {
            secret: kr_crypto::secret::Secret::from_bytes(bytes),
        }
    }

    /// Returns true when the presented value is this credential.
    ///
    /// The comparison is the host's own constant-time one, so how much of a wrong value was right
    /// is not something a caller can measure.
    #[must_use]
    pub fn authenticates(&self, presented: &[u8]) -> bool {
        presented.len() == CREDENTIAL_BYTES
            && kr_crypto::constant_time_eq(self.secret.expose(), presented)
    }

    /// Renders the credential for the registration file the launched process reads.
    ///
    /// Private on purpose: the value leaves the broker through the registration file and nowhere
    /// else. It never goes into an argument vector, an environment variable, a URL or a
    /// diagnostic. The rendering is bytes rather than a `String` so the caller can overwrite it.
    fn to_registration_bytes(&self) -> kr_crypto::secret::SecretVec {
        let mut rendered = Vec::with_capacity(CREDENTIAL_BYTES * 2);
        for byte in self.secret.expose() {
            rendered.push(HEX[usize::from(byte >> 4)]);
            rendered.push(HEX[usize::from(byte & 0x0f)]);
        }
        kr_crypto::secret::SecretVec::new(rendered)
    }

    /// Reads a credential back from its registration text.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the text is not exactly the right length of
    /// hexadecimal.
    pub fn from_registration_text(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.len() != CREDENTIAL_BYTES * 2 {
            return Err(BrokerError::invalid(
                "a launch credential is 64 hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; CREDENTIAL_BYTES];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let pair = text
                .get(index * 2..index * 2 + 2)
                .ok_or_else(|| BrokerError::invalid("a launch credential is hexadecimal"))?;
            *slot = u8::from_str_radix(pair, 16)
                .map_err(|_| BrokerError::invalid("a launch credential is hexadecimal"))?;
        }
        Ok(Self::from_bytes(bytes))
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Credential(<redacted>)")
    }
}

/// How the broker reaches one upstream.
///
/// Section 11 lists the supported transports and then fixes the rule that matters: "Transport
/// handles bind the selected executable, launch, upstream identity and environment; a plugin
/// cannot replace them with an arbitrary URL, process or filesystem path."
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BrokerTransport {
    /// Newline-delimited JSON over the process's own standard input and output.
    StdioJsonLines,
    /// A private Unix socket or Windows named pipe.
    PrivateSocket,
    /// Loopback HTTP.
    LoopbackHttp,
    /// A WebSocket over loopback.
    LoopbackWebSocket,
    /// Server-sent events over loopback.
    LoopbackServerSentEvents,
    /// A bounded byte stream for a custom framing.
    BoundedByteStream,
    /// An explicitly granted transcript tail.
    TranscriptTail,
}

impl BrokerTransport {
    /// Every transport, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::StdioJsonLines,
        Self::PrivateSocket,
        Self::LoopbackHttp,
        Self::LoopbackWebSocket,
        Self::LoopbackServerSentEvents,
        Self::BoundedByteStream,
        Self::TranscriptTail,
    ];

    /// Returns the stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StdioJsonLines => "stdio_json_lines",
            Self::PrivateSocket => "private_socket",
            Self::LoopbackHttp => "loopback_http",
            Self::LoopbackWebSocket => "loopback_websocket",
            Self::LoopbackServerSentEvents => "loopback_server_sent_events",
            Self::BoundedByteStream => "bounded_byte_stream",
            Self::TranscriptTail => "transcript_tail",
        }
    }

    /// Returns true when this transport can carry the qualified opaque forwarding path.
    ///
    /// A transcript tail cannot: it is read-only content, and forwarding needs a channel the host
    /// can write an answer back on.
    #[must_use]
    pub const fn carries_forwarding(self) -> bool {
        !matches!(self, Self::TranscriptTail)
    }
}

impl std::fmt::Display for BrokerTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A transport handle, bound to the launch it belongs to.
///
/// The three bindings are the whole point. A component that asked for "the connection" would be
/// asking for a channel it could then point anywhere; what it gets is a handle that already names
/// the executable, the process and the environment it reaches, and a handle is not something a
/// component can construct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportHandle {
    /// Which transport it is.
    pub transport: BrokerTransport,
    /// The application instance it reaches.
    pub application_instance_id: ApplicationInstanceId,
    /// The executable the launch resolved, by its digest.
    pub executable_digest: Digest256,
    /// The process the launch started.
    pub process: ProcessStartIdentity,
}

/// One upstream process the broker launched and owns.
#[derive(Debug)]
pub struct ManagedProcess {
    /// The instance the process is.
    pub application_instance_id: ApplicationInstanceId,
    /// Its process identity, checked in full on every ownership decision.
    pub process: ProcessStartIdentity,
    /// The handle the broker reaches it through.
    pub handle: TransportHandle,
    /// The credential the process authenticates with. It stays here.
    credential: Credential,
    /// True when this backend is dedicated to a native terminal this host started.
    ///
    /// Section 7: a native TUI's intentional exit ends the instance and stops its dedicated
    /// backend. A bypassed or shared backend is never claimed or terminated as owned.
    pub dedicated: bool,
    /// When the broker started it.
    pub started_at: TimestampMs,
}

impl ManagedProcess {
    /// Records a process the broker has launched.
    #[must_use]
    pub const fn new(
        application_instance_id: ApplicationInstanceId,
        process: ProcessStartIdentity,
        handle: TransportHandle,
        credential: Credential,
        dedicated: bool,
        started_at: TimestampMs,
    ) -> Self {
        Self {
            application_instance_id,
            process,
            handle,
            credential,
            dedicated,
            started_at,
        }
    }

    /// Returns true when the presented credential and process identity are this process's.
    ///
    /// Both are required. Section 11: authenticate "against the expected launch/process binding
    /// and private exchange, not an environment-variable session ID alone".
    #[must_use]
    pub fn authenticates(&self, presented: &[u8], process: &ProcessStartIdentity) -> bool {
        self.credential.authenticates(presented) && self.process.matches(process)
    }

    /// Returns true when the presented credential is this launch's private exchange.
    ///
    /// This is the private exchange alone, for a bridge the launched application started: its
    /// process is not this one, and the caller has already bound it to this one by the kernel's
    /// parent chain. Section 11 still wants both halves, and the caller checks the other.
    #[must_use]
    pub fn authenticates_exchange(&self, presented: &[u8]) -> bool {
        self.credential.authenticates(presented)
    }

    /// Returns true when this platform publishes the launch credential as a file.
    ///
    /// Unix does: the host can read back the owning user and the mode bits of the directory it
    /// wrote into, so "no other account can read this" is a fact rather than a hope. Windows has
    /// no mode bits, and the host's shared file publication does not yet install or verify a
    /// restricted access-control list, so the credential is not written to disk there.
    #[must_use]
    pub const fn publishes_credential_file() -> bool {
        cfg!(unix)
    }

    /// Writes the registration file the launched process reads its credential from.
    ///
    /// The host's own owner-only publication is what writes it: the contents are complete before
    /// the name exists, and the create refuses to replace a name already there, so a file another
    /// writer planted is never written into and never read as though this host had written it.
    ///
    /// **This is a Unix path, and it is refused everywhere else.** The parent directory is checked
    /// by its owning user and its mode bits, and a platform that cannot answer those questions
    /// cannot establish that a file holding a secret is closed to other accounts. Rather than
    /// write the credential into a file whose protection this host cannot verify, the publication
    /// is refused and the launch authenticates over the endpoint instead, whose access-control
    /// list the transport sets and whose peer credentials it checks. See
    /// [`ManagedProcess::publishes_credential_file`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnsupportedCapability`] on a platform without verifiable owner-only
    /// files, and [`BrokerError::LedgerUnavailable`] when the directory is not private or the file
    /// cannot be created or written.
    pub fn write_registration(&self, path: &std::path::Path) -> Result<()> {
        if !Self::publishes_credential_file() {
            return Err(BrokerError::UnsupportedCapability {
                detail: "this platform cannot prove a file is closed to other accounts, so the \
                         launch credential is not published as a file here"
                    .to_owned(),
            });
        }
        let directory = path
            .parent()
            .ok_or_else(|| BrokerError::ledger(format!("{} names no directory", path.display())))?;
        check_private_directory(directory)?;
        let rendered = self.credential.to_registration_bytes();
        // The rendering is a copy of the secret, and it is wiped when it is dropped at the end of
        // this function, because it is the host's own zeroising buffer.
        let written = kr_ipc::paths::create_new_owner_only_file(path, rendered.expose());
        written.map_err(|error| {
            BrokerError::ledger(format!(
                "could not write the registration file {}: {error}",
                path.display()
            ))
        })
    }
}

/// Checks that a directory is the owning user's and closed to everybody else.
///
/// # Errors
///
/// Returns [`BrokerError::LedgerUnavailable`] when the directory cannot be read, is not a
/// directory, or is open to another account.
pub fn check_private_directory(directory: &std::path::Path) -> Result<()> {
    let metadata = std::fs::metadata(directory).map_err(|error| {
        BrokerError::ledger(format!(
            "could not read the registration directory {}: {error}",
            directory.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(BrokerError::ledger(format!(
            "{} is not a directory",
            directory.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != kr_ipc::paths::current_uid() || mode & 0o077 != 0 {
            return Err(BrokerError::ledger(format!(
                "{} is not owner-only (uid {}, mode {mode:o})",
                directory.display(),
                metadata.uid()
            )));
        }
    }
    Ok(())
}

/// One immutable frame of upstream bytes.
///
/// The bytes are shared rather than copied per reader, and nothing that reads them can change
/// them: a decoder is given a handle and a slice, and two decoders reading the same frame read the
/// same bytes.
#[derive(Clone, Debug)]
pub struct SourceFrame {
    /// The handle a decoder names when it offers a resource from this frame.
    pub handle: SourceEventHandle,
    /// The generation this frame belongs to.
    pub generation: SourceGeneration,
    /// The digest of the bytes, so the original is identifiable after the frame has gone.
    pub digest: Digest256,
    /// The bytes themselves.
    bytes: std::sync::Arc<[u8]>,
    /// When the broker received them.
    pub received_at: TimestampMs,
}

impl SourceFrame {
    /// Records one frame of upstream bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the frame is larger than one message may be.
    pub fn new(
        handle: SourceEventHandle,
        generation: SourceGeneration,
        bytes: &[u8],
        received_at: TimestampMs,
    ) -> Result<Self> {
        if bytes.len() > MAX_SOURCE_FRAME_BYTES {
            return Err(BrokerError::invalid(format!(
                "a source frame is at most {MAX_SOURCE_FRAME_BYTES} bytes and this one is {}",
                bytes.len()
            )));
        }
        Ok(Self {
            handle,
            generation,
            digest: Digest256::from_bytes(kr_cbor::sha256(bytes)),
            bytes: bytes.into(),
            received_at,
        })
    }

    /// Returns the frame's bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::identity::ProcessStartSource;
    use kr_protocol::scalars::Uuid;

    fn process(pid: u64, start: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, start)
    }

    fn managed(credential: Credential) -> ManagedProcess {
        let instance = ApplicationInstanceId::new(Uuid::from_bytes([2; 16]));
        ManagedProcess::new(
            instance,
            process(41, 900),
            TransportHandle {
                transport: BrokerTransport::PrivateSocket,
                application_instance_id: instance,
                executable_digest: Digest256::from_bytes([3; 32]),
                process: process(41, 900),
            },
            credential,
            true,
            TimestampMs::new(1),
        )
    }

    #[test]
    fn a_credential_never_prints_itself() {
        let credential = Credential::from_bytes([9; CREDENTIAL_BYTES]);
        assert_eq!(format!("{credential:?}"), "Credential(<redacted>)");
    }

    #[test]
    fn a_registration_round_trip_is_the_only_way_a_credential_moves() {
        let credential = Credential::from_bytes([9; CREDENTIAL_BYTES]);
        let rendered = credential.to_registration_bytes();
        let text = std::str::from_utf8(rendered.expose()).expect("the rendering is ASCII");
        let read = Credential::from_registration_text(text).expect("the text is well formed");
        assert!(read.authenticates(&[9; CREDENTIAL_BYTES]));
        assert!(!read.authenticates(&[8; CREDENTIAL_BYTES]));
        assert!(!read.authenticates(&[9; 16]));
        assert!(Credential::from_registration_text("nonsense").is_err());
    }

    #[test]
    fn a_process_needs_its_credential_and_its_identity() {
        let managed = managed(Credential::from_bytes([9; CREDENTIAL_BYTES]));
        assert!(managed.authenticates(&[9; CREDENTIAL_BYTES], &process(41, 900)));
        // The right secret from the wrong process: a session identifier that leaked is not a
        // launch binding.
        assert!(!managed.authenticates(&[9; CREDENTIAL_BYTES], &process(42, 900)));
        // The same identifier, a different start time: a recycled process identifier.
        assert!(!managed.authenticates(&[9; CREDENTIAL_BYTES], &process(41, 901)));
        // The right process with the wrong secret.
        assert!(!managed.authenticates(&[8; CREDENTIAL_BYTES], &process(41, 900)));
    }

    // Unix only: a credential file is written only where its protection can be proved, which is
    // an owner-only directory; the case below is the other platforms'.
    #[cfg(unix)]
    #[test]
    fn a_registration_file_is_owner_only_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made private");
        let path = directory.join("registration");
        let managed = managed(Credential::from_bytes([9; CREDENTIAL_BYTES]));
        managed
            .write_registration(&path)
            .expect("the registration is written");
        let mode = std::fs::metadata(&path)
            .expect("the file is there")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(
            managed.write_registration(&path).is_err(),
            "a registration file another writer planted is never written into"
        );
        let open = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&open).expect("the directory is created");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755))
            .expect("the directory is made readable by others");
        assert!(
            managed
                .write_registration(&open.join("registration"))
                .is_err(),
            "a credential is never written into a directory other users can read"
        );
        let _ = std::fs::remove_dir_all(&open);
        let text = std::fs::read_to_string(&path).expect("the file reads");
        let read = Credential::from_registration_text(&text).expect("the text is well formed");
        assert!(read.authenticates(&[9; CREDENTIAL_BYTES]));
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_source_frame_is_immutable_and_bounded() {
        let frame = SourceFrame::new(
            SourceEventHandle::new("frame-1").expect("valid"),
            SourceGeneration::new(1),
            b"{\"method\":\"session/update\"}",
            TimestampMs::new(1),
        )
        .expect("the frame is recorded");
        let copy = frame.clone();
        assert_eq!(frame.bytes(), copy.bytes());
        assert_eq!(frame.digest, copy.digest);

        let oversized = vec![0_u8; MAX_SOURCE_FRAME_BYTES + 1];
        assert!(
            SourceFrame::new(
                SourceEventHandle::new("frame-2").expect("valid"),
                SourceGeneration::new(1),
                &oversized,
                TimestampMs::new(1),
            )
            .is_err()
        );
    }

    // Off Unix only: the case above is Unix's, and here no credential file is written at all.
    #[cfg(not(unix))]
    #[test]
    fn a_credential_is_never_written_where_its_protection_cannot_be_proved() {
        let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        let managed = managed(Credential::from_bytes([9; CREDENTIAL_BYTES]));
        assert!(!ManagedProcess::publishes_credential_file());
        assert!(
            managed
                .write_registration(&directory.join("registration"))
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_transcript_tail_cannot_carry_forwarding() {
        assert!(!BrokerTransport::TranscriptTail.carries_forwarding());
        for transport in BrokerTransport::ALL {
            if *transport != BrokerTransport::TranscriptTail {
                assert!(transport.carries_forwarding(), "{transport} should forward");
            }
        }
    }
}

/// How long a dedicated backend is given to stop before it is forced.
///
/// Section 7 makes the native TUI's intentional exit stop its dedicated backend "through the
/// normal grace period", and section 7's close sequence is where that period is defined.
pub const BACKEND_GRACE: std::time::Duration = crate::session::GRACE_PERIOD;

/// How often a stopping backend is looked at again.
const BACKEND_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// How long this host waits for the kernel to agree that a forced stop happened.
const FORCED_CONFIRMATION: std::time::Duration = std::time::Duration::from_secs(2);

/// What stopping one dedicated backend did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendStop {
    /// True when this host asked the process to stop.
    ///
    /// False means the identity named no running process: either it had already ended, or the
    /// identifier belongs to something else now, and section 7 stops what this host started rather
    /// than whatever holds that identifier.
    pub asked: bool,
    /// True when the grace period ended with the process still running, so it was forced.
    pub forced: bool,
    /// True when the kernel says the process this host started has gone.
    pub ended: bool,
    /// True when the kernel would not say whether it has gone.
    ///
    /// It is neither running nor known to have ended, and section 7 does not let this host report
    /// a shutdown it cannot establish.
    pub unresolved: bool,
}

/// Stops one dedicated backend through the normal grace period.
///
/// The identity is checked before anything is signalled and again before anything is forced,
/// because a bare process identifier can be reused and signalling a stranger is worse than leaving
/// a backend running.
pub async fn stop_backend(
    process: &ProcessStartIdentity,
    grace: std::time::Duration,
) -> BackendStop {
    let mut state = kr_ipc::identity::process_state(process);
    if !matches!(state, kr_ipc::identity::ProcessState::Running) {
        return settled(false, false, &state);
    }
    signal(process, false);
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        state = kr_ipc::identity::process_state(process);
        if !matches!(state, kr_ipc::identity::ProcessState::Running) {
            return settled(true, false, &state);
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(BACKEND_POLL).await;
    }
    signal(process, true);
    // A forced stop is not instant, and reading the state once the instant after it would report a
    // process still running as a shutdown that did not happen. This waits for the kernel to agree,
    // within a bound, and reports what it actually saw.
    let confirm = tokio::time::Instant::now() + FORCED_CONFIRMATION;
    loop {
        let state = kr_ipc::identity::process_state(process);
        if !matches!(state, kr_ipc::identity::ProcessState::Running)
            || tokio::time::Instant::now() >= confirm
        {
            return settled(true, true, &state);
        }
        tokio::time::sleep(BACKEND_POLL).await;
    }
}

/// Reads the last state this host saw as what it proves, and nothing more.
///
/// `Ended` is the kernel saying the process has gone. `Unknown` is the kernel saying it cannot
/// tell, which is not the same thing and is never recorded as one: a caller that read `ended` for
/// it would believe a backend had stopped on evidence nobody has.
fn settled(asked: bool, forced: bool, state: &kr_ipc::identity::ProcessState) -> BackendStop {
    BackendStop {
        asked,
        forced,
        ended: matches!(state, kr_ipc::identity::ProcessState::Ended),
        unresolved: matches!(state, kr_ipc::identity::ProcessState::Unknown { .. }),
    }
}

#[cfg(unix)]
fn signal(process: &ProcessStartIdentity, force: bool) {
    let signal = if force {
        rustix::process::Signal::KILL
    } else {
        rustix::process::Signal::TERM
    };
    let Ok(pid) = i32::try_from(process.pid.get()) else {
        return;
    };
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return;
    };
    let _ = rustix::process::kill_process(pid, signal);
}

#[cfg(not(unix))]
fn signal(_process: &ProcessStartIdentity, _force: bool) {
    // The job object this worker owns ends its processes when it is closed. Nothing here signals
    // one at a time, and section 12 keeps the Windows managed gateway unsupported until its own
    // protected exchange exists.
}
