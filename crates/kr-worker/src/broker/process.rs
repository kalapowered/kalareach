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

    /// Returns a second holder of the same credential, inside the broker.
    ///
    /// A backend that authenticates its launch before the launch's record exists keeps one, and
    /// the record takes the other; a launch that is given back leaves the backend its own, so a
    /// retry of the same invocation still authenticates. It never leaves the broker.
    #[must_use]
    pub(crate) const fn duplicate(&self) -> Self {
        Self {
            secret: kr_crypto::secret::Secret::from_bytes(*self.secret.expose()),
        }
    }

    /// Writes the credential to a new owner-only file inside an owner-only directory.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnsupportedCapability`] on a platform without verifiable owner-only
    /// files, and [`BrokerError::LedgerUnavailable`] when the directory is not private or the file
    /// cannot be created or written.
    pub(crate) fn write_file(&self, path: &std::path::Path) -> Result<()> {
        if !ManagedProcess::publishes_credential_file() {
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
        let rendered = self.to_registration_bytes();
        // The rendering is a copy of the secret, and it is wiped when it is dropped at the end of
        // this function, because it is the host's own zeroising buffer.
        let written = kr_ipc::paths::create_new_owner_only_file(path, rendered.expose());
        written.map_err(|error| {
            BrokerError::ledger(format!(
                "could not write the credential file {}: {error}",
                path.display()
            ))
        })
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
    /// Unix and Windows do. On Unix the host reads back the owning user and the mode bits of the
    /// directory it writes into; on Windows it reads the directory's access-control list from an
    /// opened handle and refuses a list that names an account the host does not trust, so on both
    /// "no other account can read this" is a fact rather than a hope. A platform that can do
    /// neither is refused before anything starts, and [`crate::broker::NativeGateway::launch`] asks
    /// this first.
    #[must_use]
    pub const fn publishes_credential_file() -> bool {
        cfg!(any(unix, windows))
    }

    /// Returns why this platform's command backends do not run, or nothing where they do: an
    /// integrated invocation is given a backend before it starts, and its launcher reaches it.
    ///
    /// It is a fact about the platform apart from [`Self::publishes_credential_file`]: a platform
    /// can prove a file closed to other accounts and still have no launcher that reaches a backend.
    /// Unix runs them. Windows runs them where the kernel's record of when a process started can be
    /// believed on this machine, which is what places a launcher and its program against the
    /// backend: on a machine whose record cannot be believed no launch is admitted. The reason is
    /// one fixed sentence, which the daemon's doctor can state as its own; what the record did is
    /// in [`crate::windows::lineage::start_clock`]'s error. The doctor reads this to say whether an
    /// enabled integration can launch here, and why not.
    #[must_use]
    pub fn command_backends_failure() -> Option<&'static str> {
        #[cfg(windows)]
        {
            crate::windows::lineage::start_clock()
                .is_err()
                .then_some(START_RECORD_NOT_BELIEVED)
        }
        #[cfg(not(windows))]
        {
            (!cfg!(unix)).then_some("this platform has no command backend")
        }
    }

    /// Returns true when this platform's command backends run: see
    /// [`Self::command_backends_failure`].
    #[must_use]
    pub fn runs_command_backends() -> bool {
        Self::command_backends_failure().is_none()
    }

    /// Writes the registration file the launched process reads its credential from.
    ///
    /// The host's own owner-only publication is what writes it: the contents are complete before
    /// the name exists, and the create refuses to replace a name already there, so a file another
    /// writer planted is never written into and never read as though this host had written it.
    ///
    /// The directory it goes in is checked first ([`check_private_directory`]), and a platform that
    /// cannot establish that a file holding a secret is closed to other accounts refuses the
    /// publication instead of writing it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnsupportedCapability`] on a platform without verifiable owner-only
    /// files, and [`BrokerError::LedgerUnavailable`] when the directory is not private or the file
    /// cannot be created or written.
    pub fn write_registration(&self, path: &std::path::Path) -> Result<()> {
        self.credential.write_file(path)
    }
}

/// Checks that a directory is the owning user's and closed to everybody else.
///
/// On Unix that is the owning user and the mode bits. On Windows it is the directory's own
/// access-control list, read from the opened directory and not from its name: the list must be
/// protected, so nothing above it widens it, and must name no account the machine does not already
/// trust. A directory that is itself a link is refused, whatever it points at.
///
/// # Errors
///
/// Returns [`BrokerError::LedgerUnavailable`] when the directory cannot be read, is not a
/// directory, or is open to another account.
pub fn check_private_directory(directory: &std::path::Path) -> Result<()> {
    #[cfg(windows)]
    {
        check_private_directory_list(directory)
    }
    #[cfg(not(windows))]
    {
        check_private_directory_mode(directory)
    }
}

/// The Windows check of [`check_private_directory`].
#[cfg(windows)]
fn check_private_directory_list(directory: &std::path::Path) -> Result<()> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::windows::io::AsHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let unreadable = |error: std::io::Error| {
        BrokerError::ledger(format!(
            "could not read the registration directory {}: {error}",
            directory.display()
        ))
    };
    // A directory has no data to read, and Windows will not open one without the backup semantics
    // that say so. A link is opened as the link itself and refused by its attributes below, so what
    // the list is read from is the directory that was named and not whatever it points at.
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory)
        .map_err(unreadable)?;
    let attributes = opened.metadata().map_err(unreadable)?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(BrokerError::ledger(format!(
            "{} is a link, so it is not the directory it names",
            directory.display()
        )));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(BrokerError::ledger(format!(
            "{} is not a directory",
            directory.display()
        )));
    }
    kr_ipc::paths::check_access_list(opened.as_handle(), &directory.display().to_string(), true)
        .map_err(|refusal| match refusal {
            kr_ipc::paths::AccessListRefusal::Policy(detail)
            | kr_ipc::paths::AccessListRefusal::Unreadable(detail) => BrokerError::ledger(format!(
                "{} is not owner-only: {detail}",
                directory.display()
            )),
        })
}

/// The check of [`check_private_directory`] where the platform has owners and mode bits.
#[cfg(not(windows))]
fn check_private_directory_mode(directory: &std::path::Path) -> Result<()> {
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
    fn unix_and_windows_run_command_backends_and_publish_a_credential_file() {
        assert!(ManagedProcess::runs_command_backends());
        assert!(ManagedProcess::publishes_credential_file());
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

    /// A credential is written only into a directory the host can show is private: an ordinary
    /// directory takes none, and one the host made takes it as a file it can read back.
    #[test]
    fn a_credential_is_never_written_where_its_protection_cannot_be_proved() {
        assert!(ManagedProcess::publishes_credential_file());
        let ordinary = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&ordinary).expect("the directory is created");
        let managed = managed(Credential::from_bytes([9; CREDENTIAL_BYTES]));
        assert!(
            managed
                .write_registration(&ordinary.join("registration"))
                .is_err()
        );
        assert!(!ordinary.join("registration").exists());

        let private = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
        kr_ipc::paths::create_private_directory(&private).expect("a private directory is made");
        managed
            .write_registration(&private.join("registration"))
            .expect("a directory the host made takes it");
        let _ = std::fs::remove_dir_all(&ordinary);
        let _ = std::fs::remove_dir_all(&private);
    }

    /// A job that answers from a script, so that a query or a termination can fail where the
    /// operating system will not fail on request.
    struct Scripted {
        listings: std::sync::Mutex<std::collections::VecDeque<std::io::Result<Vec<u32>>>>,
        terminated: std::sync::atomic::AtomicBool,
        terminates: bool,
    }

    impl Scripted {
        fn new(listings: Vec<std::io::Result<Vec<u32>>>, terminates: bool) -> Self {
            Self {
                listings: std::sync::Mutex::new(listings.into()),
                terminated: std::sync::atomic::AtomicBool::new(false),
                terminates,
            }
        }

        /// The next answer; the last one is the answer from then on.
        fn list(&self) -> std::io::Result<Vec<u32>> {
            let mut listings = self.listings.lock().expect("the script");
            let next = if listings.len() > 1 {
                listings.pop_front().expect("an answer")
            } else {
                match listings.front().expect("an answer") {
                    Ok(held) => Ok(held.clone()),
                    Err(error) => Err(std::io::Error::new(error.kind(), error.to_string())),
                }
            };
            if self.terminated.load(std::sync::atomic::Ordering::SeqCst) && self.terminates {
                return Ok(Vec::new());
            }
            next
        }

        fn terminate(&self) -> std::io::Result<()> {
            self.terminated
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if self.terminates {
                Ok(())
            } else {
                Err(std::io::Error::other("the job would not end"))
            }
        }
    }

    async fn followed(job: &Scripted) -> BackendStop {
        follow_job(
            || job.list(),
            || job.terminate(),
            || {},
            std::time::Duration::from_secs(1),
        )
        .await
    }

    /// KR-REQ-07.67: a stop whose query of the job failed at any point is not reported complete,
    /// even when a later query answered that the job is empty. Control: the same stop with every
    /// query answered is complete.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_67_a_job_query_that_failed_leaves_the_stop_unresolved() {
        let answered = Scripted::new(vec![Ok(vec![7]), Ok(Vec::new())], true);
        let stop = followed(&answered).await;
        assert!(stop.asked && stop.ended && !stop.forced);
        assert!(!stop.unresolved, "every query answered, so it is complete");
        let failed = Scripted::new(
            vec![
                Err(std::io::Error::other("the job would not say")),
                Ok(Vec::new()),
            ],
            true,
        );
        let stop = followed(&failed).await;
        assert!(stop.ended, "the job listed nothing in the end");
        assert!(
            stop.unresolved,
            "a query failed on the way, so it is not complete"
        );
    }

    /// KR-REQ-07.67: a termination that failed and left the job holding something is unresolved.
    /// Control: a termination that worked ends the job and the stop is complete.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_67_a_termination_that_failed_leaves_the_stop_unresolved() {
        let works = Scripted::new(vec![Ok(vec![7])], true);
        let stop = followed(&works).await;
        assert!(stop.forced && stop.ended && !stop.unresolved);
        let fails = Scripted::new(vec![Ok(vec![7])], false);
        let stop = followed(&fails).await;
        assert!(
            stop.forced && !stop.ended,
            "the job still holds what it held"
        );
        assert!(stop.unresolved);
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

/// Why a Windows machine runs no command backend: the kernel's record of when a process started is
/// what places a launcher and its program, and it cannot be believed here.
#[cfg(windows)]
const START_RECORD_NOT_BELIEVED: &str =
    "the kernel's record of when a process started cannot be believed on this machine";

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
///
/// On Windows a backend this host started is held by a job, and that job is what is stopped: its
/// input is closed, which is how the agent is told to finish, the grace period is given to
/// everything the job holds, and then the job is terminated. It is complete only when the job lists
/// nothing, and an agent whose root has exited and whose helpers have not is not yet complete.
pub async fn stop_backend(
    process: &ProcessStartIdentity,
    grace: std::time::Duration,
) -> BackendStop {
    #[cfg(windows)]
    if let Some(stopper) = crate::windows::job::stopper(process) {
        return stop_held(stopper, grace).await;
    }
    stop_by_identity(process, grace).await
}

/// Stops the agent whose job and input are `stopper`, once, whoever asks.
///
/// The first caller does the stop while holding the record of it, and a concurrent caller waits for
/// the record and returns what the first found, so one agent is stopped by one owner and never
/// twice.
#[cfg(windows)]
async fn stop_held(
    stopper: crate::windows::job::Stopper,
    grace: std::time::Duration,
) -> BackendStop {
    let mut outcome = stopper.outcome.lock().await;
    if let Some(done) = *outcome {
        return done;
    }
    let done = stop_job(&stopper, grace).await;
    *outcome = Some(done);
    done
}

/// Closes the agent's input, waits the grace period for its job to empty, then terminates the job.
#[cfg(windows)]
async fn stop_job(
    stopper: &crate::windows::job::Stopper,
    grace: std::time::Duration,
) -> BackendStop {
    let closing = stopper.writer.clone();
    // Closing cancels a write that is blocked and takes the lock the write held, which waits, so it
    // is not done on the runtime's own threads.
    let close = move || {
        if let Some(writer) = closing {
            let _ = writer.close();
        }
    };
    follow_job(
        || stopper.job.process_ids(),
        || stopper.job.terminate(1),
        close,
        grace,
    )
    .await
}

/// Follows one job through a stop: what it holds is listed, the agent's input is closed, the grace
/// period is given to everything the job holds, and then the job is terminated.
///
/// The stop is complete only when the job lists nothing. What could not be established is never
/// reported as a stop: a query of the job that failed at any point leaves the stop unresolved, even
/// when a later one answered, and so does a termination that failed and left something in it.
#[cfg(any(windows, test))]
async fn follow_job(
    list: impl Fn() -> std::io::Result<Vec<u32>> + Sync,
    terminate: impl Fn() -> std::io::Result<()> + Sync,
    close: impl FnOnce() + Send + 'static,
    grace: std::time::Duration,
) -> BackendStop {
    let failed = std::sync::atomic::AtomicBool::new(false);
    let look = || {
        let listing = list();
        if listing.is_err() {
            failed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        listing
    };
    let failed_at_all = || failed.load(std::sync::atomic::Ordering::SeqCst);
    let emptied = |listing: &std::io::Result<Vec<u32>>| listing.as_ref().is_ok_and(Vec::is_empty);
    let first = look();
    let _ = tokio::task::spawn_blocking(close).await;
    if emptied(&first) {
        return BackendStop {
            asked: false,
            forced: false,
            ended: true,
            unresolved: failed_at_all(),
        };
    }
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        if emptied(&look()) {
            return BackendStop {
                asked: true,
                forced: false,
                ended: true,
                unresolved: failed_at_all(),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(BACKEND_POLL).await;
    }
    let terminated = terminate();
    // A termination is not instant either: the job is looked at until it is empty, within a bound.
    let confirm = tokio::time::Instant::now() + FORCED_CONFIRMATION;
    let listing = loop {
        let listing = look();
        if emptied(&listing) || tokio::time::Instant::now() >= confirm {
            break listing;
        }
        tokio::time::sleep(BACKEND_POLL).await;
    };
    let ended = emptied(&listing);
    BackendStop {
        asked: true,
        forced: true,
        ended,
        unresolved: failed_at_all() || (terminated.is_err() && !ended),
    }
}

/// Stops one process by its identity: asked, then forced once the grace period has passed.
async fn stop_by_identity(
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
