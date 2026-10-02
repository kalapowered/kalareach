//! The local listener a launched agent reaches its worker-owned backend on.
//!
//! Section 12 fixes four properties, and this module is where each one is decided rather than
//! hoped for.
//!
//! * **It is private.** A Unix socket inside the owner-only runtime directory on Unix, and a named
//!   pipe that carries its owner's own access list on Windows. On both the kernel names the process
//!   at the other end. Either way the address is local: [`ListenerAddress::is_local`] is what the
//!   host checks before it publishes one, and nothing here can produce an address a relay could
//!   carry.
//! * **A browser cannot use it.** [`reject_browser_origin`] refuses a connection that arrives with
//!   any of the headers a browser adds. A page that guesses the address still cannot speak to it.
//! * **An unauthenticated request is refused.** [`Registration::authenticate`] wants the private
//!   exchange *and* the launch binding. Section 11 is explicit that an environment-variable
//!   session identifier alone is not authentication, so one is accepted as a hint and ignored as
//!   authority.
//! * **Credentials stay out of what people see.** The address a diagnostic prints carries none,
//!   and neither does an argument vector: the secret travels in an owner-only file the launched
//!   process opens, and the file's protection is read back from the opened file before it is
//!   trusted.
//!
//! And one property that belongs to a binding rather than to the listener: an installed upgrade
//! affects new launches. [`BoundBinary`] is pinned when a process starts, and
//! [`BoundBinary::identity_for`] is what says a running binding keeps the identity it was bound
//! to.

use kr_protocol::broker::BinaryIdentity;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, LaunchProfileId};

use crate::broker::endpoint::PeerIdentity;
use crate::broker::error::{BrokerError, Result};
use crate::broker::process::ManagedProcess;

/// The headers a browser adds, any one of which disqualifies a connection.
///
/// The list is deliberately generous: a header a browser sends and a native client does not is
/// evidence enough, and refusing a native client that invented one costs nothing.
pub const BROWSER_HEADERS: &[&str] = &[
    "origin",
    "referer",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-websocket-key",
    "access-control-request-method",
];

/// The longest name a launch's pipe may have, in characters.
pub const MAX_PIPE_NAME: usize = 64;

/// The prefix every local pipe's path has.
pub const PIPE_PREFIX: &str = r"\\.\pipe\";

/// Where the launched agent connects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerAddress {
    /// A socket file inside the owner-only runtime directory.
    ///
    /// The Unix endpoint, because the filesystem answers "who may connect" before any byte is
    /// read.
    PrivateSocket(std::path::PathBuf),
    /// A named pipe, by its one name inside the local pipe namespace.
    ///
    /// The Windows endpoint. The pipe carries its owner's own access list, so the operating system
    /// answers "who may connect" before any byte is read, and the kernel names the process on the
    /// other end. The name is a fresh random one for each launch.
    NamedPipe(String),
}

/// Returns true when `name` is one component of the local pipe namespace and nothing else.
///
/// Letters, digits, hyphens and underscores only: a separator or a dot segment could make the
/// published path reach a pipe on another machine or another place in the namespace.
#[must_use]
pub fn is_pipe_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PIPE_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

impl ListenerAddress {
    /// Returns true when this address can only be reached from this machine.
    ///
    /// Section 12: "Never expose the upstream listener directly through iroh." An address that is
    /// not local is one a relay could carry, so it is refused before it is published rather than
    /// filtered afterwards.
    #[must_use]
    pub fn is_local(&self) -> bool {
        match self {
            Self::PrivateSocket(path) => path.is_absolute(),
            Self::NamedPipe(name) => is_pipe_component(name),
        }
    }

    /// Returns the address as a diagnostic prints it, which is what the registration publishes.
    ///
    /// There is no credential in it, because there is no credential in the type. A reader of a
    /// diagnostic learns where the listener is and nothing about how to speak to it.
    #[must_use]
    pub fn for_diagnostics(&self) -> String {
        match self {
            Self::PrivateSocket(path) => path.display().to_string(),
            Self::NamedPipe(name) => format!("{PIPE_PREFIX}{name}"),
        }
    }

    /// Returns the address this platform uses for one launch.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the runtime directory is not an absolute
    /// path, and the refusal [`crate::broker::process::check_private_directory`] gives when it is
    /// not private.
    pub fn for_launch(runtime_directory: &std::path::Path) -> Result<Self> {
        if !runtime_directory.is_absolute() {
            return Err(BrokerError::invalid(
                "a launch's runtime directory is an absolute path",
            ));
        }
        // The directory holds the registration and the credential, and on Unix it also decides who
        // may connect, so it is checked before an address that depends on it is handed out.
        crate::broker::process::check_private_directory(runtime_directory)?;
        let fresh: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect();
        let address = if cfg!(unix) {
            // The name is short on purpose. A socket path has a small fixed bound on every Unix,
            // and a runtime directory a person chose can already be most of it, so the part this
            // host adds stays out of the way: enough of a fresh identifier not to collide, and no
            // more.
            Self::PrivateSocket(runtime_directory.join(format!("a-{}.sock", &fresh[..12])))
        } else {
            Self::NamedPipe(format!("kr-a-{fresh}"))
        };
        debug_assert!(address.is_local());
        Ok(address)
    }

    /// Refuses an address this host will not publish.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the address is one something other than this
    /// machine could reach. Section 12: the upstream listener is never exposed through iroh, and
    /// the way to keep that true is to refuse the address rather than to filter the traffic.
    pub fn require_local(&self) -> Result<()> {
        if self.is_local() {
            Ok(())
        } else {
            Err(BrokerError::denied(format!(
                "{} is reachable from somewhere other than this machine",
                self.for_diagnostics()
            )))
        }
    }
}

/// Refuses a connection that carries anything a browser would have added.
///
/// # Errors
///
/// Returns [`BrokerError::PermissionDenied`] naming the header that disqualified it.
pub fn reject_browser_origin<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<()> {
    for (name, value) in headers {
        let lowered = name.to_ascii_lowercase();
        if BROWSER_HEADERS.contains(&lowered.as_str()) {
            return Err(BrokerError::denied(format!(
                "{name} is a header a browser adds, and this listener serves no browser (it read \
                 {value:?})"
            )));
        }
    }
    Ok(())
}

/// What a launched process is told, so it can find its backend.
///
/// The credential is deliberately absent. Section 11 asks for "a small registration file plus the
/// core `kr-hook` forwarder", and this is the small file: where to connect, which launch it
/// belongs to, and which process this host expects on the other end. The secret travels through
/// its own owner-only file, so a registration a person or a diagnostic reads carries nothing that
/// would let them speak to the listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// Where to connect.
    pub address: ListenerAddress,
    /// The launch profile this registration belongs to.
    pub profile_id: LaunchProfileId,
    /// The instance the connection will speak for.
    pub application_instance_id: ApplicationInstanceId,
    /// The process this host launched and expects on the other end.
    pub expected_process: ProcessStartIdentity,
    /// The owner-only file beside the registration that holds the launch's private exchange.
    ///
    /// The registration names it, so a launched process needs one variable, the registration's
    /// path, to find both: an application that scrubs its children's environment of anything
    /// named like a credential still passes that one on.
    pub credential: std::path::PathBuf,
}

/// What a connecting bridge presents.
///
/// `Debug` is written rather than derived, because the derived one would print the credential
/// byte by byte and a connection failure is exactly when something logs one of these.
pub struct BridgeHello {
    /// The credential it read from the registration.
    ///
    /// It lives in the host's own zeroising buffer, so it is wiped when the hello is dropped and
    /// there is no `Clone` to leave an ordinary copy behind.
    pub credential: kr_crypto::secret::SecretVec,
    /// The process it is.
    pub process: ProcessStartIdentity,
    /// A session identifier it found in its environment, if any.
    ///
    /// It is carried so a person debugging can see what the application thought it was, and it is
    /// never authority: section 11 says registration authenticates "against the expected
    /// launch/process binding and private exchange, not an environment-variable session ID
    /// alone".
    pub environment_session_id: Option<String>,
}

impl std::fmt::Debug for BridgeHello {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BridgeHello")
            .field("credential", &"<redacted>")
            .field("process", &self.process)
            .field("environment_session_id", &self.environment_session_id)
            .finish()
    }
}

impl Registration {
    /// Builds the registration for one launch.
    #[must_use]
    pub const fn new(
        address: ListenerAddress,
        profile_id: LaunchProfileId,
        application_instance_id: ApplicationInstanceId,
        expected_process: ProcessStartIdentity,
        credential: std::path::PathBuf,
    ) -> Self {
        Self {
            address,
            profile_id,
            application_instance_id,
            expected_process,
            credential,
        }
    }

    /// Authenticates the two halves a registration decides on its own: the owner and the process.
    ///
    /// The private exchange is deliberately not here. It lives in the broker's own record of the
    /// launch, and the admission that opens the connection checks it there, so the credential
    /// never has to be handed to whatever is accepting.
    ///
    /// Three things are checked and all three must hold: the connection came from this user, the
    /// process is the one this host launched, and the credential is the one this host generated
    /// for that launch. An environment session identifier is not one of the three.
    ///
    /// The first two come from [`PeerIdentity`], which only a bound endpoint produces, and the
    /// kernel names the process on every platform. That is the difference between deciding and
    /// knowing: a bridge that names somebody else's process is refused because the kernel named
    /// its own, not because it was asked to be honest.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] naming which of the checks failed.
    pub fn authenticate_peer(&self, hello: &BridgeHello, peer: &PeerIdentity) -> Result<()> {
        if !peer.is_owner() {
            return Err(BrokerError::denied(
                "this connection is not the operating-system user who owns the session",
            ));
        }
        let connecting = peer.process();
        if !connecting.matches(&hello.process) {
            return Err(BrokerError::denied(format!(
                "this connection says it is process {} and the operating system says it is \
                 process {}",
                hello.process.pid, connecting.pid
            )));
        }
        if !connecting.matches(&self.expected_process) {
            return Err(BrokerError::denied(format!(
                "this connection is process {} and the launch was process {}",
                connecting.pid, self.expected_process.pid
            )));
        }
        Ok(())
    }

    /// The same, and the private exchange as well, for a caller that holds the launch's record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] naming which of the three failed.
    pub fn authenticate(
        &self,
        hello: &BridgeHello,
        peer: &PeerIdentity,
        process: &ManagedProcess,
    ) -> Result<()> {
        if !peer.is_owner() {
            return Err(BrokerError::denied(
                "this connection is not the operating-system user who owns the session",
            ));
        }
        // The kernel's reading of the connecting process, which is what is compared with the
        // launch; the process the hello presents has to be the same one.
        let connecting = peer.process();
        if !connecting.matches(&hello.process) {
            return Err(BrokerError::denied(format!(
                "this connection says it is process {} and the operating system says it is \
                 process {}",
                hello.process.pid, connecting.pid
            )));
        }
        if !connecting.matches(&self.expected_process) {
            return Err(BrokerError::denied(format!(
                "this connection is process {} and the launch was process {}",
                connecting.pid, self.expected_process.pid
            )));
        }
        if !process.authenticates(hello.credential.expose(), connecting) {
            return Err(BrokerError::denied(
                "this connection did not present the private exchange of the launch it claims",
            ));
        }
        Ok(())
    }

    /// Authenticates a native bridge the launched application started, and validates it against
    /// the installation, before anything it sends is read.
    ///
    /// A bridge is not the process this host launched. The application starts it, once for a
    /// channel server and once for every hook, so the launch binding it proves is the one the
    /// broker places any helper by: the kernel's parent chain from the connecting process reaches
    /// the launched process, and every link is checked by its start identity, so an identifier
    /// recycled since the application started does not complete the chain. On Windows, where a
    /// recorded parent proves nothing, the job the launched process was started in must hold the
    /// connecting process instead. A chain or a job that could not be read admits nothing. The
    /// private exchange is checked where the launch's record lives, by the caller that holds it,
    /// exactly as [`Registration::authenticate_peer`] leaves it.
    ///
    /// Returns the process that started the bridge, as the first link of that chain names it, where
    /// the kernel can: hooks are ordered by when their starter started them.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] naming the first part that failed: the owner, the
    /// kernel's naming of the peer, the process the hello presents, the launch binding, or the
    /// installation.
    pub fn authenticate_bridge(
        &self,
        hello: &BridgeHello,
        peer: &PeerIdentity,
        installed: &crate::broker::bridge::InstalledBridge,
        declared: &crate::broker::bridge::BridgeDeclaration,
    ) -> Result<Option<ProcessStartIdentity>> {
        if !peer.is_owner() {
            return Err(BrokerError::denied(
                "this connection is not the operating-system user who owns the session",
            ));
        }
        // The process the hello presents is the one the kernel named, or the connection is
        // somebody speaking for a process it is not.
        let connecting = peer.process();
        if !connecting.matches(&hello.process) {
            return Err(BrokerError::denied(format!(
                "this connection says it is process {} and the operating system says it is \
                 process {}",
                hello.process.pid, connecting.pid
            )));
        }
        match crate::questions::binding::nearest_of(
            connecting,
            std::slice::from_ref(&self.expected_process),
        ) {
            crate::questions::binding::Ancestry::Reaches(_) => {}
            crate::questions::binding::Ancestry::ReachesNone => {
                return Err(BrokerError::denied(format!(
                    "process {} was not started by the application this host launched as process \
                     {}",
                    connecting.pid, self.expected_process.pid
                )));
            }
            crate::questions::binding::Ancestry::Undetermined(why) => {
                return Err(BrokerError::denied(format!(
                    "whether process {} was started by the application this host launched as \
                     process {} could not be established: {why}",
                    connecting.pid, self.expected_process.pid
                )));
            }
        }
        let running = u32::try_from(connecting.pid.get())
            .ok()
            .and_then(crate::questions::binding::executable_of)
            .map(std::path::PathBuf::from);
        installed.validate(declared, running.as_deref())?;
        Ok(crate::questions::binding::parent_of(connecting))
    }

    /// Renders the registration as the file a launched process reads.
    ///
    /// One `name=value` line each, so the `kr-hook` forwarder can read it without a parser. There
    /// is nothing secret in it: the credential line names the file the secret is in.
    ///
    /// A worker of an installed release adds a `release` line naming it: an application's own
    /// settings may start the forwarder an update has made current since this worker started, and
    /// that forwarder reads which release the session it serves runs.
    #[must_use]
    pub fn to_file(&self) -> String {
        let release = kr_ipc::install::this_process()
            .ok()
            .and_then(kr_ipc::install::Running::release);
        self.to_file_of(release)
    }

    /// Renders the registration as [`Self::to_file`] does, for a worker of `release`.
    fn to_file_of(&self, release: Option<&kr_protocol::update::ReleaseName>) -> String {
        let mut file = format!(
            "endpoint={}\nprofile={}\ninstance={}\npid={}\nstart={}\ncredential={}\n",
            self.address.for_diagnostics(),
            self.profile_id,
            self.application_instance_id,
            self.expected_process.pid,
            self.expected_process.start_value,
            self.credential.display(),
        );
        if let Some(release) = release {
            file.push_str(&format!("release={release}\n"));
        }
        file
    }
}

/// The binary one live binding is bound to.
///
/// Section 12: "An agent executable upgrade affects new launches; existing bindings retain their
/// original binary identity, schema and adapter version." The identity is pinned here when the
/// process starts, and nothing that happens on disk afterwards changes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundBinary {
    /// The identity resolved when the process started.
    pub pinned: BinaryIdentity,
    /// The process it belongs to.
    pub process: ProcessStartIdentity,
}

impl BoundBinary {
    /// Pins one binding to the binary its process started from.
    #[must_use]
    pub const fn pin(pinned: BinaryIdentity, process: ProcessStartIdentity) -> Self {
        Self { pinned, process }
    }

    /// Returns the identity this binding acts under, whatever is on disk now.
    ///
    /// The whole of section 12's rule is that this returns the pinned identity and not the
    /// installed one. It takes the installed identity so that a caller cannot accidentally ask a
    /// different question, and returns the pinned one so the answer is the rule.
    #[must_use]
    pub fn identity_for(&self, installed: &BinaryIdentity) -> &BinaryIdentity {
        let _ = installed;
        &self.pinned
    }

    /// Returns true when an installed upgrade has moved on from what this binding is bound to.
    ///
    /// It is a fact about the world rather than a permission: the binding keeps its identity
    /// either way, and this is what a diagnostic shows a person so they know why a running
    /// process reports an older version than the one on disk.
    #[must_use]
    pub fn differs_from_installed(&self, installed: &BinaryIdentity) -> bool {
        &self.pinned != installed
    }

    /// Returns the identity a *new* launch resolves.
    ///
    /// This is the other half of the same rule: an upgrade affects new launches, and it is the new
    /// launch that picks up what is on disk now.
    #[must_use]
    pub fn for_new_launch(installed: &BinaryIdentity) -> BinaryIdentity {
        installed.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::process::{BrokerTransport, CREDENTIAL_BYTES, Credential, TransportHandle};
    use kr_protocol::identity::ProcessStartSource;
    use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};

    fn instance() -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
    }

    fn process(pid: u64, start: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, start)
    }

    fn managed(identity: ProcessStartIdentity) -> ManagedProcess {
        ManagedProcess::new(
            instance(),
            identity.clone(),
            TransportHandle {
                transport: BrokerTransport::PrivateSocket,
                application_instance_id: instance(),
                executable_digest: Digest256::from_bytes([3; 32]),
                process: identity,
            },
            Credential::from_bytes([9; CREDENTIAL_BYTES]),
            true,
            TimestampMs::new(1),
        )
    }

    /// The address a launch publishes on this platform: a private socket on Unix and a named pipe
    /// on Windows.
    fn launch_address() -> ListenerAddress {
        if cfg!(unix) {
            ListenerAddress::PrivateSocket("/run/kr/agent-1.sock".into())
        } else {
            ListenerAddress::NamedPipe("kr-a-0123456789abcdef".to_owned())
        }
    }

    /// The peer the endpoint reports for a connection from `process`, built here so the unit tests
    /// can state it. The endpoint that actually reads one is the integration suite's.
    fn endpoint_peer(process: ProcessStartIdentity) -> PeerIdentity {
        PeerIdentity::from_kernel(process, true)
    }

    fn registration() -> Registration {
        Registration::new(
            launch_address(),
            LaunchProfileId::new("lp-1").expect("valid"),
            instance(),
            process(41, 900),
            std::path::PathBuf::from("/run/kr/a/credential"),
        )
    }

    fn hello() -> BridgeHello {
        BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(vec![9; CREDENTIAL_BYTES]),
            process: process(41, 900),
            environment_session_id: Some("KR_SESSION=abc".to_owned()),
        }
    }

    #[test]
    fn a_browser_is_refused_by_what_it_cannot_help_sending() {
        reject_browser_origin([("content-type", "application/json")])
            .expect("a native client's headers are fine");
        for header in BROWSER_HEADERS {
            let refusal = reject_browser_origin([(*header, "https://example.test")])
                .expect_err("a browser header disqualifies the connection");
            assert!(refusal.to_string().contains(header));
        }
        // The check is case-insensitive, because a header name is.
        assert!(reject_browser_origin([("Origin", "https://example.test")]).is_err());
    }

    #[test]
    fn an_environment_session_identifier_authenticates_nothing() {
        let registration = registration();
        let managed = managed(process(41, 900));
        registration
            .authenticate(&hello(), &endpoint_peer(process(41, 900)), &managed)
            .expect("the launch binding and the private exchange are both there");

        // The session identifier, and nothing else.
        let bare = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(Vec::new()),
            process: process(41, 900),
            environment_session_id: None,
        };
        assert!(
            registration
                .authenticate(&bare, &endpoint_peer(process(41, 900)), &managed)
                .is_err(),
            "an environment-variable session identifier is not authentication"
        );

        // The secret from the wrong process.
        let elsewhere = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(vec![9; CREDENTIAL_BYTES]),
            process: process(42, 900),
            environment_session_id: None,
        };
        assert!(
            registration
                .authenticate(&elsewhere, &endpoint_peer(process(42, 900)), &managed)
                .is_err()
        );

        // The right process from the wrong user.
        assert!(
            registration
                .authenticate(
                    &hello(),
                    &PeerIdentity::from_kernel(process(41, 900), false),
                    &managed
                )
                .is_err()
        );

        // A hello that presents another process than the one the kernel named, though the process
        // the kernel named is the launch: the connection is somebody speaking for a process it is
        // not.
        let speaking_for_another = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(vec![9; CREDENTIAL_BYTES]),
            process: process(42, 900),
            environment_session_id: None,
        };
        assert!(
            registration
                .authenticate(
                    &speaking_for_another,
                    &endpoint_peer(process(41, 900)),
                    &managed
                )
                .is_err(),
            "the process the hello presents is the one the kernel named"
        );
        assert!(
            registration
                .authenticate_peer(&speaking_for_another, &endpoint_peer(process(41, 900)))
                .is_err()
        );
        registration
            .authenticate_peer(&hello(), &endpoint_peer(process(41, 900)))
            .expect("the same hello from the process it names is admitted");

        // A recycled process identifier.
        let recycled = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(vec![9; CREDENTIAL_BYTES]),
            process: process(41, 901),
            environment_session_id: None,
        };
        assert!(
            registration
                .authenticate(&recycled, &endpoint_peer(process(41, 901)), &managed)
                .is_err()
        );
    }

    /// A worker of an installed release names it in every registration, on a line of its own, and
    /// one outside a store names none.
    #[test]
    fn a_registration_names_the_release_its_worker_runs() {
        let release =
            kr_protocol::update::ReleaseName::new("0.2.0+4254aa6e62e5").expect("a release");
        let file = registration().to_file_of(Some(&release));
        assert!(file.contains("\nrelease=0.2.0+4254aa6e62e5\n"), "{file}");
        assert_eq!(
            file.lines()
                .filter(|line| line.starts_with("release="))
                .count(),
            1
        );
        // The control: this test runs outside any store, so its own registration names none.
        assert!(!registration().to_file().contains("release="));
    }

    #[test]
    fn a_registration_carries_no_credential() {
        let file = registration().to_file();
        assert!(file.contains(&format!(
            "endpoint={}\n",
            launch_address().for_diagnostics()
        )));
        assert!(file.contains("pid=41"));
        assert!(
            file.contains("credential=/run/kr/a/credential\n"),
            "it names the file the private exchange is in, beside it"
        );
        assert!(
            !file.contains("09"),
            "the registration a person reads carries nothing that speaks to the listener"
        );
        assert!(!file.to_ascii_lowercase().contains("secret"));
    }

    /// A pipe's name is one component of the local pipe namespace, and the published path is that
    /// namespace's prefix and the name, so nothing it names can be on another machine or anywhere
    /// else in the namespace.
    #[test]
    fn a_pipe_name_is_one_component_and_nothing_else() {
        let pipe = ListenerAddress::NamedPipe("kr-a-0123456789abcdef".to_owned());
        assert!(pipe.is_local());
        pipe.require_local().expect("a fresh name is local");
        assert_eq!(
            pipe.for_diagnostics(),
            r"\\.\pipe\kr-a-0123456789abcdef",
            "the registration names the pipe by its path"
        );
        assert!(
            !pipe.for_diagnostics().contains('@'),
            "a credential never travels in a URL"
        );
        for refused in [
            "",
            ".",
            "..",
            "a.b",
            r"a\b",
            "a/b",
            r"\\host\pipe\x",
            r"..\x",
            "a b",
            "a:b",
            "é",
            &"x".repeat(MAX_PIPE_NAME + 1),
        ] {
            let address = ListenerAddress::NamedPipe(refused.to_owned());
            assert!(
                !address.is_local(),
                "{refused:?} is not one local component"
            );
            assert!(address.require_local().is_err());
        }
        assert!(ListenerAddress::NamedPipe("x".repeat(MAX_PIPE_NAME)).is_local());
    }

    // Unix only: a private socket is Unix's endpoint, and "/run/kr" is an absolute path only there.
    #[cfg(unix)]
    #[test]
    fn a_private_socket_is_local_only_at_an_absolute_path() {
        let socket = ListenerAddress::PrivateSocket("/run/kr/agent-1.sock".into());
        assert!(socket.is_local());
        assert_eq!(socket.for_diagnostics(), "/run/kr/agent-1.sock");
        let relative = ListenerAddress::PrivateSocket("agent.sock".into());
        assert!(!relative.is_local());
    }

    #[test]
    fn this_platform_binds_the_private_endpoint_it_has() {
        let directory = std::env::temp_dir().join(format!("kr-listener-{}", kr_ipc::new_uuid()));
        kr_ipc::paths::create_private_directory(&directory).expect("a private directory is made");
        let address = ListenerAddress::for_launch(&directory).expect("an address is chosen");
        address.require_local().expect("it is local");
        if cfg!(unix) {
            assert!(matches!(address, ListenerAddress::PrivateSocket(_)));
        } else {
            assert!(matches!(address, ListenerAddress::NamedPipe(_)));
        }
        let other = ListenerAddress::for_launch(&directory).expect("a second address is chosen");
        assert_ne!(address, other, "every launch names its own endpoint");

        // A directory other users can read is not one a launch's files go in.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let open = std::env::temp_dir().join(format!("kr-listener-{}", kr_ipc::new_uuid()));
            std::fs::create_dir_all(&open).expect("the directory is created");
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755))
                .expect("the directory is made readable by others");
            assert!(ListenerAddress::for_launch(&open).is_err());
            let _ = std::fs::remove_dir_all(&open);
        }
        assert!(
            ListenerAddress::for_launch(std::path::Path::new("relative")).is_err(),
            "a runtime directory is an absolute path"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_installed_upgrade_leaves_a_running_binding_where_it_was() {
        let original = BinaryIdentity {
            resolved_path: "/usr/local/bin/codex".to_owned(),
            digest: Digest256::from_bytes([3; 32]),
            version: "0.9.1".to_owned(),
            distribution: "homebrew".to_owned(),
        };
        let upgraded = BinaryIdentity {
            digest: Digest256::from_bytes([4; 32]),
            version: "0.9.2".to_owned(),
            ..original.clone()
        };
        let bound = BoundBinary::pin(original.clone(), process(41, 900));
        assert_eq!(
            bound.identity_for(&upgraded),
            &original,
            "a running binding keeps the identity it was bound to"
        );
        assert!(bound.differs_from_installed(&upgraded));
        assert!(!bound.differs_from_installed(&original));
        assert_eq!(
            BoundBinary::for_new_launch(&upgraded),
            upgraded,
            "and a new launch picks up what is on disk now"
        );
    }

    /// The installation this process stands in for: its own executable, both surfaces.
    // Unix only: the one case that uses it is.
    #[cfg(unix)]
    fn installed_here() -> crate::broker::bridge::InstalledBridge {
        crate::broker::bridge::InstalledBridge {
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/claude-code").expect("valid"),
            application: "claude-code".to_owned(),
            surfaces: [
                crate::broker::bridge::BridgeSurface::Hook,
                crate::broker::bridge::BridgeSurface::Channel,
            ]
            .into_iter()
            .collect(),
            forwarder: std::env::current_exe().expect("this test's executable"),
        }
    }

    // Unix only: the one case that uses it is.
    #[cfg(unix)]
    fn hook_declared() -> crate::broker::bridge::BridgeDeclaration {
        crate::broker::bridge::BridgeDeclaration {
            application: "claude-code".to_owned(),
            surface: crate::broker::bridge::BridgeSurface::Hook,
        }
    }

    /// KR-REQ-11.43, KR-REQ-05.09: a bridge is admitted when the kernel names it, it presents the
    /// process it is, the application this host launched started it, and it is the installation;
    /// each of those failing refuses it, and a session identifier changes none of them. The
    /// application here is this test's parent process, which started this one, and admission names
    /// it as the bridge's starter.
    // Unix only: a private socket is where the kernel names the connecting process.
    #[cfg(unix)]
    #[test]
    fn kr_req_11_43_a_bridge_is_admitted_by_its_launch_binding_and_installation() {
        let me = kr_ipc::identity::current_process_start_identity().expect("this process");
        let parent = kr_ipc::identity::process_start_identity(std::os::unix::process::parent_id())
            .expect("its parent");
        let launched = Registration::new(
            launch_address(),
            LaunchProfileId::new("lp-1").expect("valid"),
            instance(),
            parent.clone(),
            std::path::PathBuf::from("/run/kr/a/credential"),
        );
        let presenting = |process: ProcessStartIdentity| BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(vec![9; CREDENTIAL_BYTES]),
            process,
            environment_session_id: Some("KR_SESSION=abc".to_owned()),
        };
        let starter = launched
            .authenticate_bridge(
                &presenting(me.clone()),
                &PeerIdentity::from_kernel(me.clone(), true),
                &installed_here(),
                &hook_declared(),
            )
            .expect("a process the launched application started, running the installed forwarder");
        assert_eq!(starter, Some(parent));

        let mut stranger = me.clone();
        stranger.start_value = kr_protocol::scalars::U64::new(stranger.start_value.get() ^ 0xFFFF);
        let refusals = [
            // Another user.
            launched.authenticate_bridge(
                &presenting(me.clone()),
                &PeerIdentity::from_kernel(me.clone(), false),
                &installed_here(),
                &hook_declared(),
            ),
            // A hello presenting a process the kernel did not name.
            launched.authenticate_bridge(
                &presenting(stranger.clone()),
                &PeerIdentity::from_kernel(me.clone(), true),
                &installed_here(),
                &hook_declared(),
            ),
            // A process the launched application did not start.
            Registration::new(
                launch_address(),
                LaunchProfileId::new("lp-1").expect("valid"),
                instance(),
                stranger,
                std::path::PathBuf::from("/run/kr/a/credential"),
            )
            .authenticate_bridge(
                &presenting(me.clone()),
                &PeerIdentity::from_kernel(me.clone(), true),
                &installed_here(),
                &hook_declared(),
            ),
            // A bridge the installation does not have.
            launched.authenticate_bridge(
                &presenting(me.clone()),
                &PeerIdentity::from_kernel(me.clone(), true),
                &installed_here(),
                &crate::broker::bridge::BridgeDeclaration {
                    application: "codex".to_owned(),
                    surface: crate::broker::bridge::BridgeSurface::Hook,
                },
            ),
            // A forwarder the installation did not put in place.
            launched.authenticate_bridge(
                &presenting(me.clone()),
                &PeerIdentity::from_kernel(me.clone(), true),
                &crate::broker::bridge::InstalledBridge {
                    forwarder: std::path::PathBuf::from("/nonexistent/kalareach/kr-hook"),
                    ..installed_here()
                },
                &hook_declared(),
            ),
        ];
        for refused in refusals {
            let refused = refused.expect_err("refused");
            assert_eq!(
                refused.code(),
                kr_protocol::error::ErrorCode::PermissionDenied,
                "{refused}"
            );
        }
    }
}
