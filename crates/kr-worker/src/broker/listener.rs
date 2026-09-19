//! The local listener a launched agent reaches its worker-owned backend on.
//!
//! Section 12 fixes four properties, and this module is where each one is decided rather than
//! hoped for.
//!
//! * **It is private.** A Unix socket inside the owner-only runtime directory where the platform
//!   supports one; loopback with a random per-launch credential where it does not. Either way the
//!   address is local: [`ListenerAddress::is_local`] is what the host checks before it publishes
//!   one, and nothing here can produce an address a relay could carry.
//! * **A browser cannot use it.** [`reject_browser_origin`] refuses a connection that arrives with
//!   any of the headers a browser adds. A page that guesses the address still cannot speak to it.
//! * **An unauthenticated request is refused.** [`Registration::authenticate`] wants the private
//!   exchange *and* the launch binding. Section 11 is explicit that an environment-variable
//!   session identifier alone is not authentication, so one is accepted as a hint and ignored as
//!   authority.
//! * **Credentials stay out of what people see.** The address a diagnostic prints carries none,
//!   and neither does an argument vector: the secret travels in an owner-only file the launched
//!   process opens, or, where a file's protection cannot be proved, over the endpoint's own
//!   access-controlled channel.
//!
//! And one property that belongs to a binding rather than to the listener: an installed upgrade
//! affects new launches. [`BoundBinary`] is pinned when a process starts, and
//! [`BoundBinary::survives_upgrade`] is what says a running binding keeps the identity it was
//! bound to.

use kr_protocol::broker::BinaryIdentity;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, LaunchProfileId};

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

/// Where the launched agent connects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerAddress {
    /// A socket file inside the owner-only runtime directory.
    ///
    /// Preferred wherever the platform has one, because the filesystem answers "who may connect"
    /// before any byte is read.
    PrivateSocket(std::path::PathBuf),
    /// Loopback, with a random per-launch credential every connection must present.
    ///
    /// The address is not the secret. Anyone on this machine can reach a loopback port, so the
    /// credential is what decides, and it never appears in the address.
    Loopback {
        /// The interface the listener is bound to.
        ///
        /// It is here rather than assumed, because "loopback" is what has to be checked: a
        /// listener bound to every interface is reachable from the network, and a random
        /// credential is not a substitute for not being reachable.
        address: std::net::IpAddr,
        /// The port the listener is bound to.
        port: u16,
    },
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
            Self::Loopback { address, .. } => address.is_loopback(),
        }
    }

    /// Returns the address as a diagnostic prints it.
    ///
    /// There is no credential in it, because there is no credential in the type. A reader of a
    /// diagnostic learns where the listener is and nothing about how to speak to it.
    #[must_use]
    pub fn for_diagnostics(&self) -> String {
        match self {
            Self::PrivateSocket(path) => path.display().to_string(),
            Self::Loopback { address, port } => format!("{address}:{port}"),
        }
    }

    /// Returns the address this platform uses for one launch.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the runtime directory names nothing.
    pub fn for_launch(runtime_directory: &std::path::Path, port: u16) -> Result<Self> {
        if cfg!(unix) {
            if !runtime_directory.is_absolute() {
                return Err(BrokerError::invalid(
                    "a private socket lives at an absolute path inside the runtime directory",
                ));
            }
            // The directory decides who may connect, so it is checked before an address that
            // depends on it is handed out.
            crate::broker::process::check_private_directory(runtime_directory)?;
            let address = Self::PrivateSocket(
                runtime_directory.join(format!("agent-{}.sock", kr_ipc::new_uuid())),
            );
            debug_assert!(address.is_local());
            Ok(address)
        } else {
            Ok(Self::Loopback {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            })
        }
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
    ) -> Self {
        Self {
            address,
            profile_id,
            application_instance_id,
            expected_process,
        }
    }

    /// Authenticates one connecting bridge.
    ///
    /// Three things are checked and all three must hold: the connection came from this user, the
    /// process is the one this host launched, and the credential is the one this host generated
    /// for that launch. An environment session identifier is not one of the three.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] naming which of the three failed.
    pub fn authenticate(
        &self,
        hello: &BridgeHello,
        peer_is_owner: bool,
        process: &ManagedProcess,
    ) -> Result<()> {
        if !peer_is_owner {
            return Err(BrokerError::denied(
                "this connection is not the operating-system user who owns the session",
            ));
        }
        if !hello.process.matches(&self.expected_process) {
            return Err(BrokerError::denied(format!(
                "this connection is process {} and the launch was process {}",
                hello.process.pid, self.expected_process.pid
            )));
        }
        if !process.authenticates(hello.credential.expose(), &hello.process) {
            return Err(BrokerError::denied(
                "this connection did not present the private exchange of the launch it claims",
            ));
        }
        Ok(())
    }

    /// Renders the registration as the file a launched process reads.
    ///
    /// One `name=value` line each, so the `kr-hook` forwarder can read it without a parser. There
    /// is nothing secret in it.
    #[must_use]
    pub fn to_file(&self) -> String {
        format!(
            "endpoint={}\nprofile={}\ninstance={}\npid={}\nstart={}\n",
            self.address.for_diagnostics(),
            self.profile_id,
            self.application_instance_id,
            self.expected_process.pid,
            self.expected_process.start_value,
        )
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

    fn registration() -> Registration {
        Registration::new(
            ListenerAddress::PrivateSocket("/run/kr/agent-1.sock".into()),
            LaunchProfileId::new("lp-1").expect("valid"),
            instance(),
            process(41, 900),
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
            .authenticate(&hello(), true, &managed)
            .expect("the launch binding and the private exchange are both there");

        // The session identifier, and nothing else.
        let bare = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(Vec::new()),
            process: process(41, 900),
            environment_session_id: None,
        };
        assert!(
            registration.authenticate(&bare, true, &managed).is_err(),
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
                .authenticate(&elsewhere, true, &managed)
                .is_err()
        );

        // The right process from the wrong user.
        assert!(
            registration
                .authenticate(&hello(), false, &managed)
                .is_err()
        );

        // A recycled process identifier.
        let recycled = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(vec![9; CREDENTIAL_BYTES]),
            process: process(41, 901),
            environment_session_id: None,
        };
        assert!(
            registration
                .authenticate(&recycled, true, &managed)
                .is_err()
        );
    }

    #[test]
    fn a_registration_carries_no_credential() {
        let file = registration().to_file();
        assert!(file.contains("endpoint=/run/kr/agent-1.sock"));
        assert!(file.contains("pid=41"));
        assert!(
            !file.contains("09"),
            "the registration a person reads carries nothing that speaks to the listener"
        );
        assert!(!file.to_ascii_lowercase().contains("credential"));
        assert!(!file.to_ascii_lowercase().contains("secret"));
    }

    #[test]
    fn an_address_is_local_and_a_diagnostic_carries_no_credential() {
        let socket = ListenerAddress::PrivateSocket("/run/kr/agent-1.sock".into());
        assert!(socket.is_local());
        assert_eq!(socket.for_diagnostics(), "/run/kr/agent-1.sock");

        let loopback = ListenerAddress::Loopback {
            address: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 49_152,
        };
        assert!(loopback.is_local());
        loopback.require_local().expect("loopback is local");
        assert_eq!(loopback.for_diagnostics(), "127.0.0.1:49152");

        // And an address something else could reach is refused rather than published.
        let exposed = ListenerAddress::Loopback {
            address: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 49_152,
        };
        assert!(!exposed.is_local());
        assert!(exposed.require_local().is_err());
        let relative = ListenerAddress::PrivateSocket("agent.sock".into());
        assert!(!relative.is_local());
        assert!(
            !loopback.for_diagnostics().contains('@'),
            "a credential never travels in a URL"
        );
    }

    #[test]
    fn this_platform_prefers_the_private_socket_it_has() {
        let directory = std::env::temp_dir().join(format!("kr-listener-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("the directory is made private");
        }
        let address =
            ListenerAddress::for_launch(&directory, 49_152).expect("an address is chosen");
        address.require_local().expect("it is local");
        if cfg!(unix) {
            assert!(matches!(address, ListenerAddress::PrivateSocket(_)));
        } else {
            assert!(matches!(address, ListenerAddress::Loopback { .. }));
        }

        // A directory other users can read is not one a private socket goes in.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let open = std::env::temp_dir().join(format!("kr-listener-{}", kr_ipc::new_uuid()));
            std::fs::create_dir_all(&open).expect("the directory is created");
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755))
                .expect("the directory is made readable by others");
            assert!(ListenerAddress::for_launch(&open, 49_152).is_err());
            let _ = std::fs::remove_dir_all(&open);
        }
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
}
