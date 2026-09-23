//! Finding a session, and reaching the worker that owns it.
//!
//! A person types a display number. The protocol's identity is a UUID. Both are accepted, and the
//! rule for the number is the one section 7 sets: numbers are unique inside an environment and a
//! number that names sessions in two environments is **ambiguous**. The command says so and stops;
//! it never picks the first match.
//!
//! Reaching a worker does not go through the control daemon. The descriptors are published in the
//! runtime directory, so `kr attach` reads one, challenges the worker named in it, and attaches —
//! which is what keeps attaching possible while the daemon is restarting.

use kr_ipc::client::LocalClient;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::ids::{BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::worker::WorkerDescriptor;

use crate::error::{CliError, Result};

/// How a session was named on the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionSelector {
    /// A local display number.
    Display(u64),
    /// A protocol identifier.
    Identifier(SessionId),
}

impl SessionSelector {
    /// Parses what the user typed.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when the text is neither a number nor an identifier.
    pub fn parse(text: &str) -> Result<Self> {
        if let Ok(number) = text.parse::<u64>() {
            return Ok(Self::Display(number));
        }
        text.parse::<SessionId>()
            .map(Self::Identifier)
            .map_err(|_| {
                CliError::Usage(format!(
                    "{text} is neither a display number nor a session identifier"
                ))
            })
    }

    /// Returns true when this descriptor is the one named.
    #[must_use]
    pub fn matches(&self, descriptor: &WorkerDescriptor) -> bool {
        match self {
            Self::Display(number) => descriptor.display_number.get() == *number,
            Self::Identifier(session_id) => descriptor.session_id == *session_id,
        }
    }
}

impl core::fmt::Display for SessionSelector {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Display(number) => write!(formatter, "{number}"),
            Self::Identifier(session_id) => write!(formatter, "{session_id}"),
        }
    }
}

/// One environment this host has a directory for.
#[derive(Clone, Debug)]
pub struct KnownEnvironment {
    /// The environment identity.
    pub environment_id: EnvironmentId,
    /// Its directories.
    pub paths: EnvironmentPaths,
}

/// Returns the environments this installation knows about.
///
/// # Errors
///
/// Returns an error when the state directory cannot be read.
pub fn environments(paths: &HostPaths) -> Result<Vec<KnownEnvironment>> {
    // This installation's own environment always counts, whether or not it has run yet. Every
    // other one is a directory this host created and left a complete identity in; a directory
    // whose marker cannot be read is not an environment this command will act on.
    let mut found = vec![{
        let environment_id = paths.open_environment_id()?;
        KnownEnvironment {
            environment_id,
            paths: paths.environment(environment_id),
        }
    }];
    if let Ok(entries) = std::fs::read_dir(paths.state_root().join("environments")) {
        for entry in entries.flatten() {
            let Ok(environment_id) = kr_ipc::paths::read_environment_marker(&entry.path()) else {
                continue;
            };
            if found
                .iter()
                .any(|known| known.environment_id == environment_id)
            {
                continue;
            }
            found.push(KnownEnvironment {
                environment_id,
                paths: paths.environment(environment_id),
            });
        }
    }
    found.sort_by_key(|known| known.environment_id.to_string());
    Ok(found)
}

/// Returns the environment a command acts in.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the text is not an environment identifier, and
/// [`CliError::HostUnavailable`] when this installation has no such environment.
pub fn select(paths: &HostPaths, named: Option<&str>) -> Result<KnownEnvironment> {
    let known = environments(paths)?;
    let Some(text) = named else {
        // This installation's own environment, not whichever identifier happens to sort first. A
        // host can have several — a test tree, a second account's tree left behind — and answering
        // `kr new` with one of those would create a session somewhere the person never named.
        let installation = paths.open_environment_id()?;
        return known
            .into_iter()
            .find(|known| known.environment_id == installation)
            .ok_or_else(|| {
                CliError::HostUnavailable(format!(
                    "this host's environment {installation} has no runtime directory; start the \
                     control daemon, or name an environment"
                ))
            });
    };
    let wanted: EnvironmentId = text
        .parse()
        .map_err(|_| CliError::Usage(format!("{text} is not an environment identifier")))?;
    known
        .into_iter()
        .find(|known| known.environment_id == wanted)
        // A selector that names an environment this host does not have is refused rather than
        // quietly answered by the default one.
        .ok_or_else(|| CliError::HostUnavailable(format!("this host has no environment {wanted}")))
}

/// Finds the descriptor a selector names.
///
/// # Errors
///
/// Returns [`CliError::AmbiguousSession`] when a display number matches in more than one
/// environment, and [`CliError::UnknownSession`] when nothing matches.
pub fn find(
    paths: &HostPaths,
    selector: &SessionSelector,
    environment: Option<EnvironmentId>,
) -> Result<(KnownEnvironment, WorkerDescriptor)> {
    let mut found: Vec<(KnownEnvironment, WorkerDescriptor)> = Vec::new();
    for known in environments(paths)? {
        if environment.is_some_and(|wanted| wanted != known.environment_id) {
            continue;
        }
        for entry in kr_ipc::descriptor::read_all(&known.paths)? {
            let Ok(descriptor) = entry.descriptor else {
                continue;
            };
            if selector.matches(&descriptor) {
                found.push((known.clone(), descriptor));
            }
        }
    }
    match found.len() {
        0 => Err(CliError::UnknownSession(selector.to_string())),
        1 => Ok(found.remove(0)),
        // The command never selects the first match.
        _ => Err(CliError::AmbiguousSession(selector.to_string())),
    }
}

/// Connects to a worker and proves it is the one the descriptor names.
///
/// # Errors
///
/// Returns an error when the endpoint cannot be reached or the challenge fails.
pub async fn open_worker(descriptor: &WorkerDescriptor, build_id: BuildId) -> Result<LocalClient> {
    let endpoint = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint)?;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build_id)
        .await
        .map_err(|error| {
            CliError::HostUnavailable(format!(
                "could not reach session {}: {error}",
                descriptor.session_id
            ))
        })?;
    // A descriptor is data on disk. Nothing in it is acted on until the worker behind the endpoint
    // has signed a challenge that only it could answer.
    client.verify_worker(descriptor).await?;
    Ok(client)
}

/// Connects to the control daemon.
///
/// # Errors
///
/// Returns [`CliError::HostUnavailable`] when no daemon is listening.
pub async fn open_controller(paths: &EnvironmentPaths, build_id: BuildId) -> Result<LocalClient> {
    let endpoint = paths.controller_endpoint()?;
    LocalClient::connect(&endpoint, LocalClientKind::Cli, build_id)
        .await
        .map_err(|error| {
            CliError::HostUnavailable(format!(
                "no KalaReach host is running for this environment: {error}"
            ))
        })
}

/// The environment variable that names the session a command is running inside.
///
/// It identifies a candidate session. It is not a credential: the host validates the caller's
/// local peer and its session binding before it accepts anything.
pub const SESSION_VARIABLE: &str = "KR_SESSION";

/// The environment variable that names the attachment a command is running inside.
pub const ATTACHMENT_VARIABLE: &str = "KR_ATTACHMENT";

/// Returns the session this command is running inside, if any.
#[must_use]
pub fn current_session() -> Option<SessionId> {
    std::env::var(SESSION_VARIABLE)
        .ok()
        .and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    #[test]
    fn a_number_and_an_identifier_are_both_accepted() {
        assert_eq!(
            SessionSelector::parse("7").expect("parses"),
            SessionSelector::Display(7)
        );
        let identifier = Uuid::from_bytes([4; 16]);
        assert_eq!(
            SessionSelector::parse(&identifier.to_string()).expect("parses"),
            SessionSelector::Identifier(SessionId::new(identifier))
        );
    }

    #[test]
    fn anything_else_is_a_usage_failure() {
        let error = SessionSelector::parse("session-two").expect_err("refuses");
        assert_eq!(error.exit_code(), 2);
    }

    /// A descriptor for session `byte`, numbered `display`, in `environment`.
    fn published(
        environment: &EnvironmentPaths,
        environment_id: EnvironmentId,
        byte: u8,
        display: u64,
    ) -> SessionId {
        let session_id = SessionId::new(Uuid::from_bytes([byte; 16]));
        let descriptor = WorkerDescriptor {
            session_id,
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            environment_id,
            display_number: kr_protocol::session::DisplayNumber::new(display),
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            process_start_identity: kr_ipc::identity::current_process_start_identity()
                .expect("a process identity"),
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            endpoint: environment
                .worker_endpoint(kr_protocol::session::DisplayNumber::new(display))
                .expect("an endpoint")
                .as_text(),
            worker_public_key: *kr_crypto::keys::AuthorisationKeyPair::generate()
                .expect("a key pair")
                .public(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            published_at_ms: kr_protocol::scalars::TimestampMs::new(0),
        };
        kr_ipc::descriptor::publish(environment, &descriptor).expect("publishes");
        session_id
    }

    /// KR-REQ-07.49: a display number that names sessions in two environments is refused as
    /// `AMBIGUOUS_SESSION` rather than answered with the first match, and an explicit environment
    /// or the session's UUID reaches the one that was meant.
    #[test]
    fn a_number_two_environments_use_is_ambiguous_until_the_environment_or_uuid_is_named() {
        let host = kr_ipc::testing::TempHost::create();
        let first = host.environment_id();
        let second = EnvironmentId::new(kr_ipc::new_uuid());
        host.paths()
            .environment(second)
            .create()
            .expect("a second environment on this host");
        let in_first = published(&host.environment(), first, 0x11, 1);
        let in_second = published(&host.paths().environment(second), second, 0x22, 1);

        let refused = find(host.paths(), &SessionSelector::Display(1), None)
            .expect_err("two environments have a session 1");
        assert!(
            matches!(refused, CliError::AmbiguousSession(_)),
            "{refused}"
        );
        assert_eq!(refused.code(), "AMBIGUOUS_SESSION");
        assert_ne!(refused.exit_code(), 0);

        let (known, descriptor) = find(host.paths(), &SessionSelector::Display(1), Some(second))
            .expect("the environment says which");
        assert_eq!(known.environment_id, second);
        assert_eq!(descriptor.session_id, in_second);

        let (known, descriptor) = find(host.paths(), &SessionSelector::Identifier(in_first), None)
            .expect("the identifier says which");
        assert_eq!(known.environment_id, first);
        assert_eq!(descriptor.session_id, in_first);
    }
}
