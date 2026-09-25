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

use kr_client::shown;
use kr_client::shown::{Said, Shown};
use kr_ipc::client::LocalClient;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    ClosureRecord, SessionListParams, SessionListResult, SessionReadParams, SessionReadResult,
    SessionState,
};
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
                CliError::Usage(Shown::said(
                    "the text given is neither a display number nor a session identifier",
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
                CliError::HostUnavailable(shown!(
                    "this host's environment {} has no runtime directory; start the \
                     control daemon, or name an environment",
                    installation
                ))
            });
    };
    let wanted: EnvironmentId = text.parse().map_err(|_| {
        CliError::Usage(Shown::said(
            "the text given is not an environment identifier",
        ))
    })?;
    known
        .into_iter()
        .find(|known| known.environment_id == wanted)
        // A selector that names an environment this host does not have is refused rather than
        // quietly answered by the default one.
        .ok_or_else(|| CliError::HostUnavailable(shown!("this host has no environment {}", wanted)))
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
        0 => Err(CliError::UnknownSession(selector.said())),
        1 => Ok(found.remove(0)),
        // The command never selects the first match.
        _ => Err(CliError::AmbiguousSession(selector.said())),
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
            CliError::HostUnavailable(shown!(
                "could not reach session {}: {}",
                descriptor.session_id,
                Shown::ipc(&error)
            ))
        })?;
    // A descriptor is data on disk. Nothing in it is acted on until the worker behind the endpoint
    // has signed a challenge that only it could answer.
    client.verify_worker(descriptor).await?;
    Ok(client)
}

/// What a person does about an environment whose control daemon is not running: start one, or
/// set this installation up for `kr new` to start one itself.
#[cfg(unix)]
pub const SETUP_ACTION: &str = "start the control daemon, kr-controller, for it, or, for this \
                                installation's own environment, select the standalone start with \
                                `kr host startup --set standalone` so that `kr new` starts one";

/// What a person does about an environment whose control daemon is not running: start one. The
/// standalone start runs the daemon in a session of its own, which this platform does not have.
#[cfg(not(unix))]
pub const SETUP_ACTION: &str = "start the control daemon, kr-controller, for it";

/// Connects to the control daemon.
///
/// The connection and its hello together are given [`crate::startup::ANSWER_BOUND`], the time
/// `kr new` gives a daemon that is already listening, so a daemon that takes the connection and
/// never answers holds the command no longer than that.
///
/// # Errors
///
/// Returns [`CliError::HostUnavailable`] when no daemon is listening. Its message names what the
/// person has to do about it, because a failure that only says what is missing leaves the setup
/// to be guessed. Returns [`CliError::Unfinished`] with `ENVIRONMENT_UNAVAILABLE` when a daemon
/// took the connection and did not answer within the bound.
pub async fn open_controller(paths: &EnvironmentPaths, build_id: BuildId) -> Result<LocalClient> {
    open_controller_within(paths, build_id, crate::startup::ANSWER_BOUND).await
}

/// Connects to the control daemon, the connection and its hello together bounded by `bound`.
async fn open_controller_within(
    paths: &EnvironmentPaths,
    build_id: BuildId,
    bound: std::time::Duration,
) -> Result<LocalClient> {
    let endpoint = paths.controller_endpoint()?;
    match tokio::time::timeout(
        bound,
        LocalClient::connect(&endpoint, LocalClientKind::Cli, build_id),
    )
    .await
    {
        Ok(connected) => connected.map_err(|error| not_running(&error, Shown::said(SETUP_ACTION))),
        Err(_) => Err(CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "the control daemon listening for environment {} accepted the connection and did \
                 not answer within {} seconds",
                paths.environment_id(),
                bound.as_secs_f64()
            ),
        }),
    }
}

/// The failure a command that needs a control daemon is given when none answers: what went wrong,
/// and `action`, what the person does about it.
#[must_use]
pub fn not_running(error: &kr_ipc::IpcError, action: Shown) -> CliError {
    CliError::HostUnavailable(shown!(
        "no KalaReach host is running for this environment: {}; {}",
        Shown::ipc(error),
        action
    ))
}

/// Resolves a selector that names no live descriptor, through what the environment's daemon
/// retains.
///
/// An identifier is its own answer. A display number belongs to its environment for good, so a
/// session that has closed still answers to the number it was listed under, and the daemon's list
/// with closed sessions in it says which session that is.
///
/// # Errors
///
/// Returns [`CliError::UnknownSession`] for a number the daemon never gave out, and the daemon's
/// refusal or a transport failure otherwise.
pub async fn retained_session(
    client: &mut LocalClient,
    selector: &SessionSelector,
) -> Result<SessionId> {
    let number = match selector {
        SessionSelector::Identifier(session_id) => return Ok(*session_id),
        SessionSelector::Display(number) => *number,
    };
    let outcome = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        )
        .await?;
    let listed: SessionListResult =
        outcome
            .map_err(CliError::Refused)?
            .to_typed()
            .map_err(|error| {
                CliError::Other(shown!(
                    "the host's answer could not be read: {}",
                    Shown::cbor(&error)
                ))
            })?;
    listed
        .sessions
        .iter()
        .find(|summary| summary.display_number.get() == number)
        .map(|summary| summary.session_id)
        .ok_or_else(|| CliError::UnknownSession(selector.said()))
}

/// What the environment's daemon holds for a session that no descriptor names.
#[derive(Debug)]
pub enum Registered {
    /// The session has closed.
    Closed {
        /// The session.
        session_id: SessionId,
        /// The closure record the daemon keeps, when its answer carried it.
        record: Option<ClosureRecord>,
    },
    /// The daemon holds the session, it has not closed, and it has not published a descriptor to
    /// attach through yet.
    Unpublished {
        /// The session.
        session_id: SessionId,
        /// The state the daemon reports it in.
        state: SessionState,
    },
}

/// Asks the environment's daemon about a session that no descriptor names.
///
/// A descriptor goes when its session closes, so a session without one has closed, has not
/// published one yet, or was never here. Only the daemon's registry can say which: the closure it
/// records outlives the session, and nothing left on disk is evidence of one. A daemon that cannot
/// be reached has said nothing, and the caller is told exactly that, never that the session closed.
///
/// The environment is the one `environment` names, or this installation's own, as `kr close` and
/// `kr status` ask.
///
/// # Errors
///
/// Returns [`CliError::UnknownSession`] when the registry never held the session,
/// [`CliError::HostUnavailable`] when no daemon answers for the environment, and the daemon's
/// refusal otherwise.
pub async fn registered(
    paths: &HostPaths,
    selector: &SessionSelector,
    environment: Option<&str>,
) -> Result<Registered> {
    let environment = select(paths, environment)?;
    let mut client = open_controller(&environment.paths, crate::build_id()).await?;
    let session_id = retained_session(&mut client, selector).await?;
    let outcome = client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await?;
    match outcome {
        Ok(value) => {
            let read: SessionReadResult = value.to_typed().map_err(|error| {
                CliError::Other(shown!(
                    "the host's answer could not be read: {}",
                    Shown::cbor(&error)
                ))
            })?;
            let summary = read.session;
            Ok(match summary.closure.0 {
                Some(record) => Registered::Closed {
                    session_id,
                    record: Some(record),
                },
                None if summary.state == SessionState::Closed => Registered::Closed {
                    session_id,
                    record: None,
                },
                None => Registered::Unpublished {
                    session_id,
                    state: summary.state,
                },
            })
        }
        // The daemon may answer the read with the closure itself.
        Err(refusal) if refusal.code == ErrorCode::SessionClosed => Ok(Registered::Closed {
            session_id,
            record: None,
        }),
        Err(refusal) if refusal.code == ErrorCode::UnknownSession => {
            Err(CliError::UnknownSession(selector.said()))
        }
        Err(refusal) => Err(CliError::Refused(refusal)),
    }
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

    /// A daemon that takes the connection and never answers its hello holds a command for no
    /// longer than the bound, and the failure says what happened.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_daemon_that_never_answers_its_hello_is_waited_for_no_longer_than_the_bound() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        // Bound and never accepted from: the connection is taken, and nothing ever answers it.
        let _listening = kr_ipc::endpoint::Listener::bind(
            &environment.controller_endpoint().expect("an endpoint"),
        )
        .expect("binds the endpoint");
        let bound = std::time::Duration::from_millis(300);
        let patience = std::time::Duration::from_secs(30);
        let Ok(opened) = tokio::time::timeout(
            patience,
            open_controller_within(&environment, crate::build_id(), bound),
        )
        .await
        else {
            panic!("the connection was still waiting for a hello after {patience:?}");
        };
        let refused = opened.map(|_| ()).expect_err("nothing answered");
        assert_eq!(refused.code(), "ENVIRONMENT_UNAVAILABLE", "{refused}");
        assert!(
            refused.to_string().contains(&format!(
                "the control daemon listening for environment {} accepted the connection and did \
                 not answer within 0.3 seconds",
                host.environment_id()
            )),
            "{refused}"
        );
    }
}
