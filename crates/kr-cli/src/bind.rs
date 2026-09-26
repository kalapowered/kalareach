//! Finding the session this process is running in, and calling its worker.
//!
//! A command does not decide which session it is in. It finds candidate sessions from the
//! descriptors this host publishes, connects to each one's worker and asks; the worker answers
//! from the kernel's own record of the calling process. `KR_SESSION` only changes the order
//! candidates are tried in, which is what section 11 means by a lookup hint rather than a
//! credential.
//!
//! Two questions are asked this way. [`discover`] is the contact helper's: which session holds
//! this process, and outside every candidate the answer is `NOT_IN_KR_SESSION` with the setup
//! instruction, and nothing has been created anywhere. [`membership`] is a guard's: whether this
//! process is inside any session at all, answered conservatively, so that anything which cannot
//! be established is neither inside nor outside.

use kr_client::shown;
use kr_client::shown::Shown;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::identity::ProcessState;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, QuestionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::question::{CallerToken, QuestionReadOwnParams};
use kr_protocol::scalars::Nullable;
use kr_protocol::worker::WorkerDescriptor;

use crate::error::{CliError, Result};

/// The instruction a caller outside a session is given.
pub const SETUP_INSTRUCTION: &str =
    "start this agent inside a KalaReach session: run `kr new --attach` and launch it there";

/// One session this helper is bound to.
#[derive(Clone)]
pub struct Bound {
    /// The worker that owns it.
    pub descriptor: WorkerDescriptor,
}

impl Bound {
    /// Returns the session identity.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.descriptor.session_id
    }

    /// Returns the target every request to this worker names.
    #[must_use]
    pub fn target(&self) -> ActionTarget {
        crate::attach::target(&self.descriptor)
    }
}

/// Connects to a worker and proves it is the one the descriptor names.
///
/// # Errors
///
/// Returns an error when the endpoint cannot be reached or the challenge fails.
pub async fn open(bound: &Bound, build_id: BuildId) -> Result<LocalClient> {
    crate::resolve::open_worker(&bound.descriptor, build_id).await
}

/// Finds the session this process is running in.
///
/// Every live session is a candidate, and the session named by `KR_SESSION` is tried first. A
/// candidate is accepted when its worker recognises this process as one of its own, which is a
/// question only the worker can answer.
///
/// # Errors
///
/// Returns [`CliError::Refused`] with `NOT_IN_KR_SESSION` when no session holds this process.
pub async fn discover(build_id: &BuildId) -> Result<Bound> {
    let paths = kr_ipc::paths::HostPaths::discover()?;
    let named = crate::resolve::current_session();
    let mut candidates: Vec<WorkerDescriptor> = Vec::new();
    for known in crate::resolve::environments(&paths)? {
        for entry in kr_ipc::descriptor::read_all(&known.paths)? {
            if let Ok(descriptor) = entry.descriptor {
                candidates.push(descriptor);
            }
        }
    }
    // The hint decides the order and nothing else. A forged one reaches a worker that refuses it.
    candidates.sort_by_key(|descriptor| u8::from(named.as_ref() != Some(&descriptor.session_id)));
    for descriptor in candidates {
        let bound = Bound { descriptor };
        if probes_bound(&bound, build_id.clone()).await {
            return Ok(bound);
        }
    }
    Err(CliError::Refused(kr_client::error::refusal(
        ErrorCode::NotInKrSession,
        shown!(
            "this process is not inside a KalaReach session. {}",
            SETUP_INSTRUCTION
        ),
    )))
}

/// Whether this process is inside a KalaReach session, as every live session's worker answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Membership {
    /// Every live session's worker said this process is not one of its own.
    Outside,
    /// A session's worker recognised this process as one of its own.
    Inside(SessionId),
    /// Something that could hold this process did not say: a descriptor that cannot be read, a
    /// worker the kernel reports running that gave neither answer or could not establish one, or
    /// a host whose sessions cannot be listed. The reason says which.
    Unknown(Shown),
}

/// How long one worker is given to say whether this process is its own.
pub const MEMBERSHIP_PROBE_DEADLINE: Duration = Duration::from_secs(5);

/// Asks every live session's worker whether this process is inside its session.
///
/// A worker counts as live when its descriptor names this boot and the kernel reports its process
/// running: a worker from another boot, or whose process has ended, holds nothing and is passed
/// over. Only when every live worker has established that this process is not its own is the
/// answer [`Membership::Outside`]; a worker that says it is makes the answer
/// [`Membership::Inside`], and anything else, a worker that could not establish it included,
/// leaves it [`Membership::Unknown`].
pub async fn membership(build_id: &BuildId) -> Membership {
    let paths = match kr_ipc::paths::HostPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            return Membership::Unknown(shown!(
                "this host's directories cannot be found: {}",
                Shown::ipc(&error)
            ));
        }
    };
    let boot = match kr_ipc::identity::boot_identity() {
        Ok(boot) => boot,
        Err(error) => {
            return Membership::Unknown(shown!(
                "this boot cannot be identified: {}",
                Shown::ipc(&error)
            ));
        }
    };
    let environments = match every_environment(&paths) {
        Ok(environments) => environments,
        Err(why) => return Membership::Unknown(why),
    };
    let mut undecided = None;
    for known in environments {
        let entries = match kr_ipc::descriptor::read_all(&known.paths) {
            Ok(entries) => entries,
            Err(error) => {
                undecided.get_or_insert(shown!(
                    "the sessions of environment {} cannot be listed: {}",
                    known.environment_id,
                    Shown::ipc(&error)
                ));
                continue;
            }
        };
        for entry in entries {
            let descriptor = match entry.descriptor {
                Ok(descriptor) => descriptor,
                // The reason is the descriptor reader's own text about a file it found, and is not
                // repeated: which file, and that it could not be read, is what establishes nothing.
                Err(_) => {
                    undecided.get_or_insert(shown!(
                        "the session descriptor {} cannot be read",
                        Shown::stored(&entry.path, &[], &["kr"])
                    ));
                    continue;
                }
            };
            if descriptor.boot_identity != boot {
                continue;
            }
            match kr_ipc::identity::process_state(&descriptor.process_start_identity) {
                ProcessState::Ended => continue,
                ProcessState::Unknown { .. } => {
                    undecided.get_or_insert(shown!(
                        "whether the worker of session {} is running cannot be read",
                        descriptor.session_id
                    ));
                    continue;
                }
                ProcessState::Running => {}
            }
            let session_id = descriptor.session_id;
            let bound = Bound { descriptor };
            let answered =
                tokio::time::timeout(MEMBERSHIP_PROBE_DEADLINE, probe(&bound, build_id.clone()))
                    .await
                    .unwrap_or_else(|_| Probe::Silent(Shown::said("it did not answer in time")));
            match answered {
                Probe::Inside => return Membership::Inside(session_id),
                Probe::Outside => {}
                Probe::Silent(why) => {
                    undecided.get_or_insert(shown!(
                        "the worker of session {} did not say whether this process is its own: {}",
                        session_id,
                        why
                    ));
                }
            }
        }
    }
    undecided.map_or(Membership::Outside, Membership::Unknown)
}

/// Lists every environment this host has a directory for, and fails where one cannot be read.
///
/// [`crate::resolve::environments`] passes over a directory whose identity it cannot read, which is
/// right for a command acting on the environments it can reach. A guard cannot: a session in an
/// environment nobody listed is a session nobody asked. So a listing that fails, an entry that
/// cannot be inspected, a link where an environment's directory would be, and a directory whose
/// identity cannot be read each make the answer unknown. A plain file there is not an
/// environment.
fn every_environment(
    paths: &kr_ipc::paths::HostPaths,
) -> std::result::Result<Vec<crate::resolve::KnownEnvironment>, Shown> {
    let installation = paths.open_environment_id().map_err(|error| {
        shown!(
            "this installation's environment cannot be read: {}",
            Shown::ipc(&error)
        )
    })?;
    let mut found = vec![crate::resolve::KnownEnvironment {
        environment_id: installation,
        paths: paths.environment(installation),
    }];
    let root = paths.state_root().join("environments");
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(error) => {
            return Err(shown!(
                "{} cannot be listed: {}",
                Shown::within(paths.state_root(), "environments"),
                Shown::io(&error)
            ));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            shown!(
                "{} cannot be listed: {}",
                Shown::within(paths.state_root(), "environments"),
                Shown::io(&error)
            )
        })?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| {
            shown!(
                "{} cannot be inspected: {}",
                Shown::stored(&path, &[], &[]),
                Shown::io(&error)
            )
        })?;
        if kind.is_symlink() {
            return Err(shown!(
                "{} is a link where an environment's directory would be",
                Shown::stored(&path, &[], &[])
            ));
        }
        if !kind.is_dir() {
            continue;
        }
        let environment_id = kr_ipc::paths::read_environment_marker(&path).map_err(|error| {
            shown!(
                "the environment at {} cannot be identified: {}",
                Shown::stored(&path, &[], &[]),
                Shown::ipc(&error)
            )
        })?;
        if found
            .iter()
            .any(|known| known.environment_id == environment_id)
        {
            continue;
        }
        found.push(crate::resolve::KnownEnvironment {
            environment_id,
            paths: paths.environment(environment_id),
        });
    }
    Ok(found)
}

/// What one worker said about this process.
enum Probe {
    /// It is this worker's own.
    Inside,
    /// It is not.
    Outside,
    /// The worker gave neither answer, for the reason given.
    Silent(Shown),
}

/// Asks one worker whether this process is inside its session, taking only a binding answer.
async fn probes_bound(bound: &Bound, build_id: BuildId) -> bool {
    matches!(probe(bound, build_id).await, Probe::Inside)
}

/// Asks one worker whether this process is inside its session.
///
/// The probe reads a question that does not exist, and the worker binds the caller before it looks
/// anything up. One that establishes this process is not its own answers `NOT_IN_KR_SESSION`; one
/// that holds it answers that the question is unknown; one that cannot establish either answers
/// `RESOURCE_UNAVAILABLE`, saying which reading failed. Nothing is created in any case.
async fn probe(bound: &Bound, build_id: BuildId) -> Probe {
    let mut client = match open(bound, build_id).await {
        Ok(client) => client,
        Err(error) => return Probe::Silent(shown!("{}", error)),
    };
    let params = QuestionReadOwnParams {
        session_id: bound.session_id(),
        question_id: QuestionId::new(kr_ipc::new_uuid()),
        caller_token: CallerToken::new(vec![0; kr_protocol::question::CALLER_TOKEN_BYTES]),
        wait_ms: Nullable::null(),
    };
    // Only a recognised binding outcome counts. A worker that holds this process answers that the
    // question is unknown, which is `PERMISSION_DENIED`; one that established it does not hold it
    // answers `NOT_IN_KR_SESSION`. Anything else - a worker that could not establish either, an
    // unsupported method, a failing ledger, a truncated connection - says nothing about where this
    // process is: choosing a session on the strength of it would create the next question in the
    // wrong one, and a guard that took it for "outside" would let through the process it exists
    // to stop.
    match client.request(Method::QuestionReadOwn, &params).await {
        Ok(Ok(_)) => Probe::Inside,
        Ok(Err(error)) if error.code == ErrorCode::PermissionDenied => Probe::Inside,
        Ok(Err(error)) if error.code == ErrorCode::NotInKrSession => Probe::Outside,
        Ok(Err(error)) if error.code == ErrorCode::ResourceUnavailable => {
            Probe::Silent(Shown::protocol(&error))
        }
        Ok(Err(error)) => Probe::Silent(shown!("it answered {}", error.code)),
        Err(error) => Probe::Silent(Shown::ipc(&error)),
    }
}

/// Calls a read on this session's worker.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn read<P, T>(client: &mut LocalClient, method: Method, params: &P) -> Result<T>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let outcome = client.request(method, params).await?;
    decode(outcome.map_err(CliError::Refused)?)
}

/// Calls a mutation on this session's worker.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn mutate<P, T>(
    client: &mut LocalClient,
    method: Method,
    target: ActionTarget,
    params: &P,
) -> Result<T>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let outcome = client.mutate(method, action_id, target, params).await?;
    decode(outcome.map_err(CliError::Refused)?)
}

fn decode<T: kr_protocol::wire::WireMessage>(value: ParamsValue) -> Result<T> {
    value.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })
}
