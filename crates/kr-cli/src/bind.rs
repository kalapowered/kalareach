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

/// Connects to a worker for a tool call, and refuses a worker of another release.
///
/// Discovery sends every worker the probe whose shape never changes, so it opens a worker of any
/// level with [`open()`]. A call writes in the shape of this release: a worker of another level
/// answers in a shape the tools do not read, and no tool of its release was started in their
/// place, so the call says so and sends nothing.
///
/// # Errors
///
/// Returns an error when the endpoint cannot be reached or the challenge fails, and
/// [`CliError::Refused`] with `UNSUPPORTED_SCHEMA` for a worker of another level.
pub async fn open_for_a_call(bound: &Bound, build_id: BuildId) -> Result<LocalClient> {
    let client = open(bound, build_id).await?;
    if let Some(other) = crate::helper::Other::of(client.acknowledgement().build.as_ref()) {
        return Err(CliError::Refused(kr_client::error::refusal(
            ErrorCode::UnsupportedSchema,
            crate::helper::Unread {
                display: bound.descriptor.display_number.get(),
                other,
            }
            .said("agent-tools"),
        )));
    }
    Ok(client)
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

/// What a walk over the sessions' descriptors found, in the order it found it.
enum Walked {
    /// A worker that is live: its descriptor names this boot and the kernel reports its process
    /// running.
    Worker(WorkerDescriptor),
    /// Something that could hold this process and was not established, with the reason.
    Undecided(Shown),
}

/// Walks every environment's descriptors and says which workers are live and what could not be
/// established. A worker from another boot, or whose process has ended, holds nothing and is
/// passed over.
///
/// # Errors
///
/// The reason the walk could not be made at all: this host's directories, this boot or the list of
/// environments could not be read, which leaves the answer unknown.
fn walk() -> std::result::Result<Vec<Walked>, Shown> {
    let paths = kr_ipc::paths::HostPaths::discover().map_err(|error| {
        shown!(
            "this host's directories cannot be found: {}",
            Shown::ipc(&error)
        )
    })?;
    let boot = kr_ipc::identity::boot_identity()
        .map_err(|error| shown!("this boot cannot be identified: {}", Shown::ipc(&error)))?;
    let environments = every_environment(&paths)?;
    let mut walked = Vec::new();
    for known in environments {
        let entries = match kr_ipc::descriptor::read_all(&known.paths) {
            Ok(entries) => entries,
            Err(error) => {
                walked.push(Walked::Undecided(shown!(
                    "the sessions of environment {} cannot be listed: {}",
                    known.environment_id,
                    Shown::ipc(&error)
                )));
                continue;
            }
        };
        for entry in entries {
            let descriptor = match entry.descriptor {
                Ok(descriptor) => descriptor,
                // The reason is the descriptor reader's own text about a file it found, and is not
                // repeated: which file, and that it could not be read, is what establishes nothing.
                Err(_) => {
                    walked.push(Walked::Undecided(shown!(
                        "the session descriptor {} cannot be read",
                        Shown::stored(&entry.path, &[], &["kr"])
                    )));
                    continue;
                }
            };
            if descriptor.boot_identity != boot {
                continue;
            }
            match kr_ipc::identity::process_state(&descriptor.process_start_identity) {
                ProcessState::Ended => continue,
                ProcessState::Unknown { .. } => {
                    walked.push(Walked::Undecided(shown!(
                        "whether the worker of session {} is running cannot be read",
                        descriptor.session_id
                    )));
                    continue;
                }
                ProcessState::Running => {}
            }
            walked.push(Walked::Worker(descriptor));
        }
    }
    Ok(walked)
}

/// What one live worker said, within [`MEMBERSHIP_PROBE_DEADLINE`].
async fn answered(descriptor: WorkerDescriptor, build_id: BuildId) -> Probe {
    let bound = Bound { descriptor };
    tokio::time::timeout(MEMBERSHIP_PROBE_DEADLINE, probe(&bound, build_id))
        .await
        .unwrap_or_else(|_| Probe::Silent(Shown::said("it did not answer in time")))
}

/// The reason that a worker that gave neither answer leaves the membership unknown.
fn silent(session_id: SessionId, why: &Shown) -> Shown {
    shown!(
        "the worker of session {} did not say whether this process is its own: {}",
        session_id,
        *why
    )
}

/// Asks every live session's worker whether this process is inside its session.
///
/// A worker counts as live when its descriptor names this boot and the kernel reports its process
/// running: a worker from another boot, or whose process has ended, holds nothing and is passed
/// over. Only when every live worker has established that this process is not its own is the
/// answer [`Membership::Outside`]; a worker that says it is makes the answer
/// [`Membership::Inside`], and anything else, a worker that could not establish it included,
/// leaves it [`Membership::Unknown`].
pub async fn membership(build_id: &BuildId) -> Membership {
    let walked = match walk() {
        Ok(walked) => walked,
        Err(why) => return Membership::Unknown(why),
    };
    let mut undecided = None;
    for item in walked {
        match item {
            Walked::Undecided(why) => {
                undecided.get_or_insert(why);
            }
            Walked::Worker(descriptor) => {
                let session_id = descriptor.session_id;
                match answered(descriptor, build_id.clone()).await {
                    Probe::Inside => return Membership::Inside(session_id),
                    Probe::Outside => {}
                    Probe::Silent(why) => {
                        undecided.get_or_insert(silent(session_id, &why));
                    }
                }
            }
        }
    }
    undecided.map_or(Membership::Outside, Membership::Unknown)
}

/// Asks every live session's worker at once, as [`membership`] asks them in turn, and answers as
/// it does: the first worker that says this process is its own ends the question, and the wait for
/// the others is one [`MEMBERSHIP_PROBE_DEADLINE`] and not one for each worker.
pub async fn membership_together(build_id: &BuildId) -> Membership {
    let walked = match walk() {
        Ok(walked) => walked,
        Err(why) => return Membership::Unknown(why),
    };
    let build_id = build_id.clone();
    ask_together(walked, move |descriptor| {
        answered(descriptor, build_id.clone())
    })
    .await
}

/// Starts the question to every worker in `walked` before it waits for any answer, and reads the
/// answers as [`membership`] does. `ask` is how one worker is asked.
async fn ask_together<F, Fut>(walked: Vec<Walked>, ask: F) -> Membership
where
    F: Fn(WorkerDescriptor) -> Fut,
    Fut: std::future::Future<Output = Probe> + Send + 'static,
{
    let mut asking = tokio::task::JoinSet::new();
    let mut slots = Vec::with_capacity(walked.len());
    for (place, item) in walked.into_iter().enumerate() {
        slots.push(match item {
            Walked::Undecided(why) => Slot::Undecided(why),
            Walked::Worker(descriptor) => {
                let session_id = descriptor.session_id;
                let question = ask(descriptor);
                asking.spawn(async move { (place, question.await) });
                Slot::Asked(session_id, None)
            }
        });
    }
    while let Some(joined) = asking.join_next().await {
        // A probe that panicked or was aborted gave no answer, which leaves its slot unsaid.
        let Ok((place, answer)) = joined else {
            continue;
        };
        if let Probe::Inside = answer
            && let Slot::Asked(session_id, _) = &slots[place]
        {
            return Membership::Inside(*session_id);
        }
        if let Slot::Asked(_, said) = &mut slots[place] {
            *said = Some(answer);
        }
    }
    let mut undecided = None;
    for slot in slots {
        match slot {
            Slot::Undecided(why) => {
                undecided.get_or_insert(why);
            }
            Slot::Asked(_, Some(Probe::Outside)) => {}
            Slot::Asked(session_id, Some(Probe::Silent(why))) => {
                undecided.get_or_insert(silent(session_id, &why));
            }
            Slot::Asked(session_id, _) => {
                undecided.get_or_insert(silent(
                    session_id,
                    &Shown::said("its probe did not end with an answer"),
                ));
            }
        }
    }
    undecided.map_or(Membership::Outside, Membership::Unknown)
}

/// A place in the order of a walk: what could not be established, or a worker and what it said.
enum Slot {
    Undecided(Shown),
    Asked(SessionId, Option<Probe>),
}

/// Refuses unless this process is outside every KalaReach session.
///
/// A command that reads or shows something only the person at a terminal may hold, such as a
/// recovery kit or a host's first confirmation, would put it into a session's output, which the
/// session's worker keeps and an agent in it can read. So it runs outside every session, and the
/// guard takes no one's word for it: `KR_SESSION` and `KR_ATTACHMENT` refuse at once, and otherwise
/// every live session's worker is asked ([`membership`]), so a process whose environment was
/// cleaned is still found inside. Whatever cannot be established refuses too.
///
/// `because` ends each refusal and says why this command stays outside a session. The guard is not
/// isolation from other code running as the same user, which section 10 also says; it stops a
/// command started by accident inside a session.
///
/// # Errors
///
/// Returns a refusal with `PERMISSION_DENIED` when this process is inside a session, or when whether
/// it is cannot be established.
pub async fn require_outside(build_id: &BuildId, because: &'static str) -> Result<()> {
    for variable in [
        crate::resolve::SESSION_VARIABLE,
        crate::resolve::ATTACHMENT_VARIABLE,
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(inside(shown!(
                "{} is set, so this is inside a KalaReach session; {}",
                variable,
                because
            )));
        }
    }
    match membership(build_id).await {
        Membership::Outside => Ok(()),
        Membership::Inside(session_id) => Err(inside(shown!(
            "this process is inside session {}; {}",
            session_id,
            because
        ))),
        Membership::Unknown(why) => Err(inside(shown!(
            "whether this process is inside a KalaReach session cannot be established ({}); {}",
            why,
            because
        ))),
    }
}

/// Where a command that ends or restarts the control daemon is run, said to a person it refuses.
const WHERE_TO_RUN: &str = "Run it in a terminal of this account that is not a KalaReach session, \
    such as a terminal window that was not opened through the KalaReach profile, or an SSH login.";

/// Refuses a command that ends or restarts the control daemon where it is run from inside a
/// session, which is an accident and not an attack: code that runs as this account can end the
/// daemon with the platform's own tools, and this guard does not claim to stop it.
///
/// `KR_SESSION` or `KR_ATTACHMENT` set here refuses at once. Otherwise every live session's worker
/// is asked at once ([`membership_together`]) whether this process is inside its session, so that
/// a process whose environment was cleaned is still found; the command is refused when one says it
/// is. A worker that cannot say lets the command go on, where [`require_outside`] refuses: a host
/// that has to be restarted may hold a worker that does not answer.
///
/// `command` is the command as a person types it, and `what_goes_on` is what the refusal says of
/// the sessions meanwhile.
///
/// # Errors
///
/// Returns a refusal with `PERMISSION_DENIED`, in its own words, that says nothing was stopped.
pub async fn require_outside_to_end_a_daemon(
    build_id: &BuildId,
    command: &'static str,
    what_goes_on: &'static str,
) -> Result<()> {
    for variable in [
        crate::resolve::SESSION_VARIABLE,
        crate::resolve::ATTACHMENT_VARIABLE,
    ] {
        if std::env::var_os(variable).is_some() {
            return Err(inside(shown!(
                "{} runs outside a KalaReach session, and {} is set here. {} Nothing was stopped. {}",
                command,
                variable,
                WHERE_TO_RUN,
                what_goes_on
            )));
        }
    }
    match membership_together(build_id).await {
        Membership::Inside(session_id) => Err(inside(shown!(
            "{} runs outside a KalaReach session, and this process is inside session {}. {} \
             Nothing was stopped. {}",
            command,
            session_id,
            WHERE_TO_RUN,
            what_goes_on
        ))),
        Membership::Outside | Membership::Unknown(_) => Ok(()),
    }
}

fn inside(message: Shown) -> CliError {
    CliError::refused_in_its_own_words(ErrorCode::PermissionDenied, message)
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
    mutate_within(
        client,
        method,
        target,
        params,
        kr_protocol::limits::DEFAULT_MUTATION_TTL,
    )
    .await
}

/// Calls a mutation on this session's worker that asks for a lifetime of `ttl`.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn mutate_within<P, T>(
    client: &mut LocalClient,
    method: Method,
    target: ActionTarget,
    params: &P,
    ttl: kr_protocol::scalars::DurationMs,
) -> Result<T>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let outcome = client
        .mutate_within(method, action_id, target, params, ttl)
        .await?;
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kr_protocol::ids::{EnvironmentId, SessionEpoch};
    use kr_protocol::scalars::{AuthorisationKey, TimestampMs, Uuid};

    use super::*;

    /// A descriptor that names a session and nothing a question reaches: the question is asked of
    /// the test's own closure.
    fn worker(session: u8) -> WorkerDescriptor {
        WorkerDescriptor {
            session_id: SessionId::new(Uuid::from_bytes([session; 16])),
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(Uuid::from_bytes([0xe0; 16])),
            display_number: kr_protocol::session::DisplayNumber::new(u64::from(session)),
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            process_start_identity: kr_ipc::identity::current_process_start_identity()
                .expect("a process identity"),
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            endpoint: String::new(),
            worker_public_key: AuthorisationKey::from_bytes([1; 32]),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(0),
        }
    }

    fn walked(sessions: &[u8]) -> Vec<Walked> {
        sessions
            .iter()
            .map(|session| Walked::Worker(worker(*session)))
            .collect()
    }

    /// How long a case waits for something that is going to happen: a bound on a hang.
    const LIVENESS: Duration = Duration::from_secs(60);

    /// Two workers that answer only once both have been asked: asked in turn, the first would wait
    /// for the second for ever, so the order of the questions is what the case shows, and no time.
    #[tokio::test]
    async fn the_workers_are_asked_together_and_not_in_turn() {
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let answered = tokio::time::timeout(
            LIVENESS,
            ask_together(walked(&[1, 2]), move |_| {
                let barrier = Arc::clone(&barrier);
                async move {
                    barrier.wait().await;
                    Probe::Outside
                }
            }),
        )
        .await
        .expect("both workers were asked before either answered");
        assert_eq!(answered, Membership::Outside);
    }

    /// The first worker that says this process is its own ends the question, and a worker that
    /// never answers is not waited for: the control of the case above.
    #[tokio::test]
    async fn the_first_worker_that_holds_the_process_ends_the_question() {
        let answered = tokio::time::timeout(
            LIVENESS,
            ask_together(walked(&[1, 2]), |descriptor| async move {
                if descriptor.display_number.0.get() == 2 {
                    Probe::Inside
                } else {
                    std::future::pending().await
                }
            }),
        )
        .await
        .expect("the answer of the worker that holds the process ends the question");
        assert_eq!(
            answered,
            Membership::Inside(SessionId::new(Uuid::from_bytes([2; 16])))
        );
    }

    /// A worker that gives neither answer leaves the membership unknown, which the commands that
    /// end a daemon let go on, where the guard of a command that shows a secret refuses.
    #[tokio::test]
    async fn a_worker_that_cannot_say_leaves_the_membership_unknown() {
        let answered = ask_together(walked(&[1, 2]), |descriptor| async move {
            if descriptor.display_number.0.get() == 1 {
                Probe::Outside
            } else {
                Probe::Silent(Shown::said("it did not answer in time"))
            }
        })
        .await;
        assert!(matches!(answered, Membership::Unknown(_)), "{answered:?}");
    }
}
