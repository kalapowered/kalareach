//! Finding the session this helper is running in, and calling its worker.
//!
//! The helper does not decide which session it is in. It finds candidate sessions from the
//! descriptors this host publishes, connects to each one's worker and asks; the worker answers
//! from the kernel's own record of the calling process. `KR_SESSION` only changes the order
//! candidates are tried in, which is what section 11 means by a lookup hint rather than a
//! credential.
//!
//! Outside every candidate the answer is `NOT_IN_KR_SESSION` with the setup instruction, and
//! nothing has been created anywhere.

use kr_ipc::client::LocalClient;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
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
#[derive(Clone, Debug)]
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
    Err(CliError::Refused(ProtocolError::new(
        ErrorCode::NotInKrSession,
        format!("this process is not inside a KalaReach session. {SETUP_INSTRUCTION}"),
    )))
}

/// Asks one worker whether this process is inside its session.
///
/// The probe reads a question that does not exist. A worker that does not hold this process
/// answers `NOT_IN_KR_SESSION` before it looks anything up, and one that does answers that the
/// question is unknown. Nothing is created either way.
async fn probes_bound(bound: &Bound, build_id: BuildId) -> bool {
    let Ok(mut client) = open(bound, build_id).await else {
        return false;
    };
    let params = QuestionReadOwnParams {
        session_id: bound.session_id(),
        question_id: QuestionId::new(kr_ipc::new_uuid()),
        caller_token: CallerToken::new(vec![0; kr_protocol::question::CALLER_TOKEN_BYTES]),
        wait_ms: Nullable::null(),
    };
    // Only a recognised binding outcome selects a worker. A worker that holds this process
    // answers that the question is unknown, which is `PERMISSION_DENIED`; one that does not holds
    // answers `NOT_IN_KR_SESSION`. Anything else — an unsupported method, a failing ledger, a
    // truncated connection — says nothing about where this process is, and choosing a session on
    // the strength of it would create the next question in the wrong one.
    match client.request(Method::QuestionReadOwn, &params).await {
        Ok(Err(error)) => error.code == ErrorCode::PermissionDenied,
        Ok(Ok(_)) => true,
        Err(_) => false,
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
    value
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer could not be read: {error}")))
}
