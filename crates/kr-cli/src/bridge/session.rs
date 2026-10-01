//! `kr new` and `kr attach` for a session in an enrolled environment.
//!
//! Section 3 gives a Windows host one way to create a session in a WSL distribution or a container
//! and to attach to it: the explicit process bridge. This command opens one to the destination's
//! control daemon to create, or to read what sessions it has, and one to the session's own worker
//! to attach, and it carries the same frames a local `kr` would send over a local socket.
//!
//! Creating and attaching are the two actions that may start the environment they name, so they
//! open the bridge with the opening's `start` set. A listing, an enrolment and a refresh never do.
//! A stopped distribution is started by running the helper in it, and the helper then reaches the
//! destination's own configured startup for its daemon.
//!
//! Three rules decide what crosses.
//!
//! * **A session starts from the destination.** Nothing of this host's working directory or
//!   environment is meaningful there. The directory is the destination user's home unless the
//!   person named one, and the variables are the helper's own allowlisted ones, which is what a
//!   `kr new` run there would have sent.
//! * **A create whose answer never arrives is not retried.** The bridge ended without saying
//!   whether the session exists, and a second create would make a second one. The person is told
//!   the action it was asked as, and that the outcome is not known.
//! * **A closed session is refused before a terminal is touched.** What the destination retains of
//!   it is read first, over a bridge, and an attach to a closed session says how it ended.

use kr_client::shown;
use kr_client::shown::{Said, Shown};
use kr_controller::bridge::invoke;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::identity::{BridgeTarget, EnvironmentEnrolment, WorkerProfile};
use kr_protocol::ids::{ActionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    ClosureRecord, Dimensions, LaunchProfile, PaletteRequest, Presentation, SessionCreateParams,
    SessionCreateResult, SessionListParams, SessionListResult, SessionState, ShellMode,
};

use crate::attach::Attaching;
use crate::bridge::environments;
use crate::bridge::link::{Answer, BridgedLink, Link, failed};
use crate::error::{CliError, Result};
use crate::resolve::SessionSelector;
use crate::session::{AttachOptions, AttachOutcome, UndeliveredTyping};

/// What a person asked a new session to be, in the terms this host can state.
///
/// Everything about where the session runs is the destination's to fill in: the directory unless
/// one was named, the variables, and the execution context unless one was chosen.
#[derive(Clone, Debug)]
pub struct NewSession {
    /// How the session is presented. An enrolled environment has no terminal application to open,
    /// so only attaching and no presentation at all are served.
    pub presentation: Presentation,
    /// The shell to launch, or none for the destination's configured default.
    pub shell: Option<String>,
    /// The shell integration mode.
    pub shell_mode: ShellMode,
    /// The working directory, in the destination, or none for the destination user's home.
    pub cwd: Option<String>,
    /// This terminal's size, where the session is attached.
    pub dimensions: Option<Dimensions>,
    /// The execution context, or none for the destination's own default.
    pub profile: Option<WorkerProfile>,
    /// The palette, or none for the profile's own.
    pub palette: Option<PaletteRequest>,
    /// The launch profile.
    pub launch_profile: LaunchProfile,
}

/// A session this host created in an enrolled environment.
#[derive(Debug)]
pub struct Created {
    /// What the destination answered.
    pub result: SessionCreateResult,
    /// The execution context the session was asked for: the one chosen, or the destination's own
    /// default.
    pub profile: WorkerProfile,
}

/// Where a session that a person named is, as the destination retains it.
#[derive(Debug)]
pub enum Found {
    /// A session that is live, and what an attachment needs to reach it.
    Live(Attaching),
    /// A session that has closed, and how, where the destination kept the record.
    Closed {
        /// The session.
        session_id: SessionId,
        /// How it ended.
        record: Option<ClosureRecord>,
    },
}

/// Opens a bridge to what `target` names in an enrolled environment.
///
/// This is where a stopped distribution starts: running the helper in it is what starts one. The
/// opening says that it may start what it needs, so the helper in a destination with no daemon
/// reaches the destination's own configured startup rather than failing for want of one.
async fn open(enrolment: &EnvironmentEnrolment, target: BridgeTarget) -> Result<BridgedLink> {
    let opening = invoke::open_for_person(
        enrolment,
        environments::origin_environment_id(),
        crate::build_id(),
        target,
        true,
    )
    .map_err(failed)?;
    let invocation = opening.launch().await.map_err(failed)?;
    Ok(BridgedLink::new(invocation.into_stream()))
}

/// Creates a session in an enrolled environment.
///
/// # Errors
///
/// Returns the destination's refusal, a failure to reach it, or `OUTCOME_UNKNOWN` when the bridge
/// ended before the destination answered the create.
pub async fn create(enrolment: &EnvironmentEnrolment, new: &NewSession) -> Result<Created> {
    let mut link = open(enrolment, BridgeTarget::Controller).await?;
    let made = create_over(&mut link, new).await;
    link.finish().await;
    made
}

async fn create_over(link: &mut BridgedLink, new: &NewSession) -> Result<Created> {
    // The identity that answered is the one the enrolment names: the opening was refused otherwise.
    let environment_id = link.acknowledgement().environment_id;
    let base = link.acknowledgement().base.clone();
    let profile = match new.profile {
        Some(profile) => profile,
        None => {
            let info: HostInfoResult = decode(link.request(Method::HostInfo, &()).await?)?;
            info.default_worker_profile
        }
    };
    let params = SessionCreateParams {
        environment_id,
        presentation: new.presentation,
        shell: Nullable(new.shell.clone()),
        shell_mode: new.shell_mode,
        cwd: Nullable::some(new.cwd.clone().unwrap_or(base.home)),
        dimensions: Nullable(new.dimensions),
        worker_profile: profile,
        environment_snapshot: base.variables,
        palette: Nullable(new.palette.clone()),
        launch_profile: new.launch_profile.clone(),
        terminal: Nullable::null(),
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let answer = link
        .mutate(
            Method::SessionCreate,
            action_id,
            ActionTarget::environment(environment_id),
            &params,
        )
        .await
        // The destination refuses in its answer. An error here is the bridge, which ended without
        // saying whether the session was made.
        .map_err(|_| CliError::Unfinished {
            code: ErrorCode::OutcomeUnknown,
            message: shown!(
                "the bridge ended before the environment answered the create, so whether it made \
                 the session is not known; it was asked as action {}. Look for the session with \
                 `kr attach` before creating another",
                action_id
            ),
        })?;
    Ok(Created {
        result: decode(answer)?,
        profile,
    })
}

/// Finds the session a person named in an enrolled environment.
///
/// The destination's daemon is asked, over a bridge, for every session it holds, closed ones
/// included: a display number is unique inside the environment, and only the daemon retains what a
/// closed session was.
///
/// # Errors
///
/// Returns the destination's refusal, a failure to reach it, or `UNKNOWN_SESSION`.
pub async fn locate(enrolment: &EnvironmentEnrolment, selector: &SessionSelector) -> Result<Found> {
    let mut link = open(enrolment, BridgeTarget::Controller).await?;
    let listed = listed(&mut link).await;
    link.finish().await;
    let sessions = listed?.sessions;
    let found = sessions.into_iter().find(|summary| match selector {
        SessionSelector::Display(number) => summary.display_number.get() == *number,
        SessionSelector::Identifier(session_id) => summary.session_id == *session_id,
    });
    let Some(summary) = found else {
        return Err(CliError::UnknownSession(selector.said()));
    };
    if summary.state == SessionState::Closed || summary.closure.is_present() {
        return Ok(Found::Closed {
            session_id: summary.session_id,
            record: summary.closure.0,
        });
    }
    Ok(Found::Live(Attaching {
        session_id: summary.session_id,
        environment_id: summary.environment_id,
        display_number: summary.display_number,
    }))
}

async fn listed(link: &mut BridgedLink) -> Result<SessionListResult> {
    decode(
        link.request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        )
        .await?,
    )
}

/// Attaches this terminal to a live session in an enrolled environment, and drives it until the
/// attachment ends.
///
/// The bridge to the session's worker is opened after this terminal has been asked what it is, as
/// a local attach opens its socket, and is ended once the terminal is the person's again.
///
/// # Errors
///
/// Returns the destination's refusal, a terminal failure, or the failure the attachment ended
/// with. A session that closed since it was located is `SESSION_CLOSED`.
pub async fn attach(
    enrolment: &EnvironmentEnrolment,
    attaching: Attaching,
    options: AttachOptions,
    owed: UndeliveredTyping,
) -> Result<(AttachOutcome, SessionId)> {
    let session_id = attaching.session_id;
    crate::session::run_over(
        attaching,
        || open(enrolment, BridgeTarget::Session { session_id }),
        owed,
        options,
    )
    .await
}

/// Reads what the destination answered as the type it should be.
fn decode<T: kr_protocol::wire::WireMessage>(answer: Answer) -> Result<T> {
    answer
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| {
            CliError::Other(shown!(
                "the environment's answer could not be read: {}",
                Shown::cbor(&error)
            ))
        })
}
