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
#[derive(Clone)]
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
pub struct Created {
    /// What the destination answered.
    pub result: SessionCreateResult,
    /// The execution context the session was asked for: the one chosen, or the destination's own
    /// default.
    pub profile: WorkerProfile,
}

/// Where a session that a person named is, as the destination retains it.
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

kr_client::debug_as_name!(NewSession);
kr_client::debug_as_name!(Created);
kr_client::debug_as_name!(Found);

/// Opens a bridge to what `target` names in an enrolled environment.
///
/// This is where a stopped distribution starts: running the helper in it is what starts one. The
/// opening says that it may start what it needs, so the helper in a destination with no daemon
/// reaches the destination's own configured startup rather than failing for want of one.
async fn open(enrolment: &EnvironmentEnrolment, target: BridgeTarget) -> Result<BridgedLink> {
    started(enrolment).await?;
    reach(enrolment, target, true).await
}

/// Opens a bridge to the control daemon of an enrolled environment that is already running, and
/// starts nothing.
///
/// The environment is checked as `require_running` does, and the opening says that it may not
/// start the environment's daemon either, so a running environment whose daemon is not is reported
/// by the helper.
///
/// # Errors
///
/// Returns `ENVIRONMENT_UNAVAILABLE` for an environment that is not running, and the destination's
/// refusal or a failure to reach it otherwise.
pub async fn open_running(enrolment: &EnvironmentEnrolment) -> Result<BridgedLink> {
    require_running(enrolment).await?;
    reach(enrolment, BridgeTarget::Controller, false).await
}

/// Refuses an enrolled environment that is not running, and starts nothing.
///
/// Running the helper in a stopped distribution starts it, and a container's runtime refuses to
/// run anything in a stopped one, so what the platform says of the environment is asked first, as
/// an enrolment by probe asks it: one that is not running is reported rather than started. Only a
/// refresh told to start it, a create or an attach may start an environment.
///
/// # Errors
///
/// Returns `ENVIRONMENT_UNAVAILABLE` for an environment that is not running, or that this host
/// could not ask about.
pub(crate) async fn require_running(enrolment: &EnvironmentEnrolment) -> Result<()> {
    use kr_controller::bridge::platform::PlatformObserver;
    use kr_controller::bridge::store::Observer as _;
    use kr_protocol::identity::EnvironmentPresence;

    let observed = {
        let enrolment = enrolment.clone();
        tokio::task::spawn_blocking(move || PlatformObserver.observe(&enrolment))
            .await
            .map_err(|_| CliError::Other(Shown::said("asking the environment did not finish")))?
    };
    match observed {
        Ok(EnvironmentPresence::Running) => Ok(()),
        Ok(_) | Err(_) => Err(CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(
                "the environment is not running, or this host could not ask whether it is, and \
                 this command starts nothing; start it, then run the command again",
            ),
        }),
    }
}

async fn reach(
    enrolment: &EnvironmentEnrolment,
    target: BridgeTarget,
    start: bool,
) -> Result<BridgedLink> {
    let opening = invoke::open_for_person(
        enrolment,
        environments::origin_environment_id(),
        crate::build_id(),
        target,
        start,
    )
    .map_err(failed)?;
    let invocation = opening.launch().await.map_err(failed)?;
    Ok(BridgedLink::new(invocation.into_stream()))
}

/// Starts the container an enrolment names, when it is stopped.
///
/// A WSL distribution is started by running the helper in it, and that is all starting one takes. A
/// container's runtime refuses to run anything in a stopped container, so it is started first, by
/// the platform's own command and only here, where a create or an attach asked for it. A
/// distribution, and a container that is already running, are left as they are.
async fn started(enrolment: &EnvironmentEnrolment) -> Result<()> {
    use kr_controller::bridge::platform::PlatformObserver;
    use kr_controller::bridge::store::Observer as _;
    use kr_protocol::identity::{EnvironmentAccess, EnvironmentPresence};

    if enrolment.access != EnvironmentAccess::Container {
        return Ok(());
    }
    let enrolment = enrolment.clone();
    tokio::task::spawn_blocking(move || {
        if PlatformObserver.observe(&enrolment)? == EnvironmentPresence::Running {
            return Ok(());
        }
        PlatformObserver.start(&enrolment)?;
        match PlatformObserver.observe(&enrolment)? {
            EnvironmentPresence::Running => Ok(()),
            _ => Err(kr_controller::error::ControllerError::supervision(
                "the container was asked to start and is not running".to_owned(),
            )),
        }
    })
    .await
    .map_err(|_| CliError::Other(Shown::said("starting the container did not finish")))?
    // What the runtime printed is the runtime's to write and is not repeated.
    .map_err(
        |_: kr_controller::error::ControllerError| CliError::Unfinished {
            code: ErrorCode::EnvironmentUnavailable,
            message: Shown::said(
                "the container this environment names could not be started; start it with its \
             runtime, or check that the runtime is installed",
            ),
        },
    )
}

/// Creates a session in an enrolled environment.
///
/// # Errors
///
/// Returns the destination's refusal, a failure to reach it, or `OUTCOME_UNKNOWN` when the bridge
/// ended before the destination answered the create.
pub async fn create(enrolment: &EnvironmentEnrolment, new: &NewSession) -> Result<Created> {
    let mut link = open(enrolment, BridgeTarget::Controller).await?;
    let made = create_over(&mut link, new, || open(enrolment, BridgeTarget::Controller)).await;
    // A failure of the bridge is returned as the create's own, and is not said again.
    link.finish_told().await;
    made
}

/// The worker profile the destination creates sessions with unless the person chose one.
///
/// Reading the destination's configuration is what puts it into force, so a ceiling edited there
/// takes effect during the read, and one that changes what a caller may do withdraws the authority
/// this connection was admitted under. That is the change working, not a failure, so the read is
/// made again on a new bridge, as a command on the destination's own host makes it again, and a
/// second refusal is the answer. `link` is replaced by the new bridge.
async fn default_profile<O, F>(link: &mut BridgedLink, reopen: O) -> Result<WorkerProfile>
where
    O: Fn() -> F,
    F: std::future::Future<Output = Result<BridgedLink>>,
{
    let mut answer = link.request(Method::HostInfo, &()).await?;
    if matches!(&answer, Err(refused) if refused.code == ErrorCode::PermissionDenied) {
        let fresh = reopen().await?;
        std::mem::replace(link, fresh).finish().await;
        answer = link.request(Method::HostInfo, &()).await?;
    }
    let info: HostInfoResult = decode(answer)?;
    Ok(info.default_worker_profile)
}

async fn create_over<O, F>(link: &mut BridgedLink, new: &NewSession, reopen: O) -> Result<Created>
where
    O: Fn() -> F,
    F: std::future::Future<Output = Result<BridgedLink>>,
{
    let profile = match new.profile {
        Some(profile) => profile,
        None => default_profile(link, reopen).await?,
    };
    // The identity that answered is the one the enrolment names: the opening was refused otherwise.
    // It is read after the profile, which may have been read on a new bridge.
    let environment_id = link.acknowledgement().environment_id;
    let base = link.acknowledgement().base.clone();
    let params = SessionCreateParams {
        environment_id,
        presentation: new.presentation,
        shell: Nullable(new.shell.clone()),
        shell_mode: new.shell_mode,
        cwd: Nullable::some(new.cwd.clone().unwrap_or(base.home)),
        dimensions: Nullable(new.dimensions),
        worker_profile: profile,
        environment_snapshot: crate::create::environment_snapshot(new.presentation, || {
            base.variables
        }),
        palette: Nullable(new.palette),
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
        // saying whether the session was made, and why it ended is said with that.
        .map_err(|stopped| CliError::Unfinished {
            code: ErrorCode::OutcomeUnknown,
            message: shown!(
                "the bridge ended before the environment answered the create, so whether it made \
                 the session is not known; it was asked as action {}. {}. Look for the session \
                 with `kr attach` before creating another",
                action_id,
                stopped.said()
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
    link.finish_told().await;
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
        || {
            open(
                enrolment,
                BridgeTarget::Session {
                    session_id,
                    // This terminal takes the clipboard writes the session asks for only where the
                    // owner named it as the environment's clipboard destination.
                    clipboard_writes: enrolment.takes_clipboard_writes(),
                },
            )
        },
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use kr_controller::bridge::invoke::Opening;
    use kr_controller::bridge::launch::BridgeCommand;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
    use kr_protocol::frame::{FrameCodec, StreamKind};
    use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION};
    use kr_protocol::identity::{
        BootIdentity, BootIdentitySource, BridgeFrame, BridgeHello, BridgeHelloAck, DestinationBase,
    };
    use kr_protocol::ids::{BuildId, ConnectionId, EnvironmentId, RequestId};
    use kr_protocol::local::LocalRole;
    use kr_protocol::scalars::{Bytes, DurationMs, TimestampMs, U64, Uuid};

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([3; 16]))
    }

    /// A bridge whose helper answers the opening and then the frames given, one per request, and
    /// stays until the bridge is closed on it.
    fn answering(answers: &[Outcome]) -> (tempfile::TempDir, Opening) {
        helper_of(answers, true)
    }

    /// A bridge whose helper answers the opening and then the frames given, and ends.
    fn answering_then_ending(answers: &[Outcome]) -> (tempfile::TempDir, Opening) {
        helper_of(answers, false)
    }

    /// A helper that has said all it will say stays for as long as the bridge to it is open, which
    /// is what a helper does: it ends when its standard input does. A helper that ended after a
    /// period of its own would end at a time the test does not control, and a test that was
    /// delayed past it would read a bridge that had ended.
    fn helper_of(answers: &[Outcome], stays: bool) -> (tempfile::TempDir, Opening) {
        let connection_id = ConnectionId::new(Uuid::from_bytes([7; 16]));
        let codec = FrameCodec::new(StreamKind::Control);
        let directory = tempfile::tempdir().expect("a temporary directory");
        let mut bytes = codec
            .encode_message(&BridgeFrame::HelloAck(Box::new(BridgeHelloAck {
                protocol_version: PROTOCOL_VERSION,
                build: Some(kr_protocol::local::LocalBuild::this(
                    BuildId::new("kr/0.1.0").expect("a build"),
                )),
                base: DestinationBase {
                    home: "/home/kala".to_owned(),
                    variables: Vec::new(),
                },
                environment_id: environment(),
                os_user: "kala".to_owned(),
                role: LocalRole::Controller,
                connection_id,
                boot_identity: BootIdentity {
                    source: BootIdentitySource::LinuxBootId,
                    value: Bytes::new(b"boot".to_vec()),
                },
                max_frame_len: U64::new(65_536),
                action_window: ActionWindow {
                    action_window_id: kr_protocol::ids::ActionWindowId::new("w").expect("a window"),
                    connection_id,
                    boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                    issued_at_ms: TimestampMs::new(0),
                    valid_for_ms: DurationMs::new(120_000),
                },
            })))
            .expect("encodes");
        for (index, outcome) in answers.iter().enumerate() {
            bytes.extend(
                codec
                    .encode_message(&BridgeFrame::Control(Box::new(ControlFrame::Response(
                        Response {
                            request_id: RequestId::new(index as u64 + 1),
                            outcome: outcome.clone(),
                        },
                    ))))
                    .expect("encodes"),
            );
        }
        let file = directory.path().join("answers");
        std::fs::write(&file, bytes).expect("written");
        let opening = Opening {
            command: BridgeCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    if stays {
                        "head -c 4 >/dev/null; cat \"$1\"; cat >/dev/null"
                    } else {
                        "head -c 4 >/dev/null; cat \"$1\""
                    }
                    .to_owned(),
                    "sh".to_owned(),
                    file.to_str().expect("text").to_owned(),
                ],
            },
            environment_id: environment(),
            hello: BridgeHello {
                protocol_version: PROTOCOL_VERSION,
                build_id: BuildId::new("kr-test/0").expect("a build"),
                origin_environment_id: EnvironmentId::new(Uuid::from_bytes([8; 16])),
                origin_ingress: ActorIngress::LocalIpc,
                already_bridged: false,
                start: true,
                target: BridgeTarget::Controller,
            },
        };
        (directory, opening)
    }

    async fn linked(opening: Opening) -> BridgedLink {
        BridgedLink::new(
            opening
                .launch()
                .await
                .expect("the helper answered")
                .into_stream(),
        )
    }

    fn host_info(profile: WorkerProfile) -> Outcome {
        Outcome::Ok(
            ParamsValue::from_typed(&HostInfoResult {
                build_id: BuildId::new("kr-controller/0.1.0").expect("a build"),
                protocol_version: PROTOCOL_VERSION,
                environment_id: environment(),
                generation: kr_protocol::ids::ControllerGeneration::new(1),
                boot_identity: BootIdentity {
                    source: BootIdentitySource::LinuxBootId,
                    value: Bytes::new(b"boot".to_vec()),
                },
                started_at_ms: TimestampMs::new(0),
                live_sessions: U64::new(0),
                session_limit: U64::new(128),
                default_worker_profile: profile,
                power: kr_protocol::desktop::SleepInhibitionState::off(
                    kr_protocol::desktop::InhibitionMechanism::None,
                    kr_protocol::desktop::PowerSource::Unknown,
                ),
                machine: None,
            })
            .expect("a payload"),
        )
    }

    fn withdrawn() -> Outcome {
        Outcome::Error(kr_protocol::error::ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the authority this connection was admitted under was withdrawn",
        ))
    }

    /// A ceiling that the read of the configuration puts into force withdraws the authority the
    /// first bridge was admitted under, so the read is made again on a new one, and what it answers
    /// is the profile.
    #[tokio::test]
    async fn a_profile_read_that_withdrew_its_own_authority_is_made_again_on_a_new_bridge() {
        let (_first, first) = answering(&[withdrawn()]);
        let (_second, second) = answering(&[host_info(WorkerProfile::DesktopBound)]);
        let second = std::cell::RefCell::new(Some(second));
        let mut link = linked(first).await;
        let opened = std::cell::Cell::new(0);
        let profile = default_profile(&mut link, || {
            opened.set(opened.get() + 1);
            let opening = second.borrow_mut().take().expect("opened once");
            async move { Ok(linked(opening).await) }
        })
        .await
        .expect("the second read answers");
        assert_eq!(profile, WorkerProfile::DesktopBound);
        assert_eq!(opened.get(), 1, "one new bridge, and no more");
        let _ = link.close().await;
    }

    /// A create whose bridge ends before it is answered says that it is not known whether the
    /// session was made, which action asked, and why the bridge ended: the command then says that
    /// and nothing else of the bridge.
    #[tokio::test]
    async fn a_create_whose_bridge_ends_unanswered_says_why_it_ended() {
        // The helper answers the opening and then says nothing more and ends.
        let (_directory, opening) = answering_then_ending(&[]);
        let mut link = linked(opening).await;
        let new = NewSession {
            presentation: Presentation::Invisible,
            shell: None,
            shell_mode: ShellMode::NativeCompat,
            cwd: None,
            dimensions: None,
            profile: Some(WorkerProfile::HeadlessUser),
            palette: None,
            launch_profile: LaunchProfile::default(),
        };
        let refused = create_over(&mut link, &new, || async {
            panic!("the profile was named, so nothing is read")
        })
        .await
        .expect_err("the bridge ended");
        let CliError::Unfinished { code, message } = &refused else {
            panic!("{refused:?}");
        };
        assert_eq!(*code, ErrorCode::OutcomeUnknown);
        let said = message.as_str();
        assert!(
            said.contains("whether it made the session is not known"),
            "{said}"
        );
        assert!(said.contains("it was asked as action"), "{said}");
        assert!(
            said.contains("said nothing for")
                || said.contains("the bridge to the environment failed"),
            "the reason the bridge ended is said: {said}"
        );
        let _ = link.close().await;
    }

    /// A second refusal is the answer: it is not read again.
    #[tokio::test]
    async fn a_second_refusal_of_the_profile_read_is_the_answer() {
        let (_first, first) = answering(&[withdrawn()]);
        let (_second, second) = answering(&[withdrawn()]);
        let second = std::cell::RefCell::new(Some(second));
        let mut link = linked(first).await;
        let refused = default_profile(&mut link, || {
            let opening = second.borrow_mut().take().expect("opened once");
            async move { Ok(linked(opening).await) }
        })
        .await;
        assert!(
            matches!(&refused, Err(CliError::Refused(error)) if error.code == ErrorCode::PermissionDenied),
            "{refused:?}"
        );
        let _ = link.close().await;
    }

    /// The control: a read that is answered is not made again.
    #[tokio::test]
    async fn a_profile_read_that_is_answered_opens_no_second_bridge() {
        let (_first, first) = answering(&[host_info(WorkerProfile::HeadlessUser)]);
        let mut link = linked(first).await;
        let profile = default_profile(&mut link, || async {
            panic!("a second bridge was opened");
            #[allow(unreachable_code)]
            Err(CliError::Other(Shown::said("unreachable")))
        })
        .await
        .expect("answered");
        assert_eq!(profile, WorkerProfile::HeadlessUser);
        let _ = link.close().await;
    }
}
