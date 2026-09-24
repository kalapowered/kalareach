//! Every command the WebView may call, and nothing else.
//!
//! Each command names one [`Method`] in its own body, and parses the page's parameters into that
//! method's own Rust type before anything is sent. The page supplies values; it never supplies a
//! method, a path or a command line, and a value it supplies that is not the shape the method
//! takes is refused here rather than on the wire.
//!
//! That parse is not a formality. The protocol's canonical encoding is KR-CBOR-1, where an
//! identifier is a byte string and a counter is an unsigned integer, while the same values in the
//! page's JSON are text. Passing the page's JSON straight through would put text on the wire where
//! the host expects bytes. Going through the typed struct is what makes the two agree.
//!
//! [`NAMED_COMMANDS`] is the surface as data, and the crate's tests hold it against the handler
//! list, so a command added in one place and not the other fails the build rather than widening
//! the boundary quietly.

use kr_protocol::method::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;

use crate::error::{CommandError, Result};
use crate::state::AppState;
use crate::target::Subject;
use crate::{export, links, pairing, remote, setup};

/// How long a mutation this application submits may stay acceptable.
///
/// Long enough that a person who presses a button and watches the receipt settle sees the outcome,
/// short enough that an application closed mid-action does not leave one acceptable for an hour.
pub const MUTATION_TTL: kr_protocol::scalars::DurationMs =
    kr_protocol::scalars::DurationMs::new(60_000);

/// The complete command surface, as a table of names and the methods they perform.
pub const NAMED_COMMANDS: &[(&str, Option<Method>)] = &[
    // Hosts and environments.
    ("host_info", Some(Method::HostInfo)),
    ("environment_list", Some(Method::EnvironmentList)),
    // First-start setup.
    (
        "environment_capabilities",
        Some(Method::EnvironmentCapabilities),
    ),
    ("setup_identity", None),
    ("setup_open_settings", None),
    // Sessions.
    ("session_list", Some(Method::SessionList)),
    ("session_read", Some(Method::SessionRead)),
    ("session_create", Some(Method::SessionCreate)),
    ("session_close", Some(Method::SessionClose)),
    // Attachments and the terminal view.
    ("session_attach", Some(Method::SessionAttach)),
    ("session_detach", Some(Method::SessionDetach)),
    ("attachment_configure", Some(Method::AttachmentConfigure)),
    ("attachment_viewport", Some(Method::AttachmentViewport)),
    ("terminal_resize", Some(Method::TerminalResize)),
    // Input.
    ("input_acquire", Some(Method::InputAcquire)),
    ("input_release", Some(Method::InputRelease)),
    ("input_interrupt", Some(Method::InputInterrupt)),
    ("input_write", Some(Method::InputWrite)),
    // The launch surface.
    ("shell_launch", Some(Method::ShellLaunch)),
    // Drafts and attachments.
    ("draft_create", Some(Method::DraftCreate)),
    ("draft_update", Some(Method::DraftUpdate)),
    (
        "draft_add_attachment",
        Some(Method::AgentDraftAddAttachment),
    ),
    ("attachment_upload", Some(Method::UploadBegin)),
    ("attachment_upload_status", Some(Method::UploadStatus)),
    ("attachment_image", Some(Method::DownloadBegin)),
    ("attachment_image_chunk", Some(Method::DownloadChunk)),
    // Events and history.
    ("events_subscribe", Some(Method::EventsSubscribe)),
    ("events_snapshot", Some(Method::EventsSnapshot)),
    ("history_page", Some(Method::HistoryPage)),
    ("action_read", Some(Method::ActionRead)),
    ("action_cancel", Some(Method::ActionCancel)),
    // Questions.
    ("question_read", Some(Method::QuestionRead)),
    ("question_answer", Some(Method::QuestionAnswer)),
    // Pairing.
    ("pairing_set_origin", None),
    ("pairing_view", None),
    ("pairing_start_code", None),
    ("pairing_paste", None),
    ("pairing_start_read", None),
    ("pairing_stop", None),
    // The owner's confirmations of this computer's hosts.
    ("owner_confirmations", None),
    ("owner_confirmation_review", None),
    // Voice.
    ("voice_prepare", Some(Method::VoicePrepare)),
    ("voice_start", Some(Method::VoiceStart)),
    ("voice_stop", Some(Method::VoiceStop)),
    ("voice_grant", Some(Method::VoiceGrant)),
    ("voice_delegate", Some(Method::VoiceDelegate)),
    ("voice_context", Some(Method::VoiceContext)),
    // The two local silences and the call's own state. They reach the call this device is holding
    // and no service at all, which is what keeps them working when the broker does not.
    ("voice_set_muted", None),
    ("voice_call_state", None),
    // The application's own boundary.
    ("open_external", None),
    ("import_remote_image", None),
    ("choose_export_destination", None),
    ("export_semantic_json", None),
    ("export_asciicast", None),
    ("connection_state", None),
];

/// The commands whose native code performs protocol methods of its own, and which.
///
/// Every one is a `None` entry in [`NAMED_COMMANDS`]: the page supplies none of these methods'
/// parameters. What reaches the host is built in native code from this computer's own state, its
/// keys, its records and what the host listed, and none of it is handed back to the page.
/// `owner.confirmation.complete` appears only under `owner_confirmation_review`, and `pair.finish`
/// and `pair.redeem` only under the two starts.
pub const NATIVE_METHODS: &[(&str, &[Method])] = &[
    (
        "pairing_start_code",
        &[
            Method::PairFinish,
            Method::PairStatus,
            Method::EnvironmentList,
        ],
    ),
    (
        "pairing_start_read",
        &[
            Method::PairRedeem,
            Method::PairFinish,
            Method::PairStatus,
            Method::EnvironmentList,
        ],
    ),
    ("owner_confirmations", &[Method::OwnerConfirmationPending]),
    (
        "owner_confirmation_review",
        &[
            Method::OwnerConfirmationPending,
            Method::OwnerConfirmationComplete,
        ],
    ),
];

/// The command handlers, in the form Tauri registers.
///
/// The page can reach exactly these. There is no handler that takes a method name.
pub fn handlers() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        host_info,
        environment_list,
        environment_capabilities,
        setup_identity,
        setup_open_settings,
        session_list,
        session_read,
        session_create,
        session_close,
        session_attach,
        session_detach,
        attachment_configure,
        attachment_viewport,
        terminal_resize,
        input_acquire,
        input_release,
        input_interrupt,
        input_write,
        shell_launch,
        draft_create,
        draft_update,
        draft_add_attachment,
        attachment_upload,
        attachment_upload_status,
        attachment_image,
        attachment_image_chunk,
        events_subscribe,
        events_snapshot,
        history_page,
        action_read,
        action_cancel,
        question_read,
        question_answer,
        pairing_set_origin,
        pairing_view,
        pairing_start_code,
        pairing_paste,
        pairing_start_read,
        pairing_stop,
        owner_confirmations,
        owner_confirmation_review,
        voice_prepare,
        voice_start,
        voice_stop,
        voice_grant,
        voice_delegate,
        voice_context,
        voice_set_muted,
        voice_call_state,
        open_external,
        import_remote_image,
        choose_export_destination,
        export_semantic_json,
        export_asciicast,
        connection_state,
    ]
}

/// A method that takes no parameters.
///
/// Serialised as the empty map the protocol's request shape expects, rather than as a null.
#[derive(Debug, Serialize)]
struct NoParams {}

/// The subject preconditions this application states.
///
/// None, deliberately. Every precondition this client relies on is one the method carries itself:
/// the prompt generation and buffer revision on a launch, the revision on a draft update, the
/// declared size and digest on an upload. A second copy in a separate map would be a second place
/// for them to disagree.
#[derive(Debug, Serialize)]
struct NoPreconditions {}

/// Parses the page's parameters into the method's own type.
fn decode<T: serde::de::DeserializeOwned>(params: Value) -> Result<T> {
    serde_json::from_value(params).map_err(|error| {
        CommandError::invalid(format!(
            "those are not this operation's parameters: {error}"
        ))
    })
}

/// Turns a method's result back into what the page reads.
fn encode<T: Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| {
        CommandError::local_failure(format!("the result could not be read: {error}"))
    })
}

/// What a mutation answered with: the receipt, and the method's own result when there was one.
///
/// Section 9 makes the receipt the outcome, so it travels beside the value rather than being
/// replaced by it. An interface that shows "applied" shows it because a receipt said so.
#[derive(Debug, Serialize)]
pub struct Settled {
    /// The receipt, when the host answered with one.
    pub receipt: Option<kr_protocol::receipt::Receipt>,
    /// The method's own result, when the host answered with one.
    pub value: Option<Value>,
    /// The action identifier, which exists from the moment the request is submitted.
    pub action_id: Option<String>,
}

fn settled(answer: &kr_client::Settled) -> Result<Settled> {
    Ok(match answer {
        kr_client::Settled::Receipt(receipt) => Settled {
            action_id: Some(receipt.action_id.to_string()),
            receipt: Some((**receipt).clone()),
            value: None,
        },
        kr_client::Settled::Result(value) => Settled {
            receipt: None,
            value: Some(encode(value)?),
            action_id: None,
        },
    })
}

/// Declares a command that performs one read and nothing else.
macro_rules! read_command {
    ($(#[$meta:meta])* $name:ident, $method:expr, () => $result:ty) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(state: State<'_, AppState>) -> Result<Value> {
            let session = state.session()?;
            let answer: $result = session.read($method, &NoParams {}).await?;
            encode(&answer)
        }
    };
    ($(#[$meta:meta])* $name:ident, $method:expr, $params:ty => $result:ty) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(state: State<'_, AppState>, params: Value) -> Result<Value> {
            let typed: $params = decode(params)?;
            let session = state.session()?;
            let answer: $result = session.read($method, &typed).await?;
            encode(&answer)
        }
    };
}

/// Declares a command that performs one mutation and nothing else.
macro_rules! mutate_command {
    ($(#[$meta:meta])* $name:ident, $method:expr, $params:ty) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(
            state: State<'_, AppState>,
            subject: Subject,
            params: Value,
        ) -> Result<Settled> {
            let typed: $params = decode(params)?;
            let target = subject.target(state.environment_id()?)?;
            let session = state.session()?;
            let answer = session
                .mutate($method, target, None, &NoPreconditions {}, &typed, MUTATION_TTL)
                .await;
            match answer {
                Ok(value) => settled(&value),
                // A submission whose outcome the host never confirmed still has an identity, and
                // the interface needs it: that is the action it asks about rather than resubmits.
                Err(kr_client::ClientError::SubmissionUncertain { action_id }) => Ok(Settled {
                    receipt: None,
                    value: None,
                    action_id: Some(action_id.to_string()),
                }),
                Err(error) => Err(CommandError::from(error)),
            }
        }
    };
}

read_command!(
    /// Reads what the host is.
    host_info, Method::HostInfo, () => kr_protocol::hostinfo::HostInfoResult
);
read_command!(
    /// Lists the host's execution environments.
    environment_list, Method::EnvironmentList, () => kr_protocol::hostinfo::EnvironmentListResult
);
read_command!(
    /// Reads what may actually be done on this environment's desktop.
    ///
    /// One document: the desktop, one record per capability with what produced it and what makes
    /// it stale, what a logout does to each execution profile, and the host's sleep setting. This
    /// is what first-start setup reads, and it is a read: nothing about asking for it grants
    /// anything or changes a setting.
    environment_capabilities, Method::EnvironmentCapabilities,
    kr_protocol::desktop::EnvironmentCapabilitiesParams
        => kr_protocol::desktop::EnvironmentCapabilitiesResult
);

read_command!(
    /// Lists the sessions a row is drawn for.
    session_list, Method::SessionList,
    kr_protocol::session::SessionListParams => kr_protocol::session::SessionListResult
);
read_command!(
    /// Reads one session.
    session_read, Method::SessionRead,
    kr_protocol::session::SessionReadParams => kr_protocol::session::SessionReadResult
);
read_command!(
    /// Reads the agent's questions.
    question_read, Method::QuestionRead,
    kr_protocol::question::QuestionReadParams => kr_protocol::question::QuestionReadResult
);
read_command!(
    /// Reads what became of one action.
    action_read, Method::ActionRead,
    kr_protocol::receipt::ActionReadParams => kr_protocol::receipt::ActionReadResult
);
read_command!(
    /// Subscribes to a stream from the cursor this client holds.
    events_subscribe, Method::EventsSubscribe,
    kr_protocol::recovery::EventsSubscribeParams => kr_protocol::recovery::EventsSubscribeResult
);
read_command!(
    /// Takes a session's snapshot at the cursor the subscription began from.
    events_snapshot, Method::EventsSnapshot,
    kr_protocol::recovery::EventsSnapshotParams => kr_protocol::recovery::EventsSnapshotResult
);
read_command!(
    /// Reads one page of retained history above the live screen.
    history_page, Method::HistoryPage,
    kr_protocol::recovery::HistoryPageParams => kr_protocol::recovery::HistoryPageResult
);
read_command!(
    /// Reads how much of an upload the host already holds.
    attachment_upload_status, Method::UploadStatus,
    kr_protocol::transfer::UploadStatusParams => kr_protocol::transfer::UploadStatusResult
);

mutate_command!(
    /// Creates a session.
    session_create, Method::SessionCreate, kr_protocol::session::SessionCreateParams
);
mutate_command!(
    /// Closes a session, after the interface has shown what closing does.
    session_close, Method::SessionClose, kr_protocol::session::SessionCloseParams
);
mutate_command!(
    /// Attaches a view to a session.
    session_attach, Method::SessionAttach, kr_protocol::attachment::SessionAttachParams
);
mutate_command!(
    /// Detaches a view.
    session_detach, Method::SessionDetach, kr_protocol::attachment::SessionDetachParams
);
mutate_command!(
    /// Configures what an attachment observes.
    attachment_configure, Method::AttachmentConfigure,
    kr_protocol::attachment::AttachmentConfigureParams
);
mutate_command!(
    /// Reports this view's viewport position and dimensions.
    attachment_viewport, Method::AttachmentViewport,
    kr_protocol::attachment::AttachmentViewportParams
);
mutate_command!(
    /// Asks for a terminal size.
    terminal_resize, Method::TerminalResize, kr_protocol::attachment::TerminalResizeParams
);
mutate_command!(
    /// Takes the input lease.
    input_acquire, Method::InputAcquire, kr_protocol::input::InputAcquireParams
);
mutate_command!(
    /// Releases the input lease.
    input_release, Method::InputRelease, kr_protocol::input::InputReleaseParams
);
mutate_command!(
    /// Interrupts the foreground application.
    input_interrupt, Method::InputInterrupt, kr_protocol::input::InputInterruptParams
);
mutate_command!(
    /// Launches an installed profile or a named command at a verified empty prompt.
    shell_launch, Method::ShellLaunch, kr_protocol::root::ShellLaunchParams
);
mutate_command!(
    /// Creates a draft on the host.
    draft_create, Method::DraftCreate, kr_protocol::transfer::DraftCreateParams
);
mutate_command!(
    /// Updates a draft on the host.
    draft_update, Method::DraftUpdate, kr_protocol::transfer::DraftUpdateParams
);
mutate_command!(
    /// Adds a completed attachment handle to a draft.
    draft_add_attachment, Method::AgentDraftAddAttachment,
    kr_protocol::transfer::AgentDraftAddAttachmentParams
);
read_command!(
    /// Begins reading an image through its validated attachment handle.
    ///
    /// This is the only way an image from a session reaches the page. A renderer that followed a
    /// URL out of agent text would be fetching whatever that text named; a handle names bytes the
    /// host verified. The registry marks it a read, so it is one: a mutation of a read method is
    /// refused by the session before it reaches the host.
    attachment_image, Method::DownloadBegin,
    kr_protocol::transfer::DownloadBeginParams => kr_protocol::transfer::DownloadBeginResult
);
read_command!(
    /// Reads one chunk of the source the handle named.
    attachment_image_chunk, Method::DownloadChunk,
    kr_protocol::transfer::DownloadChunkParams => kr_protocol::transfer::DownloadChunkResult
);
mutate_command!(
    /// Answers a question.
    question_answer, Method::QuestionAnswer, kr_protocol::question::QuestionAnswerParams
);
mutate_command!(
    /// Cancels a pending action.
    action_cancel, Method::ActionCancel, kr_protocol::receipt::ActionCancelParams
);
read_command!(
    /// Reads what a voice session started now would reach, and who would be able to read it.
    ///
    /// Section 15 ¶12 asks for the provider and the selected context scope before voice starts.
    /// This is the read that can answer that honestly: `voice.context` needs a voice session that
    /// does not exist yet, and by the time `voice.start` answers, the metered provider session has
    /// been created. Asking this creates nothing, so a person can read what a call would be and
    /// then decide not to make one.
    voice_prepare, Method::VoicePrepare,
    kr_protocol::voice::VoicePrepareParams => kr_protocol::voice::VoicePrepareResult
);

/// Starts a voice session on this device's own media.
///
/// The offer is this application's, not the page's. Section 15 ¶2 puts capture, playback and the
/// media path in native code, so the page names what it wants a call to reach and this asks the
/// native call for the offer that opens it. A device that cannot negotiate a connection refuses
/// here, before anything is submitted: the broker creates a metered provider session the moment a
/// start reaches it, and a session created for a device that can carry no audio is one a person
/// pays for and cannot use.
///
/// The answer is applied to the same call the offer came from, so the connection a person ends up
/// holding is the one the service answered.
///
/// `prepared` and `expected_rate_version` are the preparation and the version of the managed rate
/// the page showed the person, as the host answered them. Both are passed on untouched: the page is
/// where the person saw them, and a start that named anything else would accept a scope or terms
/// nobody was shown.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tauri::command]
pub async fn voice_start(
    state: State<'_, AppState>,
    subject: Subject,
    session_ids: Vec<String>,
    duration_seconds: u32,
    reasoning_budget_minor: Option<String>,
    prepared: kr_protocol::scalars::Digest256,
    expected_rate_version: Option<String>,
) -> Result<VoiceStarted> {
    // What the page sent is parsed before anything else is asked, so a start that is not a start's
    // shape is refused as that, whatever this device is doing.
    let mut sessions = Vec::with_capacity(session_ids.len());
    for value in &session_ids {
        sessions.push(
            value
                .parse::<kr_protocol::ids::SessionId>()
                .map_err(|_| CommandError::invalid("that is not a session identifier"))?,
        );
    }
    let reasoning_budget_minor = match reasoning_budget_minor {
        None => kr_protocol::scalars::Nullable::null(),
        Some(value) => kr_protocol::scalars::Nullable::some(kr_protocol::scalars::U64::new(
            value
                .parse::<u64>()
                .map_err(|_| CommandError::invalid("that is not an amount in minor units"))?,
        )),
    };

    // One call at a time. A second offer would leave the first call's media running with nothing
    // holding it, and this device has one microphone.
    if crate::audio::holding_a_call() {
        return Err(CommandError::refused(
            "this device is already holding a voice call",
        ));
    }

    let call = crate::audio::DesktopVoiceCall::new()?;
    let offer_sdp = call.offer().await?;

    let params = kr_protocol::voice::VoiceStartParams {
        session_ids: sessions.into_iter().collect(),
        offer_sdp,
        duration_seconds,
        reasoning_budget_minor,
        prepared,
        expected_rate_version: kr_protocol::scalars::Nullable(expected_rate_version),
    };
    let target = subject.target(state.environment_id()?)?;
    let session = state.session()?;
    let answer = session
        .mutate(
            Method::VoiceStart,
            target,
            None,
            &NoPreconditions {},
            &params,
            MUTATION_TTL,
        )
        .await;
    let answer = match answer {
        Ok(value) => value,
        Err(kr_client::ClientError::SubmissionUncertain { action_id }) => {
            return Ok(VoiceStarted {
                receipt: None,
                value: None,
                action_id: Some(action_id.to_string()),
            });
        }
        Err(error) => return Err(CommandError::from(error)),
    };

    let started = match &answer {
        kr_client::Settled::Receipt(receipt) => {
            return Ok(VoiceStarted {
                action_id: Some(receipt.action_id.to_string()),
                receipt: Some((**receipt).clone()),
                value: None,
            });
        }
        kr_client::Settled::Result(value) => value
            .to_typed::<kr_protocol::voice::VoiceStartResult>()
            .map_err(|error| {
                CommandError::local_failure(format!("that start could not be read: {error}"))
            })?,
    };

    // Only a started call has an answer to apply. The other two outcomes are answers in their own
    // right: nothing was created, so there is nothing to hold.
    if let kr_protocol::voice::VoiceStartOutcome::Started { session } = &started.outcome {
        call.accept(&session.answer_sdp).await?;
        // The microphone opens for this answer's voice session, until this answer's deadline, and
        // for nothing else.
        call.permit(
            &session.voice_session_id.to_string(),
            session.closes_at_ms.get(),
        )?;
        crate::audio::hold_call(call)?;
    }
    Ok(VoiceStarted {
        receipt: None,
        value: Some(started),
        action_id: None,
    })
}

/// Refuses to start a voice session from a phone build.
///
/// A phone's call is the native application's own, and this process opens none. The start is
/// refused before anything is submitted, as the desktop refuses one it cannot negotiate, so no
/// metered session is created for a call this process could not carry.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[tauri::command]
pub async fn voice_start(
    state: State<'_, AppState>,
    subject: Subject,
    session_ids: Vec<String>,
    duration_seconds: u32,
    reasoning_budget_minor: Option<String>,
    prepared: kr_protocol::scalars::Digest256,
    expected_rate_version: Option<String>,
) -> Result<VoiceStarted> {
    let _ = (
        state,
        subject,
        session_ids,
        duration_seconds,
        reasoning_budget_minor,
        prepared,
        expected_rate_version,
    );
    Err(CommandError::unavailable(
        "this application cannot open a voice call on this device",
    ))
}

/// What a start answered, in the method's own shape.
///
/// The typed result travels rather than the raw answer, because the page reads the descriptor
/// field by field: the model the call actually runs on, the disclosure the service published and
/// when the call closes are all things the screen shows, and a shape it cannot read is a screen
/// that invents them instead.
#[derive(Debug, Serialize)]
pub struct VoiceStarted {
    /// The receipt, when the host answered with one instead of a result.
    pub receipt: Option<kr_protocol::receipt::Receipt>,
    /// What the start became.
    pub value: Option<kr_protocol::voice::VoiceStartResult>,
    /// The action's durable identity, when the outcome of the submission is not known.
    pub action_id: Option<String>,
}

/// Ends the call this device is holding and revokes the voice session's grant.
///
/// The local call closes first. Section 15 ¶10 keeps local mute and transport closure working when
/// the broker fails, and a closure that waited for a service to answer before silencing a
/// microphone would fail at exactly the moment a person most wants it to work. What the host said
/// is reported beside the local closure rather than in place of it, so nothing here can report a
/// grant as revoked because a microphone stopped.
#[tauri::command]
pub async fn voice_stop(
    state: State<'_, AppState>,
    subject: Subject,
    voice_session_id: String,
) -> Result<VoiceClosure> {
    let closed_locally = crate::audio::stop_active_call();

    let typed = kr_protocol::voice::VoiceStopParams {
        voice_session_id: voice_session_id
            .parse()
            .map_err(|_| CommandError::invalid("that is not a voice session identifier"))?,
    };
    let told_the_host = async {
        let target = subject.target(state.environment_id()?)?;
        let session = state.session()?;
        let answer = session
            .mutate(
                Method::VoiceStop,
                target,
                None,
                &NoPreconditions {},
                &typed,
                MUTATION_TTL,
            )
            .await
            .map_err(CommandError::from)?;
        settled(&answer)
    }
    .await;

    Ok(match told_the_host {
        Ok(settled) => VoiceClosure {
            closed_locally,
            settled: Some(settled),
            host_failure: None,
        },
        Err(error) => VoiceClosure {
            closed_locally,
            settled: None,
            host_failure: Some(error),
        },
    })
}

/// What ending a call did, locally and on the host.
#[derive(Debug, Serialize)]
pub struct VoiceClosure {
    /// Whether this device's own call was closed. True whenever one was running.
    pub closed_locally: bool,
    /// What the host answered, when it could be told.
    pub settled: Option<Settled>,
    /// Why the host could not be told, when it could not.
    pub host_failure: Option<CommandError>,
}

/// Which of the two local silences a control acts on.
///
/// A closed pair rather than a string the page chooses, because the two are exactly the pair
/// section 15 ¶13 keeps apart: one silences this device's speaker and the other stops this
/// device's microphone. Neither reaches a host and neither cancels anything.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceMute {
    /// The person's own microphone.
    Microphone,
    /// The model's voice coming out of this device.
    Playback,
}

/// Silences the microphone or the speaker on this device.
///
/// Local and immediate: it acts on the call this device is holding and contacts nothing. That is
/// what KR-REQ-15.17 asks for, and it is why this is not a mutation.
#[tauri::command]
pub fn voice_set_muted(what: VoiceMute, muted: bool) -> Result<crate::audio::VoiceCallState> {
    crate::audio::set_muted(what_is_muted(what), muted)
}

/// Maps the page's word to the call's own.
const fn what_is_muted(what: VoiceMute) -> crate::audio::Silence {
    match what {
        VoiceMute::Microphone => crate::audio::Silence::Microphone,
        VoiceMute::Playback => crate::audio::Silence::Playback,
    }
}

/// What the call this device is holding is doing.
#[tauri::command]
pub fn voice_call_state() -> Result<crate::audio::VoiceCallState> {
    crate::audio::call_state()
}

mutate_command!(
    /// Creates or updates a voice grant.
    voice_grant, Method::VoiceGrant, kr_protocol::voice::VoiceGrantParams
);
/// The request a delegation continues, when it carries the evidence a host asked for.
///
/// `None` is a first submission, which is a new intent and takes a new identity.
fn delegation_continues(
    params: &kr_protocol::voice::VoiceDelegateParams,
) -> Option<kr_protocol::ids::ActionId> {
    params
        .confirmation
        .as_ref()
        .map(|proof: &kr_protocol::voice::VoiceConfirmationProof| proof.request.action_id)
}

/// Submits a voice delegation, with the confirmation the host asked for when it asked for one.
///
/// A delegation the host will not act on without a confirmation on this device's unlocked screen
/// is answered with a challenge rather than a receipt, and that challenge names the request it was
/// issued for. The signed proof therefore has to come back as that same request: a second intent
/// with a fresh identity is a delegation the host never challenged, and it refuses it.
///
/// The identity comes out of the proof itself, so the only request this can continue is the one
/// whose challenge is being answered. The host still checks the proof against the challenge it
/// issued, and this changes nothing about that.
#[tauri::command]
pub async fn voice_delegate(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<Settled> {
    let typed: kr_protocol::voice::VoiceDelegateParams = decode(params)?;
    let target = subject.target(state.environment_id()?)?;
    let session = state.session()?;
    let answer = match delegation_continues(&typed) {
        Some(action_id) => {
            session
                .mutate_continuing(
                    action_id,
                    Method::VoiceDelegate,
                    target,
                    None,
                    &NoPreconditions {},
                    &typed,
                    MUTATION_TTL,
                )
                .await
        }
        None => {
            session
                .mutate(
                    Method::VoiceDelegate,
                    target,
                    None,
                    &NoPreconditions {},
                    &typed,
                    MUTATION_TTL,
                )
                .await
        }
    };
    match answer {
        Ok(value) => settled(&value),
        Err(kr_client::ClientError::SubmissionUncertain { action_id }) => Ok(Settled {
            receipt: None,
            value: None,
            action_id: Some(action_id.to_string()),
        }),
        Err(error) => Err(CommandError::from(error)),
    }
}

read_command!(
    /// Reads the selected voice context.
    voice_context, Method::VoiceContext,
    kr_protocol::voice::VoiceContextParams => kr_protocol::voice::VoiceContextResult
);

/// Sends one dropped file to the host, and answers with the verified attachment handle.
///
/// The page never sees the file. The platform gives this process a path when the person drops
/// something on the window, the page passes that path back, and the shared client's upload
/// sequence does the rest: declare the size and digest, send the chunks, publish the handle.
#[tauri::command]
pub async fn attachment_upload(
    state: State<'_, AppState>,
    subject: Subject,
    path: String,
    session_id: Option<String>,
) -> Result<Value> {
    // Only a file this window was actually given. The platform hands the backend a path when a
    // person drops something on the window, and that path is spent by one upload. A path the page
    // names is refused, so this command is not a general file read.
    let path = state.take_dropped_file(std::path::Path::new(&path))?;
    let environment_id = state.environment_id()?;
    let target = subject.target(environment_id)?;
    let session = state.session()?;
    let session_id = match session_id {
        None => None,
        Some(value) => Some(
            value
                .parse()
                .map_err(|_| CommandError::invalid("that is not a session identifier"))?,
        ),
    };
    let handle =
        crate::transfers::upload(&session, target, environment_id, session_id, path).await?;
    encode(&handle)
}

/// Writes one ordered batch of raw terminal input.
///
/// Raw input is the one write that is not a mutation: section 9 makes it an ordered stream keyed
/// by connection, lease epoch and sequence, with no action identifier and no receipt. It has its
/// own command for that reason.
#[tauri::command]
pub async fn input_write(state: State<'_, AppState>, params: Value) -> Result<Value> {
    let typed: kr_protocol::input::InputWriteParams = decode(params)?;
    let session = state.session()?;
    let answer = session.write_input(&typed).await?;
    encode(&answer)
}

/// Changes the origin, before an attempt starts.
#[tauri::command]
pub fn pairing_set_origin(
    state: State<'_, AppState>,
    origin: String,
) -> Result<crate::device::OriginView> {
    state.device()?.set_origin(&origin)
}

/// Everything the pairing screen shows: the origin, this computer's name, where the attempt has
/// got to, a pasted invitation's summary and the paired hosts. None of it is a secret.
#[tauri::command]
pub fn pairing_view(state: State<'_, AppState>) -> Result<crate::device::PairingView> {
    Ok(state.device()?.view())
}

/// Starts pairing with a code the person typed. The code is the one secret the page ever holds, in
/// its own field; native code parses it here and never hands it back.
#[tauri::command]
pub fn pairing_start_code(state: State<'_, AppState>, code: String) -> Result<()> {
    state.device()?.start_code(&code)
}

/// Reads an invitation from the pasteboard in native code, and holds it for the person to use.
/// The page is told what it is, never what it says.
#[tauri::command]
pub async fn pairing_paste(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<crate::device::PasteView> {
    let device = state.device()?;
    Ok(pairing::paste(&app, &device).await)
}

/// Starts pairing with the invitation read from the pasteboard.
#[tauri::command]
pub fn pairing_start_read(state: State<'_, AppState>) -> Result<()> {
    state.device()?.start_held()
}

/// Ends the attempt on this computer, or drops a pasted invitation, and returns to the start.
#[tauri::command]
pub async fn pairing_stop(state: State<'_, AppState>) -> Result<()> {
    state.device()?.stop().await;
    Ok(())
}

/// The confirmations this computer's hosts ask for, as descriptions, and the ceremony this
/// computer offers.
#[tauri::command]
pub fn owner_confirmations(state: State<'_, AppState>) -> Result<crate::owner::OwnerView> {
    Ok(state.owner()?.view())
}

/// Reviews one confirmation by its reference: native code checks it, the platform's ceremony asks
/// the person, and only a confirmed ceremony in time signs it and completes it. The page names a
/// reference and nothing else; a request with any other member is refused.
#[tauri::command]
pub async fn owner_confirmation_review(
    state: State<'_, AppState>,
    request: crate::owner::ReviewRequest,
) -> Result<kr_client::pairing::owner::ReviewOutcome> {
    state.owner()?.review(&request.reference).await
}

/// Opens an external link, after checking its scheme.
#[tauri::command]
pub async fn open_external(app: tauri::AppHandle, url: String) -> Result<links::Approved> {
    let approved = links::approve(&url)?;
    tauri_plugin_opener::OpenerExt::opener(&app)
        .open_url(approved.url.clone(), None::<&str>)
        .map_err(|error| {
            CommandError::unavailable(format!("the link could not be opened: {error}"))
        })?;
    Ok(approved)
}

/// What the WebView receives for an explicitly imported image.
#[derive(Clone, Debug, Serialize)]
pub struct ImportedImage {
    /// The URL that was fetched.
    pub url: String,
    /// The media type the server declared.
    pub media_type: String,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// Imports one remote image, because a person asked for that one image.
///
/// Nothing calls this on its own. The renderer shows a placeholder with the URL and an import
/// action; this runs when the action does.
#[tauri::command]
pub async fn import_remote_image(url: String) -> Result<ImportedImage> {
    let imported = tauri::async_runtime::spawn_blocking(move || {
        let fetcher = remote::HttpsFetcher::new();
        remote::import(&url, &fetcher)
    })
    .await
    .map_err(|error| {
        CommandError::local_failure(format!("the import did not finish: {error}"))
    })??;
    Ok(ImportedImage {
        url: imported.url,
        media_type: imported.media_type,
        bytes: imported.bytes,
    })
}

/// Asks the person where an export should go.
///
/// The platform's own dialog answers, and the answer is remembered for exactly one write. The page
/// never names a path: it passes back what this returned, and a path this did not return is
/// refused.
#[tauri::command]
pub async fn choose_export_destination(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    suggested_name: String,
) -> Result<Option<String>> {
    use tauri_plugin_dialog::DialogExt as _;

    let name = safe_file_name(&suggested_name)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_file_name(&name)
        .save_file(move |path| {
            let _ = sender.send(path);
        });
    let chosen = receiver
        .await
        .map_err(|_| CommandError::local_failure("the save dialog did not answer"))?;
    let Some(chosen) = chosen else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|error| {
        CommandError::invalid(format!("that destination is not a path: {error}"))
    })?;
    let shown = path.to_string_lossy().into_owned();
    state.allow_export_to(path);
    Ok(Some(shown))
}

/// A suggested filename, with everything that is not part of a filename removed.
fn safe_file_name(suggested: &str) -> Result<String> {
    let name: String = suggested
        .chars()
        .filter(|character| !character.is_control() && !matches!(character, '/' | '\\' | ':'))
        .collect();
    let name = name.trim_matches(['.', ' ']).to_owned();
    if name.is_empty() || name.len() > 200 {
        return Err(CommandError::invalid("that is not a filename"));
    }
    Ok(name)
}

/// What an export wrote.
#[derive(Clone, Debug, Serialize)]
pub struct Written {
    /// The destination the person chose.
    pub path: String,
    /// How many bytes were written.
    pub byte_len: u64,
    /// What the export deliberately does not carry.
    pub omissions: Vec<export::Omission>,
}

/// Writes a session's semantic archive to the file the person chose.
#[tauri::command]
pub async fn export_semantic_json(
    state: State<'_, AppState>,
    path: String,
    session_id: String,
    exported_at_ms: u64,
    dimensions: export::Dimensions,
    nodes: Vec<export::ArchivedNode>,
    omissions: Vec<export::Omission>,
) -> Result<Written> {
    let destination = state.take_export_destination(std::path::Path::new(&path))?;
    let archive =
        export::semantic_archive(&session_id, exported_at_ms, dimensions, nodes, omissions)?;
    let body = serde_json::to_vec_pretty(&archive).map_err(|error| {
        CommandError::local_failure(format!("the archive could not be written: {error}"))
    })?;
    write_chosen_file(destination, &body).await?;
    Ok(Written {
        path,
        byte_len: body.len() as u64,
        omissions: archive.omissions,
    })
}

/// Writes a session's terminal recording to the file the person chose.
#[tauri::command]
pub async fn export_asciicast(
    state: State<'_, AppState>,
    path: String,
    title: String,
    started_at_unix_seconds: u64,
    dimensions: export::Dimensions,
    frames: Vec<RecordedFrame>,
    omissions: Vec<export::Omission>,
) -> Result<Written> {
    let destination = state.take_export_destination(std::path::Path::new(&path))?;
    let frames: Vec<export::Frame> = frames
        .into_iter()
        .map(|frame| export::Frame {
            at_ms: frame.at_ms,
            text: frame.text,
        })
        .collect();
    let cast = export::asciicast(
        dimensions,
        started_at_unix_seconds,
        &title,
        &frames,
        omissions,
    )?;
    write_chosen_file(destination, cast.body.as_bytes()).await?;
    Ok(Written {
        path,
        byte_len: cast.body.len() as u64,
        omissions: cast.omissions,
    })
}

/// One recorded slice of terminal output, as the page hands it over.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedFrame {
    /// Milliseconds since the recording began.
    pub at_ms: u64,
    /// The bytes, as text.
    pub text: String,
}

/// Writes one file at the destination the platform's save dialog returned.
async fn write_chosen_file(path: std::path::PathBuf, body: &[u8]) -> Result<()> {
    let body = body.to_vec();
    tauri::async_runtime::spawn_blocking(move || std::fs::write(&path, &body))
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("the export did not finish: {error}"))
        })?
        .map_err(|error| {
            CommandError::local_failure(format!("the export could not be written: {error}"))
        })
}

/// Whether this application holds a host connection, and why not when it does not.
/// Reads the identity an operating system would record a permission against.
///
/// Setup shows this before it guides anybody through a permission, because a grant belongs to a
/// signed application: an identity that moves between launches loses every grant it was given, and
/// finding that out after four settings panes is finding it out too late.
#[tauri::command]
pub async fn setup_identity(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<setup::identity::Identity> {
    let configuration = app.config();
    let helper = match state.session() {
        Ok(session) => {
            let host: kr_protocol::hostinfo::HostInfoResult =
                session.read(Method::HostInfo, &NoParams {}).await?;
            Some((host.build_id.to_string(), host.environment_id.to_string()))
        }
        // No host is an ordinary state at first start: the identity of this application is still
        // the thing setup has to show, and it is still readable without one.
        Err(_) => None,
    };
    Ok(setup::identity::read(
        &configuration.identifier,
        configuration.version.as_deref().unwrap_or("unknown"),
        helper,
    ))
}

/// Opens one of the platform's settings panes by name.
///
/// The page names a pane out of the application's own list. It never names an address, so this is
/// a route to four privacy panes rather than a command that opens whatever it is handed.
#[tauri::command]
pub async fn setup_open_settings(
    app: tauri::AppHandle,
    pane: String,
) -> Result<&'static setup::settings::Pane> {
    let found = setup::settings::pane(&pane).ok_or_else(|| {
        CommandError::refused(format!(
            "{pane} is not a settings pane this application opens"
        ))
    })?;
    tauri_plugin_opener::OpenerExt::opener(&app)
        .open_url(found.url, None::<&str>)
        .map_err(|error| {
            CommandError::local_failure(format!("the settings pane could not be opened: {error}"))
        })?;
    Ok(found)
}

/// Whether this application holds a host connection, and why not when it does not.
#[tauri::command]
pub fn connection_state(state: State<'_, AppState>) -> crate::connection::ConnectionState {
    state.connection_state()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A delegation, with the confirmation a host's challenge asked for when one is supplied.
    fn delegation(
        confirmation: Option<kr_protocol::ids::ActionId>,
    ) -> kr_protocol::voice::VoiceDelegateParams {
        use kr_protocol::ids::{ConfirmationId, DeviceId, VoiceSessionId};
        use kr_protocol::scalars::{Digest256, Nonce256, Nullable, TimestampMs, Uuid};

        let proof = confirmation.map(|action_id| kr_protocol::voice::VoiceConfirmationProof {
            request: kr_protocol::voice::VoiceConfirmationRequest {
                confirmation_id: ConfirmationId::new(Uuid::from_bytes([7; 16])),
                voice_session_id: VoiceSessionId::new(Uuid::from_bytes([8; 16])),
                action: kr_protocol::voice::VoiceAction::ApplyDiff,
                action_digest: Digest256::from_bytes([3; 32]),
                action_id,
                host_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
                device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
                nonce: Nonce256::from_bytes([4; 32]),
                expires_at_ms: TimestampMs::new(1_700_000_000_000),
            },
            signer_key_id: kr_protocol::scalars::KeyId::from_bytes([5; 32]),
            signature: kr_protocol::scalars::Signature64::from_bytes([6; 64]),
        });

        kr_protocol::voice::VoiceDelegateParams {
            voice_session_id: VoiceSessionId::new(Uuid::from_bytes([8; 16])),
            delegation_id: kr_protocol::voice::VoiceDelegationId::new("d-1".to_owned())
                .expect("a delegation identifier"),
            offset_ms: kr_protocol::scalars::U64::new(1_200),
            action: kr_protocol::voice::VoiceAction::ApplyDiff,
            session_id: Nullable::null(),
            spoken_destination: Nullable::null(),
            approval: Nullable::null(),
            turn_id: Nullable::null(),
            confirmation: Nullable(proof),
        }
    }

    #[test]
    fn a_confirmed_delegation_continues_the_request_the_challenge_names() {
        use kr_protocol::ids::ActionId;
        use kr_protocol::scalars::Uuid;

        // A first submission is a new intent, so it takes a new identity.
        assert_eq!(delegation_continues(&delegation(None)), None);

        // The confirmed submission answers one challenge, and that challenge was issued for one
        // request. Continuing anything else would be answering for a delegation the host never
        // challenged, and the host refuses that.
        let challenged = ActionId::new(Uuid::from_bytes([0xab; 16]));
        assert_eq!(
            delegation_continues(&delegation(Some(challenged))),
            Some(challenged)
        );
    }

    /// An application whose commands are `handler`, with no host configured, and the window its
    /// page runs in.
    fn page_with(
        handler: impl Fn(tauri::ipc::Invoke<tauri::test::MockRuntime>) -> bool + Send + Sync + 'static,
    ) -> (
        tauri::App<tauri::test::MockRuntime>,
        tauri::WebviewWindow<tauri::test::MockRuntime>,
    ) {
        let app = tauri::test::mock_builder()
            .manage(AppState::new())
            .invoke_handler(handler)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        (app, window)
    }

    /// Where the bundle's pages are served from: under the application's own scheme, except on
    /// Windows, where the web view serves it over `http` on a name of its own.
    #[cfg(windows)]
    const BUNDLE: &str = "http://tauri.localhost";
    #[cfg(not(windows))]
    const BUNDLE: &str = "tauri://localhost";

    /// Calls `command` the way the page does, through the invoke path, and returns what it was
    /// refused with: the refusal's code, or the invoke layer's own sentence when the refusal came
    /// from there, or nothing when the call succeeded.
    fn refusal_of(
        window: &tauri::WebviewWindow<tauri::test::MockRuntime>,
        command: &str,
        body: serde_json::Value,
    ) -> Option<String> {
        tauri::test::get_ipc_response(
            window,
            tauri::webview::InvokeRequest {
                cmd: command.into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: BUNDLE.parse().expect("the bundle's address"),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .err()
        .map(|error| match error["code"].as_str() {
            Some(code) => code.to_owned(),
            None => error.to_string(),
        })
    }

    /// This process holds at most one voice call, in the one holder every voice command reads, so
    /// a test that holds a call, or calls a command that starts or stops one, takes turns with it.
    static CALL_HOLDER: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Takes this test's turn with the call holder, whatever a failed test left the lock in.
    fn turn_with_the_call_holder() -> std::sync::MutexGuard<'static, ()> {
        CALL_HOLDER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn every_named_command_is_unique() {
        let mut seen = BTreeSet::new();
        for (command, _) in NAMED_COMMANDS {
            assert!(seen.insert(command), "{command} is registered twice");
        }
    }

    /// KR-REQ-10.01: the command table names none of the protocol methods listed here, each of which
    /// the page must never perform.
    #[test]
    fn no_command_reaches_a_method_outside_the_named_set() {
        // This test checks that no table entry names a method in the forbidden list.
        let reachable: BTreeSet<&str> = NAMED_COMMANDS
            .iter()
            .filter_map(|(_, method)| method.map(Method::as_str))
            .collect();
        for forbidden in [
            "session.describe",
            "session.rename",
            "project.clone",
            "workflow.run",
            "device.revoke",
            "plugin.install",
            "plugin.grant",
            "owner.confirmation.complete",
            "storage.upload.create",
            "storage.object.delete",
            "authority.sync",
            "grant.create",
            "pair.invite",
            "pair.confirm",
            "terminal.geometry.transfer",
            "root.editor.enter",
        ] {
            assert!(
                !reachable.contains(forbidden),
                "{forbidden} is reachable from the page and should not be"
            );
        }
    }

    #[test]
    fn no_command_names_a_method_the_registry_does_not_hold() {
        for (command, method) in NAMED_COMMANDS {
            if let Some(method) = method {
                assert!(
                    Method::ALL.contains(method),
                    "{command} names a method outside the registry"
                );
            }
        }
    }

    #[test]
    fn the_commands_that_perform_no_method_are_the_applications_own() {
        let local: BTreeSet<&str> = NAMED_COMMANDS
            .iter()
            .filter(|(_, method)| method.is_none())
            .map(|(command, _)| *command)
            .collect();
        assert_eq!(
            local,
            BTreeSet::from([
                "choose_export_destination",
                "connection_state",
                "export_asciicast",
                "export_semantic_json",
                "import_remote_image",
                "open_external",
                "pairing_set_origin",
                "pairing_view",
                "pairing_start_code",
                "pairing_paste",
                "pairing_start_read",
                "pairing_stop",
                "owner_confirmations",
                "owner_confirmation_review",
                // Setup's own two. Neither performs a protocol operation: one reads this
                // application's identity and one opens a settings pane by name.
                "setup_identity",
                "setup_open_settings",
                // Voice's own two. Both act on the call this device is holding and contact
                // nothing: section 15 paragraph 10 keeps local mute and transport closure working
                // when the broker fails, and a silence that had to be granted by a service is one
                // that would fail at exactly the moment a person needs it.
                "voice_call_state",
                "voice_set_muted",
            ])
        );
    }

    /// KR-REQ-10.06: the commands that perform protocol methods from native state are named in
    /// `NATIVE_METHODS`, each is a registered command the page supplies no method's parameters to,
    /// `owner.confirmation.complete` is performed only by the review, and `pair.finish` and
    /// `pair.redeem` only by the two starts. None of the pairing or confirmation methods is a page
    /// method.
    #[test]
    fn the_methods_native_code_performs_are_named_and_none_is_the_pages() {
        let local: BTreeSet<&str> = NAMED_COMMANDS
            .iter()
            .filter(|(_, method)| method.is_none())
            .map(|(command, _)| *command)
            .collect();
        let page: BTreeSet<Method> = NAMED_COMMANDS
            .iter()
            .filter_map(|(_, method)| *method)
            .collect();
        for (command, _) in NATIVE_METHODS {
            assert!(
                local.contains(command),
                "{command} is a registered command the page names no method through"
            );
        }
        // What only this computer's own state may drive is no page method at all.
        for method in [
            Method::PairFinish,
            Method::PairRedeem,
            Method::PairStatus,
            Method::OwnerConfirmationPending,
            Method::OwnerConfirmationComplete,
        ] {
            assert!(!page.contains(&method), "{method} is a page method");
        }
        let performing = |method: Method| -> BTreeSet<&str> {
            NATIVE_METHODS
                .iter()
                .filter(|(_, methods)| methods.contains(&method))
                .map(|(command, _)| *command)
                .collect()
        };
        assert_eq!(
            performing(Method::OwnerConfirmationComplete),
            BTreeSet::from(["owner_confirmation_review"])
        );
        assert_eq!(
            performing(Method::PairFinish),
            BTreeSet::from(["pairing_start_code", "pairing_start_read"])
        );
        assert_eq!(
            performing(Method::PairRedeem),
            BTreeSet::from(["pairing_start_read"])
        );
    }

    /// KR-REQ-10.06: a review names a reference and nothing else. A request that also carries a
    /// proof, a challenge or a channel is refused before anything runs.
    #[test]
    fn a_review_that_carries_anything_but_a_reference_is_refused() {
        let (_app, window) = page_with(tauri::generate_handler![owner_confirmation_review]);
        for extra in ["proof", "request", "channel"] {
            let mut body = serde_json::json!({ "request": { "reference": "a" } });
            body["request"][extra] = serde_json::json!("from the page");
            let refusal = refusal_of(&window, "owner_confirmation_review", body)
                .expect("the review is refused");
            assert!(refusal.contains("unknown field"), "{extra}: {refusal}");
        }
        assert_eq!(
            refusal_of(
                &window,
                "owner_confirmation_review",
                serde_json::json!({ "request": { "reference": "a" } })
            )
            .as_deref(),
            Some("RESOURCE_UNAVAILABLE"),
            "a well-formed review reaches the service, which this window has not opened"
        );
    }

    #[test]
    fn a_suggested_filename_cannot_carry_a_path() {
        assert_eq!(
            safe_file_name("../../etc/passwd").expect("a filename"),
            "etcpasswd",
            "a suggestion is a name, and separators and leading dots are not part of one"
        );
        assert_eq!(
            safe_file_name("session-1.json").expect("a filename"),
            "session-1.json"
        );
        assert!(safe_file_name("").is_err());
        assert!(safe_file_name("...").is_err());
        assert!(safe_file_name(&"a".repeat(300)).is_err());
    }

    /// KR-REQ-10.01: parameters from the WebView are validated before anything is sent. Called the
    /// way the page calls them, through the invoke path with no host configured, every command
    /// that performs a method refuses a parameter map that is not that method's shape with
    /// `INVALID_ARGUMENT`, which it can answer only by parsing before it asks for a host. The two
    /// reads that take nothing from the page go straight to that question, and the upload, which
    /// takes a path rather than a map, refuses one that nobody dropped. A voice start and a voice
    /// stop take their values one by one rather than as a map, and refuse values that are not what
    /// they claim to be in the same way; a phone build refuses every start before reading it. The
    /// stop closes the call this device is holding before it parses anything, on purpose: section
    /// 15 keeps a local stop available whatever else fails, and that closure contacts nothing.
    #[test]
    fn parameters_that_are_not_the_methods_shape_are_refused_before_anything_is_sent() {
        let refusal: Result<kr_protocol::session::SessionReadParams> =
            decode(serde_json::json!({ "session_id": "the one I was looking at" }));
        let error = refusal.expect_err("that is not a session identifier");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);

        // The voice stop below closes whatever call this process holds.
        let _turn = turn_with_the_call_holder();

        // Every command in the table that performs a method. A command added to the table and not
        // here is not found below, which fails this test rather than leaving it unchecked.
        let (_app, window) = page_with(tauri::generate_handler![
            host_info,
            environment_list,
            environment_capabilities,
            session_list,
            session_read,
            session_create,
            session_close,
            session_attach,
            session_detach,
            attachment_configure,
            attachment_viewport,
            terminal_resize,
            input_acquire,
            input_release,
            input_interrupt,
            input_write,
            shell_launch,
            draft_create,
            draft_update,
            draft_add_attachment,
            attachment_upload,
            attachment_upload_status,
            attachment_image,
            attachment_image_chunk,
            events_subscribe,
            events_snapshot,
            history_page,
            action_read,
            action_cancel,
            question_read,
            question_answer,
            voice_prepare,
            voice_start,
            voice_stop,
            voice_grant,
            voice_delegate,
            voice_context,
        ]);
        // One body for every command: each reads the arguments it takes and nothing else. The
        // voice start and stop read theirs one by one. The identifiers they parse themselves are
        // not identifiers, and the values the invoke layer types are of their types, so the
        // refusal is the command's own rather than the invoke layer's.
        let prepared = serde_json::to_value(kr_protocol::scalars::Digest256::from_bytes([0; 32]))
            .expect("a digest");
        let foreign = serde_json::json!({
            "subject": {},
            "params": { "a_field_no_method_takes": true },
            "path": "/a/file/nobody/dropped",
            "sessionId": null,
            "sessionIds": ["the session I was looking at"],
            "durationSeconds": 60,
            "prepared": prepared,
            "voiceSessionId": "the call I was on",
        });
        for (command, method) in NAMED_COMMANDS {
            if method.is_none() {
                continue;
            }
            let expected = match *command {
                "host_info" | "environment_list" => "HOST_NOT_CONFIGURED",
                "attachment_upload" => "PERMISSION_DENIED",
                // A phone opens no call in this process, so a phone build refuses every start
                // before it reads one.
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                "voice_start" => "RESOURCE_UNAVAILABLE",
                _ => "INVALID_ARGUMENT",
            };
            assert_eq!(
                refusal_of(&window, command, foreign.clone()).as_deref(),
                Some(expected),
                "{command} answers a shape its method does not take"
            );
        }
    }

    /// KR-REQ-10.01: a voice start parses what the page sent before it asks whether this device is
    /// holding a call. With a call held, a start whose session list or budget is not what it claims
    /// to be is refused with `INVALID_ARGUMENT` rather than as a second call, and the same start in
    /// its right shape is refused for the running call, which the refusals leave running.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn a_voice_start_parses_what_the_page_sent_before_it_asks_whether_a_call_is_held() {
        /// Stops the call this test holds, however the test ends.
        struct Held;
        impl Drop for Held {
            fn drop(&mut self) {
                crate::audio::stop_active_call();
            }
        }

        let _turn = turn_with_the_call_holder();
        let (_app, window) = page_with(tauri::generate_handler![voice_start]);
        let prepared = serde_json::to_value(kr_protocol::scalars::Digest256::from_bytes([0; 32]))
            .expect("a digest");
        let start = |session_ids: serde_json::Value, budget: serde_json::Value| {
            serde_json::json!({
                "subject": {},
                "sessionIds": session_ids,
                "durationSeconds": 60,
                "reasoningBudgetMinor": budget,
                "prepared": prepared,
            })
        };

        crate::audio::hold_call(crate::audio::DesktopVoiceCall::new().expect("a call"))
            .expect("this device holds the call");
        let _held = Held;

        let not_a_session = start(
            serde_json::json!(["the session I was looking at"]),
            serde_json::Value::Null,
        );
        assert_eq!(
            refusal_of(&window, "voice_start", not_a_session).as_deref(),
            Some("INVALID_ARGUMENT"),
            "a session list that names no session is refused as that, not as a second call"
        );
        let not_an_amount = start(serde_json::json!([]), serde_json::json!("a lot"));
        assert_eq!(
            refusal_of(&window, "voice_start", not_an_amount).as_deref(),
            Some("INVALID_ARGUMENT"),
            "a budget that is not an amount is refused as that, not as a second call"
        );
        let well_formed = start(serde_json::json!([]), serde_json::Value::Null);
        assert_eq!(
            refusal_of(&window, "voice_start", well_formed).as_deref(),
            Some("PERMISSION_DENIED"),
            "a start in its right shape is refused for the call this device is holding"
        );
        assert!(
            crate::audio::holding_a_call(),
            "and the refused starts left that call running"
        );
    }

    /// KR-REQ-13.21: a command that is handed a path acts only on one the platform gave this
    /// process: a file dropped on the window, or a destination a save dialog returned. Called the
    /// way the page calls it, through the invoke path, any other path is refused with
    /// `PERMISSION_DENIED` before anything is read or written, and a path the platform handed over
    /// passes that gate once.
    #[test]
    fn a_path_the_page_names_is_refused_at_the_command_boundary() {
        use tauri::Manager as _;

        // Every command the page hands a path: the upload and both exports.
        let (app, window) = page_with(tauri::generate_handler![
            attachment_upload,
            export_semantic_json,
            export_asciicast
        ]);
        let refusal_code =
            |command: &str, body: serde_json::Value| refusal_of(&window, command, body);
        let state = app.state::<AppState>();

        // An upload of a file the page names, which nobody dropped on this window.
        let upload =
            |path: &str| serde_json::json!({ "subject": {}, "path": path, "sessionId": null });
        assert_eq!(
            refusal_code("attachment_upload", upload("/etc/passwd")).as_deref(),
            Some("PERMISSION_DENIED"),
            "a path the page names is not a file this window was given"
        );
        // A dropped file passes the gate, and stops only at the next step, which needs a host.
        state.dropped([std::path::PathBuf::from("/tmp/diagram.png")]);
        assert_eq!(
            refusal_code("attachment_upload", upload("/tmp/diagram.png")).as_deref(),
            Some("HOST_NOT_CONFIGURED"),
            "a dropped file is the one the gate lets through"
        );
        assert_eq!(
            refusal_code("attachment_upload", upload("/tmp/diagram.png")).as_deref(),
            Some("PERMISSION_DENIED"),
            "and it is spent by that one upload"
        );

        // An export to a destination the page names, which no save dialog returned.
        let directory = tempfile::tempdir().expect("a directory for the export");
        let export = |path: &std::path::Path| {
            serde_json::json!({
                "path": path.display().to_string(),
                "sessionId": "44444444-4444-4444-8444-444444444444",
                "exportedAtMs": 1,
                "dimensions": { "columns": 80, "rows": 24 },
                "nodes": [],
                "omissions": []
            })
        };
        let named = directory.path().join("named-by-the-page.json");
        assert_eq!(
            refusal_code("export_semantic_json", export(&named)).as_deref(),
            Some("PERMISSION_DENIED"),
            "a destination the page names is not one the person chose"
        );
        assert!(!named.exists(), "and nothing is written there");
        // A destination the dialog returned is written, once.
        let chosen = directory.path().join("chosen.json");
        state.allow_export_to(chosen.clone());
        assert_eq!(refusal_code("export_semantic_json", export(&chosen)), None);
        assert!(chosen.exists(), "the chosen destination is written");
        assert_eq!(
            refusal_code("export_semantic_json", export(&chosen)).as_deref(),
            Some("PERMISSION_DENIED"),
            "one dialog is one write"
        );

        // A terminal recording goes through the same gate.
        let recording = |path: &std::path::Path| {
            serde_json::json!({
                "path": path.display().to_string(),
                "title": "a session",
                "startedAtUnixSeconds": 1,
                "dimensions": { "columns": 80, "rows": 24 },
                "frames": [],
                "omissions": []
            })
        };
        let named_recording = directory.path().join("named-by-the-page.cast");
        assert_eq!(
            refusal_code("export_asciicast", recording(&named_recording)).as_deref(),
            Some("PERMISSION_DENIED"),
            "a destination the page names is not one the person chose"
        );
        assert!(!named_recording.exists(), "and nothing is written there");
        let chosen_recording = directory.path().join("chosen.cast");
        state.allow_export_to(chosen_recording.clone());
        assert_eq!(
            refusal_code("export_asciicast", recording(&chosen_recording)),
            None
        );
        assert!(
            chosen_recording.exists(),
            "the chosen destination is written"
        );
        assert_eq!(
            refusal_code("export_asciicast", recording(&chosen_recording)).as_deref(),
            Some("PERMISSION_DENIED"),
            "one dialog is one write"
        );
    }

    /// KR-REQ-10.01: an unknown field from the WebView is refused. Called the way the page calls it,
    /// `session_read` with a complete parameter map passes the parse and stops only at the host
    /// question, and the same map with one field the method does not declare is refused with
    /// `INVALID_ARGUMENT` before the host is asked.
    #[test]
    fn a_parameter_map_with_an_unknown_field_is_refused() {
        let complete = serde_json::json!({ "session_id": "44444444-4444-4444-8444-444444444444" });
        let mut widened = complete.clone();
        widened["and_also"] = serde_json::json!("run this");
        let refusal: Result<kr_protocol::session::SessionReadParams> = decode(widened.clone());
        assert!(
            refusal.is_err(),
            "a closed schema refuses what it does not name"
        );

        let (_app, window) = page_with(tauri::generate_handler![session_read]);
        assert_eq!(
            refusal_of(
                &window,
                "session_read",
                serde_json::json!({ "params": complete })
            )
            .as_deref(),
            Some("HOST_NOT_CONFIGURED"),
            "a complete map passes the parse and stops at the host question"
        );
        assert_eq!(
            refusal_of(
                &window,
                "session_read",
                serde_json::json!({ "params": widened })
            )
            .as_deref(),
            Some("INVALID_ARGUMENT"),
            "one field the method does not declare is refused"
        );
    }
}
