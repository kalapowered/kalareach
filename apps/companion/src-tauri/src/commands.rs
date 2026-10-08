//! Every command the WebView may call, and nothing else.
//!
//! Each command that performs a method names one [`Method`] in its own body, and parses the page's
//! parameters into that method's own Rust type before anything is sent. The page supplies values;
//! it never supplies a method, a path or a command line, and a value it supplies that is not the
//! shape the method takes is refused here rather than on the wire.
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
    // What a session is called and doing, for the rows that list sessions: an authorised read of
    // filtered metadata, which takes a session and nothing else.
    ("session_describe", Some(Method::SessionDescribe)),
    // Session descriptions as the host offers them at setup: what they cost before anything is
    // fetched, the two settings an owner has, and the fetch itself.
    ("description_setup", Some(Method::DescriptionSetup)),
    ("description_configure", Some(Method::DescriptionConfigure)),
    ("description_download", Some(Method::DescriptionDownload)),
    // The raw terminal view. Its attachment is made on the session's own worker, from native
    // code: the page names a session, a size, the moves it makes and the person's input, never a
    // method.
    ("terminal_view_open", None),
    ("terminal_view_resize", None),
    ("terminal_view_move", None),
    ("terminal_view_input", None),
    ("terminal_view_close", None),
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
    ("attachment_upload_bytes", Some(Method::UploadBegin)),
    ("attachment_upload_status", Some(Method::UploadStatus)),
    ("attachment_image", Some(Method::DownloadBegin)),
    ("attachment_image_chunk", Some(Method::DownloadChunk)),
    // History and receipts. A live session's are read from its own worker, and a closed one's from
    // the host's archive.
    ("history_page", Some(Method::HistoryPage)),
    ("action_read", Some(Method::ActionRead)),
    ("action_cancel", Some(Method::ActionCancel)),
    // Questions.
    ("question_read", Some(Method::QuestionRead)),
    ("question_answer", Some(Method::QuestionAnswer)),
    // The agent. Each goes to the session's own worker, which checks the caller itself: the page
    // supplies the method's parameters, and the link, the envelope and its target are native
    // code's. A prompt that names a draft goes through the host's daemon, which holds the draft.
    ("agent_capabilities", Some(Method::AgentCapabilities)),
    ("agent_snapshot", Some(Method::AgentSnapshot)),
    ("agent_commands", Some(Method::AgentCommands)),
    ("agent_approval_inspect", Some(Method::AgentApprovalInspect)),
    ("agent_prompt_submit", Some(Method::AgentPromptSubmit)),
    ("agent_prompt_queue", Some(Method::AgentPromptQueue)),
    ("agent_turn_steer", Some(Method::AgentTurnSteer)),
    ("agent_turn_cancel", Some(Method::AgentTurnCancel)),
    ("agent_approval_respond", Some(Method::AgentApprovalRespond)),
    ("session_agents", None),
    // Attention and review.
    ("attention_read", Some(Method::AttentionRead)),
    ("attention_acknowledge", Some(Method::AttentionAcknowledge)),
    ("review_read", Some(Method::ReviewRead)),
    ("review_acknowledge", Some(Method::ReviewAcknowledge)),
    // Change sets.
    ("changeset_read", Some(Method::ChangesetRead)),
    // Sharing: the devices an invitation can go to, what one would carry, issuing it and the
    // grants issued.
    ("device_list", Some(Method::DeviceList)),
    ("grant_notices", None),
    ("grant_create", Some(Method::GrantCreate)),
    ("grant_list", Some(Method::GrantList)),
    // Packages.
    ("plugin_list", Some(Method::PluginList)),
    ("catalogue_list", Some(Method::CatalogueList)),
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
    // The host a phone's commands go to.
    ("hosts_use", None),
    // Voice. The start names its method for the table, and this process refuses it before sending.
    ("voice_prepare", Some(Method::VoicePrepare)),
    ("voice_start", Some(Method::VoiceStart)),
    ("voice_stop", Some(Method::VoiceStop)),
    ("voice_allow", Some(Method::VoiceGrant)),
    ("voice_scope", None),
    ("voice_delegate", Some(Method::VoiceDelegate)),
    ("voice_context", Some(Method::VoiceContext)),
    // The two local silences and the call's own state. They reach no service at all. This process
    // holds no call, so the silences are refused and the state is a device holding none.
    ("voice_set_muted", None),
    ("voice_call_state", None),
    // The application's own boundary.
    ("open_external", None),
    ("import_remote_image", None),
    ("choose_export_destination", None),
    ("export_semantic_json", None),
    ("export_asciicast", None),
    ("connection_state", None),
    // The account: this device signing in through the system browser. None is a host method and
    // none takes an address; the page asks, and is told where it stands.
    ("account_status", None),
    ("account_sign_in", None),
    ("account_sign_in_cancel", None),
    ("account_sign_out", None),
    ("account_usage", None),
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
    // The host's own account of which environment it is, read once the connection to a paired
    // host is up: the connection carries none on its handshake.
    ("hosts_use", &[Method::HostInfo]),
    ("owner_confirmations", &[Method::OwnerConfirmationPending]),
    (
        "owner_confirmation_review",
        &[
            Method::OwnerConfirmationPending,
            Method::OwnerConfirmationComplete,
        ],
    ),
    // A view attaches, subscribes, reports its size and its window's place, takes and gives back
    // the input lease, writes the person's wheel turns and keys under it, and detaches, all on the
    // session's worker. The page supplies a session, a grid, its moves and the person's input; what
    // reaches the worker is built here.
    (
        "terminal_view_open",
        &[
            Method::SessionAttach,
            Method::EventsSubscribe,
            Method::AttachmentViewport,
            Method::SessionDetach,
        ],
    ),
    ("terminal_view_resize", &[Method::AttachmentViewport]),
    ("terminal_view_move", &[Method::AttachmentViewport]),
    (
        "terminal_view_input",
        &[
            Method::InputAcquire,
            Method::InputRelease,
            Method::InputWrite,
        ],
    ),
    ("terminal_view_close", &[Method::SessionDetach]),
    // The page names a session; native code reads the snapshot of its agent instances and of every
    // request its broker is arbitrating, following the pages of that one snapshot, on the
    // session's own worker.
    ("session_agents", &[Method::EventsSnapshot]),
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
        session_describe,
        description_setup,
        description_configure,
        description_download,
        terminal_view_open,
        terminal_view_resize,
        terminal_view_move,
        terminal_view_input,
        terminal_view_close,
        shell_launch,
        draft_create,
        draft_update,
        draft_add_attachment,
        attachment_upload,
        attachment_upload_bytes,
        attachment_upload_status,
        attachment_image,
        attachment_image_chunk,
        history_page,
        action_read,
        action_cancel,
        question_read,
        question_answer,
        agent_capabilities,
        agent_snapshot,
        agent_commands,
        agent_approval_inspect,
        agent_prompt_submit,
        agent_prompt_queue,
        agent_turn_steer,
        agent_turn_cancel,
        agent_approval_respond,
        session_agents,
        attention_read,
        attention_acknowledge,
        review_read,
        review_acknowledge,
        changeset_read,
        device_list,
        grant_notices,
        grant_create,
        grant_list,
        plugin_list,
        catalogue_list,
        pairing_set_origin,
        pairing_view,
        pairing_start_code,
        pairing_paste,
        pairing_start_read,
        pairing_stop,
        owner_confirmations,
        owner_confirmation_review,
        hosts_use,
        voice_prepare,
        voice_start,
        voice_stop,
        voice_allow,
        voice_scope,
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
        account_status,
        account_sign_in,
        account_sign_in_cancel,
        account_sign_out,
        account_usage,
    ]
}

/// A method that takes no parameters.
///
/// Serialised as the empty map the protocol's request shape expects, rather than as a null.
#[derive(Debug, Serialize)]
pub(crate) struct NoParams {}

/// The subject preconditions this application states.
///
/// None, deliberately. Every precondition this client relies on is one the method carries itself:
/// the prompt generation and buffer revision on a launch, the revision on a draft update, the
/// declared size and digest on an upload. A second copy in a separate map would be a second place
/// for them to disagree.
#[derive(Debug, Serialize)]
pub(crate) struct NoPreconditions {}

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

/// What the page is told of one submitted mutation.
///
/// A submission whose outcome the host never confirmed still has an identity, and the interface
/// needs it: that is the action it asks about rather than resubmits.
fn submitted(
    answer: std::result::Result<kr_client::Settled, kr_client::ClientError>,
) -> Result<Settled> {
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
            submitted(
                session
                    .mutate($method, target, None, &NoPreconditions {}, &typed, MUTATION_TTL)
                    .await,
            )
        }
    };
}

/// Declares a command that performs one read on the session's own worker.
///
/// The parameters name the session and the exact agent instance, and the read goes to that
/// session's worker and to nothing else.
macro_rules! agent_read_command {
    ($(#[$meta:meta])* $name:ident, $method:expr, $params:ty => $result:ty) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(
            links: State<'_, crate::agent::WorkerLinks>,
            params: Value,
        ) -> Result<Value> {
            let typed: $params = decode(params)?;
            let answer: $result = links
                .read(typed.subject.session_id, $method, &typed)
                .await?;
            encode(&answer)
        }
    };
}

/// Declares a command that submits one agent mutation to the session's own worker.
///
/// The parameters name the session, the instance and the binding revision they were prepared
/// against, and the envelope's target is built from exactly those, so the two cannot disagree.
/// `$check` refuses what the parameters' own type cannot, before anything is sent.
macro_rules! agent_mutate_command {
    ($(#[$meta:meta])* $name:ident, $method:expr, $params:ty, $check:expr) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(
            links: State<'_, crate::agent::WorkerLinks>,
            params: Value,
        ) -> Result<Settled> {
            let typed: $params = decode(params)?;
            let check: fn(&$params) -> std::result::Result<(), &'static str> = $check;
            check(&typed).map_err(CommandError::invalid)?;
            let target = typed.target;
            submitted(
                links
                    .mutate(
                        target.subject.session_id,
                        target.subject.application_instance_id,
                        target.binding_revision,
                        $method,
                        &typed,
                    )
                    .await?,
            )
        }
    };
}

/// Declares a command that sends one prompt to a session's agent.
///
/// A prompt that carries its text goes to the session's own worker, as every agent call does. A
/// prompt that names a draft goes through the host's control daemon instead, which holds the draft
/// and its attachments: the daemon records that the draft is sent to the session before it passes
/// the prompt to the worker, so what was submitted follows the session's retention. The worker
/// serves a prompt that names a draft to nothing else.
macro_rules! agent_prompt_command {
    ($(#[$meta:meta])* $name:ident, $method:expr) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(
            state: State<'_, AppState>,
            links: State<'_, crate::agent::WorkerLinks>,
            params: Value,
        ) -> Result<Settled> {
            let typed: kr_protocol::agent::AgentPromptParams = decode(params)?;
            typed.validate().map_err(CommandError::invalid)?;
            let target = typed.target;
            if typed.draft_id.is_present() {
                return send_draft_prompt(&state, $method, &typed).await;
            }
            submitted(
                links
                    .mutate(
                        target.subject.session_id,
                        target.subject.application_instance_id,
                        target.binding_revision,
                        $method,
                        &typed,
                    )
                    .await?,
            )
        }
    };
}

/// Sends a prompt that names a draft through the host's control daemon.
///
/// The envelope's target is built here from the session the daemon reports and the instance and
/// revision the parameters name, so the two cannot disagree.
async fn send_draft_prompt(
    state: &AppState,
    method: Method,
    params: &kr_protocol::agent::AgentPromptParams,
) -> Result<Settled> {
    let session = state.session()?;
    let session_id = params.target.subject.session_id;
    let read: kr_protocol::session::SessionReadResult = session
        .read(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await?;
    let target = kr_protocol::envelope::ActionTarget {
        environment_id: state.environment_id()?,
        session_id: kr_protocol::scalars::Nullable::some(session_id),
        session_epoch: kr_protocol::scalars::Nullable::some(read.session.session_epoch),
        application_instance_id: kr_protocol::scalars::Nullable::some(
            params.target.subject.application_instance_id,
        ),
        agent_binding_revision: kr_protocol::scalars::Nullable::some(
            params.target.binding_revision,
        ),
    };
    target
        .validate()
        .map_err(|error| CommandError::invalid(error.to_string()))?;
    submitted(
        session
            .mutate(
                method,
                target,
                None,
                &NoPreconditions {},
                params,
                MUTATION_TTL,
            )
            .await,
    )
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
    /// Reads what one session is called and what it is doing: the title and where it came from,
    /// the generated activity line when there is one, and how current it is.
    ///
    /// The parameters name a session and nothing else. There is no field that selects a model,
    /// supplies a prompt or asks for a description to be produced now.
    session_describe, Method::SessionDescribe,
    kr_protocol::describe::SessionDescribeParams => kr_protocol::describe::SessionDescribeResult
);
read_command!(
    /// Reads what description setup offers on this host: the exact size and sources before
    /// anything is fetched, the two settings, how a fetch is going, and why nothing is offered
    /// when nothing is.
    description_setup, Method::DescriptionSetup, () => kr_protocol::describe::DescriptionSetup
);
mutate_command!(
    /// Turns session descriptions on or off, and whether they may run on battery.
    description_configure, Method::DescriptionConfigure,
    kr_protocol::describe::DescriptionConfigureParams
);
mutate_command!(
    /// Starts the fetch of the selected profile's files, or stops one that is running.
    description_download, Method::DescriptionDownload,
    kr_protocol::describe::DescriptionDownloadParams
);
read_command!(
    /// Reads the agent's questions.
    question_read, Method::QuestionRead,
    kr_protocol::question::QuestionReadParams => kr_protocol::question::QuestionReadResult
);
/// Reads what became of one action.
///
/// The receipt of an action on a live session is that session's worker's, which performed it, so
/// it is read on the session's own worker link; the control daemon refuses a live session's
/// receipt. The daemon serves the receipts of a session whose worker has ended and of the effects
/// the host performed itself, which name no session. Which it is follows from the session the
/// request names and from whether that session's worker has a descriptor on this machine.
#[tauri::command]
pub async fn action_read(
    state: State<'_, AppState>,
    links: State<'_, crate::agent::WorkerLinks>,
    params: Value,
) -> Result<Value> {
    let typed: kr_protocol::receipt::ActionReadParams = decode(params)?;
    let answer: kr_protocol::receipt::ActionReadResult = match typed.session_id {
        Some(session_id) if links.serves(session_id)? => {
            links.read(session_id, Method::ActionRead, &typed).await?
        }
        _ => state.session()?.read(Method::ActionRead, &typed).await?,
    };
    encode(&answer)
}

/// Reads one page of a session's retained output, from the cursor and within the byte bound the
/// page names.
///
/// A live session's output is its worker's, so the page is read on the session's own worker link;
/// the control daemon serves the archive of a session whose worker has ended, and refuses a live
/// one. Which it is follows from whether the session's worker has a descriptor on this machine.
#[tauri::command]
pub async fn history_page(
    state: State<'_, AppState>,
    links: State<'_, crate::agent::WorkerLinks>,
    params: Value,
) -> Result<Value> {
    let typed: kr_protocol::recovery::HistoryPageParams = decode(params)?;
    let page: kr_protocol::recovery::HistoryPageResult = if links.serves(typed.session_id)? {
        links
            .read(typed.session_id, Method::HistoryPage, &typed)
            .await?
    } else {
        state.session()?.read(Method::HistoryPage, &typed).await?
    };
    encode(&page)
}
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

agent_read_command!(
    /// Reads what the bound agent can do now, with the evidence behind each capability, and the
    /// binding the answer is about.
    agent_capabilities, Method::AgentCapabilities,
    kr_protocol::agent::AgentCapabilitiesParams => kr_protocol::agent::AgentCapabilitiesResult
);
agent_read_command!(
    /// Reads one part of the bound agent's semantic history, filtered as the caller's authority
    /// requires, from the node the page names.
    agent_snapshot, Method::AgentSnapshot,
    kr_protocol::agent::AgentSnapshotParams => kr_protocol::agent::AgentSnapshotResult
);
agent_read_command!(
    /// Reads the commands the bound agent advertises.
    agent_commands, Method::AgentCommands,
    kr_protocol::agent::AgentCommandsParams => kr_protocol::agent::AgentCommandsResult
);
agent_read_command!(
    /// Reads what an installed decoder read of one approval request and the decisions it offered,
    /// with the request's original bytes, so a person can check the one against the other before
    /// answering.
    agent_approval_inspect, Method::AgentApprovalInspect,
    kr_protocol::agent::AgentApprovalInspectParams => kr_protocol::agent::AgentApprovalInspectResult
);
agent_prompt_command!(
    /// Submits a prompt to the bound agent: a draft or inline text, and never both.
    agent_prompt_submit, Method::AgentPromptSubmit
);
agent_prompt_command!(
    /// Queues a prompt behind the bound agent's current turn: a draft or inline text, and never
    /// both.
    agent_prompt_queue, Method::AgentPromptQueue
);
agent_mutate_command!(
    /// Steers the turn the bound agent is running.
    agent_turn_steer, Method::AgentTurnSteer, kr_protocol::agent::AgentSteerParams,
    |_| Ok(())
);
agent_mutate_command!(
    /// Cancels the turn the bound agent is running, by the upstream's own identifier for it.
    agent_turn_cancel, Method::AgentTurnCancel, kr_protocol::agent::AgentCancelParams,
    |_| Ok(())
);
agent_mutate_command!(
    /// Answers one approval request with one of the decisions its decoder offered.
    agent_approval_respond, Method::AgentApprovalRespond,
    kr_protocol::agent::AgentApprovalRespondParams, |_| Ok(())
);

/// Reads a session's live agent instances and every request its broker is still arbitrating.
///
/// The page names the session. The snapshot is taken on the session's own worker, every page of it
/// is read before anything is answered, and what the page is told is the instances and the
/// requests, not the snapshot's cursors.
#[tauri::command]
pub async fn session_agents(
    links: State<'_, crate::agent::WorkerLinks>,
    session_id: String,
) -> Result<crate::agent::SessionAgents> {
    let session_id: kr_protocol::ids::SessionId = session_id
        .parse()
        .map_err(|_| CommandError::invalid("that is not a session identifier"))?;
    links.agents(session_id).await
}

read_command!(
    /// Reads the attention inbox this computer's owner sees.
    attention_read, Method::AttentionRead,
    kr_protocol::attention::AttentionReadParams => kr_protocol::attention::AttentionReadResult
);
mutate_command!(
    /// Records that this computer's owner has seen attention items, each at the revision shown.
    attention_acknowledge, Method::AttentionAcknowledge,
    kr_protocol::attention::AttentionAcknowledgeParams
);
read_command!(
    /// Reads review state: which completed turns and change sets wait for review, at which
    /// versions.
    review_read, Method::ReviewRead,
    kr_protocol::attention::ReviewReadParams => kr_protocol::attention::ReviewReadResult
);
mutate_command!(
    /// Records that one exact version was reviewed. It approves nothing and changes no file.
    review_acknowledge, Method::ReviewAcknowledge,
    kr_protocol::attention::ReviewAcknowledgeParams
);
read_command!(
    /// Reads one exact version of a change set, with every version of it.
    changeset_read, Method::ChangesetRead,
    kr_protocol::changeset::ChangesetReadParams => kr_protocol::changeset::ChangesetReadResult
);
read_command!(
    /// Lists the devices paired with this host, which is who an invitation can be issued to.
    device_list, Method::DeviceList,
    kr_protocol::sharing::DeviceListParams => kr_protocol::sharing::DeviceListResult
);
mutate_command!(
    /// Issues one invitation: a grant to a paired device, carrying the notices its issuer was
    /// shown. The host refuses one whose notices differ from what the grant actually carries.
    grant_create, Method::GrantCreate, kr_protocol::sharing::GrantCreateParams
);
read_command!(
    /// Lists the grants this host has issued.
    grant_list, Method::GrantList,
    kr_protocol::sharing::GrantListParams => kr_protocol::sharing::GrantListResult
);
read_command!(
    /// Lists the packages installed in an environment.
    plugin_list, Method::PluginList,
    kr_protocol::catalogue::PluginListParams => kr_protocol::catalogue::PluginListResult
);
read_command!(
    /// Lists the package repositories an environment has enrolled.
    catalogue_list, Method::CatalogueList,
    kr_protocol::catalogue::CatalogueListParams => kr_protocol::catalogue::CatalogueListResult
);

/// What an invitation with one role and its explicit choices would carry, before it is issued.
#[derive(Debug, Serialize)]
pub struct GrantNotices {
    /// The actions the selection compiles to. The host authorises from these, never from a role.
    pub actions: Vec<kr_protocol::rights::ActionRight>,
    /// Every notice those actions carry, with the fixed sentence that states it.
    pub notices: Vec<GrantNotice>,
}

/// One consequence of a grant, as the issuer is shown it.
#[derive(Debug, Serialize)]
pub struct GrantNotice {
    /// Which notice it is. An issuance names these back as the notices its issuer accepted.
    pub notice: kr_protocol::sharing::AuthorityNotice,
    /// The sentence that states it, in the host's own words.
    pub sentence: &'static str,
}

/// Says what an invitation would carry: the actions its role and choices compile to, and the
/// notices those actions carry, each in the one sentence that states it.
///
/// The notices come from the protocol's own table, so no surface decides for itself that an action
/// is harmless or words a consequence more softly than the host does. It reaches nothing: the page
/// asks before it issues, and issuing sends the same notices back for the host to check.
#[tauri::command]
pub fn grant_notices(selection: Value) -> Result<GrantNotices> {
    let selection: kr_protocol::sharing::RoleSelection = decode(selection)?;
    let actions = selection.actions();
    let notices = kr_protocol::sharing::AuthorityNotice::for_actions(actions.iter())
        .iter()
        .map(|notice| GrantNotice {
            notice: *notice,
            sentence: notice.sentence(),
        })
        .collect();
    Ok(GrantNotices {
        actions: actions.iter().copied().collect(),
        notices,
    })
}
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

/// Refuses to start a voice session from this application.
///
/// Section 15 ¶2 puts capture, playback and the connection in native WebRTC and platform audio,
/// and this process holds neither, so it has no offer to give. The phone applications' Swift and
/// Kotlin calls are their own. A start is refused before anything is submitted, because the broker
/// creates a metered provider session the moment a start reaches it, and a session created for a
/// device that can carry no audio is one a person pays for and cannot use.
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
    Err(CommandError::unsupported(
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

/// Asks the host to revoke the voice session's grant.
///
/// This process holds no call, so there is no local call to close first, and the answer says so.
/// Section 15 ¶10 keeps local mute and transport closure working
/// when the broker fails, and a closure that waited for a service to answer before silencing a
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
    /// Whether a call of this process's own was closed. It holds none, so this is false.
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

/// Refuses to silence the microphone or the speaker: this process holds no call to act on.
///
/// Local and immediate, and it contacts nothing, which is why this is not a mutation.
#[tauri::command]
pub fn voice_set_muted(what: VoiceMute, muted: bool) -> Result<crate::audio::VoiceCallState> {
    let _ = (what, muted);
    crate::audio::set_muted()
}

/// What a call on this device is doing. This process holds none, so it reports a device holding no
/// call.
#[tauri::command]
pub fn voice_call_state() -> Result<crate::audio::VoiceCallState> {
    crate::audio::call_state()
}

/// One action a voice grant permits, as the person is shown it before allowing it.
#[derive(Debug, Serialize)]
pub struct VoiceScopeAction {
    /// The action, by its protocol name.
    pub action: kr_protocol::voice::VoiceAction,
    /// The sentence that states it.
    pub sentence: &'static str,
    /// True when using it still takes a confirmation on an unlocked screen every time.
    pub needs_unlocked_screen: bool,
}

/// What allowing voice on this device permits by default.
#[derive(Debug, Serialize)]
pub struct VoiceScope {
    /// The default actions, each in the sentence that states it.
    pub actions: Vec<VoiceScopeAction>,
}

/// What a voice grant permits when the person chooses nothing further, from the protocol's own
/// table, so the surface that asks the question cannot word an action more softly than the host
/// states it. It reaches nothing: the page asks before it allows, and allowing sends the same
/// actions back for the host to check.
#[tauri::command]
pub fn voice_scope() -> VoiceScope {
    VoiceScope {
        actions: kr_protocol::voice::VoiceAction::ALL
            .iter()
            .filter(|action| action.in_default_scope())
            .map(|action| VoiceScopeAction {
                action: *action,
                sentence: action.statement(),
                needs_unlocked_screen: action.needs_unlocked_screen(),
            })
            .collect(),
    }
}

/// What the page asks of `voice_allow`: which sessions, and which actions. The device is not here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VoiceAllow {
    /// The sessions the grant covers. None covers every session the device's own grant covers.
    session_ids: Vec<String>,
    /// The actions to permit. Absent takes the default scope of section 15 paragraph 13.
    actions: Option<Vec<kr_protocol::voice::VoiceAction>>,
}

/// What allowing voice came to: the sentences the grant states, and what it could not carry. The
/// device the grant is for is not in it.
#[derive(Debug, Serialize)]
pub struct VoiceAllowed {
    /// What the grant permits, each action in the sentence that states it.
    pub statement: kr_protocol::voice::VoiceGrantStatement,
    /// The actions the person asked for that this device's own grant does not carry, so the grant
    /// does not either.
    pub not_held_by_device: kr_protocol::scalars::CanonicalSet<kr_protocol::voice::VoiceAction>,
}

/// Lets the person allow what a voice call on this device may do, for the host it is paired with.
///
/// The grant is this device's own, so native code names the device: the page does not hold the
/// identity the host gave it, and a grant for any other device is a host-management change that
/// this application, a paired device, does not make. The answer states every action the grant
/// permits and every one the device's own grant could not carry, and nothing else of what the host
/// answered: the identity of the device stays here.
#[tauri::command]
pub async fn voice_allow(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<Settled> {
    let allowed: VoiceAllow = decode(params)?;
    let session_ids = allowed
        .session_ids
        .iter()
        .map(|id| {
            id.parse()
                .map_err(|_| CommandError::invalid("that is not a session identifier"))
        })
        .collect::<Result<Vec<kr_protocol::ids::SessionId>>>()?;
    // One connection's identity, environment and session, so the grant cannot name a device of one
    // host and be sent to another.
    let (device_id, environment_id, session) = state.paired_snapshot()?;
    let typed = kr_protocol::voice::VoiceGrantParams {
        device_id,
        session_ids: session_ids.into_iter().collect(),
        actions: kr_protocol::scalars::Nullable::from(
            allowed.actions.map(|actions| actions.into_iter().collect()),
        ),
    };
    let target = subject.target(environment_id)?;
    let settled = session
        .mutate(
            Method::VoiceGrant,
            target,
            None,
            &NoPreconditions {},
            &typed,
            MUTATION_TTL,
        )
        .await;
    match settled {
        Ok(kr_client::Settled::Result(value)) => {
            let granted: kr_protocol::voice::VoiceGrantResult = value
                .to_typed()
                .map_err(|error| CommandError::local_failure(error.to_string()))?;
            Ok(Settled {
                receipt: None,
                action_id: None,
                value: Some(encode(&VoiceAllowed {
                    statement: granted.statement,
                    not_held_by_device: granted.not_held_by_device,
                })?),
            })
        }
        other => submitted(other),
    }
}

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
    submitted(answer)
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

/// The header a handed file's name comes in, percent-encoded, because a header carries no other
/// text.
pub const HANDED_NAME_HEADER: &str = "kr-file-name";

/// The header the subject of a handed file's upload comes in, as the JSON a subject takes.
pub const HANDED_SUBJECT_HEADER: &str = "kr-subject";

/// Sends one file the page handed over as bytes, pasted onto the window or picked on a phone, and
/// answers with the verified attachment handle.
///
/// The platform gave the file to the page rather than a path to this process, so the page hands
/// over the bytes, raw, as the call's body; the file's name and what the upload is about come in
/// two headers. The bytes go through the same upload a dropped file does, bounded by
/// [`crate::transfers::MAX_HANDED_BYTES`].
#[tauri::command]
pub async fn attachment_upload_bytes(
    state: State<'_, AppState>,
    request: tauri::ipc::Request<'_>,
) -> Result<Value> {
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err(CommandError::invalid(
            "a pasted or picked file is handed over as raw bytes",
        ));
    };
    let name = match request.headers().get(HANDED_NAME_HEADER) {
        None => String::new(),
        Some(value) => percent_decoded(
            value
                .to_str()
                .map_err(|_| CommandError::invalid("the file's name is not header text"))?,
        )?,
    };
    let subject: Subject = match request.headers().get(HANDED_SUBJECT_HEADER) {
        None => Subject::default(),
        Some(value) => serde_json::from_str(
            value
                .to_str()
                .map_err(|_| CommandError::invalid("the subject is not header text"))?,
        )
        .map_err(|error| CommandError::invalid(format!("that is not a subject: {error}")))?,
    };
    let file = crate::transfers::HandedFile::new(bytes.clone(), &name)?;
    let environment_id = state.environment_id()?;
    let target = subject.target(environment_id)?;
    let session_id = match subject.session_id.as_deref() {
        None => None,
        Some(value) => Some(
            value
                .parse()
                .map_err(|_| CommandError::invalid("that is not a session identifier"))?,
        ),
    };
    let session = state.session()?;
    let handle =
        crate::transfers::upload_handed(&session, target, environment_id, session_id, file).await?;
    encode(&handle)
}

/// Decodes a percent-encoded header value into the UTF-8 text it carries.
fn percent_decoded(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let pair = bytes
                .get(index + 1..index + 3)
                .and_then(|pair| std::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| CommandError::invalid("the file's name is not percent-encoded"))?;
            decoded.push(pair);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| CommandError::invalid("the file's name is not UTF-8"))
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
pub async fn pairing_paste(state: State<'_, AppState>) -> Result<crate::device::PasteView> {
    let device = state.device()?;
    let platform = state.paste()?;
    Ok(pairing::paste(&*platform, &device).await)
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

/// Takes a host this computer is paired with as the one its commands go to, and says where that
/// stands once the first attempt to reach it has ended.
///
/// The page names the host by the reference the pairing screen listed it under. The choice is kept
/// across runs, and a connection that ends is taken up again; the application says it is not
/// connected for as long as it is not.
#[tauri::command]
pub async fn hosts_use<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    reference: String,
) -> Result<crate::connection::ConnectionState> {
    let host = state
        .device()?
        .host_by_reference(&reference)
        .ok_or_else(crate::hosts::unknown_host)?;
    crate::hosts::use_host(&app, host).await
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

/// One screen the raw terminal view drew, as the page hands it over.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedFrame {
    /// Milliseconds since the recording began.
    pub at_ms: u64,
    /// The screen, as the drawing a player repeats.
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

/// Opens a raw terminal view of one session, `columns` by `rows` cells, and returns its handle.
///
/// The view's link, its attachment and its screen are held in native code. The page is sent each
/// state on `on_state`, the channel it passed, and on nothing else, and the handle comes back
/// before anything is asked of the host.
#[tauri::command]
pub async fn terminal_view_open<R: tauri::Runtime>(
    webview: tauri::Webview<R>,
    views: State<'_, crate::terminal::TerminalViews>,
    session_id: String,
    columns: u64,
    rows: u64,
    on_state: tauri::ipc::Channel<crate::terminal::TerminalViewState>,
) -> Result<String> {
    let session_id: kr_protocol::ids::SessionId = session_id
        .parse()
        .map_err(|_| CommandError::invalid("that is not a session identifier"))?;
    let dimensions = view_size(columns, rows)?;
    let publish: crate::terminal::Publish = std::sync::Arc::new(move |state| {
        // A page that has gone takes nothing; its load ends the view.
        let _ = on_state.send(state);
    });
    Ok(views.open(webview.label(), session_id, dimensions, publish))
}

/// Tells an open view that the page's grid is now `columns` by `rows` cells.
#[tauri::command]
pub fn terminal_view_resize(
    views: State<'_, crate::terminal::TerminalViews>,
    view: String,
    columns: u64,
    rows: u64,
) -> Result<()> {
    views.resize(&view, view_size(columns, rows)?);
    Ok(())
}

/// Moves an open view's window, as move `number` of the page's: by `across` columns and `down` rows,
/// or, with `live`, back to the live screen. The page numbers its moves in the order it makes them.
#[tauri::command]
pub fn terminal_view_move(
    views: State<'_, crate::terminal::TerminalViews>,
    view: String,
    number: u64,
    across: i64,
    down: i64,
    live: bool,
) -> Result<()> {
    let asked = if live {
        crate::terminal::Move::Live { number }
    } else {
        crate::terminal::Move::Pan {
            number,
            across,
            down,
        }
    };
    views.move_window(&view, asked);
    Ok(())
}

/// Hands an open view the person's input: a take or a release of control of the program, numbered
/// by the page in the order it makes them, or a turn of the program's wheel at a cell of the
/// session's grid, a key, text or a paste, each naming the take it was made under. A key is named,
/// never spelled: the view spells it in the encoding the program reads.
///
/// The input is read as the page sends it, and anything else is refused before the view is asked.
/// It answers once the view has taken the input, not once the program has: what the session
/// answers reaches the page as the view's state. An input the view may not write, since it does not
/// control the program under the take it names, is refused `LEASE_LOST`, and nothing is written;
/// so is any input to a view that has ended. One that cannot reach the program as it reads keys
/// now, or before the view holds the session's screen, is refused `INPUT_INCOMPATIBLE` with words
/// that say why, and the view keeps control.
#[tauri::command]
pub async fn terminal_view_input(
    views: State<'_, crate::terminal::TerminalViews>,
    view: String,
    input: Value,
) -> Result<()> {
    let input: crate::terminal::Input = decode(input)?;
    views
        .input(&view, input)
        .await
        .map_err(|refused| match refused {
            crate::terminal::Refused::NotControlling(_) => {
                CommandError::new(kr_protocol::error::ErrorCode::LeaseLost, refused.message())
            }
            // The words say why the program cannot take the input, which no update would change.
            crate::terminal::Refused::Unsent(_) => CommandError::stated(
                kr_protocol::error::ErrorCode::InputIncompatible,
                refused.message(),
            ),
        })
}

/// Closes a view: it detaches, closes its link and publishes nothing more.
#[tauri::command]
pub async fn terminal_view_close(
    views: State<'_, crate::terminal::TerminalViews>,
    view: String,
) -> Result<()> {
    views.close(&view).await;
    Ok(())
}

/// A view's grid, held to the protocol's bounds on a terminal's size.
fn view_size(columns: u64, rows: u64) -> Result<kr_protocol::session::Dimensions> {
    let dimensions = kr_protocol::session::Dimensions::new(columns, rows);
    dimensions.validate().map_err(|error| {
        CommandError::invalid(format!("that is not a terminal's size: {error}"))
    })?;
    Ok(dimensions)
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
            // No host runs here, so no session's worker can be reached either.
            .manage(crate::agent::WorkerLinks::with(std::sync::Arc::new(|| {
                Err("this test runs no host".to_owned())
            })))
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
                // The host a phone's commands go to: it pairs, and then it chooses.
                "hosts_use",
                // Setup's own two. Neither performs a protocol operation: one reads this
                // application's identity and one opens a settings pane by name.
                "setup_identity",
                "setup_open_settings",
                // What allowing voice permits, read from the protocol's table: nothing is contacted.
                "voice_scope",
                // Voice's own two. Both contact nothing: section 15 paragraph 10 keeps local mute
                // and transport closure working when the broker fails, and a silence that had to
                // be granted by a service is one that would fail at exactly the moment a person
                // needs it.
                "voice_call_state",
                "voice_set_muted",
                // The account's five. Each reaches the account service or this device's secure
                // store, and none reaches a host.
                "account_sign_in",
                "account_sign_in_cancel",
                "account_sign_out",
                "account_status",
                "account_usage",
                // The raw terminal view's five. The view attaches on the session's own worker,
                // which the control daemon does not proxy for this computer, so the page names a
                // session, a size, its moves and the person's input, and native code makes every
                // call.
                "terminal_view_close",
                "terminal_view_input",
                "terminal_view_move",
                "terminal_view_open",
                "terminal_view_resize",
                // The session's agent instances and pending requests, which native code reads on
                // the session's own worker from a session the page names.
                "session_agents",
                // What an invitation would carry, from the protocol's own table. It reaches
                // nothing.
                "grant_notices",
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
        // A terminal view's calls are the view's own, on its own link: no page method attaches,
        // subscribes, reports a window, resizes, configures, takes or gives back the input lease,
        // writes input, interrupts under the lease or detaches.
        for method in [
            Method::SessionAttach,
            Method::SessionDetach,
            Method::AttachmentConfigure,
            Method::AttachmentViewport,
            Method::TerminalResize,
            Method::EventsSubscribe,
            Method::EventsSnapshot,
            Method::InputAcquire,
            Method::InputRelease,
            Method::InputWrite,
            Method::InputInterrupt,
        ] {
            assert!(!page.contains(&method), "{method} is a page method");
        }
        assert_eq!(
            performing(Method::SessionAttach),
            BTreeSet::from(["terminal_view_open"])
        );
        assert_eq!(
            performing(Method::SessionDetach),
            BTreeSet::from(["terminal_view_close", "terminal_view_open"])
        );
        assert_eq!(
            performing(Method::AttachmentViewport),
            BTreeSet::from([
                "terminal_view_move",
                "terminal_view_open",
                "terminal_view_resize"
            ])
        );
        // A session's agent instances and pending requests are read by one command, which follows
        // every page of one snapshot itself.
        assert_eq!(
            performing(Method::EventsSnapshot),
            BTreeSet::from(["session_agents"])
        );
        // The view's input goes through one command: taking and giving back the lease, and every
        // write under it.
        for method in [
            Method::InputAcquire,
            Method::InputRelease,
            Method::InputWrite,
        ] {
            assert_eq!(
                performing(method),
                BTreeSet::from(["terminal_view_input"]),
                "{method}"
            );
        }
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
    /// takes a path rather than a map, refuses one that nobody dropped. A voice stop takes its
    /// values one by one rather than as a map, and refuses values that are not what they claim to
    /// be in the same way; a voice start refuses every request before reading it, because this
    /// application opens no call.
    #[test]
    fn parameters_that_are_not_the_methods_shape_are_refused_before_anything_is_sent() {
        let refusal: Result<kr_protocol::session::SessionReadParams> =
            decode(serde_json::json!({ "session_id": "the one I was looking at" }));
        let error = refusal.expect_err("that is not a session identifier");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);

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
            session_describe,
            description_setup,
            description_configure,
            description_download,
            shell_launch,
            draft_create,
            draft_update,
            draft_add_attachment,
            attachment_upload,
            attachment_upload_bytes,
            attachment_upload_status,
            attachment_image,
            attachment_image_chunk,
            history_page,
            action_read,
            action_cancel,
            question_read,
            question_answer,
            agent_capabilities,
            agent_snapshot,
            agent_commands,
            agent_approval_inspect,
            agent_prompt_submit,
            agent_prompt_queue,
            agent_turn_steer,
            agent_turn_cancel,
            agent_approval_respond,
            attention_read,
            attention_acknowledge,
            review_read,
            review_acknowledge,
            changeset_read,
            device_list,
            grant_create,
            grant_list,
            plugin_list,
            catalogue_list,
            voice_prepare,
            voice_start,
            voice_stop,
            voice_allow,
            voice_delegate,
            voice_context,
        ]);
        // One body for every command: each reads the arguments it takes and nothing else. The
        // voice stop reads its own one by one, and the voice start reads none after the invoke
        // layer has typed them. The identifier the stop parses itself is not an identifier, and the
        // values the invoke layer types are of their types, so the refusal is the command's own
        // rather than the invoke layer's.
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
                "host_info" | "environment_list" | "description_setup" => "HOST_NOT_CONFIGURED",
                "attachment_upload" => "PERMISSION_DENIED",
                // This application opens no call, so it refuses every start before it reads one.
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

    /// KR-REQ-13.16: a file the page hands over as bytes is read from the call's raw body with its
    /// name and subject from their headers, bounded, and reaches the upload only then; a body that
    /// is not raw bytes, a name that is not percent-encoded UTF-8 and a subject that is not one are
    /// each refused before anything is sent.
    #[test]
    fn a_handed_file_is_read_from_raw_bytes_and_two_headers() {
        let (_app, window) = page_with(tauri::generate_handler![attachment_upload_bytes]);
        let call = |body: tauri::ipc::InvokeBody, headers: &[(&'static str, &str)]| {
            let mut map = tauri::http::HeaderMap::new();
            for (name, value) in headers {
                map.insert(*name, value.parse().expect("header text"));
            }
            tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: "attachment_upload_bytes".into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body,
                    headers: map,
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
            .err()
            .map(|error| error["code"].as_str().unwrap_or_default().to_owned())
        };
        let raw = || tauri::ipc::InvokeBody::Raw(b"hello".to_vec());
        assert_eq!(
            call(tauri::ipc::InvokeBody::Json(serde_json::json!({})), &[]).as_deref(),
            Some("INVALID_ARGUMENT"),
            "a file is handed over as raw bytes"
        );
        assert_eq!(
            call(raw(), &[(HANDED_NAME_HEADER, "caf%C3")]).as_deref(),
            Some("INVALID_ARGUMENT"),
            "a name cut inside a character is not UTF-8"
        );
        assert_eq!(
            call(raw(), &[(HANDED_SUBJECT_HEADER, "{\"sessionId\":1}")]).as_deref(),
            Some("INVALID_ARGUMENT"),
            "a subject is the JSON a subject takes"
        );
        // Everything read, the next step needs a host this test does not run.
        assert_eq!(
            call(
                raw(),
                &[
                    (HANDED_NAME_HEADER, "caf%C3%A9.png"),
                    (
                        HANDED_SUBJECT_HEADER,
                        "{\"sessionId\":\"44444444-4444-4444-8444-444444444444\"}"
                    )
                ]
            )
            .as_deref(),
            Some("HOST_NOT_CONFIGURED"),
            "a well-formed handed file reaches the upload"
        );
        assert_eq!(
            percent_decoded("caf%C3%A9.png").expect("decodes"),
            "café.png"
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

    /// KR-REQ-10.01: the two commands whose calls native code builds itself read what the page sent
    /// before anything else. The session whose agents are read has to be a session identifier; an
    /// invitation's selection has to be one, with nothing the selection does not declare.
    #[test]
    fn the_agents_read_and_an_invitations_notices_read_what_the_page_sent_first() {
        let (_app, window) = page_with(tauri::generate_handler![session_agents, grant_notices]);
        assert_eq!(
            refusal_of(
                &window,
                "session_agents",
                serde_json::json!({ "sessionId": "the session I was looking at" })
            )
            .as_deref(),
            Some("INVALID_ARGUMENT")
        );
        assert_eq!(
            refusal_of(
                &window,
                "session_agents",
                serde_json::json!({ "sessionId": "44444444-4444-4444-8444-444444444444" })
            )
            .as_deref(),
            Some("RESOURCE_UNAVAILABLE"),
            "a session identifier is taken, and stops only where no host is there to reach"
        );
        let mut selection = serde_json::json!({
            "role": "viewer",
            "history_from_cursor_ms": null,
            "include_live_screen": false,
            "include_question_respond": true,
            "named_questions": [],
            "named_approvals": []
        });
        assert_eq!(
            refusal_of(
                &window,
                "grant_notices",
                serde_json::json!({ "selection": selection.clone() })
            ),
            None
        );
        selection["and_also"] = serde_json::json!("everything");
        assert_eq!(
            refusal_of(
                &window,
                "grant_notices",
                serde_json::json!({ "selection": selection })
            )
            .as_deref(),
            Some("INVALID_ARGUMENT")
        );
    }

    /// KR-REQ-10.42, KR-REQ-25.08: a viewer asked to answer the agent's questions carries the
    /// notice that an answer is input the agent acts on under its own permissions, in the
    /// protocol's own sentence, which says it is not a restricted sandbox. A plain viewer carries
    /// no notice at all, and a controller carries the account one too.
    #[test]
    fn an_invitations_notices_are_the_protocols_own_sentences() {
        let notices_of = |role: &str, answering: bool| {
            grant_notices(serde_json::json!({
                "role": role,
                "history_from_cursor_ms": null,
                "include_live_screen": false,
                "include_question_respond": answering,
                "named_questions": [],
                "named_approvals": []
            }))
            .expect("a selection")
        };
        let plain = notices_of("viewer", false);
        assert!(plain.notices.is_empty());
        assert_eq!(
            plain.actions,
            vec![kr_protocol::rights::ActionRight::SessionView]
        );

        let answering = notices_of("viewer", true);
        assert!(
            answering
                .actions
                .contains(&kr_protocol::rights::ActionRight::QuestionRespond),
            "the explained option adds question.respond"
        );
        let sentences: Vec<&str> = answering
            .notices
            .iter()
            .map(|notice| notice.sentence)
            .collect();
        assert_eq!(
            sentences,
            vec![kr_protocol::sharing::AuthorityNotice::AgentPermissions.sentence()]
        );
        assert!(sentences[0].contains("This is not a restricted sandbox."));

        let controller: Vec<kr_protocol::sharing::AuthorityNotice> =
            notices_of("controller", false)
                .notices
                .iter()
                .map(|notice| notice.notice)
                .collect();
        assert_eq!(
            controller,
            vec![
                kr_protocol::sharing::AuthorityNotice::AccountAccess,
                kr_protocol::sharing::AuthorityNotice::AgentPermissions
            ]
        );
    }

    /// KR-REQ-10.01 and KR-REQ-22.01: the description commands take what their methods declare and
    /// nothing else. A read of one session's description that also names a prompt, a model or a
    /// sampler, and a fetch that names an address, are refused when the parameters are parsed, so
    /// the page has no way to steer what the host runs or where it fetches from.
    #[test]
    fn the_description_commands_refuse_a_field_their_methods_do_not_declare() {
        let session = "44444444-4444-4444-8444-444444444444";
        let described: Result<kr_protocol::describe::SessionDescribeParams> =
            decode(serde_json::json!({ "session_id": session }));
        assert!(described.is_ok(), "the declared shape passes the parse");
        for foreign in ["prompt", "model", "sampler", "temperature", "now"] {
            let refused: Result<kr_protocol::describe::SessionDescribeParams> =
                decode(serde_json::json!({ "session_id": session, foreign: "anything" }));
            assert!(
                refused.is_err(),
                "{foreign} is not a field of session.describe"
            );
        }

        let started: Result<kr_protocol::describe::DescriptionDownloadParams> =
            decode(serde_json::json!({ "action": "start" }));
        assert!(started.is_ok(), "the declared shape passes the parse");
        for widened in [
            serde_json::json!({ "action": "start", "url": "https://example.test/model" }),
            serde_json::json!({ "action": "start", "profile_id": "another" }),
            serde_json::json!({ "action": "delete" }),
        ] {
            let refused: Result<kr_protocol::describe::DescriptionDownloadParams> =
                decode(widened.clone());
            assert!(
                refused.is_err(),
                "{widened} is not a fetch this host offers"
            );
        }

        let settings: Result<kr_protocol::describe::DescriptionConfigureParams> =
            decode(serde_json::json!({ "enabled": true, "on_battery": null }));
        assert!(settings.is_ok(), "the two settings pass the parse");
        let widened: Result<kr_protocol::describe::DescriptionConfigureParams> = decode(
            serde_json::json!({ "enabled": true, "on_battery": null, "profile_id": "another" }),
        );
        assert!(widened.is_err(), "a third setting is not one an owner has");
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

/// Where this device stands with an account.
#[tauri::command]
pub async fn account_status(
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::account::AccountView> {
    Ok(account.get().await?.status().await)
}

/// Signs this device in through the system browser, and settles when the attempt ends.
///
/// The page names nothing: the address the browser opens, its state, verifier and code stay in
/// this process, and the answer is only where the device now stands.
#[tauri::command]
pub async fn account_sign_in(
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::account::AccountView> {
    Ok(account.get().await?.sign_in().await)
}

/// Ends the sign-in that is waiting for the browser.
#[tauri::command]
pub async fn account_sign_in_cancel(account: State<'_, crate::account::AccountSlot>) -> Result<()> {
    account.get().await?.cancel();
    Ok(())
}

/// Signs this device out, and tells the service.
#[tauri::command]
pub async fn account_sign_out(
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::account::AccountView> {
    Ok(account.get().await?.sign_out().await)
}

/// The account's usage, in words and figures, and nothing about money.
#[tauri::command]
pub async fn account_usage(
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::account::UsageView> {
    Ok(account.get().await?.usage().await)
}
