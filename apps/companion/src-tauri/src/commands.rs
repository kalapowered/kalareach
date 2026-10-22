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
    // The disclosed checks, asked for once the interface has shown what each one does. The page
    // names the environment and no file.
    (
        "environment_capabilities_check",
        Some(Method::EnvironmentCapabilitiesCheck),
    ),
    ("setup_identity", None),
    ("setup_open_settings", None),
    // Sessions.
    ("session_list", Some(Method::SessionList)),
    ("session_read", Some(Method::SessionRead)),
    ("session_create", Some(Method::SessionCreate)),
    ("session_close", Some(Method::SessionClose)),
    // A session screen on a host this device is paired with: the host opens the session on a
    // connection of its own, under the grant the screen runs under, and says what it allows. The
    // page chooses the opening and passes it with every command about the session.
    ("session_open", None),
    ("session_leave", None),
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
    // The drafts this device keeps. They are the device's own, in a store of its own: the page
    // names a draft, the version it was shown and what to keep, never a path or a method.
    ("device_drafts", None),
    ("device_draft_save", None),
    ("device_draft_retarget", None),
    ("device_draft_discard", None),
    ("device_draft_mark_removal", None),
    // Drafts and attachments.
    ("draft_create", Some(Method::DraftCreate)),
    (
        "draft_add_attachment",
        Some(Method::AgentDraftAddAttachment),
    ),
    ("attachment_upload", Some(Method::UploadBegin)),
    ("attachment_upload_bytes", Some(Method::UploadBegin)),
    ("attachment_upload_status", Some(Method::UploadStatus)),
    // History and receipts. A live session's are read from its own worker, and a closed one's from
    // the host's archive.
    ("history_page", Some(Method::HistoryPage)),
    ("action_read", Some(Method::ActionRead)),
    ("action_cancel", Some(Method::ActionCancel)),
    // Questions. Each goes to the session's own worker, and the answers kept while it cannot be
    // reached are this device's: the page names a question and an answer, never a method or a path.
    ("question_read", Some(Method::QuestionRead)),
    ("question_answer", Some(Method::QuestionAnswer)),
    ("question_kept", None),
    ("question_settle", None),
    ("question_send_kept", None),
    ("question_dismiss_kept", None),
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
    // Sharing: the devices an invitation can go to, what one would carry, the screen it would
    // include, issuing it, taking it back, accepting one and the grants issued and held. The four
    // actions that change who holds a session are attempts this application keeps its word about,
    // and the hand-over of control asks an owner device first.
    ("device_list", Some(Method::DeviceList)),
    // What privacy mode reports: whether it is on, and the copies that have left the host and are
    // shown rather than erased. The page lists them and offers no action on them.
    ("privacy_status", Some(Method::PrivacyStatus)),
    ("grant_notices", None),
    ("session_screen_preview", Some(Method::SessionScreenPreview)),
    ("grant_create", Some(Method::GrantCreate)),
    ("grant_list", Some(Method::GrantList)),
    ("grant_revoke", Some(Method::GrantRevoke)),
    ("grant_redeem", Some(Method::GrantRedeem)),
    ("grant_held", Some(Method::GrantHeld)),
    ("transfer_ask", None),
    ("transfer_answered", None),
    ("transfer_finish", None),
    ("transfer_cancel", None),
    ("attempts_list", None),
    ("attempt_ask", None),
    ("attempt_set_hidden", None),
    ("attempt_remove", None),
    // Packages.
    ("plugin_list", Some(Method::PluginList)),
    ("catalogue_list", Some(Method::CatalogueList)),
    // Pairing.
    ("pairing_set_origin", None),
    ("pairing_view", None),
    ("pairing_start_code", None),
    ("pairing_paste", None),
    ("pairing_scan", None),
    ("pairing_scan_photo", None),
    ("pairing_keep_awake", None),
    ("pairing_start_read", None),
    ("pairing_stop", None),
    // The application's own place in the system's settings: whether the camera is allowed, and the
    // page where the person allows it.
    ("camera_access", None),
    ("app_open_settings", None),
    // The owner's confirmations of this computer's hosts.
    ("owner_confirmations", None),
    ("owner_confirmation_review", None),
    // The devices of the hosts this computer owns, and revoking one of them.
    ("revocation_view", None),
    ("revocation_revoke", None),
    // The host a phone's commands go to.
    ("hosts_use", None),
    ("hosts_forget", None),
    // Notifications: where each paired host's stand, turning them on for one, looking again, and the
    // screen a tap on a notification opened.
    ("push_view", None),
    ("push_enable", None),
    ("push_refresh", None),
    ("notification_route", None),
    // Voice. The start names its method for the table, and this process refuses it before sending.
    ("voice_prepare", Some(Method::VoicePrepare)),
    ("voice_start", Some(Method::VoiceStart)),
    ("voice_stop", Some(Method::VoiceStop)),
    ("voice_allow", Some(Method::VoiceGrant)),
    ("voice_scope", None),
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
    ("account_sign_in_for_recovery", None),
    ("account_sign_in_cancel", None),
    ("account_sign_out", None),
    ("account_usage", None),
    // The sync service this computer is set to use, and the recovery material kept on it. None is
    // a host method. The page names an origin, or a destination a save dialog returned, and is
    // never given the seed, the locator or a token.
    ("sync_service_view", None),
    ("sync_service_set", None),
    ("recovery_view", None),
    ("recovery_turn_on", None),
    ("recovery_settle", None),
    ("recovery_save_kit", None),
    // The kit as a QR code, the archives the recovery bundle names, and an offline export of the
    // bundle and one archive. None is a host method: this computer reads the sync service with the
    // account, and the page names a destination a save dialog returned and an archive it was shown.
    ("recovery_save_kit_qr", None),
    ("recovery_archives", None),
    ("recovery_export_offline", None),
    // Covering the host on this computer with this computer's recovery. The page supplies nothing
    // but whether a replacement is asked for; native code reads the host's status, builds the call
    // from this computer's own seed and bundle, and sends it to the host.
    ("recovery_cover_host", None),
    // The person's settings: the colour mode now, and keeping it in step with their other devices.
    // None is a host method. The page names a mode from a closed set and is told where things
    // stand; it holds no copy of its own and is given no key, identity or token.
    ("settings_view", None),
    ("settings_colour_mode_set", None),
    ("settings_sync_turn_on", None),
    ("settings_sync_now", None),
    ("settings_conflicts", None),
    ("settings_conflict_resolve", None),
    ("settings_drafts_set", None),
    ("settings_devices_refresh", None),
    ("settings_device_share", None),
    ("settings_device_remove", None),
    ("settings_devices_dismiss", None),
    ("settings_join", None),
];

/// The commands that reach a session's worker or name a session on a host this device is paired
/// with.
///
/// Each takes the opening of the screen making it and goes over that opening's link, or goes over a
/// link kept for calls made outside any screen when it names none. The connection for the host
/// alone refuses them all, because the host serves no worker on it. A command that is not offered
/// over a paired host is in the list too, because it is refused here before anything is sent. A
/// sharing command that is also refused on a paired standing before anything is sent, such as the
/// preview of a screen, is not in the list, because it never names a session of a paired host. The
/// session tour in `tests/phone_sessions.rs` calls each of these once, so one that reaches a worker
/// over the wrong connection fails there.
pub const SESSION_BOUND_COMMANDS: &[&str] = &[
    "session_agents",
    "session_close",
    "session_open",
    "session_leave",
    "agent_capabilities",
    "agent_snapshot",
    "agent_commands",
    "agent_approval_inspect",
    "agent_prompt_submit",
    "agent_prompt_queue",
    "agent_turn_steer",
    "agent_turn_cancel",
    "agent_approval_respond",
    "question_read",
    "question_answer",
    "question_settle",
    "question_send_kept",
    "action_read",
    "action_cancel",
    "history_page",
    "shell_launch",
    "draft_create",
    "draft_add_attachment",
    "attachment_upload",
    "attachment_upload_bytes",
    "terminal_view_open",
];

/// The commands whose native code performs protocol methods of its own, and which.
///
/// Every one is a `None` entry in [`NAMED_COMMANDS`]: the page supplies none of these methods'
/// parameters. What reaches the host is built in native code from this computer's own state, its
/// keys, its records and what the host listed, and none of it is handed back to the page.
/// `owner.confirmation.complete` appears only under `owner_confirmation_review`, and `pair.finish`
/// and `pair.redeem` only under the two starts.
pub const NATIVE_METHODS: &[(&str, &[Method])] = &[
    // Covering the host on this computer with this computer's recovery: the host's status is read,
    // and the host is set up under this computer's recovery with a bundle this computer sealed.
    (
        "recovery_cover_host",
        &[Method::BackupStatus, Method::BackupEnable],
    ),
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
    ("hosts_use", &[Method::HostInfo, Method::SessionOpen]),
    // A phone hands its host the credential its installation was issued, and says it holds the
    // key the host seals previews to. The page names a host and nothing else.
    (
        "push_enable",
        &[Method::DevicePushRegister, Method::DevicePreviewKeyUpdate],
    ),
    (
        "push_refresh",
        &[Method::DevicePushRegister, Method::DevicePreviewKeyUpdate],
    ),
    ("owner_confirmations", &[Method::OwnerConfirmationPending]),
    // Settings sync keeps drafts in step host by host and shares the settings' key between the
    // person's devices. Before a draft leaves it asks the connected host whether the host holds the
    // draft's session, and reads the host's privacy mode; before a device is given the key, and when
    // a step checks who still may hold it, it asks each host it can who it lists. Every command that
    // can run a step is named, and the page supplies none of the methods' parameters.
    (
        "settings_colour_mode_set",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_sync_turn_on",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_sync_now",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_drafts_set",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_conflict_resolve",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_devices_refresh",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_device_share",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_device_remove",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "settings_join",
        &[
            Method::SessionRead,
            Method::PrivacyStatus,
            Method::DeviceList,
        ],
    ),
    (
        "owner_confirmation_review",
        &[
            Method::OwnerConfirmationPending,
            Method::OwnerConfirmationComplete,
        ],
    ),
    // The devices of the host on this computer, and of each host this computer owns, are listed; a
    // revocation reaches the host on this computer by `device.revoke` over a connection that host
    // admits, and any other host through its feed, which is a service and not a host method. A
    // revocation this computer sent is passed to settings sync, which runs a step of its own: it
    // asks the hosts who they list and reads the connected host's sessions and privacy mode, as
    // every command that can run a step is named to do. The page names a host and a device by
    // references native code gave it.
    (
        "revocation_view",
        &[
            Method::DeviceList,
            Method::SessionRead,
            Method::PrivacyStatus,
        ],
    ),
    (
        "revocation_revoke",
        &[
            Method::DeviceList,
            Method::DeviceRevoke,
            Method::SessionRead,
            Method::PrivacyStatus,
        ],
    ),
    // A view attaches, subscribes, reports its size and its window's place, takes and gives back
    // the input lease, writes the person's wheel turns and keys under it, and detaches, all on the
    // session's worker. The page supplies a session, a grid, its moves and the person's input; what
    // reaches the worker is built here.
    (
        "terminal_view_open",
        &[
            Method::SessionOpen,
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
    // A hand-over of a session's control: the host describes the plan from its own records and
    // asks the owner devices to confirm exactly that, native code reads whether one has, and only
    // then sends the transfer, under the action the plan names.
    (
        "transfer_ask",
        &[
            Method::DeviceList,
            Method::GrantList,
            Method::SessionRead,
            Method::OwnerConfirmationRequest,
        ],
    ),
    ("transfer_answered", &[Method::OwnerConfirmationPending]),
    (
        "transfer_finish",
        &[Method::OwnerConfirmationPending, Method::GrantTransfer],
    ),
    // What was left unfinished. Asking the host again is an exact repeat of the request that was
    // sent, and a state check reads what the host shows; neither is an action of its own.
    ("attempts_list", &[Method::GrantList, Method::GrantHeld]),
    (
        "attempt_ask",
        &[
            Method::GrantCreate,
            Method::GrantRevoke,
            Method::GrantRedeem,
            Method::GrantTransfer,
            Method::GrantList,
            Method::GrantHeld,
        ],
    ),
    // The host opens a session for a screen and says what the grant it runs under allows. The
    // page names the session, the share when it holds one, and the opening it chose.
    ("session_open", &[Method::SessionOpen]),
    // The page names a session; native code reads the snapshot of its agent instances and of every
    // request its broker is arbitrating, following the pages of that one snapshot, on the
    // session's own worker. On a paired host the worker's agents alone are read, which a share
    // without the live screen is served.
    (
        "session_agents",
        &[Method::EventsSnapshot, Method::AgentInstances],
    ),
    // A kept answer is settled, sent and dismissed on this device: settling reads the session's
    // questions and, for a session the worker no longer serves, the daemon's record of it; sending
    // reads them again first and then answers. The page names a question, never a method.
    (
        "question_settle",
        &[Method::QuestionRead, Method::SessionRead],
    ),
    (
        "question_send_kept",
        &[
            Method::QuestionRead,
            Method::SessionRead,
            Method::QuestionAnswer,
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
        environment_capabilities_check,
        setup_identity,
        setup_open_settings,
        session_list,
        session_read,
        session_create,
        session_close,
        session_open,
        session_leave,
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
        device_drafts,
        device_draft_save,
        device_draft_retarget,
        device_draft_discard,
        device_draft_mark_removal,
        draft_create,
        draft_add_attachment,
        attachment_upload,
        attachment_upload_bytes,
        attachment_upload_status,
        history_page,
        action_read,
        action_cancel,
        question_read,
        question_answer,
        question_kept,
        question_settle,
        question_send_kept,
        question_dismiss_kept,
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
        privacy_status,
        grant_notices,
        session_screen_preview,
        grant_create,
        grant_list,
        grant_revoke,
        grant_redeem,
        grant_held,
        transfer_ask,
        transfer_answered,
        transfer_finish,
        transfer_cancel,
        attempts_list,
        attempt_ask,
        attempt_set_hidden,
        attempt_remove,
        plugin_list,
        catalogue_list,
        pairing_set_origin,
        pairing_view,
        pairing_start_code,
        pairing_paste,
        pairing_scan,
        pairing_scan_photo,
        pairing_keep_awake,
        pairing_start_read,
        pairing_stop,
        camera_access,
        app_open_settings,
        owner_confirmations,
        owner_confirmation_review,
        revocation_view,
        revocation_revoke,
        hosts_use,
        hosts_forget,
        push_view,
        push_enable,
        push_refresh,
        notification_route,
        voice_prepare,
        voice_start,
        voice_stop,
        voice_allow,
        voice_scope,
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
        account_sign_in_for_recovery,
        account_sign_in_cancel,
        account_sign_out,
        account_usage,
        sync_service_view,
        sync_service_set,
        recovery_view,
        recovery_turn_on,
        recovery_settle,
        recovery_save_kit,
        recovery_save_kit_qr,
        recovery_archives,
        recovery_export_offline,
        recovery_cover_host,
        settings_view,
        settings_colour_mode_set,
        settings_sync_turn_on,
        settings_sync_now,
        settings_conflicts,
        settings_conflict_resolve,
        settings_drafts_set,
        settings_devices_refresh,
        settings_device_share,
        settings_device_remove,
        settings_devices_dismiss,
        settings_join,
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
        // The connection ended after the request was sent, or the host said it cannot establish
        // whether it happened: either way the action exists, and is what the page asks about.
        Err(
            kr_client::ClientError::SubmissionUncertain { action_id }
            | kr_client::ClientError::OutcomeUnknown { action_id, .. },
        ) => Ok(Settled {
            receipt: None,
            value: None,
            action_id: Some(action_id.to_string()),
        }),
        Err(error) => Err(CommandError::from(error)),
    }
}

/// What a mutation answered with, when the page reads the method's own result.
///
/// A result the host sent is a value of KR-CBOR-1, whose JSON form is diagnostic: an identifier is
/// a byte string there, and renders as base64url, which is not the form the protocol's JSON gives
/// an identifier and not the form a later call has to name it in. So the result is read into the
/// method's own type and written as that type's JSON, as a read's result is.
fn settled_as<R>(answer: &kr_client::Settled) -> Result<Settled>
where
    R: kr_protocol::wire::WireMessage + Serialize,
{
    match answer {
        kr_client::Settled::Result(value) => {
            let own: R = value.to_typed().map_err(|error| {
                CommandError::local_failure(format!(
                    "the host's answer was not the method's own result: {error}"
                ))
            })?;
            Ok(Settled {
                receipt: None,
                value: Some(encode(&own)?),
                action_id: None,
            })
        }
        kr_client::Settled::Receipt(_) => settled(answer),
    }
}

/// What the page is told of one submitted mutation whose own result it reads.
fn submitted_as<R>(
    answer: std::result::Result<kr_client::Settled, kr_client::ClientError>,
) -> Result<Settled>
where
    R: kr_protocol::wire::WireMessage + Serialize,
{
    match answer {
        Ok(value) => settled_as::<R>(&value),
        Err(
            kr_client::ClientError::SubmissionUncertain { action_id }
            | kr_client::ClientError::OutcomeUnknown { action_id, .. },
        ) => Ok(Settled {
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

/// Declares a command that performs one mutation and gives the page the method's own result.
macro_rules! mutate_result_command {
    ($(#[$meta:meta])* $name:ident, $method:expr, $params:ty => $result:ty) => {
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
            submitted_as::<$result>(
                session
                    .mutate($method, target, None, &NoPreconditions {}, &typed, MUTATION_TTL)
                    .await,
            )
        }
    };
}

/// Opens a session for a screen on a host this device is paired with, and says what the grant it
/// runs under allows. On the host on this machine it holds every right and opens nothing.
///
/// The page names the session, the share when it holds one, and the opening it chose.
#[tauri::command]
pub async fn session_open<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    session_id: String,
    grant_id: Option<String>,
    opening: String,
) -> Result<crate::standing::SessionStanding> {
    crate::standing::open_session(&app, &state, &session_id, grant_id.as_deref(), &opening).await
}

/// Leaves a screen's opening of a session: its commands are refused from now on, and its link
/// closes once the mutations in flight on it have answered.
#[tauri::command]
pub fn session_leave(
    state: State<'_, AppState>,
    session_id: String,
    opening: String,
) -> Result<()> {
    crate::standing::leave_session(&state, &session_id, &opening)
}

/// Declares a command that performs one mutation about a session.
///
/// On the host on this machine it goes over the connection every other command uses. On a host
/// this device is paired with, the host serves it only on the connection opened for the session,
/// so it goes over the link of the opening the page names, and a call that names none is refused.
macro_rules! session_mutate_command {
    ($(#[$meta:meta])* $name:ident, $method:expr, $params:ty) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(
            state: State<'_, AppState>,
            links: State<'_, crate::agent::WorkerLinks>,
            subject: Subject,
            params: Value,
            opening: Option<String>,
        ) -> Result<Settled> {
            let typed: $params = decode(params)?;
            if state.paired_context().is_none() {
                let target = subject.target(state.environment_id()?)?;
                let session = state.session()?;
                return submitted(
                    session
                        .mutate($method, target, None, &NoPreconditions {}, &typed, MUTATION_TTL)
                        .await,
                );
            }
            let session_id: kr_protocol::ids::SessionId = subject
                .session_id
                .as_deref()
                .ok_or_else(|| CommandError::invalid("this is about a session, and names none"))?
                .parse()
                .map_err(|_| CommandError::invalid("that is not a session identifier"))?;
            let Some(opening) = opening.as_deref() else {
                return Err(CommandError::invalid(
                    "over a host this device is paired with, this is asked from the session's \
                     own screen",
                ));
            };
            let link = links.link(&state, session_id, Some(opening)).await?;
            let target = subject.target(link.ids.environment_id)?;
            let answer = links.submit(link.link(), $method, target, &typed).await;
            if answer.as_ref().is_err_and(crate::agent::ends_the_link) {
                links.forget(&state, session_id, link.link());
            }
            submitted(answer)
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
            state: State<'_, AppState>,
            links: State<'_, crate::agent::WorkerLinks>,
            params: Value,
            opening: Option<String>,
        ) -> Result<Value> {
            let typed: $params = decode(params)?;
            let answer: $result = links
                .read(
                    &state,
                    typed.subject.session_id,
                    opening.as_deref(),
                    $method,
                    &typed,
                )
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
            state: State<'_, AppState>,
            links: State<'_, crate::agent::WorkerLinks>,
            params: Value,
            opening: Option<String>,
        ) -> Result<Settled> {
            let typed: $params = decode(params)?;
            let check: fn(&$params) -> std::result::Result<(), &'static str> = $check;
            check(&typed).map_err(CommandError::invalid)?;
            let target = typed.target;
            submitted(
                links
                    .mutate(&state, opening.as_deref(), target, $method, &typed)
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
            opening: Option<String>,
        ) -> Result<Settled> {
            let typed: kr_protocol::agent::AgentPromptParams = decode(params)?;
            typed.validate().map_err(CommandError::invalid)?;
            let target = typed.target;
            if typed.draft_id.is_present() {
                not_on_a_paired_host(&state, "a prompt that names a draft")?;
                return send_draft_prompt(&state, $method, &typed).await;
            }
            submitted(
                links
                    .mutate(&state, opening.as_deref(), target, $method, &typed)
                    .await?,
            )
        }
    };
}

/// Refuses what a device paired with a host cannot do: the host serves no file to it, so it keeps
/// no draft with an attachment there, and a command that reaches the host's desktop or its files
/// is not made from here.
fn not_on_a_paired_host(state: &AppState, what: &str) -> Result<()> {
    if state.paired_context().is_some() {
        return Err(CommandError::unsupported(format!(
            "{what} is not offered over a host this device is paired with"
        )));
    }
    Ok(())
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

/// Asks the host to perform the disclosed checks in a session's own worker, and answers where they
/// stand: running, or why nothing was started.
///
/// The checks take a screen image and start an application, so the interface asks only after it
/// has shown what each one does. The page names the environment and nothing else: the parameters
/// are those of `environment.capabilities`, which refuse any other field, and the file the read
/// check reads is not the page's to name, so none is sent. The checks belong to the host on this
/// computer, not to one this device is paired with.
#[tauri::command]
pub async fn environment_capabilities_check(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<Settled> {
    not_on_a_paired_host(&state, "the disclosed checks")?;
    let asked: kr_protocol::desktop::EnvironmentCapabilitiesParams = decode(params)?;
    let typed = kr_protocol::desktop::EnvironmentCapabilitiesCheckParams {
        environment_id: asked.environment_id,
        authorised_file: kr_protocol::scalars::Nullable::null(),
    };
    let target = subject.target(state.environment_id()?)?;
    let session = state.session()?;
    submitted_as::<kr_protocol::desktop::CapabilityChecks>(
        session
            .mutate(
                Method::EnvironmentCapabilitiesCheck,
                target,
                None,
                &NoPreconditions {},
                &typed,
                MUTATION_TTL,
            )
            .await,
    )
}

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
/// Runs a step of the draft store, which blocks on the file system, off the runtime's threads.
async fn blocking<T: Send + 'static>(
    step: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tauri::async_runtime::spawn_blocking(step)
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("keeping the draft stopped: {error}"))
        })?
}

/// Reads the drafts this device keeps.
#[tauri::command]
pub async fn device_drafts(state: State<'_, AppState>) -> Result<Value> {
    let drafts = state.drafts();
    encode(&blocking(move || drafts.read()).await?)
}

/// Keeps a draft: makes it, or replaces the version the page names.
#[tauri::command]
pub async fn device_draft_save(state: State<'_, AppState>, params: Value) -> Result<Value> {
    let typed: crate::drafts::SaveParams = decode(params)?;
    let drafts = state.drafts();
    encode(&blocking(move || drafts.save(typed, kr_ipc::now_ms())).await?)
}

/// Points a draft at a session and conversation a person chose.
#[tauri::command]
pub async fn device_draft_retarget(state: State<'_, AppState>, params: Value) -> Result<Value> {
    let typed: crate::drafts::RetargetParams = decode(params)?;
    let drafts = state.drafts();
    encode(&blocking(move || drafts.retarget(typed, kr_ipc::now_ms())).await?)
}

/// Throws away a draft, if it is still the version the person was shown.
#[tauri::command]
pub async fn device_draft_discard(state: State<'_, AppState>, params: Value) -> Result<Value> {
    let typed: crate::drafts::DiscardParams = decode(params)?;
    let drafts = state.drafts();
    encode(&blocking(move || drafts.discard(&typed)).await?)
}

/// Records a removal of a draft that could not be made, so that the next start makes it.
#[tauri::command]
pub async fn device_draft_mark_removal(state: State<'_, AppState>, params: Value) -> Result<Value> {
    let typed: crate::drafts::DiscardParams = decode(params)?;
    let drafts = state.drafts();
    blocking(move || drafts.mark_removal(typed)).await?;
    encode(&())
}

/// Reads a session's questions.
///
/// On this machine's own host the questions are the session's worker's, and are read over the link
/// held for its agent calls: the daemon here carries neither `question.read` nor `question.answer`
/// for this computer. On a host this device is paired with, the daemon forwards them. What is read
/// is remembered with the place an answer goes, because the answer is checked against the question
/// as the person was shown it.
#[tauri::command]
pub async fn question_read(
    links: State<'_, crate::agent::WorkerLinks>,
    state: State<'_, AppState>,
    params: Value,
    opening: Option<String>,
) -> Result<Value> {
    let typed: kr_protocol::question::QuestionReadParams = decode(params)?;
    encode(&crate::questions::read(&state, &links, opening.as_deref(), typed).await?)
}

/// Answers a question, or keeps the answer on this device when the host did not confirm that it took it.
///
/// The page names the question and the revision it was shown; the question itself and the place
/// the answer goes are the ones read. An answer kept is sent only by [`question_send_kept`].
#[tauri::command]
pub async fn question_answer(
    links: State<'_, crate::agent::WorkerLinks>,
    state: State<'_, AppState>,
    params: Value,
    opening: Option<String>,
) -> Result<Value> {
    let typed: kr_protocol::question::QuestionAnswerParams = decode(params)?;
    let answer = crate::questions::answer(&state, &links, opening.as_deref(), typed).await?;
    encode(&answer)
}

/// Lists the answers kept on this device, in every environment.
#[tauri::command]
pub async fn question_kept(state: State<'_, AppState>) -> Result<Value> {
    encode(&crate::questions::kept(&state))
}

/// Says where the questions of the answers kept for one session stand now. Sends and removes
/// nothing.
#[tauri::command]
pub async fn question_settle(
    links: State<'_, crate::agent::WorkerLinks>,
    state: State<'_, AppState>,
    params: Value,
    opening: Option<String>,
) -> Result<Value> {
    let typed: crate::questions::SettleParams = decode(params)?;
    encode(&crate::questions::settle(&state, &links, opening.as_deref(), &typed).await?)
}

/// Sends one kept answer, for a person who chose to.
#[tauri::command]
pub async fn question_send_kept(
    links: State<'_, crate::agent::WorkerLinks>,
    state: State<'_, AppState>,
    params: Value,
    opening: Option<String>,
) -> Result<Value> {
    let typed: crate::questions::KeptRef = decode(params)?;
    encode(&crate::questions::send(&state, &links, opening.as_deref(), &typed).await?)
}

/// Dismisses one kept answer, if it is still the one the person was shown.
#[tauri::command]
pub async fn question_dismiss_kept(state: State<'_, AppState>, params: Value) -> Result<Value> {
    let typed: crate::questions::KeptRef = decode(params)?;
    encode(&crate::questions::dismiss(&state, &typed).await?)
}
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
    opening: Option<String>,
) -> Result<Value> {
    let typed: kr_protocol::receipt::ActionReadParams = decode(params)?;
    // Over a host this device is paired with, a receipt is read on the session's own link: the
    // connection for the host alone resolves no session. A read that names no session or no
    // opening is refused here, because the host would otherwise resolve the session itself from
    // the route it recorded, under whichever grant that connection holds.
    if state.paired_context().is_some() {
        let (Some(session_id), Some(opening)) = (typed.session_id, opening.as_deref()) else {
            return Err(CommandError::invalid(
                "over a host this device is paired with, a receipt is read from the session's own \
                 screen, naming the session",
            ));
        };
        let answer = links
            .read_receipt(&state, session_id, Some(opening), &typed)
            .await?;
        return encode(&answer);
    }
    let answer = match typed.session_id {
        Some(session_id) if links.serves(session_id)? => {
            links.read_receipt(&state, session_id, None, &typed).await?
        }
        _ => state.session()?.read_receipt(&typed).await?,
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
    // A host does not serve retained output to a paired device: a byte range cannot be narrowed to
    // the time a grant reaches back to. The page is told so and nothing is asked.
    not_on_a_paired_host(&state, "a session's retained output")?;
    let page: kr_protocol::recovery::HistoryPageResult = if links.serves(typed.session_id)? {
        links
            .read(&state, typed.session_id, None, Method::HistoryPage, &typed)
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

mutate_result_command!(
    /// Creates a session, and answers with the method's own result: the page names the new session
    /// in the next call, so its identifier has to be written as the protocol writes one.
    session_create, Method::SessionCreate, kr_protocol::session::SessionCreateParams
        => kr_protocol::session::SessionCreateResult
);
session_mutate_command!(
    /// Closes a session, after the interface has shown what closing does.
    ///
    /// On a host this device is paired with, the close goes over the link of the opening the
    /// screen holds, because the host's connection for the host alone does not close a session.
    session_close, Method::SessionClose, kr_protocol::session::SessionCloseParams
);

/// Launches an installed profile or a named command at a verified empty prompt.
///
/// Not offered over a host this device is paired with: the host takes a launch only from the
/// connection that holds the session's input.
#[tauri::command]
pub async fn shell_launch(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<Settled> {
    not_on_a_paired_host(&state, "launching")?;
    let typed: kr_protocol::root::ShellLaunchParams = decode(params)?;
    let target = subject.target(state.environment_id()?)?;
    let session = state.session()?;
    submitted(
        session
            .mutate(
                Method::ShellLaunch,
                target,
                None,
                &NoPreconditions {},
                &typed,
                MUTATION_TTL,
            )
            .await,
    )
}

/// Creates a draft on the host, which a file is then bound to.
///
/// Not offered over a host this device is paired with: that host serves no file to a device, so a
/// draft there carries no attachment and a prompt sends its text inline.
#[tauri::command]
pub async fn draft_create(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<Settled> {
    not_on_a_paired_host(&state, "a draft")?;
    let typed: kr_protocol::transfer::DraftCreateParams = decode(params)?;
    let target = subject.target(state.environment_id()?)?;
    let session = state.session()?;
    submitted_as::<kr_protocol::transfer::DraftCreateResult>(
        session
            .mutate(
                Method::DraftCreate,
                target,
                None,
                &NoPreconditions {},
                &typed,
                MUTATION_TTL,
            )
            .await,
    )
}

/// Binds a completed attachment handle to a draft, and answers with the draft after it and the
/// binding, whose read grant names the path the file can be read at.
///
/// Not offered over a host this device is paired with, for the reason a draft is not.
#[tauri::command]
pub async fn draft_add_attachment(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<Settled> {
    not_on_a_paired_host(&state, "an attachment")?;
    let typed: kr_protocol::transfer::AgentDraftAddAttachmentParams = decode(params)?;
    let target = subject.target(state.environment_id()?)?;
    let session = state.session()?;
    submitted_as::<kr_protocol::transfer::AgentDraftAddAttachmentResult>(
        session
            .mutate(
                Method::AgentDraftAddAttachment,
                target,
                None,
                &NoPreconditions {},
                &typed,
                MUTATION_TTL,
            )
            .await,
    )
}

session_mutate_command!(
    /// Cancels a pending action.
    ///
    /// A live session's pending action is its worker's: on a host this device is paired with it is
    /// cancelled over the link of the opening the screen holds, and the request names the session.
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
    state: State<'_, AppState>,
    links: State<'_, crate::agent::WorkerLinks>,
    session_id: String,
    opening: Option<String>,
) -> Result<crate::agent::SessionAgents> {
    let session_id: kr_protocol::ids::SessionId = session_id
        .parse()
        .map_err(|_| CommandError::invalid("that is not a session identifier"))?;
    links.agents(&state, session_id, opening.as_deref()).await
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
read_command!(
    /// Reads where privacy mode stands and what has already left the host: the archives and
    /// notifications it sent and the devices that may hold a copy. They are shown and not erased.
    privacy_status, Method::PrivacyStatus,
    kr_protocol::privacy::PrivacyStatusParams => kr_protocol::privacy::PrivacyReport
);
/// Issues one invitation: a grant to a paired device, carrying the notices its issuer was shown.
/// The host refuses one whose notices differ from what the grant actually carries.
///
/// The request is composed and kept before it is sent, and a lost answer is asked about again with
/// the same request: the answer is the attempt, and the host's own result when it gave it.
#[tauri::command]
pub async fn grant_create(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<crate::sharing::Attempted> {
    crate::sharing::create(&state, subject, decode(params)?).await
}

/// Reads the lines on a session's screen, as an invitation that includes the live view would carry
/// them. Nothing is sent to the host's daemon: the session's own worker answers.
#[tauri::command]
pub async fn session_screen_preview(
    links: State<'_, crate::agent::WorkerLinks>,
    state: State<'_, AppState>,
    params: Value,
) -> Result<Value> {
    encode(&crate::sharing::preview(&state, &links, decode(params)?).await?)
}

/// Takes a share back, or withdraws an invitation that has not been accepted.
#[tauri::command]
pub async fn grant_revoke(
    state: State<'_, AppState>,
    params: Value,
) -> Result<crate::sharing::Attempted> {
    crate::sharing::revoke(&state, decode(params)?).await
}

/// Accepts an invitation that names this device.
#[tauri::command]
pub async fn grant_redeem(
    state: State<'_, AppState>,
    params: Value,
) -> Result<crate::sharing::Attempted> {
    crate::sharing::redeem(&state, decode(params)?).await
}

/// Reads what this device is offered and holds, every page of both lists.
#[tauri::command]
pub async fn grant_held(state: State<'_, AppState>) -> Result<crate::sharing::Held> {
    crate::sharing::held(&state).await
}

/// Asks the owner devices to confirm handing a session's control to another device. Nothing that
/// changes who holds the session is sent.
#[tauri::command]
pub async fn transfer_ask(
    state: State<'_, AppState>,
    subject: Subject,
    params: Value,
) -> Result<crate::sharing::HandoverAsked> {
    crate::sharing::transfer_ask(&state, subject, decode(params)?).await
}

/// Says whether an owner device has answered the confirmation a hand-over waits for.
#[tauri::command]
pub async fn transfer_answered(
    state: State<'_, AppState>,
    reference: String,
) -> Result<crate::sharing::HandoverState> {
    crate::sharing::transfer_answered(&state, &reference).await
}

/// Sends the hand-over an owner device confirmed, once.
#[tauri::command]
pub async fn transfer_finish(
    state: State<'_, AppState>,
    reference: String,
) -> Result<crate::sharing::Attempted> {
    crate::sharing::transfer_finish(&state, &reference).await
}

/// Stops waiting for an owner device's confirmation of a hand-over.
#[tauri::command]
pub async fn transfer_cancel(state: State<'_, AppState>, reference: String) -> Result<()> {
    crate::sharing::transfer_cancel(&state, &reference).await
}

/// The attempts this application keeps for the host it is connected to.
#[tauri::command]
pub fn attempts_list(state: State<'_, AppState>) -> Result<crate::sharing::Attempts> {
    crate::sharing::attempts(&state)
}

fn action_of(text: &str) -> Result<kr_protocol::ids::ActionId> {
    text.parse()
        .map_err(|_| CommandError::invalid("that is not an attempt's identifier"))
}

/// Asks the host what became of an attempt, once, with the exact request that was sent. It is the
/// person's choice and is never made by itself.
#[tauri::command]
pub async fn attempt_ask(
    state: State<'_, AppState>,
    action_id: String,
) -> Result<crate::sharing::Attempted> {
    crate::sharing::ask_the_host(&state, action_of(&action_id)?).await
}

/// Takes an attempt out of view, or shows it again. Hiding releases nothing.
#[tauri::command]
pub fn attempt_set_hidden(
    state: State<'_, AppState>,
    action_id: String,
    hidden: bool,
) -> Result<crate::sharing::AttemptView> {
    crate::sharing::set_hidden(&state, action_of(&action_id)?, hidden)
}

/// Deletes the record of an attempt that is over.
#[tauri::command]
pub fn attempt_remove(state: State<'_, AppState>, action_id: String) -> Result<()> {
    crate::sharing::remove(&state, action_of(&action_id)?)
}
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

/// Starts a voice call on this device.
///
/// The call is this application's own: native code holds its media, and the task that owns it
/// asks the host to create it, applies the provider's answer, permits it and opens its control
/// at the voice service. A start is refused before the host is asked for anything when this
/// device cannot control the call afterwards, which is when it has no account token for the voice
/// scope: the service closes a call nobody controls, and a person pays for the seconds it ran.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn voice_start<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    calls: State<'_, crate::voice::Calls>,
    account: State<'_, crate::account::AccountSlot>,
    subject: Subject,
    session_ids: Vec<String>,
    duration_seconds: u32,
    reasoning_budget_minor: Option<String>,
    prepared: kr_protocol::scalars::Digest256,
    expected_rate_version: Option<String>,
) -> Result<VoiceStarted> {
    let session_ids = session_ids
        .iter()
        .map(|id| {
            id.parse()
                .map_err(|_| CommandError::invalid("that is not a session identifier"))
        })
        .collect::<Result<Vec<kr_protocol::ids::SessionId>>>()?;
    let reasoning_budget_minor = reasoning_budget_minor
        .map(|minor| {
            minor
                .parse::<u64>()
                .map_err(|_| CommandError::invalid("a reasoning budget is a whole number"))
        })
        .transpose()?;
    let tokens = account.get().await?.tokens();
    let started = calls
        .start(
            crate::voice::StartRequest {
                session_ids,
                duration_seconds,
                reasoning_budget_minor,
                prepared,
                expected_rate_version,
                subject,
            },
            std::sync::Arc::new(crate::voice::AppReach::new(app)),
            tokens,
        )
        .await?;
    Ok(match started {
        crate::voice::Started::Result(value) => VoiceStarted {
            receipt: None,
            value: Some(value),
            action_id: None,
        },
        crate::voice::Started::Receipt(receipt) => VoiceStarted {
            action_id: Some(receipt.action_id.to_string()),
            receipt: Some(*receipt),
            value: None,
        },
        crate::voice::Started::Unknown { action_id } => VoiceStarted {
            receipt: None,
            value: None,
            action_id: Some(action_id.to_string()),
        },
    })
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

/// Ends the call this device holds, and asks the host to revoke its grant.
///
/// The media stops first and the host is asked at once, each with a bound of its own, so a call
/// that cannot be stopped locally never holds a revocation, and a host that cannot be reached
/// never holds the media (section 15 paragraph 10). The answer keeps the two apart: what was done
/// here, and what the host said. The voice service is finalised after that, and the screen does
/// not wait for it. A page that names a call this device does not hold asks the host about that
/// one and closes nothing here.
#[tauri::command]
pub async fn voice_stop<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    calls: State<'_, crate::voice::Calls>,
    voice_session_id: Option<String>,
) -> Result<VoiceClosure> {
    let named = voice_session_id
        .map(|id| {
            id.parse()
                .map_err(|_| CommandError::invalid("that is not a voice session identifier"))
        })
        .transpose()?;
    let reach = crate::voice::AppReach::new(app);
    let closed = calls.stop(named, &reach).await?;
    Ok(VoiceClosure::from_closed(closed))
}

/// What a stop's answer shows of the fence its withdrawal owed, as the page is given it.
///
/// The page needs one thing of the host's answer, whether every worker holds the revision that
/// refuses what the call sent, and it is given that and nothing else of the answer: a member this
/// build does not read is not passed on. The answer is a stop's result when it is a result at all,
/// so the host revoked the grant; the `barrier` member is then read on its own, and the page is
/// given the barrier without the names of the actions the fence named ([`without_the_names`]), or
/// that the host owed no fence, which a host says with a null `barrier`. A barrier that is absent
/// or that this build cannot read is not "owed none": it is reported as unreadable, because
/// whether a worker may still take up what the call sent is then not known here. An answer that is
/// a receipt is not a stop's result, and is a failure to read what the host said.
pub(crate) fn fence_of(answer: &kr_client::Settled) -> Result<VoiceFence> {
    let kr_client::Settled::Result(value) = answer else {
        return Err(CommandError::local_failure(
            "the host answered the stop with a receipt, not with its result",
        ));
    };
    let barrier = match value.as_value() {
        kr_cbor::CanonicalValue::Map(result) => result.get("barrier"),
        _ => None,
    };
    Ok(match barrier {
        Some(kr_cbor::CanonicalValue::Null) => VoiceFence::NotOwed,
        Some(barrier) => {
            match kr_protocol::envelope::ParamsValue::from(barrier.clone())
                .to_typed::<kr_protocol::action::RevocationBarrier>()
            {
                Ok(barrier) => VoiceFence::Barrier {
                    barrier: without_the_names(barrier),
                },
                Err(_) => VoiceFence::Unreadable,
            }
        }
        None => VoiceFence::Unreadable,
    })
}

/// A replacement's result as the page reads it: what the grant permits and could not carry, each
/// read strictly, and what the answer showed of the fence its replacement owed, read the way a
/// stop's is ([`fence_of`]).
///
/// The host has replaced the grant by the time it answers. So an answer this build cannot read
/// (a host older than the build that added the fence's status, say) is not a failure to ask: the
/// grant may have changed, and the person is told that, not that the request failed here.
fn allowed_from(answer: &kr_client::Settled) -> Result<VoiceAllowed> {
    let unreadable = || {
        CommandError::unavailable(
            "The host answered, but this application could not read what it granted, so the \
             grant may have changed. Allow voice again to read it.",
        )
    };
    let kr_client::Settled::Result(value) = answer else {
        return Err(unreadable());
    };
    let kr_cbor::CanonicalValue::Map(result) = value.as_value() else {
        return Err(unreadable());
    };
    let member = |name: &str| result.get(name).cloned().ok_or_else(unreadable);
    let statement = kr_protocol::envelope::ParamsValue::from(member("statement")?)
        .to_typed::<kr_protocol::voice::VoiceGrantStatement>()
        .map_err(|_| unreadable())?;
    let not_held_by_device =
        kr_protocol::envelope::ParamsValue::from(member("not_held_by_device")?)
            .to_typed::<kr_protocol::scalars::CanonicalSet<kr_protocol::voice::VoiceAction>>()
            .map_err(|_| unreadable())?;
    Ok(VoiceAllowed {
        statement,
        not_held_by_device,
        fence: fence_of(answer)?,
    })
}

/// What the host's answer to a stop showed of the fence its withdrawal owed (read by `fence_of`).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VoiceFence {
    /// The host said it owed no fence.
    NotOwed,
    /// The status of the workers the fence waited for, without the names of the actions it named.
    /// A worker still `pending` may yet take up what the call sent.
    Barrier {
        /// The barrier, as a stop's result carries it.
        barrier: kr_protocol::action::RevocationBarrier,
    },
    /// The host revoked the grant, and its answer gave no status for its workers that this build
    /// could read, so whether every worker holds is not known here.
    Unreadable,
}

/// What ending a call did, locally and on the host.
#[derive(Debug, Serialize)]
pub struct VoiceClosure {
    /// Whether this device's own call is stopped: native code returned from the stop, or had ended
    /// the call already. False when this device held no call (the page named one it does not hold,
    /// and only the host was asked) and when native code did not return from the stop in time.
    pub closed_locally: bool,
    /// What the host's answer showed of its fence; none when there was no answer to read: the host
    /// could not be told, or what it answered was not a stop's result.
    pub fence: Option<VoiceFence>,
    /// Why the host could not be told, or its answer not read, when it could not.
    pub host_failure: Option<CommandError>,
    /// Whether the host answered that it holds no call of this device by that name. A stop from
    /// this device can end nothing more there; the answer says nothing of a grant or of the
    /// workers' fence, and the host keeps what it owes.
    pub not_held: bool,
}

impl VoiceClosure {
    /// The closure for what ending a call did here and at the host.
    fn from_closed(closed: crate::voice::Closed) -> Self {
        use crate::voice::HostEnd;
        let told = match closed.host {
            HostEnd::Revoked { fence, .. } => Ok(Some(fence)),
            HostEnd::NotNeeded => Ok(None),
            HostEnd::NotHeld { .. } => {
                return Self {
                    closed_locally: closed.local,
                    fence: None,
                    host_failure: None,
                    not_held: true,
                };
            }
            HostEnd::Refused { words } => Err(CommandError::refused(words)),
            HostEnd::NotTold { words } => Err(CommandError::unavailable(words)),
        };
        match told {
            Ok(fence) => Self {
                closed_locally: closed.local,
                fence,
                host_failure: None,
                not_held: false,
            },
            Err(error) => Self::of(closed.local, Err(error)),
        }
    }

    /// The closure for what the host said, or for why it could not be told.
    fn of(closed_locally: bool, told_the_host: Result<VoiceFence>) -> Self {
        match told_the_host {
            Ok(fence) => Self {
                closed_locally,
                fence: Some(fence),
                host_failure: None,
                not_held: false,
            },
            Err(error) => Self {
                closed_locally,
                fence: None,
                host_failure: Some(error),
                not_held: false,
            },
        }
    }
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

/// Silences the microphone or the model's voice on this device, or ends the silence.
///
/// Local and immediate: native code carries it out, and the voice service is only told of a
/// microphone's mute as advice to the provider.
#[tauri::command]
pub async fn voice_set_muted(
    calls: State<'_, crate::voice::Calls>,
    what: VoiceMute,
    muted: bool,
) -> Result<crate::voice::VoiceCallState> {
    let what = match what {
        VoiceMute::Microphone => companion_platform::call::Mute::Microphone,
        VoiceMute::Playback => companion_platform::call::Mute::Playback,
    };
    calls.set_muted(what, muted).await
}

/// What the call this device holds is doing, how the last one ended, and what a person is told
/// before starting another.
#[tauri::command]
pub async fn voice_call_state(
    state: State<'_, AppState>,
    calls: State<'_, crate::voice::Calls>,
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::voice::VoiceCallState> {
    let generation = match account.get().await {
        Ok(account) => match account.tokens().status() {
            Ok(kr_client::services::account::AccountStatus::SignedIn { generation, .. }) => {
                Some(generation)
            }
            _ => None,
        },
        Err(_) => None,
    };
    let environment = state.environment_id().ok().map(|id| id.to_string());
    Ok(calls.state(calls.note_key(environment, generation).as_ref()))
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

/// What allowing voice came to: the sentences the grant states, what it could not carry, and what
/// the answer showed of the fence that replacing the grant owed. The device the grant is for is
/// not in it.
///
/// Replacing the standing grant ends the calls under it, and when a close sent under one of them
/// can still reach a worker the host's answer names the workers that have not acknowledged the
/// fence. That is passed on as a stop's is (see `fence_of`): the barrier less the names of the
/// actions the fence named, `not_owed` when the replacement owed none, and `unreadable` when the
/// answer gave no status this build can read, so the screen can say that those workers are still
/// to confirm, or that it cannot tell.
#[derive(Debug, Serialize)]
pub struct VoiceAllowed {
    /// What the grant permits, each action in the sentence that states it.
    pub statement: kr_protocol::voice::VoiceGrantStatement,
    /// The actions the person asked for that this device's own grant does not carry, so the grant
    /// does not either.
    pub not_held_by_device: kr_protocol::scalars::CanonicalSet<kr_protocol::voice::VoiceAction>,
    /// What the answer showed of the fence the replacement owed.
    pub fence: VoiceFence,
}

/// A fence's barrier as the page reads it: which workers have held and which have not, with every
/// total, and none of the names of the actions the fence named.
///
/// A fence names an action by the principal that submitted it, and a call's own close is the
/// device's, so the names carry the identity the host gave this device. The page reads which
/// session's worker has not held and how many there were, and holds no identity.
fn without_the_names(
    barrier: kr_protocol::action::RevocationBarrier,
) -> kr_protocol::action::RevocationBarrier {
    kr_protocol::action::RevocationBarrier {
        workers: barrier
            .workers
            .into_iter()
            .map(|worker| kr_protocol::action::WorkerBarrier {
                rejected_actions: Vec::new(),
                possibly_executed: Vec::new(),
                ..worker
            })
            .collect(),
        ..barrier
    }
}

/// Lets the person allow what a voice call on this device may do, for the host it is paired with.
///
/// The grant is this device's own, so native code names the device: the page does not hold the
/// identity the host gave it, and a grant for any other device is a host-management change that
/// this application, a paired device, does not make. The answer states every action the grant
/// permits, every one the device's own grant could not carry and the barrier of the fence the
/// replacement owed without the names of the actions it named, and nothing else of what the host
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
        Ok(answer @ kr_client::Settled::Result(_)) => Ok(Settled {
            receipt: None,
            action_id: None,
            value: Some(encode(&allowed_from(&answer)?)?),
        }),
        other => submitted(other),
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
    // A host this device is paired with takes no file from it.
    not_on_a_paired_host(&state, "a file")?;
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
    // A host this device is paired with takes no file from it.
    not_on_a_paired_host(&state, "a file")?;
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
pub async fn pairing_paste(state: State<'_, AppState>) -> Result<crate::device::IntakeView> {
    take_in(&state, pairing::Source::Pasteboard).await
}

/// Shows the phone's scanner, reads an invitation from the code it sees in native code, and holds it
/// for the person to use. The page is told what it is, never what it says.
#[tauri::command]
pub async fn pairing_scan(state: State<'_, AppState>) -> Result<crate::device::IntakeView> {
    take_in(&state, pairing::Source::Camera).await
}

/// Shows the system's picker, reads an invitation from the code in the picture the person chose in
/// native code, and holds it for the person to use. The page is told what it is, never what it says.
#[tauri::command]
pub async fn pairing_scan_photo(state: State<'_, AppState>) -> Result<crate::device::IntakeView> {
    take_in(&state, pairing::Source::Photo).await
}

/// Says whether the system lets this application use the camera, so the attachment picker offers
/// it only where it would do something, and tells the person where it would not.
#[tauri::command]
pub async fn camera_access<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<companion_platform::scan::CameraAccess> {
    Ok(companion_platform::scan::camera_access(&app).await)
}

/// Opens this application's page in the system's settings, where the camera is allowed. It opens
/// nothing else.
#[tauri::command]
pub async fn app_open_settings<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<()> {
    companion_platform::scan::open_settings(&app)
        .await
        .map_err(|error| CommandError::local_failure(error.to_string()))
}

/// Keeps a phone's screen on while the value to compare with the host's shows, and lets it sleep
/// again when the value goes. It changes nothing else.
#[tauri::command]
pub async fn pairing_keep_awake<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    on: bool,
) -> Result<()> {
    companion_platform::scan::keep_awake(&app, on)
        .await
        .map_err(|error| CommandError::local_failure(error.to_string()))
}

async fn take_in(
    state: &State<'_, AppState>,
    source: pairing::Source,
) -> Result<crate::device::IntakeView> {
    let device = state.device()?;
    let platform = state.intake()?;
    Ok(pairing::take_in(&*platform, &device, source).await)
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

/// Where each paired host's notifications stand.
///
/// A computer has none, and says so: the view is empty and not available.
#[tauri::command]
pub fn push_view(state: State<'_, AppState>) -> Result<crate::push::PushView> {
    Ok(state
        .push()
        .map_or_else(unavailable_push_view, |desk| desk.view()))
}

/// Turns notifications on for the host the page named, and starts the steps that make this phone a
/// place the host can send them to.
///
/// The page names the host by the reference the pairing screen listed it under. Native code asks
/// the system, asks the notification service, waits for its own receiver to answer the challenge,
/// and gives the host the credential; the page is told where it stands on `kr://push`.
#[tauri::command]
pub fn push_enable(state: State<'_, AppState>, reference: String) -> Result<crate::push::PushView> {
    state
        .push()
        .ok_or_else(|| CommandError::unsupported("notifications are a phone's"))?
        .enable(&reference)
}

/// Looks again at where notifications stand, and mends what a change since the last look needs.
#[tauri::command]
pub async fn push_refresh(state: State<'_, AppState>) -> Result<crate::push::PushView> {
    let Some(desk) = state.push() else {
        return Ok(unavailable_push_view());
    };
    Ok(desk.refresh().await)
}

/// The screen a tap on a notification opened the application on, once.
#[tauri::command]
pub async fn notification_route(state: State<'_, AppState>) -> Result<Option<String>> {
    let Some(desk) = state.push() else {
        return Ok(None);
    };
    Ok(desk.route().await)
}

fn unavailable_push_view() -> crate::push::PushView {
    crate::push::PushView {
        available: false,
        hosts: Vec::new(),
    }
}

/// Forgets a host this computer is paired with, named by the reference the pairing screen listed it
/// under, and says where that leaves the connection.
///
/// A local action that reaches no host, so it works after a host has revoked this computer. The
/// host keeps what it holds of this device; this computer stops listing, using and trying it.
#[tauri::command]
pub fn hosts_forget<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    reference: String,
) -> Result<crate::connection::ConnectionState> {
    let host = state
        .device()?
        .host_by_reference(&reference)
        .ok_or_else(crate::hosts::unknown_host)?;
    let forgotten = crate::hosts::forget_host(&app, &host)?;
    // What is kept of a host's notifications goes with the host. The host's own destination stays
    // until its owner removes this device: only the host revokes an authorisation it holds.
    if let Some(desk) = state.push() {
        desk.forgotten(host.host_device_id);
    }
    Ok(forgotten)
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

/// The devices of the host on this computer and of every host this computer owns, each with where a
/// revocation of it stands, and what each host's feed holds of its last acknowledgement. Every host
/// and every feed is asked.
#[tauri::command]
pub async fn revocation_view(
    state: State<'_, AppState>,
) -> Result<crate::revocation::RevocationView> {
    Ok(state.revocations()?.look(&state.revocation_context()).await)
}

/// Revokes a device on a host this computer owns, once the person confirms it with the platform's
/// ceremony. The page names a host and a device by the references the view gave it, never a key, an
/// identifier or a method: native code sends the revocation to the host on this computer directly
/// and to any other host through its feed.
#[tauri::command]
pub async fn revocation_revoke(
    state: State<'_, AppState>,
    host: String,
    device: String,
) -> Result<crate::revocation::RevocationView> {
    state
        .revocations()?
        .revoke(&state.revocation_context(), &host, &device)
        .await
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
///
/// On a host this device is paired with the view has a connection of its own, which the host opens
/// for the session under the grant the screen's opening runs under; the view belongs to that
/// opening and ends when it does. When the view's connection ends and the opening's link does not,
/// the host is asked again what the opening allows, and the page is told.
#[tauri::command]
pub async fn terminal_view_open<R: tauri::Runtime>(
    webview: tauri::Webview<R>,
    state: State<'_, AppState>,
    session_id: String,
    columns: u64,
    rows: u64,
    opening: Option<String>,
    on_state: tauri::ipc::Channel<crate::terminal::TerminalViewState>,
) -> Result<String> {
    use tauri::{Emitter as _, Manager as _};

    let views = webview.state::<crate::terminal::TerminalViews>();
    let session_id: kr_protocol::ids::SessionId = session_id
        .parse()
        .map_err(|_| CommandError::invalid("that is not a session identifier"))?;
    let dimensions = view_size(columns, rows)?;
    let Some(context) = state.paired_context() else {
        let publish: crate::terminal::Publish = std::sync::Arc::new(move |state| {
            // A page that has gone takes nothing; its load ends the view.
            let _ = on_state.send(state);
        });
        return Ok(views.open(webview.label(), session_id, dimensions, publish));
    };
    let Some(opening) = opening else {
        return Err(CommandError::invalid(
            "over a host this device is paired with, a view is opened from the session's own screen",
        ));
    };
    let links = std::sync::Arc::clone(state.paired_links());
    let grant = links.opening_grant(session_id, &opening)?;
    let dial = crate::standing::Dial::new(context.device, context.host);
    let publish: crate::terminal::Publish = {
        let (links, opening) = (std::sync::Arc::clone(&links), opening.clone());
        std::sync::Arc::new(move |view_state| {
            if matches!(
                view_state,
                crate::terminal::TerminalViewState::Showing { .. }
            ) {
                // The view's connection held long enough to draw: its losses so far are forgiven.
                links.drew(session_id, &opening);
            }
            // A page that has gone takes nothing; its load ends the view.
            let _ = on_state.send(view_state);
        })
    };
    // A view that ended because its own connection went may have lost only that: the host is asked
    // again, on the link the opening holds, what the opening allows.
    let on_lost: Box<dyn FnOnce() + Send> = {
        let (links, opening) = (std::sync::Arc::clone(&links), opening.clone());
        let emitter = webview.app_handle().clone();
        Box::new(move || {
            links.note_recheck();
            tauri::async_runtime::spawn(async move {
                let emit: crate::standing::Emitter = std::sync::Arc::new(move |event| {
                    let _ = emitter.emit(crate::standing::STANDING_EVENT, event);
                });
                links.recheck(&emit, session_id, &opening).await;
            });
        })
    };
    let handle = views.open_paired(
        webview.label(),
        crate::terminal::Paired {
            dial,
            grant,
            on_lost,
        },
        session_id,
        dimensions,
        publish,
    );
    // The view belongs to the opening: leaving or replacing it, or the share ending, closes the
    // view, which holds the session's input for as long as it lives.
    if let Err(close) = links.attach_view(session_id, &opening, views.closer(&handle)) {
        close();
        return Err(CommandError::stated(
            kr_protocol::error::ErrorCode::StaleSession,
            "This screen was replaced by another opening of the session.",
        ));
    }
    Ok(handle)
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

    /// The barrier of a fence that named the device's own close, with one worker in this state.
    fn a_barrier_with(
        state: kr_protocol::action::BarrierState,
        session: kr_protocol::ids::SessionId,
    ) -> kr_protocol::action::RevocationBarrier {
        use kr_protocol::action::{FencedAction, RevocationBarrier, WorkerBarrier};
        use kr_protocol::ids::{ActionId, ActorId, AuthorityRevision};
        use kr_protocol::scalars::{Nullable, U64, Uuid};

        RevocationBarrier::new(
            AuthorityRevision::new(5),
            vec![WorkerBarrier {
                session_id: session,
                state,
                acknowledged_revision: Nullable::null(),
                rejected_actions: vec![FencedAction {
                    actor_id: ActorId::new("device:phone").expect("a principal"),
                    action_id: ActionId::new(Uuid::from_bytes([1; 16])),
                }],
                rejected_actions_total: U64::new(1),
                possibly_executed: Vec::new(),
                possibly_executed_total: U64::new(0),
                omitted_actions: U64::new(0),
                names_pending: U64::new(0),
                detail: String::new(),
            }],
        )
    }

    /// The barrier of a fence that named the device's own close, with one worker that has not held.
    fn a_barrier_with_a_pending_worker() -> kr_protocol::action::RevocationBarrier {
        a_barrier_with(
            kr_protocol::action::BarrierState::Pending,
            kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
        )
    }

    /// A replacement's answer as the client gives it: the result the host sends as a map, with the
    /// member `without` left out when a test names one.
    fn a_replacement_answered_without(without: Option<&str>) -> kr_client::Settled {
        use kr_protocol::ids::GrantId;
        use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

        let granted = kr_protocol::voice::VoiceGrantResult {
            grant_id: GrantId::new(Uuid::from_bytes([5; 16])),
            device_id: kr_protocol::ids::DeviceId::new(Uuid::from_bytes([4; 16])),
            statement: kr_protocol::voice::VoiceGrantStatement::of(&CanonicalSet::new()),
            not_held_by_device: CanonicalSet::new(),
            barrier: Nullable::some(a_barrier_with_a_pending_worker()),
        };
        let kr_cbor::CanonicalValue::Map(typed) =
            kr_cbor::to_canonical_value(&granted).expect("it encodes")
        else {
            panic!("a result is a map");
        };
        let mut result = kr_cbor::CanonicalMap::new();
        for (key, held) in typed.entries() {
            if Some(key.as_str()) != without {
                result.insert(key.clone(), held.clone()).expect("a key");
            }
        }
        kr_client::Settled::Result(kr_cbor::CanonicalValue::Map(result).into())
    }

    /// A replacement's result reaches the page without the names of the actions the fence named,
    /// and as the page reads a session: its identifier as text, not as the wire's bytes.
    #[test]
    fn a_replacements_result_reaches_the_page_without_names() {
        use kr_protocol::scalars::Uuid;

        let read = encode(&allowed_from(&a_replacement_answered_without(None)).expect("it reads"))
            .expect("it encodes");

        let said = read.to_string();
        assert!(!said.contains("device:phone"), "{said}");
        assert!(read.get("device_id").is_none(), "{said}");
        assert_eq!(read["fence"]["kind"], "barrier");
        assert_eq!(
            read["fence"]["barrier"]["workers"][0]["session_id"],
            kr_protocol::ids::SessionId::new(Uuid::from_bytes([9; 16])).to_string(),
            "the page reads a session as text"
        );
        assert_eq!(read["fence"]["barrier"]["workers"][0]["state"], "pending");
        assert_eq!(read["fence"]["barrier"]["workers_total"], "1");
    }

    /// The host has replaced the grant by the time it answers, so an answer this build cannot read
    /// is not a failure of the request: the page is told the grant may have changed, and what the
    /// answer showed of its fence is not taken for "none owed" when it showed none.
    #[test]
    fn a_replacement_this_build_cannot_read_is_told_as_unreadable_and_not_as_a_local_failure() {
        for without in ["statement", "not_held_by_device"] {
            let error = allowed_from(&a_replacement_answered_without(Some(without)))
                .expect_err("an answer without its sentences is not read");
            assert_eq!(
                error.code,
                kr_protocol::error::ErrorCode::ResourceUnavailable,
                "{without}: {error:?}"
            );
            assert!(
                error.message.contains("may have changed"),
                "{without}: {error:?}"
            );
        }

        let read =
            allowed_from(&a_replacement_answered_without(Some("barrier"))).expect("it reads");
        assert!(
            matches!(read.fence, VoiceFence::Unreadable),
            "no status for the workers is not none owed: {read:?}"
        );
    }

    /// A stop's answer as the client gives it: the result the host sends, as a map the test may add
    /// a member to, with the barrier the caller gives in place of the typed one, or none.
    fn a_stop_answered_with(barrier: Option<kr_cbor::CanonicalValue>) -> kr_cbor::CanonicalMap {
        use kr_protocol::ids::GrantId;
        use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};

        let stopped = kr_protocol::voice::VoiceStopResult {
            voice_session_id: kr_protocol::ids::VoiceSessionId::new(Uuid::from_bytes([7; 16])),
            revoked_grant_id: GrantId::new(Uuid::from_bytes([6; 16])),
            revoked_at_ms: TimestampMs::new(1_700_000_000_000),
            broker_notified: true,
            sessions_left_running: CanonicalSet::new(),
            barrier: Nullable::some(a_barrier_with_a_pending_worker()),
        };
        let kr_cbor::CanonicalValue::Map(typed) =
            kr_cbor::to_canonical_value(&stopped).expect("it encodes")
        else {
            panic!("a result is a map");
        };
        let mut result = kr_cbor::CanonicalMap::new();
        for (key, held) in typed.entries() {
            if key == "barrier" {
                if let Some(barrier) = &barrier {
                    result.insert(key.clone(), barrier.clone()).expect("a key");
                }
            } else {
                result.insert(key.clone(), held.clone()).expect("a key");
            }
        }
        result
    }

    fn the_barrier_as_the_host_sends_it() -> kr_cbor::CanonicalValue {
        kr_cbor::to_canonical_value(&a_barrier_with_a_pending_worker()).expect("it encodes")
    }

    /// What the page is given for a stop answered with this result, as the command encodes it.
    fn the_closure_for(result: kr_cbor::CanonicalMap) -> serde_json::Value {
        let answered = kr_client::Settled::Result(kr_cbor::CanonicalValue::Map(result).into());
        serde_json::to_value(VoiceClosure::of(true, fence_of(&answered))).expect("it encodes")
    }

    /// Section 9: a stop answered with a worker that has not held reaches the page as pending, with
    /// the worker's session as text, its state and the totals, and no name of an action. A member
    /// of the answer this build does not read is not passed on, whatever it carries: a host newer
    /// than this build has still revoked the grant, and its pending worker is still shown.
    #[test]
    fn a_stop_with_a_pending_worker_reaches_the_page_as_pending_and_without_names() {
        for unknown_member in [false, true] {
            let mut result = a_stop_answered_with(Some(the_barrier_as_the_host_sends_it()));
            if unknown_member {
                result
                    .insert(
                        "a_member_a_later_host_adds".to_owned(),
                        kr_cbor::CanonicalValue::Text("device:phone".to_owned()),
                    )
                    .expect("a new key");
            }

            let closure = the_closure_for(result);

            let said = closure.to_string();
            assert!(!said.contains("device:phone"), "{unknown_member}: {said}");
            assert!(
                !said.contains("a_member_a_later_host_adds"),
                "{unknown_member}: {said}"
            );
            assert_eq!(closure["fence"]["kind"], "barrier", "{said}");
            let worker = &closure["fence"]["barrier"]["workers"][0];
            assert_eq!(worker["state"], "pending", "{unknown_member}: {said}");
            assert_eq!(
                worker["session_id"],
                kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]))
                    .to_string()
            );
            assert_eq!(closure["fence"]["barrier"]["workers_total"], "1");
            assert_eq!(closure["host_failure"], serde_json::Value::Null);
            let mut members: Vec<&str> = closure
                .as_object()
                .expect("a closure is an object")
                .keys()
                .map(String::as_str)
                .collect();
            members.sort_unstable();
            assert_eq!(
                members,
                ["closed_locally", "fence", "host_failure", "not_held"]
            );
        }
    }

    /// Section 9: a stop whose answer gives no status for its workers that this build can read (a
    /// barrier with a member it does not know, a barrier that is absent, a result that is not a
    /// map) is reported as unreadable, not as a fence the host did not owe, and the page is given
    /// nothing the answer carried. A null `barrier` is the host saying it owed none.
    #[test]
    fn a_stop_with_no_status_this_build_can_read_is_reported_as_unreadable() {
        let mut barrier = match the_barrier_as_the_host_sends_it() {
            kr_cbor::CanonicalValue::Map(barrier) => barrier,
            other => panic!("a barrier is a map: {other:?}"),
        };
        barrier
            .insert(
                "a_member_a_later_host_adds".to_owned(),
                kr_cbor::CanonicalValue::Text("device:phone".to_owned()),
            )
            .expect("a new key");
        let unknown_in_the_barrier =
            a_stop_answered_with(Some(kr_cbor::CanonicalValue::Map(barrier)));
        let no_barrier = a_stop_answered_with(None);
        let not_a_map = kr_client::Settled::Result(kr_cbor::CanonicalValue::Bool(true).into());
        let null_barrier = a_stop_answered_with(Some(kr_cbor::CanonicalValue::Null));

        for (what, result, kind) in [
            (
                "an unknown member in the barrier",
                unknown_in_the_barrier,
                "unreadable",
            ),
            ("no barrier member", no_barrier, "unreadable"),
            ("a null barrier", null_barrier, "not_owed"),
        ] {
            let closure = the_closure_for(result);
            assert_eq!(closure["fence"]["kind"], kind, "{what}: {closure}");
            assert!(
                !closure.to_string().contains("device:phone"),
                "{what}: {closure}"
            );
            assert_eq!(closure["fence"].as_object().map(|each| each.len()), Some(1));
        }
        let closure = serde_json::to_value(VoiceClosure::of(false, fence_of(&not_a_map)))
            .expect("it encodes");
        assert_eq!(closure["fence"]["kind"], "unreadable", "{closure}");
    }

    /// A stop answered with a receipt is not an answer the host gave to the stop: the page is told
    /// the host could not be read, so it says the grant may still be open, and is given no fence.
    #[test]
    fn a_stop_answered_with_a_receipt_is_a_failure_to_read_the_host() {
        use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

        let receipt = kr_protocol::receipt::Receipt {
            action_id: kr_protocol::ids::ActionId::new(Uuid::from_bytes([1; 16])),
            actor_id: kr_protocol::ids::ActorId::new("device:phone").expect("a principal"),
            method: Method::VoiceStop.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            revision: U64::new(2),
            state: kr_protocol::receipt::ReceiptState::Dispatching,
            reason: Nullable::null(),
            payload_digest: Digest256::from_bytes([0; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::null(),
            error_withheld: false,
            updated_at_ms: TimestampMs::new(0),
        };

        let closure = serde_json::to_value(VoiceClosure::of(
            false,
            fence_of(&kr_client::Settled::Receipt(Box::new(receipt))),
        ))
        .expect("it encodes");

        assert_eq!(closure["fence"], serde_json::Value::Null, "{closure}");
        assert_ne!(
            closure["host_failure"],
            serde_json::Value::Null,
            "{closure}"
        );
        assert!(!closure.to_string().contains("device:phone"), "{closure}");
    }

    /// The closures the page is given for a stop are the ones the page is tested with: the cases
    /// of the fixture the page's tests read are built here from the answers a host sends, and
    /// encoded as the command encodes them, so a name or a shape that native code gives and the page
    /// does not read fails here.
    #[test]
    fn the_closures_the_page_is_given_for_a_stop_are_the_ones_the_page_is_tested_with() {
        use kr_protocol::action::BarrierState;

        let cases: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../test/fixtures/voice-stop-closures.json"))
                .expect("the cases");
        let session: kr_protocol::ids::SessionId = "8a7b6c50-22bb-4c3d-8e4f-000000000101"
            .parse()
            .expect("a session");
        let barrier = |state| {
            kr_cbor::to_canonical_value(&a_barrier_with(state, session)).expect("it encodes")
        };
        let mut unreadable = match barrier(BarrierState::Pending) {
            kr_cbor::CanonicalValue::Map(barrier) => barrier,
            other => panic!("a barrier is a map: {other:?}"),
        };
        unreadable
            .insert(
                "a_member_a_later_host_adds".to_owned(),
                kr_cbor::CanonicalValue::Bool(true),
            )
            .expect("a new key");
        let answers = [
            (
                "the host owed no fence",
                a_stop_answered_with(Some(kr_cbor::CanonicalValue::Null)),
            ),
            (
                "every worker holds",
                a_stop_answered_with(Some(barrier(BarrierState::Acknowledged))),
            ),
            (
                "a worker has not held",
                a_stop_answered_with(Some(barrier(BarrierState::Pending))),
            ),
            (
                "the host's status could not be read",
                a_stop_answered_with(Some(kr_cbor::CanonicalValue::Map(unreadable))),
            ),
        ];

        // A host that holds no call of this device by that name is not a stop's result: it is the
        // refusal of the stop, read from the host's code and carried as the closure of a stop.
        let not_held = serde_json::to_value(VoiceClosure::from_closed(crate::voice::Closed {
            local: true,
            host: crate::voice::HostEnd::NotHeld {
                words: "there is no such voice session on this host".to_owned(),
            },
        }))
        .expect("it encodes");

        assert_eq!(
            cases.len(),
            answers.len() + 1,
            "every case has an answer, and one is the host's refusal"
        );
        for (name, answer) in answers {
            let case = cases
                .iter()
                .find(|case| case["name"] == name)
                .unwrap_or_else(|| panic!("no case is named {name}"));
            assert_eq!(the_closure_for(answer), case["closure"], "{name}");
        }
        let case = cases
            .iter()
            .find(|case| case["name"] == "the host holds no call of this device")
            .expect("the case of a host that holds no such call");
        assert_eq!(not_held, case["closure"]);
    }

    /// A fence names an action by the principal that submitted it, which for a call's own close is
    /// the device. The page is given the barrier without those names, and with everything else: the
    /// session of each worker, its state and every total.
    #[test]
    fn the_barrier_the_page_reads_names_no_action_and_keeps_every_count() {
        use kr_protocol::action::{
            BarrierState, FencedAction, PossiblyExecutedAction, RevocationBarrier, WorkerBarrier,
        };
        use kr_protocol::ids::{ActionId, ActorId, AuthorityRevision, SessionId};
        use kr_protocol::scalars::{Nullable, U64, Uuid};

        let device = ActorId::new("device:phone").expect("a principal");
        let session = SessionId::new(Uuid::from_bytes([9; 16]));
        let barrier = RevocationBarrier::new(
            AuthorityRevision::new(5),
            vec![WorkerBarrier {
                session_id: session,
                state: BarrierState::Pending,
                acknowledged_revision: Nullable::null(),
                rejected_actions: vec![FencedAction {
                    actor_id: device.clone(),
                    action_id: ActionId::new(Uuid::from_bytes([1; 16])),
                }],
                rejected_actions_total: U64::new(1),
                possibly_executed: vec![PossiblyExecutedAction {
                    action_id: ActionId::new(Uuid::from_bytes([2; 16])),
                    actor_id: device,
                    method: Method::SessionClose.into(),
                    state: kr_protocol::receipt::ReceiptState::Unknown,
                }],
                possibly_executed_total: U64::new(1),
                omitted_actions: U64::new(0),
                names_pending: U64::new(0),
                detail: "the worker has not acknowledged the revision".to_owned(),
            }],
        );

        let read = without_the_names(barrier.clone());

        assert!(read.workers[0].rejected_actions.is_empty());
        assert!(read.workers[0].possibly_executed.is_empty());
        assert_eq!(read.workers[0].rejected_actions_total.get(), 1);
        assert_eq!(read.workers[0].possibly_executed_total.get(), 1);
        assert_eq!(read.pending(), barrier.pending());
        assert_eq!(read.workers_total, barrier.workers_total);
        assert!(
            !serde_json::to_string(&read)
                .expect("it encodes")
                .contains("device:phone")
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
            // This window holds no call, and no account is signed in.
            .manage(crate::voice::Calls::absent())
            .manage(crate::account::AccountSlot::new(Box::new(|| {
                Box::pin(async { Err("no account runs in this test".to_owned()) })
            })))
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

    /// The commands that reach a session are all commands the application registers, and none is
    /// listed twice.
    #[test]
    fn every_session_bound_command_is_a_named_command() {
        let mut seen = BTreeSet::new();
        for command in SESSION_BOUND_COMMANDS {
            assert!(seen.insert(command), "{command} is listed twice");
            assert!(
                NAMED_COMMANDS.iter().any(|(name, _)| name == command),
                "{command} is not a command the application registers"
            );
        }
    }

    /// The commands that open no link to a session's worker on a paired host: the host's own
    /// reads, the application's own, the sharing commands, which go over the connection for the
    /// host alone or to the worker on this computer, and the four that act on a terminal view
    /// already opened on a session's own connection, whose route the terminal tests prove. Every
    /// named command is in this list or in [`SESSION_BOUND_COMMANDS`], so a command added to the
    /// table is not left out of the one tour that proves the route of the commands that reach a
    /// session: adding one fails this test until it is classified.
    const HOST_OR_LOCAL_COMMANDS: &[&str] = &[
        "push_view",
        "push_enable",
        "push_refresh",
        "notification_route",
        "host_info",
        "environment_list",
        "environment_capabilities",
        "environment_capabilities_check",
        "setup_identity",
        "setup_open_settings",
        "session_list",
        "session_read",
        "session_create",
        "session_describe",
        "description_setup",
        "description_configure",
        "description_download",
        "terminal_view_resize",
        "terminal_view_move",
        "terminal_view_input",
        "terminal_view_close",
        "device_drafts",
        "device_draft_save",
        "device_draft_retarget",
        "device_draft_discard",
        "device_draft_mark_removal",
        "attachment_upload_status",
        "question_kept",
        "question_dismiss_kept",
        "attention_read",
        "attention_acknowledge",
        "review_read",
        "review_acknowledge",
        "changeset_read",
        "device_list",
        "privacy_status",
        "grant_notices",
        "grant_create",
        "grant_list",
        "grant_revoke",
        "grant_redeem",
        "grant_held",
        "session_screen_preview",
        "transfer_ask",
        "transfer_answered",
        "transfer_finish",
        "transfer_cancel",
        "attempts_list",
        "attempt_ask",
        "attempt_set_hidden",
        "attempt_remove",
        "plugin_list",
        "catalogue_list",
        "pairing_set_origin",
        "pairing_view",
        "pairing_start_code",
        "pairing_paste",
        "pairing_scan",
        "pairing_scan_photo",
        "pairing_keep_awake",
        "pairing_start_read",
        "pairing_stop",
        "camera_access",
        "app_open_settings",
        "owner_confirmations",
        "owner_confirmation_review",
        "revocation_view",
        "revocation_revoke",
        "hosts_use",
        "hosts_forget",
        "voice_prepare",
        "voice_start",
        "voice_stop",
        "voice_allow",
        "voice_scope",
        "voice_context",
        "voice_set_muted",
        "voice_call_state",
        "open_external",
        "import_remote_image",
        "choose_export_destination",
        "export_semantic_json",
        "export_asciicast",
        "connection_state",
        "account_status",
        "account_sign_in",
        "account_sign_in_cancel",
        "account_sign_out",
        "account_usage",
        "account_sign_in_for_recovery",
        "sync_service_view",
        "sync_service_set",
        "recovery_view",
        "recovery_turn_on",
        "recovery_settle",
        "recovery_save_kit",
        "recovery_save_kit_qr",
        "recovery_archives",
        "recovery_export_offline",
        "recovery_cover_host",
        "settings_view",
        "settings_colour_mode_set",
        "settings_sync_turn_on",
        "settings_sync_now",
        "settings_conflicts",
        "settings_conflict_resolve",
        "settings_drafts_set",
        "settings_devices_refresh",
        "settings_device_share",
        "settings_device_remove",
        "settings_devices_dismiss",
        "settings_join",
    ];

    #[test]
    fn every_named_command_is_classified_by_the_route_it_takes() {
        for (command, _) in NAMED_COMMANDS {
            let session = SESSION_BOUND_COMMANDS.contains(command);
            let other = HOST_OR_LOCAL_COMMANDS.contains(command);
            assert!(
                session != other,
                "{command} is classified {} times: it reaches a session, or it does not",
                u8::from(session) + u8::from(other)
            );
        }
        for command in HOST_OR_LOCAL_COMMANDS {
            assert!(
                NAMED_COMMANDS.iter().any(|(name, _)| name == command),
                "{command} is not a command the application registers"
            );
        }
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
            "owner.confirmation.request",
            "grant.transfer",
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
                "pairing_scan",
                "pairing_scan_photo",
                "pairing_keep_awake",
                "pairing_start_read",
                "pairing_stop",
                "camera_access",
                "app_open_settings",
                "owner_confirmations",
                "owner_confirmation_review",
                // The devices of the hosts this computer owns, and revoking one of them: native
                // code lists them, asks the person, and sends the revocation itself.
                "revocation_view",
                "revocation_revoke",
                // The host a phone's commands go to: it pairs, then it chooses, and it may forget.
                "hosts_use",
                "hosts_forget",
                // Notifications: where each paired host's stand, turning them on for one, looking
                // again, and the screen a tap opened. Native code asks the gateway, waits for its
                // own receiver, and hands the host the credential; the page names a host.
                "push_view",
                "push_enable",
                "push_refresh",
                "notification_route",
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
                // The account's six. Each reaches the account service or this device's secure
                // store, and none reaches a host.
                "account_sign_in",
                "account_sign_in_cancel",
                "account_sign_in_for_recovery",
                "account_sign_out",
                "account_status",
                "account_usage",
                // The sync service setting's two and recovery's five. The setting is one origin
                // kept on this computer; recovery's seed is made, kept and written by native code,
                // and a kit is written only where a save dialog put it. The fifth covers the host
                // on this computer: it performs methods of its own (see `NATIVE_METHODS`) and the
                // page names only whether a replacement is asked for.
                "sync_service_set",
                "sync_service_view",
                "recovery_archives",
                "recovery_cover_host",
                "recovery_export_offline",
                "recovery_save_kit",
                "recovery_save_kit_qr",
                "recovery_settle",
                "recovery_turn_on",
                "recovery_view",
                // The person's settings' four. The colour mode is kept in a file on this computer,
                // and settings sync sends the settings sealed under a key only this person's
                // devices hold; the page names a mode and nothing else.
                "settings_view",
                "settings_colour_mode_set",
                "settings_sync_turn_on",
                "settings_sync_now",
                // The versions of a setting two devices changed, and the person's choice between
                // them. The page names a copy this computer showed it, or this computer's own, and
                // is shown neither key nor identity.
                "settings_conflicts",
                "settings_conflict_resolve",
                // Whether drafts are kept in step too. The page names a switch and nothing else.
                "settings_drafts_set",
                // Who shares the settings: asking the hosts who they list, giving a device the
                // key once the person confirms on this computer, taking one out, and joining what
                // another device shares. The page names a device by a reference this computer
                // showed it, never a key, and the person's presence is the platform's ceremony.
                "settings_devices_refresh",
                "settings_device_share",
                "settings_device_remove",
                "settings_devices_dismiss",
                "settings_join",
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
                // A session screen's opening: the host opens the session for it on a connection of
                // its own, and the screen leaves it.
                "session_open",
                "session_leave",
                // What an invitation would carry, from the protocol's own table. It reaches
                // nothing.
                "grant_notices",
                // A hand-over of control: the host describes the plan and asks the owner devices,
                // native code reads whether one answered, and only then sends the transfer. The
                // page names a session, a grant, a device and a reference, never a method.
                "transfer_ask",
                "transfer_answered",
                "transfer_finish",
                "transfer_cancel",
                // The attempts to share, accept, take back and hand over that this application
                // keeps, and what a person does with one that was left unfinished.
                "attempts_list",
                "attempt_ask",
                "attempt_set_hidden",
                "attempt_remove",
                // The answers kept for a worker out of reach, and what a person does with them:
                // the questions themselves go to the session's worker.
                "question_kept",
                "question_settle",
                "question_send_kept",
                "question_dismiss_kept",
                // The drafts this device keeps, in a store of its own.
                "device_drafts",
                "device_draft_save",
                "device_draft_retarget",
                "device_draft_discard",
                "device_draft_mark_removal",
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
            Method::OwnerConfirmationRequest,
            Method::GrantTransfer,
            Method::DeviceRevoke,
            Method::BackupEnable,
            Method::DevicePushRegister,
            Method::DevicePreviewKeyUpdate,
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
        // A device is revoked at the host on this computer by the one command that asks the person
        // first, and at any other host through its feed, which is no host method.
        assert_eq!(
            performing(Method::DeviceRevoke),
            BTreeSet::from(["revocation_revoke"])
        );
        assert_eq!(
            performing(Method::PairFinish),
            BTreeSet::from(["pairing_start_code", "pairing_start_read"])
        );
        // A confirmation is asked for by the hand-over's own command, and a transfer is sent by
        // the one that has the owner device's answer, or by the person asking the host about it.
        assert_eq!(
            performing(Method::OwnerConfirmationRequest),
            BTreeSet::from(["transfer_ask"])
        );
        assert_eq!(
            performing(Method::GrantTransfer),
            BTreeSet::from(["attempt_ask", "transfer_finish"])
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
    /// be in the same way, and so does a voice start, which parses its sessions before it asks
    /// for an account or a host.
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
            environment_capabilities_check,
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
            draft_add_attachment,
            attachment_upload,
            attachment_upload_bytes,
            attachment_upload_status,
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
            privacy_status,
            session_screen_preview,
            grant_create,
            grant_list,
            grant_revoke,
            grant_redeem,
            grant_held,
            plugin_list,
            catalogue_list,
            voice_prepare,
            voice_start,
            voice_stop,
            voice_allow,
            voice_context,
        ]);
        // One body for every command: each reads the arguments it takes and nothing else. The
        // voice stop and the voice start read their own one by one. The identifiers they parse
        // themselves are not identifiers, and the values the invoke layer types are of their types,
        // so the refusal is the command's own rather than the invoke layer's.
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
                // What a device holds takes no parameters, and the application is not connected.
                "host_info" | "environment_list" | "description_setup" | "grant_held" => {
                    "HOST_NOT_CONFIGURED"
                }
                "attachment_upload" => "PERMISSION_DENIED",
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
    /// KR-REQ-25.25, the part about the destination of an export at the command boundary: a
    /// semantic JSON or asciicast export is written to a destination registered as the save
    /// dialog's answer, once, and a path the page names writes nothing.
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

/// Signs this device in again through the system browser, asking for the right to write the
/// account's backup storage as well, which keeping a recovery bundle takes.
#[tauri::command]
pub async fn account_sign_in_for_recovery(
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::account::AccountView> {
    Ok(account.get().await?.sign_in_for_recovery().await)
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

/// The sync service this computer is set to use.
#[tauri::command]
pub fn sync_service_view(
    state: State<'_, AppState>,
) -> Result<crate::sync_service::SyncServiceView> {
    Ok(state.sync_service()?.view())
}

/// Chooses another sync service. The page names an origin and nothing else: no path, no token.
///
/// The choice is flushed to disk twice, so it is kept on a thread of its own and does not hold the
/// window.
#[tauri::command]
pub async fn sync_service_set(
    state: State<'_, AppState>,
    origin: String,
) -> Result<crate::sync_service::SyncServiceView> {
    let service = state.sync_service()?;
    tauri::async_runtime::spawn_blocking(move || service.set(&origin))
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("the sync service setting was not kept: {error}"))
        })?
}

/// Where recovery stands on this computer, and what stops the next step.
#[tauri::command]
pub async fn recovery_view(
    state: State<'_, AppState>,
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::recovery::RecoveryView> {
    state.recovery()?.view(account.get().await?).await
}

/// Makes the recovery seed, keeps it in this device's secure store, and puts the bundle at the
/// sync service before anything is written down for the person to keep.
#[tauri::command]
pub async fn recovery_turn_on(
    state: State<'_, AppState>,
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::recovery::RecoveryView> {
    state.recovery()?.turn_on(account.get().await?).await
}

/// Ends a write to the recovery bundle that was not answered, so that the next one can go.
#[tauri::command]
pub async fn recovery_settle(
    state: State<'_, AppState>,
    account: State<'_, crate::account::AccountSlot>,
) -> Result<crate::recovery::RecoveryView> {
    state.recovery()?.settle(account.get().await?).await
}

/// Writes the recovery kit to the file the person chose, as a QR code to print.
///
/// The kit holds the seed, so it is drawn and written by this process to a destination a save
/// dialog returned, and the page is told only where.
#[tauri::command]
pub async fn recovery_save_kit_qr(
    state: State<'_, AppState>,
    path: String,
) -> Result<crate::recovery::KitSaved> {
    let destination = state.take_export_destination(std::path::Path::new(&path))?;
    state.recovery()?.save_kit_qr(&destination).await?;
    Ok(crate::recovery::KitSaved { path })
}

/// The archives the recovery bundle names at the sync service, each with its newest generation.
#[tauri::command]
pub async fn recovery_archives(
    state: State<'_, AppState>,
    account: State<'_, crate::account::AccountSlot>,
) -> Result<Vec<crate::recovery::ArchiveView>> {
    state.recovery()?.archives(account.get().await?).await
}

/// Writes an offline export to the file the person chose: the recovery bundle and, when an archive
/// is named, that archive's newest generation, as ciphertext. Nothing decrypted is written.
#[tauri::command]
pub async fn recovery_export_offline(
    state: State<'_, AppState>,
    account: State<'_, crate::account::AccountSlot>,
    path: String,
    archive: Option<String>,
) -> Result<crate::recovery::ExportSaved> {
    let archive = archive
        .map(|text| {
            text.parse::<kr_protocol::ids::ArchiveId>()
                .map_err(|_| CommandError::invalid("that is not an archive identifier"))
        })
        .transpose()?;
    let destination = state.take_export_destination(std::path::Path::new(&path))?;
    state
        .recovery()?
        .export_offline(account.get().await?, &destination, archive)
        .await
}

/// Covers the host on this computer with this computer's recovery, or says why it cannot.
///
/// The page says only whether a replacement is asked for. The host's status is read over the
/// connection to the host on this computer, the bundle is committed naming the host's archive, and
/// the host is set up under this computer's recovery with the bytes that landed; nothing the kit
/// opens, no key and no locator reaches the page.
#[tauri::command]
pub async fn recovery_cover_host(
    state: State<'_, AppState>,
    account: State<'_, crate::account::AccountSlot>,
    replace: bool,
) -> Result<crate::recovery::HostCoverView> {
    let connection = state.connection()?;
    if !matches!(connection.standing(), crate::connection::Standing::Owner) {
        return Err(CommandError::refused(
            "recovery covers the host on this computer, and this application is connected to \
             another host",
        ));
    }
    let host =
        kr_client::recovery::SessionHost::new(connection.session(), connection.environment_id());
    state
        .recovery()?
        .cover_host(account.get().await?, &host, replace)
        .await
}

/// Writes the recovery kit to the file the person chose.
///
/// The kit holds the seed, so it is written by this process to a destination a save dialog
/// returned, and the page is told only where. Nothing the kit holds reaches the page.
#[tauri::command]
pub async fn recovery_save_kit(
    state: State<'_, AppState>,
    path: String,
) -> Result<crate::recovery::KitSaved> {
    let destination = state.take_export_destination(std::path::Path::new(&path))?;
    state.recovery()?.save_kit(&destination).await?;
    Ok(crate::recovery::KitSaved { path })
}

/// The person's settings, and where keeping them in step with their other devices stands.
#[tauri::command]
pub fn settings_view(state: State<'_, AppState>) -> Result<crate::settings::SettingsView> {
    Ok(state.settings()?.view())
}

/// Keeps the person's choice of colour mode, and sends it to their other devices when settings
/// sync is on.
///
/// The page names one of three words. The choice is on this computer's disk before the answer
/// comes back, whether or not the sync service can be reached.
#[tauri::command]
pub async fn settings_colour_mode_set(
    state: State<'_, AppState>,
    mode: crate::settings::ColourMode,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.set_colour_mode(mode).await
}

/// Turns settings sync on: the settings are sealed under a key only this person's devices hold and
/// kept at the sync service.
#[tauri::command]
pub async fn settings_sync_turn_on(
    state: State<'_, AppState>,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.sync_turn_on().await
}

/// Brings this computer and the sync service to the same settings now, when settings sync is on.
#[tauri::command]
pub async fn settings_sync_now(
    state: State<'_, AppState>,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.sync_now().await
}

/// The versions of the settings the person is asked to choose between, when two devices changed the
/// same setting. Nothing is sent.
#[tauri::command]
pub fn settings_conflicts(
    state: State<'_, AppState>,
) -> Result<Option<crate::settings::ConflictView>> {
    state.settings()?.conflicts()
}

/// Turns the keeping of drafts in step with the person's other devices on or off. Settings sync has
/// to be on first: drafts travel in its collection. A draft that arrives from another device is kept
/// beside this computer's own and is never sent anywhere.
#[tauri::command]
pub async fn settings_drafts_set(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.drafts_set(enabled).await
}

/// Looks at the hosts and their feeds: a request of this computer's that a feed holds is found
/// there and recorded, so that a device it may revoke is not offered to be shared with again, and
/// one the feed shows a host refused is let go of.
async fn looked_at_the_feeds(state: &State<'_, AppState>) {
    if let Ok(revocations) = state.revocations() {
        revocations.view(&state.revocation_context()).await;
    }
}

/// Asks every host who it lists, brings this computer and the sync service to the same settings, and
/// on a computer that shares none, looks for collections other devices share with it. When the
/// sheet then shows a device kept out because it was revoked, the feeds are looked at, so that what
/// they hold of this computer's requests says whether it is offered.
#[tauri::command]
pub async fn settings_devices_refresh(
    state: State<'_, AppState>,
) -> Result<crate::settings::SettingsView> {
    let settings = state.settings()?;
    let view = settings.devices_refresh().await?;
    if !settings.shows_held_out() {
        return Ok(view);
    }
    looked_at_the_feeds(&state).await;
    Ok(settings.view())
}

/// A device the person's hosts list is given the settings' key, once the person confirms it on this
/// computer with the platform's ceremony. The page names the device by the reference it was shown.
/// The feeds are looked at first: a request of this computer's for the device that a feed holds
/// keeps it from being given the key.
#[tauri::command]
pub async fn settings_device_share(
    state: State<'_, AppState>,
    reference: String,
) -> Result<crate::settings::SettingsView> {
    let settings = state.settings()?;
    looked_at_the_feeds(&state).await;
    settings.device_share(&reference).await
}

/// A device is taken out of the shared settings. Taking rights away asks for no ceremony.
#[tauri::command]
pub async fn settings_device_remove(
    state: State<'_, AppState>,
    reference: String,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.device_remove(&reference).await
}

/// The outcomes of changes the page has shown are let go.
#[tauri::command]
pub async fn settings_devices_dismiss(
    state: State<'_, AppState>,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.devices_dismiss().await
}

/// This computer joins the settings another of the person's devices shares, once the person
/// confirms it here with the platform's ceremony. The page names the offer by its reference.
#[tauri::command]
pub async fn settings_join(
    state: State<'_, AppState>,
    reference: String,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.device_join(&reference).await
}

/// Records which version the person keeps. The page names this computer's own or a copy this
/// computer showed it; whichever is kept, every copy that waited is let go.
#[tauri::command]
pub async fn settings_conflict_resolve(
    state: State<'_, AppState>,
    keep: crate::settings::Keep,
) -> Result<crate::settings::SettingsView> {
    state.settings()?.resolve_conflict(keep).await
}
