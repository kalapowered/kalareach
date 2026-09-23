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
use serde::Serialize;
use serde_json::Value;
use tauri::State;

use crate::error::{CommandError, Result};
use crate::state::AppState;
use crate::target::Subject;
use crate::{export, links, pairing, remote, setup, verify};

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
    ("pairing_origin", None),
    ("pairing_set_origin", None),
    ("pairing_scan", None),
    ("pairing_verify_owner", None),
    ("pair_status", Some(Method::PairStatus)),
    // The application's own boundary.
    ("open_external", None),
    ("import_remote_image", None),
    ("choose_export_destination", None),
    ("export_semantic_json", None),
    ("export_asciicast", None),
    ("connection_state", None),
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
        pairing_origin,
        pairing_set_origin,
        pairing_scan,
        pairing_verify_owner,
        pair_status,
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
    /// Reads a pairing attempt's state.
    pair_status, Method::PairStatus,
    kr_protocol::preauth::PairStatusParams => kr_protocol::preauth::PairStatusResult
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

/// The rendezvous origin this device is configured with.
///
/// The interface shows it on manual code entry and on the issuing screen, which is why it is a
/// command rather than a value the page holds.
#[tauri::command]
pub fn pairing_origin(state: State<'_, AppState>) -> pairing::Origin {
    state.origin()
}

/// Changes the rendezvous origin, before an attempt starts.
#[tauri::command]
pub fn pairing_set_origin(state: State<'_, AppState>, origin: String) -> Result<pairing::Origin> {
    state.set_origin(&origin)
}

/// Reads a scanned QR payload against the configured origin.
///
/// A code QR that names another origin comes back marked as needing confirmation; the interface
/// shows the hostname and waits for the person before anything is sent to it.
#[tauri::command]
pub fn pairing_scan(state: State<'_, AppState>, payload: String) -> Result<pairing::Scanned> {
    pairing::scan(&payload, &state.origin())
}

/// Runs the platform's user-verification ceremony on this device.
///
/// The ceremony is the platform's own window and a person may take a while over it, so it runs on
/// a blocking worker rather than holding a command thread.
#[tauri::command]
pub async fn pairing_verify_owner(reason: String) -> Result<verify::Presence> {
    tauri::async_runtime::spawn_blocking(move || verify::verify_owner_presence(&reason))
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("the ceremony did not finish: {error}"))
        })?
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

    #[test]
    fn every_named_command_is_unique() {
        let mut seen = BTreeSet::new();
        for (command, _) in NAMED_COMMANDS {
            assert!(seen.insert(command), "{command} is registered twice");
        }
    }

    /// KR-REQ-10.01: the WebView reaches only the named commands the native side validates.
    #[test]
    fn no_command_reaches_a_method_outside_the_named_set() {
        // The page cannot name a method, so the reachable set is exactly the methods these
        // commands name. This is the sentence the boundary rests on, written as a test.
        let reachable: BTreeSet<&str> = NAMED_COMMANDS
            .iter()
            .filter_map(|(_, method)| method.map(Method::as_str))
            .collect();
        for forbidden in [
            "session.describe",
            "session.rename",
            "project.clone",
            "workflow.run",
            "voice.start",
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
                "pairing_origin",
                "pairing_scan",
                "pairing_set_origin",
                "pairing_verify_owner",
                // Setup's own two. Neither performs a protocol operation: one reads this
                // application's identity and one opens a settings pane by name.
                "setup_identity",
                "setup_open_settings",
            ])
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

    /// KR-REQ-10.01: parameters from the WebView are validated before anything is sent.
    #[test]
    fn parameters_that_are_not_the_methods_shape_are_refused_before_anything_is_sent() {
        let refusal: Result<kr_protocol::session::SessionReadParams> =
            decode(serde_json::json!({ "session_id": "the one I was looking at" }));
        let error = refusal.expect_err("that is not a session identifier");
        assert_eq!(error.code, kr_protocol::error::ErrorCode::InvalidArgument);
    }

    /// KR-REQ-13.21: a command that is handed a path acts only on one the platform gave this
    /// process: a file dropped on the window, or a destination a save dialog returned. Called the
    /// way the page calls it, through the invoke path, any other path is refused with
    /// `PERMISSION_DENIED` before anything is read or written, and a path the platform handed over
    /// passes that gate once.
    #[test]
    fn a_path_the_page_names_is_refused_at_the_command_boundary() {
        use tauri::Manager as _;

        let app = tauri::test::mock_builder()
            .manage(AppState::new())
            .invoke_handler(tauri::generate_handler![
                attachment_upload,
                export_semantic_json
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        let refusal_code = |command: &str, body: serde_json::Value| -> Option<String> {
            tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: command.into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: "tauri://localhost".parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
            .err()
            .map(|error| error["code"].as_str().unwrap_or_default().to_owned())
        };
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
    }

    /// KR-REQ-10.01: an unknown field from the WebView is refused.
    #[test]
    fn a_parameter_map_with_an_unknown_field_is_refused() {
        let refusal: Result<kr_protocol::session::SessionReadParams> = decode(serde_json::json!({
            "session_id": "44444444-4444-4444-8444-444444444444",
            "and_also": "run this"
        }));
        assert!(
            refusal.is_err(),
            "a closed schema refuses what it does not name"
        );
    }
}
