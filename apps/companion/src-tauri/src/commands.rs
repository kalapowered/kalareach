//! Every command the WebView may call, and nothing else.
//!
//! Each command names one [`Method`] in its own body. The page supplies parameters; it never
//! supplies a method, a path or a command line. An operation with no command here cannot be
//! reached from the page at all, which is what section 13 means by exposing only the shared
//! client's named commands.
//!
//! [`NAMED_COMMANDS`] is that surface as data. The crate's tests hold it against the handler list
//! and against the Tauri capability file, so a command added in one place and not the others fails
//! the build rather than widening the boundary quietly.

use kr_protocol::method::Method;
use serde_json::Value;
use tauri::State;

use crate::error::{CommandError, Result};
use crate::state::AppState;
use crate::{export, links, pairing, remote, verify};

/// One command, and the protocol method it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Named {
    /// The name the WebView invokes.
    pub command: &'static str,
    /// The protocol method it performs, where it performs one.
    pub method: Option<Method>,
}

/// The complete command surface.
pub const NAMED_COMMANDS: &[Named] = &[
    // Hosts and environments.
    Named { command: "host_info", method: Some(Method::HostInfo) },
    Named { command: "environment_list", method: Some(Method::EnvironmentList) },
    Named { command: "environment_capabilities", method: Some(Method::EnvironmentCapabilities) },
    // Sessions.
    Named { command: "session_list", method: Some(Method::SessionList) },
    Named { command: "session_read", method: Some(Method::SessionRead) },
    Named { command: "session_create", method: Some(Method::SessionCreate) },
    Named { command: "session_close", method: Some(Method::SessionClose) },
    Named { command: "session_rename", method: Some(Method::SessionRename) },
    // Attachments and the terminal view.
    Named { command: "session_attach", method: Some(Method::SessionAttach) },
    Named { command: "session_detach", method: Some(Method::SessionDetach) },
    Named { command: "attachment_configure", method: Some(Method::AttachmentConfigure) },
    Named { command: "attachment_viewport", method: Some(Method::AttachmentViewport) },
    Named { command: "terminal_resize", method: Some(Method::TerminalResize) },
    Named { command: "terminal_palette_set", method: Some(Method::TerminalPaletteSet) },
    // Input.
    Named { command: "input_acquire", method: Some(Method::InputAcquire) },
    Named { command: "input_release", method: Some(Method::InputRelease) },
    Named { command: "input_interrupt", method: Some(Method::InputInterrupt) },
    Named { command: "input_write", method: Some(Method::InputWrite) },
    // The launch surface.
    Named { command: "shell_launch", method: Some(Method::ShellLaunch) },
    // The semantic interface.
    Named { command: "agent_capabilities", method: Some(Method::AgentCapabilities) },
    Named { command: "agent_snapshot", method: Some(Method::AgentSnapshot) },
    Named { command: "agent_commands", method: Some(Method::AgentCommands) },
    Named { command: "composer_submit", method: Some(Method::AgentPromptSubmit) },
    Named { command: "composer_queue", method: Some(Method::AgentPromptQueue) },
    Named { command: "composer_steer", method: Some(Method::AgentTurnSteer) },
    Named { command: "composer_interrupt", method: Some(Method::AgentTurnCancel) },
    Named { command: "approval_respond", method: Some(Method::AgentApprovalRespond) },
    Named { command: "plugin_action_invoke", method: Some(Method::PluginActionInvoke) },
    // Drafts and attachments.
    Named { command: "draft_create", method: Some(Method::DraftCreate) },
    Named { command: "draft_update", method: Some(Method::DraftUpdate) },
    Named { command: "draft_add_attachment", method: Some(Method::AgentDraftAddAttachment) },
    Named { command: "attachment_image", method: Some(Method::DownloadBegin) },
    Named { command: "attachment_image_chunk", method: Some(Method::DownloadChunk) },
    // Events and history.
    Named { command: "events_subscribe", method: Some(Method::EventsSubscribe) },
    Named { command: "events_snapshot", method: Some(Method::EventsSnapshot) },
    Named { command: "history_page", method: Some(Method::HistoryPage) },
    Named { command: "action_read", method: Some(Method::ActionRead) },
    Named { command: "action_cancel", method: Some(Method::ActionCancel) },
    // Attention and review.
    Named { command: "attention_read", method: Some(Method::AttentionRead) },
    Named { command: "attention_acknowledge", method: Some(Method::AttentionAcknowledge) },
    Named { command: "review_read", method: Some(Method::ReviewRead) },
    Named { command: "review_acknowledge", method: Some(Method::ReviewAcknowledge) },
    // Questions, sharing and the explained invitation.
    Named { command: "question_read", method: Some(Method::QuestionRead) },
    Named { command: "question_answer", method: Some(Method::QuestionAnswer) },
    Named { command: "grant_list", method: Some(Method::GrantList) },
    Named { command: "grant_create", method: Some(Method::GrantCreate) },
    Named { command: "grant_revoke", method: Some(Method::GrantRevoke) },
    // Plugins: Installed, Catalogue and Repositories.
    Named { command: "plugin_list", method: Some(Method::PluginList) },
    Named { command: "plugin_capabilities", method: Some(Method::PluginCapabilities) },
    Named { command: "catalogue_list", method: Some(Method::CatalogueList) },
    Named { command: "catalogue_sync", method: Some(Method::CatalogueSync) },
    // Change sets and diffs.
    Named { command: "changeset_read", method: Some(Method::ChangesetRead) },
    Named { command: "diff_read", method: Some(Method::DiffRead) },
    // Privacy and retained artefacts.
    Named { command: "storage_status", method: Some(Method::StorageStatus) },
    Named { command: "storage_object_delete", method: Some(Method::StorageObjectDelete) },
    // Pairing.
    Named { command: "pairing_origin", method: None },
    Named { command: "pairing_set_origin", method: None },
    Named { command: "pairing_scan", method: None },
    Named { command: "pairing_verify_owner", method: None },
    Named { command: "pair_invite", method: Some(Method::PairInvite) },
    Named { command: "pair_confirm", method: Some(Method::PairConfirm) },
    Named { command: "pair_cancel", method: Some(Method::PairCancel) },
    Named { command: "pair_status", method: Some(Method::PairStatus) },
    // The application's own boundary.
    Named { command: "open_external", method: None },
    Named { command: "import_remote_image", method: None },
    Named { command: "export_semantic_json", method: None },
    Named { command: "export_asciicast", method: None },
    Named { command: "connection_state", method: None },
];

/// The command handlers, in the form Tauri registers.
///
/// The page can reach exactly these. There is no handler that takes a method name.
#[must_use]
pub fn handlers() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        host_info,
        environment_list,
        environment_capabilities,
        session_list,
        session_read,
        session_create,
        session_close,
        session_rename,
        session_attach,
        session_detach,
        attachment_configure,
        attachment_viewport,
        terminal_resize,
        terminal_palette_set,
        input_acquire,
        input_release,
        input_interrupt,
        input_write,
        shell_launch,
        agent_capabilities,
        agent_snapshot,
        agent_commands,
        composer_submit,
        composer_queue,
        composer_steer,
        composer_interrupt,
        approval_respond,
        plugin_action_invoke,
        draft_create,
        draft_update,
        draft_add_attachment,
        attachment_image,
        attachment_image_chunk,
        events_subscribe,
        events_snapshot,
        history_page,
        action_read,
        action_cancel,
        attention_read,
        attention_acknowledge,
        review_read,
        review_acknowledge,
        question_read,
        question_answer,
        grant_list,
        grant_create,
        grant_revoke,
        plugin_list,
        plugin_capabilities,
        catalogue_list,
        catalogue_sync,
        changeset_read,
        diff_read,
        storage_status,
        storage_object_delete,
        pairing_origin,
        pairing_set_origin,
        pairing_scan,
        pairing_verify_owner,
        pair_invite,
        pair_confirm,
        pair_cancel,
        pair_status,
        open_external,
        import_remote_image,
        export_semantic_json,
        export_asciicast,
        connection_state,
    ]
}

/// Performs one method through the current host link.
async fn perform(
    state: &AppState,
    method: Method,
    environment_id: &str,
    params: Value,
) -> Result<Value> {
    let target = crate::link::environment_target(environment_id)?;
    state.link().call(method, target, params).await
}

/// Declares one command that performs one method and nothing else.
macro_rules! protocol_command {
    ($(#[$meta:meta])* $name:ident, $method:expr) => {
        $(#[$meta])*
        #[tauri::command]
        pub async fn $name(
            state: State<'_, AppState>,
            environment_id: String,
            params: Value,
        ) -> Result<Value> {
            perform(&state, $method, &environment_id, params).await
        }
    };
}

protocol_command!(
    /// Reads what the host is.
    host_info, Method::HostInfo
);
protocol_command!(
    /// Lists the host's execution environments.
    environment_list, Method::EnvironmentList
);
protocol_command!(
    /// Reads one environment's capabilities, including desktop readiness.
    environment_capabilities, Method::EnvironmentCapabilities
);
protocol_command!(
    /// Lists the sessions a row is drawn for.
    session_list, Method::SessionList
);
protocol_command!(
    /// Reads one session.
    session_read, Method::SessionRead
);
protocol_command!(
    /// Creates a session.
    session_create, Method::SessionCreate
);
protocol_command!(
    /// Closes a session, after the interface has shown what closing does.
    session_close, Method::SessionClose
);
protocol_command!(
    /// Renames a session.
    session_rename, Method::SessionRename
);
protocol_command!(
    /// Attaches a view to a session.
    session_attach, Method::SessionAttach
);
protocol_command!(
    /// Detaches a view.
    session_detach, Method::SessionDetach
);
protocol_command!(
    /// Configures what an attachment observes.
    attachment_configure, Method::AttachmentConfigure
);
protocol_command!(
    /// Reports this view's viewport position and dimensions.
    attachment_viewport, Method::AttachmentViewport
);
protocol_command!(
    /// Asks for a terminal size.
    terminal_resize, Method::TerminalResize
);
protocol_command!(
    /// Sets the palette a session was created with.
    terminal_palette_set, Method::TerminalPaletteSet
);
protocol_command!(
    /// Takes the input lease.
    input_acquire, Method::InputAcquire
);
protocol_command!(
    /// Releases the input lease.
    input_release, Method::InputRelease
);
protocol_command!(
    /// Interrupts the foreground application.
    input_interrupt, Method::InputInterrupt
);
protocol_command!(
    /// Writes one ordered batch of raw terminal input.
    input_write, Method::InputWrite
);
protocol_command!(
    /// Launches an installed profile or a named command at a verified empty prompt.
    shell_launch, Method::ShellLaunch
);
protocol_command!(
    /// Reads what the bound agent supports.
    agent_capabilities, Method::AgentCapabilities
);
protocol_command!(
    /// Reads the agent's current semantic snapshot.
    agent_snapshot, Method::AgentSnapshot
);
protocol_command!(
    /// Reads the agent's slash commands.
    agent_commands, Method::AgentCommands
);
protocol_command!(
    /// Submits the draft as a prompt.
    composer_submit, Method::AgentPromptSubmit
);
protocol_command!(
    /// Queues a prompt behind the current turn.
    composer_queue, Method::AgentPromptQueue
);
protocol_command!(
    /// Steers the running turn.
    composer_steer, Method::AgentTurnSteer
);
protocol_command!(
    /// Cancels the running turn.
    composer_interrupt, Method::AgentTurnCancel
);
protocol_command!(
    /// Answers an approval request.
    approval_respond, Method::AgentApprovalRespond
);
protocol_command!(
    /// Invokes one declarative control's registered action.
    plugin_action_invoke, Method::PluginActionInvoke
);
protocol_command!(
    /// Creates a draft on the host.
    draft_create, Method::DraftCreate
);
protocol_command!(
    /// Updates a draft on the host.
    draft_update, Method::DraftUpdate
);
protocol_command!(
    /// Adds a completed attachment handle to a draft.
    draft_add_attachment, Method::AgentDraftAddAttachment
);
protocol_command!(
    /// Begins reading an image through its validated attachment handle.
    ///
    /// This is the only way an image reaches the page. A renderer that followed a URL out of agent
    /// text would be fetching whatever that text named; a handle names bytes the host verified.
    attachment_image, Method::DownloadBegin
);
protocol_command!(
    /// Reads one chunk of an image the handle named.
    attachment_image_chunk, Method::DownloadChunk
);
protocol_command!(
    /// Subscribes to a stream from the cursor this client holds.
    events_subscribe, Method::EventsSubscribe
);
protocol_command!(
    /// Takes a session's snapshot at the cursor the subscription began from.
    events_snapshot, Method::EventsSnapshot
);
protocol_command!(
    /// Reads one page of retained history above the live screen.
    history_page, Method::HistoryPage
);
protocol_command!(
    /// Reads what became of one action.
    action_read, Method::ActionRead
);
protocol_command!(
    /// Cancels a pending action.
    action_cancel, Method::ActionCancel
);
protocol_command!(
    /// Reads the attention inbox.
    attention_read, Method::AttentionRead
);
protocol_command!(
    /// Acknowledges one attention entry.
    attention_acknowledge, Method::AttentionAcknowledge
);
protocol_command!(
    /// Reads completed work awaiting review.
    review_read, Method::ReviewRead
);
protocol_command!(
    /// Marks reviewed work as seen.
    review_acknowledge, Method::ReviewAcknowledge
);
protocol_command!(
    /// Reads a pending question.
    question_read, Method::QuestionRead
);
protocol_command!(
    /// Answers a question.
    question_answer, Method::QuestionAnswer
);
protocol_command!(
    /// Lists the grants a session has issued.
    grant_list, Method::GrantList
);
protocol_command!(
    /// Issues a grant, including the explained answering option a viewer or reviewer needs.
    grant_create, Method::GrantCreate
);
protocol_command!(
    /// Revokes a grant.
    grant_revoke, Method::GrantRevoke
);
protocol_command!(
    /// Lists installed packages.
    plugin_list, Method::PluginList
);
protocol_command!(
    /// Reads one package's capability evidence.
    plugin_capabilities, Method::PluginCapabilities
);
protocol_command!(
    /// Lists enrolled repositories and their catalogue state.
    catalogue_list, Method::CatalogueList
);
protocol_command!(
    /// Synchronises one repository's signed catalogue metadata.
    catalogue_sync, Method::CatalogueSync
);
protocol_command!(
    /// Reads one immutable change set.
    changeset_read, Method::ChangesetRead
);
protocol_command!(
    /// Reads a diff.
    diff_read, Method::DiffRead
);
protocol_command!(
    /// Reads what this host retains, including artefacts a privacy generation left behind.
    storage_status, Method::StorageStatus
);
protocol_command!(
    /// Deletes one retained artefact, as a separately authorised action.
    storage_object_delete, Method::StorageObjectDelete
);
protocol_command!(
    /// Issues a pairing invitation.
    pair_invite, Method::PairInvite
);
protocol_command!(
    /// Confirms a candidate the owner approved.
    pair_confirm, Method::PairConfirm
);
protocol_command!(
    /// Cancels an invitation.
    pair_cancel, Method::PairCancel
);
protocol_command!(
    /// Reads a pairing attempt's state.
    pair_status, Method::PairStatus
);

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
#[tauri::command]
pub fn pairing_verify_owner(reason: String) -> Result<verify::Presence> {
    verify::verify_owner_presence(&reason)
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
#[derive(Clone, Debug, serde::Serialize)]
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
    let fetcher = remote::HttpsFetcher::new();
    let imported = tokio::task::spawn_blocking(move || remote::import(&url, &fetcher))
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("the import task did not finish: {error}"))
        })??;
    Ok(ImportedImage {
        url: imported.url,
        media_type: imported.media_type,
        bytes: imported.bytes,
    })
}

/// What an export wrote.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Written {
    /// The destination the person chose.
    pub path: String,
    /// How many bytes were written.
    pub byte_len: u64,
    /// What the export deliberately does not carry.
    pub omissions: Vec<export::Omission>,
}

/// Writes a session's semantic archive to a file the person chose.
#[tauri::command]
pub async fn export_semantic_json(
    path: String,
    session_id: String,
    exported_at_ms: u64,
    dimensions: export::Dimensions,
    nodes: Vec<export::ArchivedNode>,
    omissions: Vec<export::Omission>,
) -> Result<Written> {
    let archive = export::semantic_archive(
        &session_id,
        exported_at_ms,
        dimensions,
        nodes,
        omissions.clone(),
    )?;
    let body = serde_json::to_vec_pretty(&archive).map_err(|error| {
        CommandError::local_failure(format!("the archive could not be written: {error}"))
    })?;
    write_chosen_file(&path, &body).await?;
    Ok(Written {
        path,
        byte_len: body.len() as u64,
        omissions: archive.omissions,
    })
}

/// Writes a session's terminal recording to a file the person chose.
#[tauri::command]
pub async fn export_asciicast(
    path: String,
    title: String,
    started_at_unix_seconds: u64,
    dimensions: export::Dimensions,
    frames: Vec<RecordedFrame>,
    omissions: Vec<export::Omission>,
) -> Result<Written> {
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
    write_chosen_file(&path, cast.body.as_bytes()).await?;
    Ok(Written {
        path,
        byte_len: cast.body.len() as u64,
        omissions: cast.omissions,
    })
}

/// One recorded slice of terminal output, as the page hands it over.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct RecordedFrame {
    /// Milliseconds since the recording began.
    pub at_ms: u64,
    /// The bytes, as text.
    pub text: String,
}

/// Writes one file at a destination the platform's save dialog returned.
///
/// The page never names a path of its own: the dialog plugin returns the destination and the page
/// passes it straight back, so this writes where the person pointed and nowhere else.
async fn write_chosen_file(path: &str, body: &[u8]) -> Result<()> {
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute() {
        return Err(CommandError::invalid(
            "an export is written to the destination the save dialog returned",
        ));
    }
    let body = body.to_vec();
    tokio::task::spawn_blocking(move || std::fs::write(&path, &body))
        .await
        .map_err(|error| {
            CommandError::local_failure(format!("the export task did not finish: {error}"))
        })?
        .map_err(|error| {
            CommandError::local_failure(format!("the export could not be written: {error}"))
        })
}

/// Whether this application currently holds a host connection.
#[tauri::command]
pub fn connection_state(state: State<'_, AppState>) -> bool {
    state.link().connected()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_named_command_is_unique() {
        let mut seen = BTreeSet::new();
        for named in NAMED_COMMANDS {
            assert!(
                seen.insert(named.command),
                "{} is registered twice",
                named.command
            );
        }
    }

    #[test]
    fn no_command_reaches_a_method_outside_the_named_set() {
        // The page cannot name a method, so the reachable set is exactly the methods these
        // commands name. This is the sentence the boundary rests on, written as a test.
        let reachable: BTreeSet<&str> = NAMED_COMMANDS
            .iter()
            .filter_map(|named| named.method.map(Method::as_str))
            .collect();
        for forbidden in [
            "session.describe",
            "project.clone",
            "workflow.run",
            "voice.start",
            "device.revoke",
            "plugin.install",
            "plugin.grant",
            "owner.confirmation.complete",
            "storage.upload.create",
            "authority.sync",
        ] {
            assert!(
                !reachable.contains(forbidden),
                "{forbidden} is reachable from the page and should not be"
            );
        }
    }

    #[test]
    fn no_command_names_a_method_the_registry_does_not_hold() {
        for named in NAMED_COMMANDS {
            if let Some(method) = named.method {
                assert!(
                    Method::ALL.contains(&method),
                    "{} names a method outside the registry",
                    named.command
                );
            }
        }
    }

    #[test]
    fn the_commands_that_perform_no_method_are_the_applications_own() {
        let local: BTreeSet<&str> = NAMED_COMMANDS
            .iter()
            .filter(|named| named.method.is_none())
            .map(|named| named.command)
            .collect();
        assert_eq!(
            local,
            BTreeSet::from([
                "connection_state",
                "export_asciicast",
                "export_semantic_json",
                "import_remote_image",
                "open_external",
                "pairing_origin",
                "pairing_scan",
                "pairing_set_origin",
                "pairing_verify_owner",
            ])
        );
    }
}
