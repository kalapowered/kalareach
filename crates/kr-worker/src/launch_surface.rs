//! The answer to `shell.launch.surface`: whether a launch could be made at the root editor now.
//!
//! The answer is advice. `verified` rests on the one proof the root-editor contract gives that the
//! buffer was empty at an instant the worker can place, the reader's fence acknowledgement, and on
//! nothing the worker admitted or learned since. A launch quotes the prompt generation and the
//! buffer revision this answer names, and the worker and the reader refuse a quote that has gone
//! stale before anything is typed.
//!
//! The reasons are tested in the order [`LaunchUnverified`] declares them, and the first that
//! holds is the answer. A caller whose grant does not reach the live screen is told none of what
//! the editor is doing, nor who holds the input: both are what that screen shows.

use kr_protocol::ids::AttachmentId;
use kr_protocol::root::{
    LaunchEditor, LaunchInput, LaunchOffer, LaunchShell, LaunchUnverified, ShellLaunchSurfaceResult,
};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{SessionState, ShellMode};
use kr_shell_integration::contract::fence::LaunchStanding;
use kr_shell_integration::contract::qualification::ShellKind;

use crate::session::Session;

/// Builds the answer for one caller.
///
/// `shown` says whether the caller's grant reaches the live screen. `holds_attachment` says
/// whether an attachment belongs to the asking connection, which is what makes the input lease
/// `held_here`. `offers` are what the host has an admitted agent package for.
pub(crate) fn answer(
    session: &Session,
    shown: bool,
    holds_attachment: impl Fn(AttachmentId) -> bool,
    offers: Vec<LaunchOffer>,
) -> ShellLaunchSurfaceResult {
    let summary = session.summary();
    let standing = session.launch_standing();
    let shell = if summary.root.is_some() {
        None
    } else {
        session
            .fence()
            .and_then(|driver| driver.phase().shell())
            .map(shell_of_kind)
            .or_else(|| shell_of_program(&summary.shell_path))
    };
    let editor = match verdict(&summary, session, shown, standing) {
        Ok((prompt_generation, buffer_revision, cwd_revision)) => LaunchEditor::Verified {
            prompt_generation,
            buffer_revision,
            cwd_revision,
        },
        Err(reason) => LaunchEditor::Unverified { reason },
    };
    let input = if shown {
        match session.lease().holder.0 {
            None => LaunchInput::Free,
            Some(holder) if holds_attachment(holder) => LaunchInput::HeldHere,
            Some(_) => LaunchInput::HeldElsewhere,
        }
    } else {
        LaunchInput::Withheld
    };
    ShellLaunchSurfaceResult {
        session_id: summary.session_id,
        editor,
        input,
        shell: Nullable(shell),
        offers,
    }
}

/// Returns the numbers a launch quotes when the editor is verified, and otherwise the first reason
/// it is not.
fn verdict(
    summary: &kr_protocol::session::SessionSummary,
    session: &Session,
    shown: bool,
    standing: Option<LaunchStanding>,
) -> Result<
    (
        kr_protocol::root::PromptGeneration,
        kr_protocol::root::EditorBufferRevision,
        kr_protocol::root::CwdRevision,
    ),
    LaunchUnverified,
> {
    if matches!(summary.state, SessionState::Closing | SessionState::Closed)
        || standing == Some(LaunchStanding::Closing)
    {
        return Err(LaunchUnverified::Closing);
    }
    if summary.root.is_some() {
        return Err(LaunchUnverified::NotAShell);
    }
    if summary.shell_mode == ShellMode::NativeCompat {
        return Err(LaunchUnverified::StockShell);
    }
    if !session.config().launch_profile.fenced_launch {
        return Err(LaunchUnverified::ProfileForbids);
    }
    if !shown {
        return Err(LaunchUnverified::NotShown);
    }
    // A managed session always holds a driver; one that does not has no integration to launch
    // through.
    let Some(standing) = standing else {
        return Err(LaunchUnverified::IntegrationLost);
    };
    match standing {
        LaunchStanding::Closing => Err(LaunchUnverified::Closing),
        LaunchStanding::Starting => Err(LaunchUnverified::Starting),
        LaunchStanding::IntegrationLost => Err(LaunchUnverified::IntegrationLost),
        LaunchStanding::NotAtPrompt => Err(LaunchUnverified::NotAtPrompt),
        LaunchStanding::NotPrimaryPrompt => Err(LaunchUnverified::NotPrimaryPrompt),
        LaunchStanding::LaunchInProgress => Err(LaunchUnverified::LaunchInProgress),
        LaunchStanding::NoFence => Err(LaunchUnverified::NoFence),
        LaunchStanding::Fenced(editor) => {
            if !editor.acknowledged.buffer_empty {
                Err(LaunchUnverified::BufferNotEmpty)
            } else if !editor.acknowledged.pending.is_idle() {
                Err(LaunchUnverified::ReaderPending)
            } else if editor.changed {
                Err(LaunchUnverified::ChangedSinceFence)
            } else {
                Ok((
                    editor.prompt_generation,
                    editor.buffer_revision,
                    editor.cwd_revision,
                ))
            }
        }
    }
}

/// The shell a managed package is for.
const fn shell_of_kind(kind: ShellKind) -> LaunchShell {
    match kind {
        ShellKind::Zsh => LaunchShell::Zsh,
        ShellKind::Bash => LaunchShell::Bash,
        ShellKind::Fish => LaunchShell::Fish,
        ShellKind::PowerShell => LaunchShell::Powershell,
    }
}

/// The shell a program is, by its file name: the base name, lower-cased, without `.exe`.
///
/// A shell that is none of these is not one the host knows how to quote for.
fn shell_of_program(program: &str) -> Option<LaunchShell> {
    let name = std::path::Path::new(program)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(program)
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    match name {
        "sh" | "dash" | "ash" => Some(LaunchShell::Sh),
        "zsh" => Some(LaunchShell::Zsh),
        "bash" => Some(LaunchShell::Bash),
        "fish" => Some(LaunchShell::Fish),
        "pwsh" | "powershell" => Some(LaunchShell::Powershell),
        _ => None,
    }
}
