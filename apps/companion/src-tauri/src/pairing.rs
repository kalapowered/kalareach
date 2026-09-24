//! The pairing screen's native half: the pasteboard, the question before another service is
//! contacted, and the events that tell the page where an attempt has got to.
//!
//! An invitation's text is read from the pasteboard here, by the official clipboard plugin, which
//! the page holds no permission for, so the text and the secret a direct invitation carries never
//! reach the page. When the pasteboard held an invitation it is cleared. A code whose invitation
//! names another service than the one this computer uses is not used until the person accepts it
//! in the platform's own dialog, which shows the service's full name; declining contacts nothing.

use std::sync::Arc;

use kr_client::pairing::FailureKind;
use kr_client::pairing::invitation::Invitation;
use kr_protocol::pairing::RendezvousOrigin;
use tauri::{AppHandle, Runtime};
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons, MessageDialogKind};

use crate::device::{Device, PasteView};

/// The event the page is told the pairing screen's state on.
pub const PAIRING_EVENT: &str = "kr://pairing";

/// The event the page is told the owner confirmations on.
pub const CONFIRMATIONS_EVENT: &str = "kr://confirmations";

/// Reads an invitation from the pasteboard and holds it for the person to use.
pub async fn paste<R: Runtime>(app: &AppHandle<R>, device: &Arc<Device>) -> PasteView {
    let nothing = |failure| PasteView {
        invitation: None,
        failure: Some(failure),
        cleared: false,
        declined: false,
    };
    let Some(text) = app
        .clipboard()
        .read_text()
        .ok()
        .filter(|text| !text.trim().is_empty())
    else {
        return nothing(FailureKind::NothingToPaste);
    };
    let invitation = match device.read(&text) {
        Ok(invitation) => invitation,
        Err(failure) => return nothing(failure.kind),
    };
    // It was an invitation, so it leaves the pasteboard, where anything could read it.
    let cleared = app.clipboard().clear().is_ok();
    if let Invitation::Code(code) = &invitation
        && code.names_another_origin
    {
        let configured = device.view().origin;
        if !use_another_service(app, &code.origin, &configured.origin).await {
            return PasteView {
                invitation: None,
                failure: None,
                cleared,
                declined: true,
            };
        }
    }
    PasteView {
        invitation: Some(device.hold(invitation)),
        failure: None,
        cleared,
        declined: false,
    }
}

/// Asks the person, in the platform's own dialog, whether to contact `named` for this attempt
/// instead of `configured`.
async fn use_another_service<R: Runtime>(
    app: &AppHandle<R>,
    named: &RendezvousOrigin,
    configured: &str,
) -> bool {
    let host = kr_client::pairing::invitation::origin_host(named).to_owned();
    let (answered, answer) = tokio::sync::oneshot::channel();
    app.dialog()
        .message(format!(
            "This code belongs to {}. KalaReach will contact that service to reach your host. \
             You are set to use {configured}.",
            named.as_str()
        ))
        .title("Use another pairing service?")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            format!("Use {host}"),
            "Cancel".to_owned(),
        ))
        .show(move |accepted| {
            let _ = answered.send(accepted);
        });
    answer.await.unwrap_or(false)
}
