//! The pairing screen's native half: the pasteboard, the question before another service is
//! contacted, and the events that tell the page where an attempt has got to.
//!
//! An invitation's text is read from the pasteboard here, by the official clipboard plugin, which
//! the page holds no permission for, so the text and the secret a direct invitation carries never
//! reach the page. When the pasteboard held an invitation it is cleared. A code whose invitation
//! names another service than the one this computer uses is not used until the person accepts it
//! in the platform's own dialog, which shows the service's full name; declining contacts nothing.

use std::sync::Arc;

use kr_client::pairing::invitation::Invitation;
use kr_client::pairing::{BoxFuture, FailureKind};
use kr_protocol::pairing::RendezvousOrigin;
use tauri::{AppHandle, Runtime};
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons, MessageDialogKind};

use crate::device::{Device, PasteView};

/// The event the page is told the pairing screen's state on.
pub const PAIRING_EVENT: &str = "kr://pairing";

/// The event the page is told the owner confirmations on.
pub const CONFIRMATIONS_EVENT: &str = "kr://confirmations";

/// What pasting an invitation asks of the platform: the pasteboard's text, emptying it, and the
/// person's answer before another service is contacted. The product's is [`NativePaste`]; a test
/// gives its own.
pub trait PastePlatform: Send + Sync + std::fmt::Debug {
    /// The text the pasteboard holds, when it holds any.
    fn text(&self) -> Option<String>;

    /// Empties the pasteboard. True when it was emptied.
    fn clear(&self) -> bool;

    /// Asks the person, in the platform's own dialog, whether to contact `named` for this attempt
    /// instead of `configured`, the service this computer is set to use.
    fn use_another_service<'a>(
        &'a self,
        named: &'a RendezvousOrigin,
        configured: &'a str,
    ) -> BoxFuture<'a, bool>;
}

/// The platform's pasteboard, through the official clipboard plugin, and the platform's own alert,
/// modal to the companion's window.
pub struct NativePaste<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> NativePaste<R> {
    /// The pasteboard and alerts of the application `app` runs.
    #[must_use]
    pub const fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: Runtime> std::fmt::Debug for NativePaste<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativePaste")
    }
}

impl<R: Runtime> PastePlatform for NativePaste<R> {
    fn text(&self) -> Option<String> {
        self.app.clipboard().read_text().ok()
    }

    fn clear(&self) -> bool {
        self.app.clipboard().clear().is_ok()
    }

    fn use_another_service<'a>(
        &'a self,
        named: &'a RendezvousOrigin,
        configured: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let host = kr_client::pairing::invitation::origin_host(named).to_owned();
            let (answered, answer) = tokio::sync::oneshot::channel();
            let dialog = self
                .app
                .dialog()
                .message(format!(
                    "This code belongs to {}. KalaReach will contact that service to reach your \
                     host. You are set to use {configured}.",
                    named.as_str()
                ))
                .title("Use another pairing service?")
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom(
                    format!("Use {host}"),
                    "Cancel".to_owned(),
                ));
            // The alert belongs to the companion's window and is modal to it, so the question is
            // answered before anything else is done there.
            #[cfg(desktop)]
            let dialog = match tauri::Manager::get_webview_window(&self.app, "main") {
                Some(window) => dialog.parent(&window),
                None => dialog,
            };
            dialog.show(move |accepted| {
                let _ = answered.send(accepted);
            });
            answer.await.unwrap_or(false)
        })
    }
}

/// Reads an invitation from the pasteboard and holds it for the person to use.
pub async fn paste(platform: &dyn PastePlatform, device: &Arc<Device>) -> PasteView {
    let nothing = |failure| PasteView {
        invitation: None,
        failure: Some(failure),
        cleared: false,
        declined: false,
    };
    let Some(text) = platform.text().filter(|text| !text.trim().is_empty()) else {
        return nothing(FailureKind::NothingToPaste);
    };
    let invitation = match device.read(&text) {
        Ok(invitation) => invitation,
        Err(failure) => return nothing(failure.kind),
    };
    // It was an invitation, so it leaves the pasteboard, where anything could read it.
    let cleared = platform.clear();
    if let Invitation::Code(code) = &invitation
        && code.names_another_origin
    {
        let configured = device.view().origin;
        if !platform
            .use_another_service(&code.origin, &configured.origin)
            .await
        {
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
