//! The pairing screen's native half: where an invitation is taken in from, the question before
//! another service is contacted, and the events that tell the page where an attempt has got to.
//!
//! An invitation's text is taken in here, in native code, from the pasteboard (read by the official
//! clipboard plugin, which the page holds no permission for), from the phone's camera or from a
//! picture the person chose, so the text and the secret a direct invitation carries never reach the
//! page. When the pasteboard held an invitation it is cleared. A code whose invitation names
//! another service than the one this device uses is not used until the person accepts it in the
//! platform's own dialog, which shows the service's full name; declining contacts nothing.
//!
//! One intake is under way at a time. A newer one, a stop, or the start of an attempt voids the one
//! that waits, so a camera frame, a picture or an alert's answer that arrives afterwards holds
//! nothing.

use std::sync::Arc;

use companion_platform::PlatformError;
use companion_platform::scan::{Scan, Sources};
use kr_client::pairing::invitation::Invitation;
use kr_client::pairing::{BoxFuture, FailureKind};
use kr_protocol::pairing::RendezvousOrigin;
use tauri::{AppHandle, Runtime};
use tauri_plugin_clipboard_manager::ClipboardExt as _;
use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons, MessageDialogKind};

use crate::device::{Device, IntakeView};

/// The event the page is told the pairing screen's state on.
pub const PAIRING_EVENT: &str = "kr://pairing";

/// The event the page is told the owner confirmations on.
pub const CONFIRMATIONS_EVENT: &str = "kr://confirmations";

/// What [`PAIRING_EVENT`] carries, in place of the pairing screen's view, when the pairing records
/// are still not open at a try made after the start: the words that stand where the screen would
/// be, as the pairing commands give them.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PairingUnavailable {
    /// The words native code says.
    pub unavailable: String,
}

/// Where an invitation is taken in from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The pasteboard.
    Pasteboard,
    /// The phone's camera, in the scanner native code shows.
    Camera,
    /// A picture the person chooses in the system's picker.
    Photo,
}

/// What taking an invitation in asks of the platform: the pasteboard's text, emptying it, reading a
/// code from the camera or from a picture, and the person's answer before another service is
/// contacted. The product's is [`NativeIntake`]; a test gives its own.
pub trait IntakePlatform: Send + Sync + std::fmt::Debug {
    /// The text the pasteboard holds, when it holds any.
    fn text(&self) -> Option<String>;

    /// Empties the pasteboard. True when it was emptied.
    fn clear(&self) -> bool;

    /// Which sources besides the pasteboard this device reads a code from.
    fn sources(&self) -> BoxFuture<'_, Sources>;

    /// Reads a code from the camera or from a picture, and answers when the scanner or the picker
    /// closes. The text it answers with clears itself when it is dropped.
    fn read_code(&self, source: Source) -> BoxFuture<'_, Result<Scan, PlatformError>>;

    /// Asks the person, in the platform's own dialog, whether to contact `named` for this attempt
    /// instead of `configured`, the service this computer is set to use.
    fn use_another_service<'a>(
        &'a self,
        named: &'a RendezvousOrigin,
        configured: &'a str,
    ) -> BoxFuture<'a, bool>;
}

/// The platform's pasteboard, through the official clipboard plugin, the phone's scanner and
/// picker, and the platform's own alert, modal to the companion's window.
pub struct NativeIntake<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> NativeIntake<R> {
    /// The pasteboard, scanner and alerts of the application `app` runs.
    #[must_use]
    pub const fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: Runtime> std::fmt::Debug for NativeIntake<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeIntake")
    }
}

impl<R: Runtime> IntakePlatform for NativeIntake<R> {
    fn text(&self) -> Option<String> {
        self.app.clipboard().read_text().ok()
    }

    fn clear(&self) -> bool {
        self.app.clipboard().clear().is_ok()
    }

    fn sources(&self) -> BoxFuture<'_, Sources> {
        Box::pin(companion_platform::scan::sources(&self.app))
    }

    fn read_code(&self, source: Source) -> BoxFuture<'_, Result<Scan, PlatformError>> {
        Box::pin(async move {
            match source {
                Source::Camera => companion_platform::scan::camera(&self.app).await,
                Source::Photo => companion_platform::scan::photo(&self.app).await,
                Source::Pasteboard => Err(PlatformError(
                    "the pasteboard is read as text, not scanned".to_owned(),
                )),
            }
        })
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

/// What taking an invitation in found, for the page.
fn nothing(failure: FailureKind) -> IntakeView {
    IntakeView {
        invitation: None,
        failure: Some(failure),
        cleared: false,
        declined: false,
        cancelled: false,
    }
}

/// Takes an invitation in from `source` and holds it for the person to use.
///
/// The text is read in native code and never reaches the page. An invitation that was read is
/// held only while this intake is the one under way: when a newer one, a stop or the start of an
/// attempt came first, nothing is held and the person is told nothing happened.
pub async fn take_in(
    platform: &dyn IntakePlatform,
    device: &Arc<Device>,
    source: Source,
) -> IntakeView {
    let intake = device.begin_intake();
    let text = match source {
        Source::Pasteboard => match platform.text().filter(|text| !text.trim().is_empty()) {
            Some(text) => zeroize::Zeroizing::new(text),
            None => return nothing(FailureKind::NothingToPaste),
        },
        Source::Camera | Source::Photo => {
            let read = platform.read_code(source).await;
            // Whatever the reader answered, an intake that was overtaken while it waited says
            // nothing: not a failure, not an alert, not a word on the page.
            if !device.owns(intake) {
                return IntakeView::cancelled();
            }
            match read {
                Ok(Scan::Text(text)) => text,
                Ok(Scan::Cancelled) => return IntakeView::cancelled(),
                Ok(Scan::NoCode) => return nothing(FailureKind::NoCodeFound),
                Ok(Scan::CameraDenied) => return nothing(FailureKind::CameraDenied),
                Ok(Scan::Failed) => return nothing(FailureKind::ReaderFailed),
                Err(error) => {
                    tracing::warn!(%error, ?source, "the platform could not read a code");
                    return nothing(FailureKind::ReaderFailed);
                }
            }
        }
    };
    device.mark_read(intake);
    let invitation = match device.read(&text) {
        Ok(invitation) => invitation,
        Err(failure) => return nothing(failure.kind),
    };
    drop(text);
    // Taken from the pasteboard, it leaves the pasteboard, where anything could read it.
    let cleared = source == Source::Pasteboard && platform.clear();
    if let Invitation::Code(code) = &invitation
        && code.names_another_origin
    {
        let configured = device.view().origin;
        // What the code says is let go of the moment the intake is void (the application left the
        // front, a newer intake began), not when a person finally answers an alert nobody sees.
        let accepted = tokio::select! {
            accepted = platform.use_another_service(&code.origin, &configured.origin) => accepted,
            () = device.voided(intake) => {
                drop(invitation);
                return IntakeView {
                    cleared,
                    ..IntakeView::cancelled()
                };
            }
        };
        // An answer to the alert after a newer intake, a stop or an attempt came first is no
        // answer to anything the person is looking at now.
        if !device.owns(intake) {
            return IntakeView {
                cleared,
                ..IntakeView::cancelled()
            };
        }
        if !accepted {
            return IntakeView {
                invitation: None,
                failure: None,
                cleared,
                declined: true,
                cancelled: false,
            };
        }
    }
    match device.hold_for(intake, invitation) {
        Some(summary) => IntakeView {
            invitation: Some(summary),
            failure: None,
            cleared,
            declined: false,
            cancelled: false,
        },
        None => IntakeView {
            cleared,
            ..IntakeView::cancelled()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page tells these words from a pairing view by their one field, so that field is what the
    /// event carries when the records are still not open at a try after the start.
    #[test]
    fn the_words_that_stand_for_the_screen_are_sent_in_the_one_field_the_page_looks_for() {
        let sent = serde_json::to_string(&PairingUnavailable {
            unavailable: "the words".to_owned(),
        })
        .expect("a payload");
        assert_eq!(sent, r#"{"unavailable":"the words"}"#);
    }
}
