//! What the application does when the system takes its scene away and gives one back.
//!
//! On iOS the window belongs to a scene. The system may disconnect the scene while the process
//! lives on, and connect one again later. The windowing library reports the disconnect as the
//! window's destruction. With no window left, the runtime asks the application to exit, and iOS
//! ignores an exit, so letting that request pass would leave a process with no window, while a call
//! or a pairing goes on in it. This refuses that request (only the runtime's own: an exit the
//! application asks for carries a code and passes) and opens the main window again when the system
//! returns a scene.
//!
//! The runtime hands every event to the application on the thread that runs the platform's loop, one
//! after the other, so the check for a window and the opening of one cannot interleave: two returns
//! in a row open one window. Nothing else is started again. The state, the services and the pairing
//! records are made once in setup and outlive the window; only what is tied to the window is made
//! again.

use tauri::{AppHandle, Manager as _, RunEvent};

/// The runtime's events, as far as a scene concerns them.
pub(crate) fn on_run_event(app: &AppHandle, event: &RunEvent) {
    match event {
        RunEvent::ExitRequested {
            code: None, api, ..
        } => api.prevent_exit(),
        RunEvent::SceneRequested { .. } => open_main_window_once(app),
        _ => {}
    }
}

/// Opens the main window if the application has none, with what is tied to it.
pub(crate) fn open_main_window_once(app: &AppHandle) {
    if !app.webview_windows().is_empty() {
        return;
    }
    match crate::open_main_window(app) {
        Ok(()) => {
            crate::watch_drops(app);
            tracing::info!("a scene came back, so the main window was opened again");
        }
        Err(error) => {
            tracing::error!(%error, "a scene came back and the main window could not be opened")
        }
    }
}
