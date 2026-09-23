//! The KalaReach companion application's native backend.
//!
//! The window is a WebView and the WebView is not trusted. Section 13 fixes the boundary: the
//! production front end is bundled, the WebView reaches the host only through named commands, and
//! no command is a general shell, a general filesystem path or a general protocol call. This crate
//! is that boundary, and the commands in [`commands`] are the whole of it.
//!
//! ```text
//!   WebView (bundled React)                native backend                 host
//!   ─────────────────────────   invoke     ──────────────────   kr-client  ────
//!   session_list            ────────────▶  Method::SessionList ──────────▶ session.list
//!   composer_submit         ────────────▶  Method::AgentPromptSubmit ────▶ agent.prompt.submit
//!   open_external           ────────────▶  scheme policy, then the platform opener
//!   …one command per operation, and nothing that names a method itself
//! ```
//!
//! # What keeps it a boundary
//!
//! Each command names exactly one [`kr_protocol::method::Method`] in its own body. The WebView
//! passes parameters; it never passes a method. A protocol operation the application does not use
//! has no command, so it cannot be reached from the page at all. [`commands::NAMED_COMMANDS`] is
//! that list as data, and the crate's tests hold the handler list and the allowlist to each other.

pub mod commands;
pub mod connection;
pub mod error;
pub mod export;
pub mod links;
pub mod pairing;
pub mod remote;
pub mod setup;
pub mod state;
pub mod target;
pub mod transfers;
pub mod verify;

pub mod audio;

pub use error::{CommandError, Result};
pub use state::AppState;

/// Builds and runs the desktop application.
///
/// The window opens whether or not a host answers. A host that cannot be reached is a state the
/// interface has to have anyway, and starting into it is the honest thing to do: the person sees
/// the application, and the application says it is not in contact.
///
/// # Panics
///
/// Panics when the window cannot be created, which is not a condition the application can
/// continue past.
///
/// iOS and Android do not run a binary of their own: the system starts the process and calls
/// into this library. [`mobile`] is where that call arrives.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::new())
        .invoke_handler(commands::handlers())
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                reach_local_host(handle).await;
            });
            watch_drops(app.handle());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the companion window could not be created");
}

/// The entry point the phone's own runtime calls.
///
/// A desktop build runs a binary whose `main` calls [`run`]. iOS and Android start the process
/// themselves and call a C entry point instead, which the framework's macro writes beside the
/// function it is put on. That generated item carries no documentation of its own and there is
/// nowhere to put any, so the rule is relaxed for this module and for nothing else.
#[cfg(mobile)]
pub mod mobile {
    #![allow(
        missing_docs,
        reason = "the platform's entry point is written by the framework's macro"
    )]

    /// Starts the application on a phone.
    ///
    /// The same `run` the desktop window uses. There is no second application here: a phone and a
    /// desktop differ in how the process begins, and in nothing after that.
    #[tauri::mobile_entry_point]
    pub fn start() {
        super::run();
    }
}

/// Records what the platform drops on this window, and tells the interface about it.
///
/// The bytes never reach the page: the platform gives this process a path, the backend remembers
/// it, and the page is told the name so it can show what was dropped. An upload spends one of
/// these, and a path the page names on its own was never dropped.
///
/// This reads the window's own event rather than the application's event bus. The bus carries an
/// event of the same name to the page, and the page can emit on it: a backend that took its
/// authority from the bus would let the page name any file it liked and have it read. The
/// window's callback comes from the platform and nothing in the page can produce it.
fn watch_drops(app: &tauri::AppHandle) {
    use tauri::{Emitter as _, Manager as _};

    for (_, window) in app.webview_windows() {
        let handle = app.clone();
        window.on_window_event(move |event| {
            let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event
            else {
                return;
            };
            if paths.is_empty() {
                return;
            }
            handle.state::<AppState>().dropped(paths.clone());
            let named: Vec<String> = paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect();
            let _ = handle.emit(DROPPED_EVENT, named);
        });
    }
}

/// The event the backend publishes the paths of dropped files on.
pub const DROPPED_EVENT: &str = "kr://dropped";

/// Connects to the controller on this machine and starts publishing its events.
async fn reach_local_host(app: tauri::AppHandle) {
    use tauri::{Emitter as _, Manager as _};

    let state = app.state::<AppState>();
    match connection::connect_local().await {
        Ok(connection) => {
            let session = connection.session();
            state.connected(connection);
            connection::publish_events(app.clone(), session);
            let _ = app.emit(connection::CONNECTION_EVENT, state.connection_state());
        }
        Err(error) => {
            state.disconnected(error.message.clone());
            let _ = app.emit(connection::CONNECTION_EVENT, state.connection_state());
        }
    }
}
