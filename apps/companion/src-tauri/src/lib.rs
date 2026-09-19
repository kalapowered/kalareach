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
pub mod state;
pub mod target;
pub mod verify;

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
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the companion window could not be created");
}

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
