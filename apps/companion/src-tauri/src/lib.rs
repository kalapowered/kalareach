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

pub mod account;
pub mod commands;
pub mod connection;
pub mod device;
pub mod error;
pub mod export;
pub mod links;
pub mod owner;
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
    use tauri::Manager as _;

    tauri::Builder::default()
        // The page holds no permission for the pasteboard: native code reads an invitation there
        // itself, so its text never reaches the page.
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(companion_platform::init())
        .manage(AppState::new())
        .invoke_handler(commands::handlers())
        .setup(|app| {
            open_main_window(app.handle())?;
            app.manage(account::AccountSlot::new(account_builder(
                app.handle().clone(),
            )));
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                reach_local_host(handle).await;
            });
            // The account is built off the thread the platform starts the application on: opening
            // the secure store on a phone asks the native half, which runs on that thread.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = handle.state::<account::AccountSlot>().get().await {
                    tracing::warn!(%error, "the account is not available on this device");
                }
            });
            watch_drops(app.handle());
            open_pairing(app.handle());
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

/// Opens the main window from its configuration, with the navigation guard.
///
/// The window's settings stay in `tauri.conf.json`, which marks it not to be created by itself, so
/// it is built here with handlers that keep it on the bundled interface.
fn open_main_window(app: &tauri::AppHandle) -> tauri::Result<()> {
    let configuration = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .cloned()
        .expect("the configuration describes the main window");
    let development = if tauri::is_dev() {
        app.config().build.dev_url.clone()
    } else {
        None
    };
    account::navigation::guard(
        tauri::WebviewWindowBuilder::from_config(app, &configuration)?,
        development,
    )
    .build()?;
    Ok(())
}

/// Builds the account: the managed service on its fixed origin, the device's secure store, and
/// the carrier this platform signs in through.
fn account_builder(app: tauri::AppHandle) -> account::Build {
    Box::new(move || {
        let app = app.clone();
        Box::pin(async move { build_account(&app) })
    })
}

fn build_account(
    app: &tauri::AppHandle,
) -> std::result::Result<std::sync::Arc<account::Account>, String> {
    use std::sync::Arc;

    use kr_client::services::account::{
        ACCOUNT_ORIGIN, AccountHttp, AccountService, Client, ManagedAccountService, SignedInAccount,
    };
    use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};
    use tauri::Emitter as _;

    let client = if cfg!(mobile) {
        Client::Mobile
    } else {
        Client::Desktop
    };
    let origin = kr_protocol::service::GatewayOrigin::new(ACCOUNT_ORIGIN)
        .map_err(|error| error.to_string())?;
    let http = HttpService::with(origin, HttpDeadlines::default(), managed_response_limits())
        .map_err(|error| error.to_string())?;
    let service: Arc<dyn AccountService> = Arc::new(ManagedAccountService::new(
        Arc::new(http) as Arc<dyn AccountHttp>,
        client,
    ));
    let store = companion_platform::secrets::open(app).map_err(|error| error.to_string())?;
    #[allow(unused_mut, reason = "a desktop also locks across processes")]
    let mut signed_in = SignedInAccount::new(Arc::clone(&service), store, client);
    #[cfg(desktop)]
    {
        use tauri::Manager as _;
        let directory = app
            .path()
            .app_data_dir()
            .map_err(|error| error.to_string())?;
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        signed_in = signed_in.with_shared_lock(directory.join("account.lock"));
    }
    #[cfg(desktop)]
    let carrier: Arc<dyn account::carrier::Carrier> = Arc::new(account::carrier::Loopback::new(
        Arc::new(account::carrier::SystemBrowser(app.clone())),
    ));
    #[cfg(mobile)]
    let carrier: Arc<dyn account::carrier::Carrier> =
        Arc::new(account::carrier::Session::new(app.clone()));
    let emitter = app.clone();
    Ok(Arc::new(account::Account::new(
        Arc::new(signed_in),
        service,
        carrier,
        Arc::new(move |view| {
            let _ = emitter.emit(account::ACCOUNT_EVENT, view);
        }),
    )))
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

/// Opens this computer as a device that pairs, and as an owner device of the hosts it owns, on
/// this computer's own parts, ceremony and pasteboard, and starts telling the page about both.
///
/// A computer whose keys or records cannot be opened still runs: the pairing commands say so, and
/// everything else works as it did.
fn open_pairing(app: &tauri::AppHandle) {
    use std::sync::Arc;

    use tauri::Manager as _;

    let Ok(data) = app.path().app_data_dir() else {
        tracing::warn!("no application data directory, so this computer cannot pair");
        return;
    };
    let opened = device::Parts::platform(&data).and_then(|parts| {
        start_pairing(
            app,
            &data,
            parts,
            verify::platform_ceremony(app.get_webview_window("main")),
            Arc::new(pairing::NativePaste::new(app.clone())),
        )
    });
    if let Err(error) = opened {
        tracing::warn!(%error, "this computer's pairing records could not be opened");
    }
}

/// Opens this computer as a device that pairs, made of `parts` with its records under `data`, and
/// as an owner device whose confirmations `ceremony` answers, pasting invitations through `paste`;
/// tells the page about both on [`pairing::PAIRING_EVENT`] and [`pairing::CONFIRMATIONS_EVENT`];
/// and starts both.
///
/// # Errors
///
/// Returns a local failure when this computer's keys or records cannot be opened.
pub fn start_pairing<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    data: &std::path::Path,
    parts: device::Parts,
    ceremony: std::sync::Arc<dyn kr_client::pairing::owner::Ceremony>,
    paste: std::sync::Arc<dyn pairing::PastePlatform>,
) -> Result<()> {
    use std::sync::Arc;

    use tauri::{Emitter as _, Manager as _};

    let emitter = app.clone();
    let device = device::Device::with(data, parts, move || {
        if let Ok(device) = emitter.state::<AppState>().device() {
            let _ = emitter.emit(pairing::PAIRING_EVENT, device.view());
        }
    })?;
    let emitter = app.clone();
    let owner = owner::Owner::new(Arc::clone(&device), ceremony, move || {
        if let Ok(owner) = emitter.state::<AppState>().owner() {
            let _ = emitter.emit(pairing::CONFIRMATIONS_EVENT, owner.view());
        }
    });
    app.state::<AppState>()
        .opened(Arc::clone(&device), Arc::clone(&owner), paste);
    device.start();
    owner.start();
    Ok(())
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
