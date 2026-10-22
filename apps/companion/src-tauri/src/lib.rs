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
//!   agent_prompt_submit     ────────────▶  Method::AgentPromptSubmit ────▶ agent.prompt.submit,
//!                                                                          on the session's worker,
//!                                                                          or through the host's
//!                                                                          daemon for a draft
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

#[cfg(target_os = "macos")]
mod access_list;
pub mod account;
pub mod agent;
pub mod commands;
pub mod connection;
pub mod device;
/// The checks a debug build runs on a phone for what the device keeps for itself.
#[cfg(debug_assertions)]
pub mod device_probe;
pub mod drafts;
pub mod error;
pub mod export;
pub mod hosts;
pub mod links;
pub mod mailbox;
pub mod owner;
pub mod pairing;
/// The checks a debug build runs for the voice call's bridge on a phone.
#[cfg(debug_assertions)]
pub mod probe;
pub mod questions;
pub mod recovery;
pub mod remote;
pub mod revocation;
pub mod settings;
pub mod setup;
pub mod sharing;
pub mod standing;
pub mod state;
pub mod sync_service;
pub mod target;
pub mod terminal;
pub mod transfers;
pub mod verify;
pub mod voice;
pub mod worker;

pub use error::{CommandError, Result};
pub use state::AppState;

use kr_protocol::error::ErrorCode;

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
/// into this library. `mobile` is where that call arrives.
pub fn run() {
    use tauri::Manager as _;

    let builder = tauri::Builder::default()
        // The page holds no permission for the pasteboard: native code reads an invitation there
        // itself, so its text never reaches the page.
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(companion_platform::init())
        .manage(AppState::new())
        // The links to each session's own worker, which the agent's calls travel on.
        .manage(agent::WorkerLinks::local())
        .invoke_handler(commands::handlers());
    // The raw terminal views, and the rule that ends a page's views when it loads again.
    terminal::install(builder, terminal::TerminalViews::local())
        .setup(|app| {
            // A simulator launch can ask to start with the device locked, before anything reads the
            // secure store.
            #[cfg(all(debug_assertions, target_os = "ios"))]
            companion_platform::protection::model::arm_from_environment();
            // The place for what this application keeps on this device: the answers a host did not
            // confirm and the drafts a person has not sent. It is given before the window opens, so
            // no command the page calls at once finds the application without it.
            match app.path().app_data_dir() {
                Ok(data) => app.state::<AppState>().keep_under(&data),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "no application data directory, so no answer and no draft can be kept"
                    );
                }
            }
            open_main_window(app.handle())?;
            // A debug build on a phone reads the request a probe left. A run of a whole call
            // names the voice service and the account it uses, and they are managed here, before
            // the application's own: a state is managed once, and the first one stays.
            #[cfg(all(debug_assertions, mobile))]
            let probe = probe::take(app.handle());
            #[cfg(all(debug_assertions, mobile))]
            if let Some(harness) = probe.as_ref().and_then(probe::Request::harness) {
                manage_harness(app.handle(), harness)?;
            }
            app.manage(account::AccountSlot::new(account_builder(
                app.handle().clone(),
            )));
            // A computer with a host of its own reaches that one. A phone has none, and takes up
            // the paired host it was last told to use, once its pairing records are open below.
            #[cfg(desktop)]
            {
                let _ = connection::reach_host_on_this_machine(
                    app.handle(),
                    connection::this_machines_host,
                );
            }
            // The account is built off the thread the platform starts the application on, so the
            // window does not wait for it. The pairing records are opened below on this thread,
            // because a phone's host list needs them at once; the secure store answers there, since
            // the native half is called on a queue of its own and not on this thread.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = handle.state::<account::AccountSlot>().get().await {
                    tracing::warn!(%error, "the account is not available on this device");
                }
            });
            app.manage(voice_calls(app.handle()));
            watch_drops(app.handle());
            #[cfg(mobile)]
            watch_suspension(app.handle());
            open_sync_service(app.handle());
            open_pairing(app.handle());
            #[cfg(all(debug_assertions, mobile))]
            if let Some(request) = probe {
                probe::start(app.handle(), request);
            }
            #[cfg(all(debug_assertions, mobile))]
            device_probe::start(app.handle());
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
    use tauri::Manager as _;

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
    // The person's settings are in the window's document before the page's first script runs, so
    // the colour mode is applied before the first paint.
    let settings = app
        .state::<AppState>()
        .settings()
        .map(|settings| settings.local().initial_script())
        .unwrap_or_default();
    account::navigation::guard(
        tauri::WebviewWindowBuilder::from_config(app, &configuration)?
            .initialization_script(settings),
        development,
    )
    .build()?;
    Ok(())
}

/// The voice calls of this application: a phone's own through native code, and none on a desktop,
/// which negotiates no media connection.
#[cfg(mobile)]
fn voice_calls(app: &tauri::AppHandle) -> voice::Calls {
    use std::sync::Arc;

    use companion_platform::call::{NativeCalls, PluginCommands};
    use tauri::Manager as _;

    match voice::Service::managed() {
        Ok(service) => voice::Calls::on_phone(
            Arc::new(NativeCalls::new(PluginCommands::new(app.clone()))),
            service,
            voice::Timings::default(),
            // What a call left owed, and the note, are kept in the application's own directory.
            match app.path().app_data_dir() {
                Ok(directory) => voice::Kept::at(directory),
                Err(error) => {
                    tracing::warn!(%error, "this device has no place to keep what a voice call left owed");
                    voice::Kept::nowhere()
                }
            },
        ),
        Err(error) => {
            tracing::warn!(%error, "this device cannot reach the voice service, so it holds no call");
            voice::Calls::absent()
        }
    }
}

#[cfg(desktop)]
fn voice_calls(_app: &tauri::AppHandle) -> voice::Calls {
    voice::Calls::absent()
}

/// Gives a run of a whole call on a phone the voice service and the account it names, and calls
/// made through native code at that service.
#[cfg(all(debug_assertions, mobile))]
fn manage_harness(
    app: &tauri::AppHandle,
    harness: &probe::harness::Harness,
) -> std::result::Result<(), String> {
    use std::sync::Arc;

    use companion_platform::call::{NativeCalls, PluginCommands};
    use tauri::Manager as _;

    let kept = match app.path().app_data_dir() {
        Ok(directory) => voice::Kept::at(directory),
        Err(_) => voice::Kept::nowhere(),
    };
    app.manage(harness.account());
    app.manage(voice::Calls::on_phone(
        Arc::new(NativeCalls::new(PluginCommands::new(app.clone()))),
        harness.service()?,
        voice::Timings::default(),
        kept,
    ));
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
    let http = HttpService::with(
        origin.clone(),
        HttpDeadlines::default(),
        managed_response_limits(),
    )
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
        origin,
        carrier,
        Arc::new(move |view| {
            let _ = emitter.emit(account::ACCOUNT_EVENT, view);
        }),
    )))
}

/// Lets go of what a phone read and has not used when the application stops being in front: the
/// invitation held for the person, and an intake that waits for the answer to the alert. The event
/// is the platform's (`onPause` on Android); nothing in the page can produce it.
#[cfg(target_os = "android")]
fn watch_suspension(app: &tauri::AppHandle) {
    use tauri::Manager as _;

    for (_, window) in app.webview_windows() {
        let handle = app.clone();
        window.on_window_event(move |event| {
            if matches!(event, tauri::WindowEvent::Suspended)
                && let Ok(device) = handle.state::<AppState>().device()
            {
                device.suspend();
            }
        });
    }
}

/// The same on iOS, where the window's `Suspended` event is raised at `applicationWillResignActive`,
/// which iOS also sends for the Control Center, the Notification Center and the system's own
/// questions: a person who turns on Wi-Fi in the middle of pairing has not left, and the invitation
/// they scanned stays. The platform plugin says when the application goes to the background.
#[cfg(target_os = "ios")]
fn watch_suspension(app: &tauri::AppHandle) {
    use tauri::Manager as _;

    let handle = app.clone();
    let watching = companion_platform::scan::on_background(app, move || {
        if let Ok(device) = handle.state::<AppState>().device() {
            device.suspend();
        }
    });
    if let Err(error) = watching {
        tracing::warn!(%error, "the application's going to the background cannot be heard, so what a phone read stays until it is used");
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

/// Opens this computer as a device that pairs, and as an owner device of the hosts it owns, on
/// this computer's own parts, ceremony and pasteboard, and starts telling the page about both,
/// and then starts what needs the pairing records.
///
/// A computer whose keys or records cannot be opened still runs: the pairing commands say why
/// they cannot, in words the page shows where the pairing screen would be, and everything else
/// works as it did. A phone that was started before its first unlock cannot open them yet, and
/// opens them in place when the device may have been unlocked ([`open_after_unlock`]).
fn open_pairing(app: &tauri::AppHandle) {
    // The system is listened to before the first try, so an unlock that falls between the try and
    // the wait is heard.
    #[cfg(target_os = "ios")]
    watch_for_unlock(app);
    if matches!(open_records(app), Opening::Opened) {
        start_with_records(app);
    }
}

/// What one try at opening the pairing records came to.
enum Opening {
    /// This try opened them.
    Opened,
    /// They were open already, and the try did nothing.
    AlreadyOpen,
    /// They are still not open, and the reason is recorded.
    Failed,
}

/// Tries to open the pairing records, unless they are open, one try at a time.
///
/// A try that fails records why, and says the device is locked when the system says so: the
/// records are then opened again at the next unlock.
fn open_records(app: &tauri::AppHandle) -> Opening {
    use tauri::Manager as _;

    let state = app.state::<AppState>();
    let _turn = state.opening_records();
    if state.records_are_open() {
        return Opening::AlreadyOpen;
    }
    match open_the_records(app) {
        Ok(()) => Opening::Opened,
        Err(error) => {
            tracing::warn!(%error, "this computer's pairing records could not be opened");
            state.records_not_opened(if companion_platform::protection::is_available(app) {
                state::RecordsNotOpen::Failed(error.message)
            } else {
                state::RecordsNotOpen::Locked
            });
            Opening::Failed
        }
    }
}

/// Has the pairing records opened again each time the device may have been unlocked, until they
/// are open.
#[cfg(target_os = "ios")]
fn watch_for_unlock(app: &tauri::AppHandle) {
    let handle = app.clone();
    let watching = companion_platform::protection::on_unlock(app, move || {
        // The system calls this on its own thread, which must not wait for the native half.
        let handle = handle.clone();
        tauri::async_runtime::spawn_blocking(move || open_after_unlock(&handle));
    });
    if let Err(error) = watching {
        tracing::warn!(%error, "the device's unlock cannot be heard, so the pairing records open at the next start");
    }
}

/// Opens the pairing records at an unlock, or when the application comes to the foreground, when a
/// start before it could not, starts what needs them, and then tells the page, so that what the page
/// asks for next is there. A try that fails tells the page the words that now stand where the
/// pairing screen would be: the device is no longer locked, and the cause is another.
#[cfg(target_os = "ios")]
fn open_after_unlock(app: &tauri::AppHandle) {
    match open_records(app) {
        Opening::Opened => {
            start_with_records(app);
            tell_the_page_the_records_are_open(app);
        }
        Opening::Failed => tell_the_page_the_records_are_not_open(app),
        Opening::AlreadyOpen => {}
    }
}

/// Tells the page, which read the records as not open for one reason, the words for the reason
/// that stands now.
#[cfg(target_os = "ios")]
fn tell_the_page_the_records_are_not_open(app: &tauri::AppHandle) {
    use tauri::{Emitter as _, Manager as _};

    if let Err(error) = app.state::<AppState>().device() {
        let _ = app.emit(
            pairing::PAIRING_EVENT,
            pairing::PairingUnavailable {
                unavailable: error.message,
            },
        );
    }
}

/// Tells the page, which read the records as not open, what it would have read had they been.
#[cfg(target_os = "ios")]
fn tell_the_page_the_records_are_open(app: &tauri::AppHandle) {
    use tauri::{Emitter as _, Manager as _};

    let state = app.state::<AppState>();
    if let Ok(device) = state.device() {
        let _ = app.emit(pairing::PAIRING_EVENT, device.view());
    }
    if let Ok(owner) = state.owner() {
        let _ = app.emit(pairing::CONFIRMATIONS_EVENT, owner.view());
    }
}

/// Starts what needs the pairing records: on a phone the host its commands last went to, and
/// recovery and settings sync, which need this computer's keys.
fn start_with_records(app: &tauri::AppHandle) {
    #[cfg(mobile)]
    hosts::resume(app);
    open_recovery(app);
    open_mailbox(app);
}

fn open_the_records(app: &tauri::AppHandle) -> Result<()> {
    use std::sync::Arc;

    use tauri::Manager as _;

    let data = app.path().app_data_dir().map_err(|error| {
        error::CommandError::stated(
            ErrorCode::ResourceUnavailable,
            format!("there is no application data directory: {error}"),
        )
    })?;
    keep_records_out_of_backup(app, &data)?;
    // The application's one secure store, as the account opens it: on a phone the native one,
    // which the keyring the host's own store goes through does not reach.
    let secrets = companion_platform::secrets::open(app).map_err(|error| {
        error::CommandError::stated(
            ErrorCode::ResourceUnavailable,
            format!("the secret store could not be opened: {error}"),
        )
    })?;
    let parts = device::Parts::platform(secrets, application_clock(app)?)?;
    start_pairing(
        app,
        &data,
        parts,
        verify::pairing_ceremony(app),
        verify::platform_ceremony(app.get_webview_window("main")),
        Arc::new(pairing::NativeIntake::new(app.clone())),
    )
}

/// The clock this computer's pairing attempts are measured on.
///
/// The Apple mobile systems name no boot to an application, so a phone keeps the small record its
/// clock reads the boot from beside the application's caches (see
/// [`kr_client::pairing::clock`]). Every other system's kernel names its boot.
#[cfg(all(target_vendor = "apple", not(target_os = "macos")))]
fn application_clock(app: &tauri::AppHandle) -> Result<kr_client::pairing::clock::DeviceClock> {
    use tauri::Manager as _;

    let caches = app.path().app_cache_dir().map_err(|error| {
        error::CommandError::stated(
            ErrorCode::ResourceUnavailable,
            format!("there is no application cache directory: {error}"),
        )
    })?;
    kr_client::pairing::clock::DeviceClock::resumed(&caches.join("pairing-boot")).map_err(|error| {
        error::CommandError::stated(
            ErrorCode::ResourceUnavailable,
            format!("this device's boot could not be recorded: {error}"),
        )
    })
}

#[cfg(not(all(target_vendor = "apple", not(target_os = "macos"))))]
fn application_clock(_app: &tauri::AppHandle) -> Result<kr_client::pairing::clock::DeviceClock> {
    kr_client::pairing::clock::DeviceClock::current().map_err(error::CommandError::from)
}

/// Makes `directory` and marks it as not to be backed up, so that nothing written in it afterwards
/// is.
///
/// What it keeps means something only beside this device's keychain keys, and those keys stay on
/// this device: a backup restored onto another phone would bring the records without the keys.
#[cfg(target_os = "ios")]
fn keep_out_of_backup<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    directory: &std::path::Path,
) -> Result<()> {
    let unavailable = |what: &str, error: &dyn std::fmt::Display| {
        error::CommandError::stated(
            ErrorCode::ResourceUnavailable,
            format!("{} could not be {what}: {error}", directory.display()),
        )
    };
    kr_ipc::paths::create_private_directory(directory)
        .map_err(|error| unavailable("made", &error))?;
    companion_platform::backup::keep_out(app, directory)
        .map_err(|error| unavailable("kept out of the backup", &error))
}

/// Marks the directories of the pairing records as not to be backed up, before they are opened.
///
/// A backup restored onto another phone would bring the records without the keys, and the attempt
/// budget would then refuse every code. With no records restored the person pairs again.
#[cfg(target_os = "ios")]
fn keep_records_out_of_backup(app: &tauri::AppHandle, data: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    // A new installation has no data directory yet: the system names it and does not make it. It
    // is made here, owner-only with any parent it is missing, as the attempt budget makes its own
    // path; the records' directories are made inside it.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data)
        .map_err(|error| {
            error::CommandError::stated(
                ErrorCode::ResourceUnavailable,
                format!("{} could not be made: {error}", data.display()),
            )
        })?;
    for name in [device::HOSTS_DIRECTORY, device::BUDGET_DIRECTORY] {
        keep_out_of_backup(app, &data.join(name))?;
    }
    Ok(())
}

#[cfg(not(target_os = "ios"))]
const fn keep_records_out_of_backup(
    _app: &tauri::AppHandle,
    _data: &std::path::Path,
) -> Result<()> {
    Ok(())
}

/// Opens the sync service setting, which needs no keys, and starts telling the page about the
/// settings, so a step that begins at once is heard.
fn open_sync_service(app: &tauri::AppHandle) {
    use tauri::Manager as _;

    let Ok(data) = app.path().app_data_dir() else {
        tracing::warn!("no application data directory, so this computer keeps no sync setting");
        return;
    };
    start_sync_service(app, &data);
    watch_settings(app);
}

/// Opens recovery and lets this computer take part in settings sync, on this computer's own keys.
/// They are started when the pairing records are open, since the keys are opened with them.
fn open_recovery(app: &tauri::AppHandle) {
    use tauri::Manager as _;

    let Ok(data) = app.path().app_data_dir() else {
        return;
    };
    let Ok(device) = app.state::<AppState>().device() else {
        return;
    };
    if let Err(error) = start_recovery(app, &data, device.identity()) {
        tracing::warn!(%error, "this computer's recovery records could not be opened");
    }
    let hosts = std::sync::Arc::new(settings::connected::ConnectedHosts::new(app.clone()));
    let ceremony = verify::platform_ceremony(app.get_webview_window("main"));
    match start_settings_sync(app, device.identity(), hosts, ceremony) {
        Ok(()) => keep_settings_in_step(app),
        Err(error) => {
            tracing::warn!(%error, "this computer cannot take part in settings sync");
        }
    }
}

/// Opens this computer's reader of its own mailbox, once the pairing records and the sync service
/// setting are open.
fn open_mailbox(app: &tauri::AppHandle) {
    use tauri::Manager as _;

    let Ok(data) = app.path().app_data_dir() else {
        return;
    };
    if let Err(error) = start_mailbox(app, &data) {
        tracing::warn!(%error, "this computer's reader of its mailbox could not be opened");
    }
}

/// Tells the page, on [`settings::SETTINGS_EVENT`], whenever what it shows of the settings changes.
pub fn watch_settings<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::{Emitter as _, Manager as _};

    let Ok(settings) = app.state::<AppState>().settings() else {
        return;
    };
    let handle = app.clone();
    settings.told().by(move || {
        if let Ok(settings) = handle.state::<AppState>().settings() {
            let _ = handle.emit(settings::SETTINGS_EVENT, settings.view());
        }
    });
}

/// Lets this computer take part in settings sync, on `identity`'s keys and secure store and the
/// sync service the setting names, with its records under the data directory the settings were
/// opened with. The drafts of this computer's draft desk travel in the same collection when the
/// person turns that on, `hosts` says what this computer can read of each host's privacy mode and
/// which devices each lists, and `ceremony` is what adding a device to the settings and joining
/// them ask the person to complete.
///
/// # Errors
///
/// Returns a local failure when the settings or the sync service setting were not opened first, or
/// sync's directory cannot be made.
pub fn start_settings_sync<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    identity: &device::DeviceIdentity,
    hosts: std::sync::Arc<dyn settings::Hosts>,
    ceremony: std::sync::Arc<dyn kr_client::pairing::owner::Ceremony>,
) -> Result<()> {
    use std::sync::Arc;

    use tauri::Manager as _;

    let state = app.state::<AppState>();
    state.settings()?.take_part(
        settings::SyncParts {
            keys: identity.keys.clone(),
            secrets: Arc::clone(&identity.secrets),
            service: state.sync_service()?,
        },
        state.drafts(),
        hosts,
        ceremony,
    )
}

/// How long settings sync waits between looking for what another device changed.
const SETTINGS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// How long a change to the drafts is let settle before a pass takes it up, so that a person typing
/// is one pass and not one for every pause.
const DRAFTS_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);

/// Starts the task that brings this computer and the sync service to the same settings now, every
/// [`SETTINGS_INTERVAL`] after, and shortly after a draft is saved or removed. Nothing is sent
/// while settings sync is off.
fn keep_settings_in_step(app: &tauri::AppHandle) {
    use tauri::Manager as _;

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok(settings) = handle.state::<AppState>().settings() else {
                tokio::time::sleep(SETTINGS_INTERVAL).await;
                continue;
            };
            let _ = settings.sync_quietly().await;
            tokio::select! {
                () = tokio::time::sleep(SETTINGS_INTERVAL) => {}
                () = settings.drafts_changed() => tokio::time::sleep(DRAFTS_SETTLE).await,
            }
        }
    });
}

/// Opens the sync service setting kept under `data`.
pub fn start_sync_service<R: tauri::Runtime>(app: &tauri::AppHandle<R>, data: &std::path::Path) {
    use tauri::Manager as _;

    app.state::<AppState>()
        .sync_service_opened(std::sync::Arc::new(sync_service::SyncService::open(data)));
}

/// Opens recovery over the records kept under `data`, with the seed in `identity`'s secret store
/// and `identity`'s authorisation key signing for the sync service the setting names.
///
/// # Errors
///
/// Returns a local failure when the setting was not opened first or recovery's directory cannot
/// be made.
pub fn start_recovery<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    data: &std::path::Path,
    identity: &device::DeviceIdentity,
) -> Result<()> {
    use std::sync::Arc;

    use tauri::Manager as _;

    // Recovery's records name a bundle whose seed is in this device's keychain, so a restore onto
    // another phone must not bring them. The directory is marked before it is opened, and a fault
    // here stays with recovery.
    #[cfg(target_os = "ios")]
    keep_out_of_backup(app, &data.join(recovery::DIRECTORY))?;
    let state = app.state::<AppState>();
    let recovery = recovery::Recovery::open(
        data,
        Arc::clone(&identity.secrets),
        identity.keys.authorisation.clone(),
        state.sync_service()?,
    )?;
    state.recovery_opened(Arc::new(recovery));
    Ok(())
}

/// Opens this computer's reader of its own mailbox, with its record under `data`, over the
/// pairing records and the sync service setting, which are opened first. The record's directory is
/// made when the reader first needs it.
///
/// # Errors
///
/// Returns a local failure when the pairing records or the setting are not open.
pub fn start_mailbox<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    data: &std::path::Path,
) -> Result<()> {
    use std::sync::Arc;

    use tauri::Manager as _;

    let state = app.state::<AppState>();
    let desk = mailbox::MailboxDesk::new(data, state.device()?, state.sync_service()?);
    state.mailbox_opened(Arc::new(desk));
    Ok(())
}

/// Opens this computer as a device that pairs, made of `parts` with its records under `data`, and
/// as an owner device whose confirmations `ceremony` answers (a revocation is answered by
/// `revocation_ceremony`, which a phone leaves without one), taking invitations in through `intake`;
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
    revocation_ceremony: std::sync::Arc<dyn kr_client::pairing::owner::Ceremony>,
    intake: std::sync::Arc<dyn pairing::IntakePlatform>,
) -> Result<()> {
    use std::sync::Arc;

    use tauri::{Emitter as _, Manager as _};

    let emitter = app.clone();
    let device = device::Device::with(data, parts, move || {
        if let Ok(device) = emitter.state::<AppState>().device() {
            let view = device.view();
            let paired = matches!(
                view.state,
                kr_client::pairing::candidate::AttemptState::Paired { .. }
            );
            let _ = emitter.emit(pairing::PAIRING_EVENT, view);
            if paired {
                // A computer that reaches no host takes the first one it pairs with as the one its
                // commands go to, so a phone that has just paired is talking to the host it paired
                // with without a second step. Once a host is in use, or while one is reached
                // (a computer's own host, say), this does nothing.
                if device.host_in_use().is_none()
                    && !emitter.state::<AppState>().connection_state().connected
                    && let Some(host) = device.newest_host()
                {
                    let app = emitter.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = hosts::use_host(&app, host).await;
                    });
                }
            }
        }
    })?;
    let revocations = revocation::Revocations::new(Arc::clone(&device), revocation_ceremony);
    let emitter = app.clone();
    let owner = owner::Owner::new(Arc::clone(&device), ceremony, move || {
        if let Ok(owner) = emitter.state::<AppState>().owner() {
            let _ = emitter.emit(pairing::CONFIRMATIONS_EVENT, owner.view());
        }
    });
    let reading = Arc::clone(&intake);
    app.state::<AppState>()
        .opened(Arc::clone(&device), Arc::clone(&owner), intake, revocations);
    device.start();
    owner.start();
    // Where this device reads a code from is asked of the platform without waiting for it, and the
    // page is told when it is known.
    let known = Arc::clone(&device);
    tauri::async_runtime::spawn(async move {
        known.set_sources(reading.sources().await);
    });
    Ok(())
}

/// The event the backend publishes the paths of dropped files on.
pub const DROPPED_EVENT: &str = "kr://dropped";
