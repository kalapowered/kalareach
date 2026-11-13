//! What the application does when the system takes its scene away and gives one back.
//!
//! On iOS the window belongs to a scene. The system may disconnect the scene while the process
//! lives on, and connect one again later. The windowing library reports the disconnect as the
//! window's destruction. With no window left, the runtime asks the application to exit, and iOS
//! ignores an exit, so the process lives on with no window while a call or a pairing goes on in it.
//! This refuses that request (only the runtime's own: an exit the application asks for carries a
//! code and passes), which keeps the runtime from treating the application as finished, and opens
//! the main window again when the system returns a scene: that is what gives the page back.
//!
//! What a simulator shows of this is limited. The system's own disconnect of the only scene in a
//! live process happens under memory pressure and cannot be caused: a request to destroy the scene
//! is refused when the application turns multiple scenes off, and where the last scene of an
//! application that allows them is destroyed, the system ends the process. A debug build's probe
//! therefore calls the runtime's scene delegate with the disconnect and the connect, on the real
//! scene, and shows what this module does with the events that follow. The real form needs a phone
//! under memory pressure.
//!
//! The runtime hands every event to the application on the thread that runs the platform's loop, one
//! after the other, so the check for a window and the opening of one cannot interleave: two returns
//! in a row open one window. Nothing else is started again. The state, the services and the pairing
//! records are made once in setup and outlive the window; only what is tied to the window is made
//! again.

use objc2_foundation::MainThreadMarker;
use objc2_ui_kit::{UIApplication, UIScene, UIWindowScene};
use tauri::{AppHandle, Manager as _, RunEvent};

use crate::scene_role;

/// The runtime's events, as far as a scene concerns them.
pub(crate) fn on_run_event(app: &AppHandle, event: &RunEvent) {
    #[cfg(debug_assertions)]
    trace(app, event);
    match event {
        RunEvent::ExitRequested {
            code: None, api, ..
        } => api.prevent_exit(),
        RunEvent::SceneRequested { scene, .. } => {
            // Only the application's own scene is the phone's screen. A scene of another role (an
            // external display's) is left without a window, which keeps the system's mirroring.
            let role = scene.session().role().to_string();
            if scene_role::takes_the_main_window(&role) {
                open_main_window_once(app);
                bring_windows_here(app, scene);
            } else {
                tracing::info!("a scene of another role was requested, so it was given no window");
                #[cfg(debug_assertions)]
                eprintln!(
                    "KalaReach scene probe (rust): a scene of another role was given no window"
                );
            }
        }
        _ => {}
    }
}

/// What a debug build says on its error stream of the events that concern a scene, for a device run
/// that has to tell which event brought the window back. The other events are not worth a line.
#[cfg(debug_assertions)]
fn trace(app: &AppHandle, event: &RunEvent) {
    let what = match event {
        RunEvent::ExitRequested { code, .. } => format!("exit requested, code {code:?}"),
        RunEvent::SceneRequested { .. } => "scene requested".to_owned(),
        RunEvent::WindowEvent {
            label,
            event: tauri::WindowEvent::Destroyed,
            ..
        } => format!("window {label} destroyed"),
        RunEvent::Resumed => "resumed".to_owned(),
        _ => return,
    };
    eprintln!(
        "KalaReach scene probe (rust): {what}, windows={}",
        app.webview_windows().len()
    );
}

/// Puts every window that sits in a scene of another role into the scene that was just given back.
///
/// The windowing library puts a new window in the first connected scene that has none, whatever its
/// role, and the application's own scene is one of two such scenes when an external display's scene
/// is connected without a window: the main window can then land on the display, and the phone stays
/// blank while the existing-window check refuses to open another. A window cannot be asked for in a
/// given scene, so it is moved after the fact. Nothing moves when every window is in a scene of the
/// application's own role, which is the case unless a display is connected.
fn bring_windows_here(app: &AppHandle, scene: &UIScene) {
    let (Some(mtm), Some(here)) = (
        MainThreadMarker::new(),
        scene.downcast_ref::<UIWindowScene>(),
    ) else {
        return;
    };
    let mut moved = 0_usize;
    for other in UIApplication::sharedApplication(mtm)
        .connectedScenes()
        .iter()
    {
        let Some(other) = other.downcast_ref::<UIWindowScene>() else {
            continue;
        };
        if scene_role::takes_the_main_window(&other.session().role().to_string()) {
            continue;
        }
        for window in other.windows().iter() {
            window.setWindowScene(Some(here));
            moved += 1;
        }
    }
    if moved > 0 {
        tracing::info!(
            moved,
            "windows in a scene of another role were moved to the application's scene"
        );
    }
    #[cfg(debug_assertions)]
    {
        let here_id = scene.session().persistentIdentifier().to_string();
        let main_id = app
            .get_webview_window("main")
            .and_then(|window| window.as_ref().window().scene_identifier().ok());
        eprintln!(
            "KalaReach scene probe (rust): windows moved={moved}, the main window is in the application scene: {}",
            main_id.as_deref() == Some(here_id.as_str())
        );
    }
    #[cfg(not(debug_assertions))]
    let _ = app;
}

/// Opens the main window if the application has none, with what is tied to it.
pub(crate) fn open_main_window_once(app: &AppHandle) {
    if !app.webview_windows().is_empty() {
        #[cfg(debug_assertions)]
        eprintln!("KalaReach scene probe (rust): a window exists, so none was opened");
        return;
    }
    match crate::open_main_window(app) {
        Ok(()) => {
            crate::watch_drops(app);
            #[cfg(debug_assertions)]
            eprintln!("KalaReach scene probe (rust): the main window was opened again");
            tracing::info!("a scene came back, so the main window was opened again");
        }
        Err(error) => {
            tracing::error!(%error, "a scene came back and the main window could not be opened")
        }
    }
}
