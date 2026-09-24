//! Navigation and popups at runtime: the main window stays on the bundled interface.
//!
//! Section 13: the production application loads its interface from the bundle, and the sign-in's
//! pages open in the system browser, never in this window. The navigation predicate's own tests
//! hold the rule as a function; this test holds what the web view actually does with the
//! production handlers, as two checks with a control each.
//!
//! * Navigation: the page asks to go to the website. With the production handler it stays on the
//!   bundled interface; the control, a window with no navigation handler, leaves.
//! * Popups: the page asks for a new window at the website. With the production handler no second
//!   web view exists; the control, a handler that creates the window, produces one.
//!
//! It opens real windows, so it has its own main thread (`harness = false`) and runs on macOS,
//! where the Mac lists run it. Windows and Linux run the same handlers without this check.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!(
        "navigation: the runtime check runs on macOS; the predicate's tests hold the rule here"
    );
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(macos::run());
}

#[cfg(target_os = "macos")]
mod macos {
    use std::time::{Duration, Instant};

    use tauri::webview::NewWindowResponse;
    use tauri::{AppHandle, Manager as _, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    const WEBSITE: &str = "https://reach.kala.to/";

    pub fn run() -> i32 {
        // A test context: the library already embeds the application's Info.plist, and a second
        // copy is a duplicate symbol.
        let app = tauri::Builder::default()
            .build(tauri::generate_context!(
                "tests/navigation/tauri.conf.json",
                test = true
            ))
            .expect("the check's application builds");
        let mut started = false;
        app.run_return(move |handle, event| {
            if matches!(event, tauri::RunEvent::Ready) && !started {
                started = true;
                let handle = handle.clone();
                std::thread::spawn(move || {
                    let code = match check(&handle) {
                        Ok(()) => {
                            println!("navigation: every check held");
                            0
                        }
                        Err(failure) => {
                            eprintln!("navigation: {failure}");
                            1
                        }
                    };
                    handle.exit(code);
                });
            }
        })
    }

    fn wait_for(what: &str, limit: Duration, done: impl Fn() -> bool) -> Result<(), String> {
        let started = Instant::now();
        while !done() {
            if started.elapsed() > limit {
                return Err(format!("{what} did not happen within {limit:?}"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    fn address(window: &WebviewWindow) -> String {
        window.url().map(|url| url.to_string()).unwrap_or_default()
    }

    fn bundled(window: &WebviewWindow) -> bool {
        address(window).starts_with("tauri://localhost")
    }

    fn open(app: &AppHandle, label: &str, guarded: bool) -> Result<WebviewWindow, String> {
        let builder = WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into()))
            .title(label)
            .inner_size(320.0, 240.0);
        let builder = if guarded {
            companion_tauri::account::navigation::guard(builder, None)
        } else {
            let app = app.clone();
            builder.on_new_window(move |_url, features| {
                // The control: a handler that creates the window the page asked for.
                let created = WebviewWindowBuilder::new(
                    &app,
                    "control-popup",
                    WebviewUrl::External("about:blank".parse().expect("an address")),
                )
                .window_features(features)
                .build();
                match created {
                    Ok(window) => NewWindowResponse::Create { window },
                    Err(_) => NewWindowResponse::Deny,
                }
            })
        };
        let window = builder.build().map_err(|error| error.to_string())?;
        wait_for(
            &format!("{label} loading the bundle"),
            Duration::from_secs(20),
            || bundled(&window),
        )?;
        Ok(window)
    }

    fn check(app: &AppHandle) -> Result<(), String> {
        // Navigation, with the production handler: the window stays on the bundled interface.
        let guarded = open(app, "guarded", true)?;
        guarded
            .eval(format!("location.assign('{WEBSITE}')"))
            .map_err(|error| error.to_string())?;
        std::thread::sleep(Duration::from_secs(3));
        if !bundled(&guarded) {
            return Err(format!(
                "the guarded window left the bundle for {}",
                address(&guarded)
            ));
        }

        // Popups, with the production handler: no second web view exists.
        guarded
            .eval(format!("window.open('{WEBSITE}')"))
            .map_err(|error| error.to_string())?;
        std::thread::sleep(Duration::from_secs(3));
        let held = app.webview_windows().len();
        if held != 1 {
            return Err(format!("the guarded window's popup made {held} web views"));
        }
        if !bundled(&guarded) {
            return Err("the guarded window's popup navigated it".to_owned());
        }

        // The controls: without the handlers the same page leaves, and a permissive handler
        // creates the popup, so the two checks above are checks of the handlers.
        let control = open(app, "control", false)?;
        control
            .eval(format!("window.open('{WEBSITE}')"))
            .map_err(|error| error.to_string())?;
        wait_for("the control's popup", Duration::from_secs(10), || {
            app.webview_windows().len() == 3
        })?;
        control
            .eval(format!("location.assign('{WEBSITE}')"))
            .map_err(|error| error.to_string())?;
        wait_for(
            "the control leaving the bundle",
            Duration::from_secs(20),
            || address(&control).starts_with(WEBSITE),
        )?;
        Ok(())
    }
}
