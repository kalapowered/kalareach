//! Navigation and popups at runtime: the main window stays on the bundled interface.
//!
//! Section 13: the production application loads its interface from the bundle, and the sign-in's
//! pages open in the system browser, never in this window. The navigation predicate's own tests
//! hold the rule as a function; this test holds what the web view actually does with the
//! production handlers, as two checks with a control each.
//!
//! * Navigation: the page asks to go to the website. With the production handler it stays on the
//!   bundled interface and the handler reports the refusal; the control, a window with no
//!   navigation handler, leaves.
//! * Popups: the page asks for a new window at the website. The production handler reports that
//!   it was asked and refused, and no second web view exists; the control, a handler that creates
//!   the window, produces one.
//!
//! The handlers' reports are the application's own log lines, read through a subscriber this test
//! installs.
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
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tauri::webview::NewWindowResponse;
    use tauri::{AppHandle, Manager as _, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    const WEBSITE: &str = "https://reach.kala.to/";
    const NAVIGATION_REFUSED: &str = "a navigation away from the interface was refused";
    const WINDOW_REFUSED: &str = "a new window was refused";

    /// Every message the application logs while the check runs.
    #[derive(Clone, Default)]
    struct Messages(Arc<Mutex<Vec<String>>>);

    impl Messages {
        fn count(&self, message: &str) -> usize {
            self.0
                .lock()
                .expect("the record")
                .iter()
                .filter(|logged| logged.as_str() == message)
                .count()
        }
    }

    impl tracing::Subscriber for Messages {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().expect("the record").push(message.0);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    pub fn run() -> i32 {
        let messages = Messages::default();
        tracing::subscriber::set_global_default(messages.clone())
            .expect("the check's subscriber is the first");
        // A test context: the library already embeds the application's Info.plist, and a second
        // copy is a duplicate symbol.
        let app = tauri::Builder::default()
            .build(tauri::generate_context!(
                "tests/navigation/tauri.conf.json",
                test = true
            ))
            .expect("the check's application builds");
        // The checks' own verdict. The window loop's return value is not it: on macOS the loop
        // returns 0 whatever code the application exits with, so a failed check would pass.
        let verdict = Arc::new(std::sync::atomic::AtomicI32::new(1));
        let recorded = Arc::clone(&verdict);
        let mut started = false;
        let returned = app.run_return(move |handle, event| {
            if matches!(event, tauri::RunEvent::Ready) && !started {
                started = true;
                let handle = handle.clone();
                let messages = messages.clone();
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || {
                    // A check that panics is a failed check like any other, and must not leave
                    // the window loop running.
                    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        check(&handle, &messages)
                    }))
                    .unwrap_or_else(|_| Err("a check panicked".to_owned()));
                    let code = match checked {
                        Ok(()) => {
                            println!("navigation: every check held");
                            0
                        }
                        Err(failure) => {
                            eprintln!("navigation: {failure}");
                            1
                        }
                    };
                    recorded.store(code, std::sync::atomic::Ordering::SeqCst);
                    handle.exit(code);
                });
            }
        });
        returned.max(verdict.load(std::sync::atomic::Ordering::SeqCst))
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

    fn check(app: &AppHandle, messages: &Messages) -> Result<(), String> {
        // Navigation, with the production handler: the handler refuses it and the window stays on
        // the bundled interface.
        let guarded = open(app, "guarded", true)?;
        guarded
            .eval(format!("location.assign('{WEBSITE}')"))
            .map_err(|error| error.to_string())?;
        wait_for(
            "the production handler refusing the navigation",
            Duration::from_secs(10),
            || messages.count(NAVIGATION_REFUSED) == 1,
        )?;
        std::thread::sleep(Duration::from_secs(2));
        if !bundled(&guarded) {
            return Err(format!(
                "the guarded window left the bundle for {}",
                address(&guarded)
            ));
        }

        // Popups, with the production handler: it is asked and refuses, and no second web view
        // exists.
        guarded
            .eval(format!("window.open('{WEBSITE}')"))
            .map_err(|error| error.to_string())?;
        wait_for(
            "the production handler refusing the popup",
            Duration::from_secs(10),
            || messages.count(WINDOW_REFUSED) == 1,
        )?;
        std::thread::sleep(Duration::from_secs(2));
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
        // The control's windows have no production handler, so nothing more was refused.
        if messages.count(NAVIGATION_REFUSED) != 1 || messages.count(WINDOW_REFUSED) != 1 {
            return Err("a window without the production handlers reported a refusal".to_owned());
        }
        Ok(())
    }
}
