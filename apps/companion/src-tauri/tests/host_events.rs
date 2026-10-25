//! A host's events reach the page through Tauri's event IPC.
//!
//! KR-REQ-10.01: the web view is given the host's events over IPC, as the native client validated
//! them.
//!
//! Section 10: the web view is given the host's events over IPC, as the native client validated
//! them. The payload's form has a unit test of its own; this holds the path. A scripted session
//! worker pushes events on a link the application reached the way it reaches a real worker: the
//! worker proved its descriptor's key, and the client library decodes every frame it sends. The
//! application's own publisher sends each event on to the page. The page, in a real web view and
//! with only what the interface's own capability allows it, listens the way the interface does,
//! through the event API on the backend's event name, and says what it heard.
//!
//! What is checked is what the page received: each event in the order it was pushed, with its
//! stream, its sequence and its type, a payload with a JSON form as that JSON, and one without as
//! null.
//!
//! It opens a real window, so it has its own main thread (`harness = false`) and runs on macOS,
//! where the Mac lists run it, and on Windows, in WebView2. Linux runs the same publisher without
//! this check.

#[cfg(not(any(target_os = "macos", windows)))]
fn main() {
    println!(
        "host_events: the runtime check runs on macOS and Windows; the payload's unit test holds \
         the form here"
    );
}

#[cfg(any(target_os = "macos", windows))]
fn main() {
    std::process::exit(window::run());
}

#[cfg(any(target_os = "macos", windows))]
mod scripted_worker;

#[cfg(any(target_os = "macos", windows))]
mod window {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use kr_protocol::envelope::ParamsValue;
    use serde_json::{Value, json};
    use tauri::{AppHandle, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    use super::scripted_worker::{Challenge, OUTPUT_STREAM, ScriptedWorker};

    /// The window the interface's own capability names.
    const INTERFACE_WINDOW: &str = "main";

    /// How long the window loop is given to become ready before the check calls it never so.
    ///
    /// Becoming ready is the window system's own work, and a session with no desktop to show a
    /// window on can leave the loop waiting for ever, with nothing to say so.
    const READY_BOUND: Duration = Duration::from_secs(300);

    /// How long the application is given to end once the check has its verdict.
    ///
    /// The check is over by then. A web view that is torn down in a session with no desktop can
    /// hold the process open for ever, and the verdict is what the run reports.
    const END_BOUND: Duration = Duration::from_secs(30);

    /// Panics heard on any thread of the check, the application's own tasks included.
    static PANICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    pub fn run() -> i32 {
        // A task of the application that panics ends alone and says nothing to the check, so the
        // check listens for panics itself and fails on any.
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(info.to_string());
            default(info);
        }));
        // A window loop that never becomes ready is a failed check, not one that waits for ever.
        let ready = Arc::new(AtomicBool::new(false));
        let readiness = Arc::clone(&ready);
        std::thread::spawn(move || {
            std::thread::sleep(READY_BOUND);
            if !readiness.load(Ordering::SeqCst) {
                eprintln!("host_events: the window loop was not ready within {READY_BOUND:?}");
                std::process::exit(1);
            }
        });
        // The scripted worker answers on a runtime of the check's own: the application's own
        // runtime is where the publisher runs.
        let runtime = Arc::new(tokio::runtime::Runtime::new().expect("a runtime for the worker"));
        let worker = runtime.block_on(async { ScriptedWorker::start(Challenge::Answered) });
        let mut worker = Some(worker);
        // A test context: on macOS the library already embeds the application's Info.plist, and a
        // second copy is a duplicate symbol. With no capability of its own, the context takes the
        // application's, so the page is allowed what the interface is and nothing more.
        let app = tauri::Builder::default()
            // The application's own state, as the publisher finds it when its connection ends.
            .manage(companion_tauri::AppState::new())
            .build(tauri::generate_context!(
                "tests/host_events/tauri.conf.json",
                test = true
            ))
            .expect("the check's application builds");
        // The check's own verdict. The window loop's return value is not it: on macOS the loop
        // returns 0 whatever code the application exits with, so a failed check would pass.
        let verdict = Arc::new(AtomicI32::new(1));
        let recorded = Arc::clone(&verdict);
        let returned = app.run_return(move |handle, event| {
            if !matches!(event, tauri::RunEvent::Ready) {
                return;
            }
            let Some(worker) = worker.take() else {
                return;
            };
            ready.store(true, Ordering::SeqCst);
            let handle = handle.clone();
            let runtime = Arc::clone(&runtime);
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || {
                // A failed expectation inside the scripted worker panics this thread; it is a
                // failed check like any other, and must not leave the window loop running.
                let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    check(&handle, &runtime, worker)
                }))
                .unwrap_or_else(|_| Err("the check panicked".to_owned()));
                let code = match checked {
                    Ok(()) => {
                        println!("host_events: the page heard each event as it was published");
                        0
                    }
                    Err(failure) => {
                        eprintln!("host_events: {failure}");
                        1
                    }
                };
                recorded.store(code, Ordering::SeqCst);
                // If the application does not end, the process ends with the verdict.
                std::thread::spawn(move || {
                    std::thread::sleep(END_BOUND);
                    eprintln!("host_events: the application did not end within {END_BOUND:?}");
                    let panicked = !PANICS
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .is_empty();
                    std::process::exit(if panicked { 1 } else { code });
                });
                handle.exit(code);
            });
        });
        let panics = PANICS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if !panics.is_empty() {
            eprintln!("host_events: a task panicked: {panics:?}");
            return 1;
        }
        returned.max(verdict.load(Ordering::SeqCst))
    }

    /// How long the check waits for something the web view does, before it calls the thing never
    /// done. What it waits for is the web view's own work: a web process that starts, a page that
    /// loads and runs its script, and an event that crosses to it and back as a new title. On a
    /// machine with every core busy each of those takes as long as the machine takes, and the wait
    /// ends the moment the thing is done, so the bound only says that it will not be.
    const LIVENESS: Duration = Duration::from_secs(120);

    /// Waits until `done` holds and says how long that took, so that a run under load shows how
    /// much of the bound it used.
    fn wait_for(what: &str, done: impl Fn() -> bool) -> Result<Duration, String> {
        let started = Instant::now();
        while !done() {
            if started.elapsed() > LIVENESS {
                return Err(format!("{what} did not happen within {LIVENESS:?}"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let took = started.elapsed();
        println!("host_events: {what} took {took:.1?}");
        Ok(took)
    }

    /// What the page says, which it says in the window's title.
    fn said(window: &WebviewWindow) -> String {
        window.title().unwrap_or_default()
    }

    /// The events the page has heard so far, as it received them.
    fn heard(window: &WebviewWindow) -> Vec<Value> {
        serde_json::from_str::<Vec<Value>>(&said(window)).unwrap_or_default()
    }

    fn check(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        mut worker: ScriptedWorker,
    ) -> Result<(), String> {
        let loads = Arc::new(AtomicUsize::new(0));
        let counting = Arc::clone(&loads);
        let window =
            WebviewWindowBuilder::new(app, INTERFACE_WINDOW, WebviewUrl::App("index.html".into()))
                .title("opening")
                .inner_size(320.0, 240.0)
                .on_page_load(move |_window, payload| {
                    if payload.event() == tauri::webview::PageLoadEvent::Finished {
                        counting.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .build()
                .map_err(|error| error.to_string())?;
        // The listener is registered through the event IPC before the page says so. A failed wait
        // says how far the page got, which tells a page that never loaded from one that loaded and
        // never said it listened.
        wait_for("the page listening", || said(&window) != "opening").map_err(|failure| {
            format!(
                "{failure}; {} page loads finished and the window's title is {:?}",
                loads.load(Ordering::SeqCst),
                said(&window)
            )
        })?;
        let listened_after = loads.load(Ordering::SeqCst);
        if said(&window) != "listening" {
            return Err(format!(
                "the page could not listen for the host's events: {}",
                said(&window)
            ));
        }

        // The session's link, reached as the application reaches a worker: the worker proves its
        // descriptor's key before anything else crosses.
        let paths = worker.paths();
        let session_id = worker.session_id;
        let (session, mut link) = runtime.block_on(async {
            let reached = companion_tauri::worker::reach(&paths, session_id)
                .await
                .map_err(companion_tauri::worker::Unreached::words)?;
            let transport = kr_client::ipc::IpcTransport::over(reached.client);
            let session =
                kr_client::Session::start(transport.shared()).map_err(|error| error.to_string())?;
            let link = worker.link().await;
            Ok::<_, String>((session, link))
        })?;
        // The connection is the application's to hold, as its state holds the host's: the
        // publisher only listens on it.
        let session = Arc::new(session);
        let host = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        // Subscribed as the application subscribes, before anything can be sent on the connection.
        // `witness` is a second subscription, which says when the session has received an event.
        let events = session.events();
        let mut witness = session.events();

        // Both events are in the session before the publisher is started: an event sent before the
        // task that forwards them first runs is one the page is still given, and the publisher
        // starting late is the order that decides it.
        runtime.block_on(async {
            link.push(
                "session.state",
                &json!({ "state": "live", "cursor": 42, "changed": [true, null] }),
            )
            .await;
            link.push_raw(
                "session.output",
                ParamsValue::new(kr_cbor::CanonicalValue::Bytes(vec![1, 2, 3])),
            )
            .await;
            for _ in 0..2 {
                tokio::time::timeout(LIVENESS, witness.recv())
                    .await
                    .map_err(|_| "the session did not receive both events".to_owned())?
                    .map_err(|error| format!("the session's events ended: {error}"))?;
            }
            Ok::<_, String>(())
        })?;
        let publisher = tauri::async_runtime::spawn(companion_tauri::connection::forward_events(
            app.clone(),
            Arc::clone(&session),
            host,
            events,
        ));
        wait_for("the page hearing both events", || heard(&window).len() >= 2).map_err(
            |failure| {
                format!(
                    "{failure}; the page has heard {:?}, its window's title is {:?}, and {} page loads \
                     finished, {listened_after} of them before it listened",
                    heard(&window),
                    said(&window),
                    loads.load(Ordering::SeqCst)
                )
            },
        )?;
        // Each event names the host it came from, which the page drops events of a host it no
        // longer uses by.
        let expected = vec![
            json!({
                "host": host.to_string(),
                "stream_id": OUTPUT_STREAM,
                "sequence": "0",
                "event_type": "session.state",
                "payload": { "state": "live", "cursor": 42, "changed": [true, null] },
            }),
            json!({
                "host": host.to_string(),
                "stream_id": OUTPUT_STREAM,
                "sequence": "1",
                "event_type": "session.output",
                "payload": null,
            }),
        ];
        let received = heard(&window);
        session.close();
        // The publisher ends when its connection does. It is waited for here, so that whatever it
        // does at its end (and a panic there) is seen by this check and not by nobody.
        tauri::async_runtime::block_on(async {
            tokio::time::timeout(LIVENESS, publisher)
                .await
                .map_err(|_| "the publisher did not end with its connection".to_owned())?
                .map_err(|error| format!("the publisher ended badly: {error}"))
        })?;
        if received != expected {
            return Err(format!(
                "the page heard {received:?}, not the events as they were published"
            ));
        }
        Ok(())
    }
}
