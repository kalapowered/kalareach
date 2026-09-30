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
//! where the Mac lists run it. Windows and Linux run the same publisher without this check.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!(
        "host_events: the runtime check runs on macOS; the payload's unit test holds the form here"
    );
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(macos::run());
}

#[cfg(target_os = "macos")]
mod scripted_worker;

#[cfg(target_os = "macos")]
mod macos {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::{Duration, Instant};

    use kr_protocol::envelope::ParamsValue;
    use serde_json::{Value, json};
    use tauri::{AppHandle, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    use super::scripted_worker::{Challenge, OUTPUT_STREAM, ScriptedWorker};

    /// The window the interface's own capability names.
    const INTERFACE_WINDOW: &str = "main";

    pub fn run() -> i32 {
        // The scripted worker answers on a runtime of the check's own: the application's own
        // runtime is where the publisher runs.
        let runtime = Arc::new(tokio::runtime::Runtime::new().expect("a runtime for the worker"));
        let worker = runtime.block_on(async { ScriptedWorker::start(Challenge::Answered) });
        let mut worker = Some(worker);
        // A test context: the library already embeds the application's Info.plist, and a second
        // copy is a duplicate symbol. With no capability of its own, the context takes the
        // application's, so the page is allowed what the interface is and nothing more.
        let app = tauri::Builder::default()
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
                handle.exit(code);
            });
        });
        returned.max(verdict.load(Ordering::SeqCst))
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
        let window =
            WebviewWindowBuilder::new(app, INTERFACE_WINDOW, WebviewUrl::App("index.html".into()))
                .title("opening")
                .inner_size(320.0, 240.0)
                .build()
                .map_err(|error| error.to_string())?;
        // The listener is registered through the event IPC before the page says so.
        wait_for("the page listening", Duration::from_secs(20), || {
            said(&window) != "opening"
        })?;
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
        companion_tauri::connection::publish_events(app.clone(), Arc::clone(&session));

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
        });
        wait_for(
            "the page hearing both events",
            Duration::from_secs(20),
            || heard(&window).len() >= 2,
        )?;
        let expected = vec![
            json!({
                "stream_id": OUTPUT_STREAM,
                "sequence": "0",
                "event_type": "session.state",
                "payload": { "state": "live", "cursor": 42, "changed": [true, null] },
            }),
            json!({
                "stream_id": OUTPUT_STREAM,
                "sequence": "1",
                "event_type": "session.output",
                "payload": null,
            }),
        ];
        let received = heard(&window);
        session.close();
        if received != expected {
            return Err(format!(
                "the page heard {received:?}, not the events as they were published"
            ));
        }
        Ok(())
    }
}
