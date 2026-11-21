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
//! where the Mac lists run it, on Windows, in WebView2, and on Linux, in WebKitGTK. A Linux host
//! with no display gets one from an `Xvfb` the check starts (see `virtual_display`); a host with
//! neither stands down with a printed reason, unless `KR_REQUIRE_VIRTUAL_DISPLAY` is set, which
//! makes that a failure.

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn main() {
    println!(
        "host_events: the runtime check runs on macOS, Windows and Linux; the payload's unit test \
         holds the form here"
    );
}

#[cfg(any(target_os = "macos", windows))]
fn main() {
    std::process::exit(window::run());
}

#[cfg(target_os = "linux")]
fn main() {
    use virtual_display::Hosted;

    let code = match virtual_display::hosted() {
        Hosted::Here => window::run(),
        Hosted::Ended(code) => code,
        Hosted::StandsDown(why) => {
            println!(
                "host_events: the runtime check stands down, because {why}; the payload's unit \
                 test holds the form here"
            );
            0
        }
        Hosted::Failed(why) => {
            eprintln!("host_events: {why}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
mod scripted_worker;

#[cfg(target_os = "linux")]
mod virtual_display;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
mod window {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use companion_tauri::contact::STATE_FIRST_WITHIN;
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

    /// How long the check as a whole is given once the window loop is ready.
    ///
    /// Each wait inside the check has a bound of its own, and together they come to under eleven
    /// minutes; this is for a call that has none, such as building the window or reading its
    /// title, which a web view that never answers leaves blocked for ever. It is longer than all
    /// of those waits together.
    const CHECK_BOUND: Duration = Duration::from_secs(6 * LIVENESS.as_secs());

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
        // application's, so the page is allowed what the interface is and nothing more. On macOS
        // its icons are the application's too, the icns included: the context writes a file for
        // each, and the files are then the ones the library's context wrote before this program was
        // built. On Windows the configuration lists no icon of the `.ico` kind that the library's
        // window icon is, so the window icon is the png, a file only this program reads.
        let app = tauri::Builder::default()
            // The application's own state, as the publisher finds it when its connection ends.
            .manage(companion_tauri::AppState::new())
            .build(tauri::generate_context!(
                "tests/host_events/tauri.conf.json",
                test = true
            ))
            .expect("the check's application builds");
        companion_tauri::contact::serve(app.handle());
        // The check's own verdict. The window loop's return value is not it: on macOS the loop
        // returns 0 whatever code the application exits with, so a failed check would pass.
        let verdict = Arc::new(AtomicI32::new(1));
        let recorded = Arc::clone(&verdict);
        // The web view keeps its own data in a directory of the check's own, so that the check
        // writes nothing in the home of the account that runs it, and runs that share a home share
        // no web view data.
        let data =
            Arc::new(std::env::temp_dir().join(format!("kr-host-events-{}", kr_ipc::new_uuid())));
        let data_for_check = Arc::clone(&data);
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
            let data = Arc::clone(&data_for_check);
            std::thread::spawn(move || {
                // A call inside the check that never returns is a failed check, not one that waits
                // for ever: the bound runs from here to the verdict, and the waits inside the check
                // keep their own.
                let decided = Arc::new(AtomicBool::new(false));
                let deciding = Arc::clone(&decided);
                std::thread::spawn(move || {
                    std::thread::sleep(CHECK_BOUND);
                    if !deciding.load(Ordering::SeqCst) {
                        eprintln!(
                            "host_events: the check reached no verdict within {CHECK_BOUND:?}"
                        );
                        std::process::exit(1);
                    }
                });
                // A failed expectation inside the scripted worker panics this thread; it is a
                // failed check like any other, and must not leave the window loop running.
                let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    check(&handle, &runtime, worker, &data)
                }))
                .unwrap_or_else(|_| Err("the check panicked".to_owned()));
                decided.store(true, Ordering::SeqCst);
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
        let _ = std::fs::remove_dir_all(data.as_path());
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

    /// Whether the keeper's bound on a connection's first events (`STATE_FIRST_WITHIN`) has not
    /// passed, measured from `offered_at`, a time taken before the keeper was given the connection.
    fn before_the_bound(offered_at: Instant) -> bool {
        offered_at.elapsed() < STATE_FIRST_WITHIN
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
        data_directory: &std::path::Path,
    ) -> Result<(), String> {
        let loads = Arc::new(AtomicUsize::new(0));
        let counting = Arc::clone(&loads);
        let builder =
            WebviewWindowBuilder::new(app, INTERFACE_WINDOW, WebviewUrl::App("index.html".into()))
                .title("opening")
                .inner_size(320.0, 240.0)
                .on_page_load(move |_window, payload| {
                    if payload.event() == tauri::webview::PageLoadEvent::Finished {
                        counting.fetch_add(1, Ordering::SeqCst);
                    }
                });
        // Only the Linux web view is given a data directory of the check's own: it is the one this
        // check runs under a virtual display, and the other platforms' web views keep theirs where
        // their own checks have always run them.
        #[cfg(target_os = "linux")]
        let builder = builder.data_directory(data_directory.to_path_buf());
        #[cfg(not(target_os = "linux"))]
        let _ = data_directory;
        let window = builder.build().map_err(|error| error.to_string())?;
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
            tauri::Manager::state::<companion_tauri::AppState>(app)
                .contact_owner()
                .revision(),
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
        // longer uses by, and the revision of the connection state it follows (none was published
        // here, so 0).
        let expected = vec![
            json!({
                "host": host.to_string(),
                "stream_id": OUTPUT_STREAM,
                "sequence": "0",
                "event_type": "session.state",
                "payload": { "state": "live", "cursor": 42, "changed": [true, null] },
                "revision": 0,
            }),
            json!({
                "host": host.to_string(),
                "stream_id": OUTPUT_STREAM,
                "sequence": "1",
                "event_type": "session.output",
                "payload": null,
                "revision": 0,
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
        a_hosts_first_events_follow_its_state(app, runtime, &window)
    }

    /// KR-REQ-10.01: what a host sends first on a connection reaches the page after the state that
    /// announces the connection, and names that state's revision. The connection is reached by the
    /// keeper, as the application reaches a host, with the publisher held before it tells the
    /// announcing state; the host's events are sent meanwhile and are not forwarded until that
    /// state has been told.
    fn a_hosts_first_events_follow_its_state(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        window: &WebviewWindow,
    ) -> Result<(), String> {
        use companion_tauri::connection::{Attempt, Connection, Standing};

        // The events the page heard before this leg began.
        let before = heard(window).len();
        let mut worker = runtime.block_on(async { ScriptedWorker::start(Challenge::Answered) });
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
        let host = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        let connection = Connection::assembled(session, host, Standing::Owner, None, None);
        let session = connection.session();
        // A second subscription, which says when the session has received an event.
        let mut witness = session.events();
        let owner =
            Arc::clone(tauri::Manager::state::<companion_tauri::AppState>(app).contact_owner());
        let started_at = owner.revision();
        let mut hold = owner.hold_the_publisher();
        let mut offered = Some(connection);
        // The keeper starts its wait for the announcing state only once it has the connection, so
        // the time since this point is never less than the time that wait has run.
        let offered_at = Instant::now();
        companion_tauri::connection::reach_host_on_this_machine(app, move || {
            let next = offered.take();
            async move { next.map_or(Attempt::Nothing, Attempt::Reached) }
        })
        .map_err(|error| error.message)?;
        runtime.block_on(async {
            tokio::time::timeout(LIVENESS, hold.reached())
                .await
                .map_err(|_| "the publisher did not take the choice's publication".to_owned())
        })?;
        // The choice and the connection are each a revision, and the keeper subscribed to the
        // connection's events before the owner held it.
        wait_for("the connection being held", || {
            owner.revision() >= started_at + 2
        })?;
        // The revision of the state that announces the connection, which the publisher tells once
        // the hold is released.
        let held_revision = owner.revision();
        runtime.block_on(async {
            link.push(
                "session.state",
                &json!({ "state": "live", "cursor": 7, "changed": [] }),
            )
            .await;
            link.push_raw(
                "session.output",
                ParamsValue::new(kr_cbor::CanonicalValue::Bytes(vec![4, 5, 6])),
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
        // The state that announces the connection is held, so the host's events wait for it.
        std::thread::sleep(Duration::from_secs(1));
        let early = heard(window)[before..].to_vec();
        // The keeper stops waiting for the state after `STATE_FIRST_WITHIN` whether it was told or
        // not, and a case cannot move that bound. What the page has not heard, and in what order it
        // hears things, is asserted only while the bound cannot have passed: the time since the
        // offer, taken after the read, is never less than the time the keeper has waited. A machine
        // that stalled for longer says nothing about that order and is not failed for it. What the
        // bound does not explain is always asserted: that the state and both events arrive, and
        // what they name.
        let held_in_time = before_the_bound(offered_at);
        if held_in_time {
            assert!(
                early.is_empty(),
                "the page heard {early:?} before the state that announces the connection was told"
            );
        } else {
            println!(
                "not exercised: what the page heard while the state was held: more than \
                 {STATE_FIRST_WITHIN:?} passed after the connection was offered"
            );
        }

        hold.release();
        // The state is told once the hold is released, and the time is taken after that: a state
        // told inside the bound was told before the keeper's wait for it could end, however slowly
        // the page hears it.
        if !runtime.block_on(owner.emitted_through(held_revision, LIVENESS)) {
            return Err(format!(
                "the publisher did not tell the state that announces the connection within \
                 {LIVENESS:?} of its release"
            ));
        }
        let in_time = before_the_bound(offered_at);
        let heard_now = || heard(window)[before..].to_vec();
        wait_for("the page hearing the state and both events", || {
            let now = heard_now();
            now.iter()
                .filter(|each| each.get("connection").is_none())
                .count()
                >= 2
                && now.iter().any(|each| {
                    each.get("connection").is_some_and(|state| {
                        state["revision"].as_u64().unwrap_or(0) >= held_revision
                    })
                })
        })?;
        let told = heard_now();
        let events: Vec<&Value> = told
            .iter()
            .filter(|each| each.get("connection").is_none())
            .collect();
        let Some(last_state) = told
            .iter()
            .rposition(|each| each.get("connection").is_some())
        else {
            panic!("the page heard no state beside the events: {told:?}");
        };
        let announced = &told[last_state]["connection"];
        assert_eq!(announced["connected"], json!(true), "{announced}");
        assert!(
            announced["revision"].as_u64().unwrap_or(0) > started_at,
            "the state names a revision after the choice: {announced}"
        );
        for event in events {
            assert_eq!(
                event["revision"], announced["revision"],
                "each event names the revision of the state it follows: {told:?}"
            );
        }
        if held_in_time && in_time {
            let first_event = told
                .iter()
                .position(|each| each.get("connection").is_none())
                .expect("the events were heard");
            assert!(
                last_state < first_event,
                "the page heard the host's first events before the state that announces the connection: {told:?}"
            );
        } else {
            println!(
                "not exercised: the order of a host's first events: more than \
                 {STATE_FIRST_WITHIN:?} passed after the connection was offered"
            );
        }
        session.close();
        a_replacement_event_sent_before_adoption_reaches_the_page(app, runtime, window)?;
        a_replacement_event_waits_for_the_replacements_own_revision(app, runtime, window)?;
        a_publisher_delayed_past_the_bound_still_precedes_host_events(app, runtime, window)?;
        a_failed_state_emit_holds_host_events_until_replay(app, runtime, window)
    }

    /// A scripted worker, the link it answers on, and the connection the application would hold to
    /// it, reached as the application reaches a real worker.
    fn scripted_connection(
        runtime: &tokio::runtime::Runtime,
    ) -> Result<
        (
            ScriptedWorker,
            super::scripted_worker::Link,
            companion_tauri::connection::Connection,
        ),
        String,
    > {
        use companion_tauri::connection::{Connection, Standing};

        let mut worker = runtime.block_on(async { ScriptedWorker::start(Challenge::Answered) });
        let paths = worker.paths();
        let session_id = worker.session_id;
        let (session, link) = runtime.block_on(async {
            let reached = companion_tauri::worker::reach(&paths, session_id)
                .await
                .map_err(companion_tauri::worker::Unreached::words)?;
            let transport = kr_client::ipc::IpcTransport::over(reached.client);
            let session =
                kr_client::Session::start(transport.shared()).map_err(|error| error.to_string())?;
            let link = worker.link().await;
            Ok::<_, String>((session, link))
        })?;
        let host = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        Ok((
            worker,
            link,
            Connection::assembled(session, host, Standing::Owner, None, None),
        ))
    }

    /// What a replacement leg starts from: the keeper supervising a first connection whose state
    /// the page has heard.
    struct First {
        _worker: ScriptedWorker,
        _link: super::scripted_worker::Link,
        session: Arc<kr_client::Session>,
        owner: Arc<companion_tauri::contact::ContactOwner>,
    }

    fn reached_first(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        window: &WebviewWindow,
    ) -> Result<First, String> {
        use companion_tauri::connection::Attempt;

        let (worker, link, connection) = scripted_connection(runtime)?;
        let session = connection.session();
        let owner =
            Arc::clone(tauri::Manager::state::<companion_tauri::AppState>(app).contact_owner());
        let mut offered = Some(connection);
        companion_tauri::connection::reach_host_on_this_machine(app, move || {
            let next = offered.take();
            async move { next.map_or(Attempt::Nothing, Attempt::Reached) }
        })
        .map_err(|error| error.message)?;
        wait_for("the connection being held", || owner.held().is_some())?;
        let revision = owner.revision();
        if !runtime.block_on(owner.emitted_through(revision, LIVENESS)) {
            return Err("the publisher did not tell the first connection's state".to_owned());
        }
        wait_for("the page hearing the first connection's state", || {
            heard(window).iter().any(|each| {
                each.get("connection")
                    .is_some_and(|state| state["revision"].as_u64() == Some(revision))
            })
        })?;
        Ok(First {
            _worker: worker,
            _link: link,
            session,
            owner,
        })
    }

    /// The worker of a replacement, and the link it pushes events on.
    struct Second {
        _worker: ScriptedWorker,
        link: super::scripted_worker::Link,
    }

    /// A replacement of the first connection, as the replacer makes one: the second connection and
    /// the receiver of its events, taken before the owner holds it. The answer is the revision the
    /// replacement was published as.
    fn replaced(runtime: &tokio::runtime::Runtime, first: &First) -> Result<(u64, Second), String> {
        let (worker, link, connection) = scripted_connection(runtime)?;
        let events = connection.session().events();
        let applied = first.owner.replaced(&first.session, connection, events);
        if !applied.value {
            return Err("the owner did not take the replacement".to_owned());
        }
        let revision = applied.revision;
        drop(applied);
        Ok((
            revision,
            Second {
                _worker: worker,
                link,
            },
        ))
    }

    /// The host events the page heard after `before`, and the states beside them.
    fn heard_since(window: &WebviewWindow, before: usize) -> (Vec<Value>, Vec<Value>) {
        let all = heard(window)[before..].to_vec();
        let states = all
            .iter()
            .filter_map(|each| each.get("connection").cloned())
            .collect();
        let events = all
            .into_iter()
            .filter(|each| each.get("connection").is_none())
            .collect();
        (events, states)
    }

    /// KR-REQ-10.01: an event the replacement sends while the keeper has not yet taken it up is not
    /// lost: it is sent on once the keeper has, and names the revision the replacement was
    /// published as.
    fn a_replacement_event_sent_before_adoption_reaches_the_page(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        window: &WebviewWindow,
    ) -> Result<(), String> {
        let first = reached_first(app, runtime, window)?;
        let before = heard(window).len();
        let mut hold = first.owner.hold_adoption();
        let (revision, mut second) = replaced(runtime, &first)?;
        runtime.block_on(async {
            tokio::time::timeout(LIVENESS, hold.reached())
                .await
                .map_err(|_| "the keeper did not reach the hold before adoption".to_owned())
        })?;
        assert!(
            first.owner.adoption_pending(),
            "the replacement is not taken up while the keeper is held"
        );
        runtime.block_on(async {
            second
                .link
                .push(
                    "session.state",
                    &json!({ "state": "live", "cursor": 21, "changed": [] }),
                )
                .await;
        });
        hold.release();
        wait_for("the page hearing the replacement's event", || {
            heard_since(window, before)
                .0
                .iter()
                .any(|event| event["payload"]["cursor"] == json!(21))
        })?;
        let (events, _) = heard_since(window, before);
        let event = events
            .iter()
            .find(|event| event["payload"]["cursor"] == json!(21))
            .expect("the event");
        assert_eq!(
            event["revision"],
            json!(revision),
            "the event names the revision the replacement was published as: {events:?}"
        );
        Ok(())
    }

    /// Replaces the first connection while the publisher is held before it tells the replacement's
    /// state, with the keeper's wait for that state set to `within`, and has the replacement send one
    /// event. Returns the revision of the held state, the host events the page heard and the states
    /// it heard, while the state is still held, and a function that releases it.
    fn an_event_beside_a_held_state(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        window: &WebviewWindow,
        within: Duration,
        stay: Duration,
    ) -> Result<
        (
            First,
            Second,
            u64,
            usize,
            companion_tauri::contact::testing::Hold,
        ),
        String,
    > {
        let first = reached_first(app, runtime, window)?;
        first.owner.wait_for_the_state_at_most(within);
        let before = heard(window).len();
        let mut hold = first.owner.hold_the_publisher();
        let (revision, mut second) = replaced(runtime, &first)?;
        runtime.block_on(async {
            tokio::time::timeout(LIVENESS, hold.reached())
                .await
                .map_err(|_| "the publisher did not take the replacement's publication".to_owned())
        })?;
        let mut witness = first
            .owner
            .held()
            .expect("the replacement is held")
            .session()
            .events();
        runtime.block_on(async {
            second
                .link
                .push(
                    "session.state",
                    &json!({ "state": "live", "cursor": 33, "changed": [] }),
                )
                .await;
            tokio::time::timeout(LIVENESS, witness.recv())
                .await
                .map_err(|_| "the replacement's session did not receive the event".to_owned())?
                .map_err(|error| format!("the replacement's events ended: {error}"))?;
            Ok::<_, String>(())
        })?;
        std::thread::sleep(stay);
        Ok((first, second, revision, before, hold))
    }

    /// KR-REQ-10.01: while the replacement's state is held, the replacement's event waits for it,
    /// and then follows it, naming the replacement's own revision and not the first connection's.
    fn a_replacement_event_waits_for_the_replacements_own_revision(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        window: &WebviewWindow,
    ) -> Result<(), String> {
        let (first, second, revision, before, hold) =
            an_event_beside_a_held_state(app, runtime, window, LIVENESS, Duration::from_secs(1))?;
        let (events, states) = heard_since(window, before);
        assert!(
            events.is_empty(),
            "the page heard {events:?} before the replacement's state was told ({states:?})"
        );
        hold.release();
        wait_for("the page hearing the replacement's state and event", || {
            let (events, states) = heard_since(window, before);
            !events.is_empty()
                && states
                    .iter()
                    .any(|state| state["revision"].as_u64() == Some(revision))
        })?;
        let told = heard(window)[before..].to_vec();
        let at_state = told
            .iter()
            .position(|each| {
                each.get("connection")
                    .is_some_and(|state| state["revision"].as_u64() == Some(revision))
            })
            .expect("the state");
        let at_event = told
            .iter()
            .position(|each| each.get("connection").is_none())
            .expect("the event");
        assert!(at_state < at_event, "the state comes first: {told:?}");
        assert_eq!(told[at_event]["revision"], json!(revision), "{told:?}");
        drop((first, second));
        Ok(())
    }

    /// KR-REQ-10.01: a publisher that is later than the keeper's bound does not make the page hear
    /// the event as though it followed its state: the event names a revision the page has not
    /// heard, which the page holds it for, and the state is told when the publisher goes on.
    fn a_publisher_delayed_past_the_bound_still_precedes_host_events(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        window: &WebviewWindow,
    ) -> Result<(), String> {
        let (first, second, revision, before, hold) = an_event_beside_a_held_state(
            app,
            runtime,
            window,
            Duration::from_millis(200),
            Duration::from_secs(1),
        )?;
        wait_for("the page hearing the event the bound let go", || {
            !heard_since(window, before).0.is_empty()
        })?;
        let (events, states) = heard_since(window, before);
        assert!(
            states
                .iter()
                .all(|state| state["revision"].as_u64().unwrap_or(0) < revision),
            "the replacement's state was heard while it was held: {states:?}"
        );
        assert_eq!(events[0]["revision"], json!(revision), "{events:?}");
        hold.release();
        wait_for("the page hearing the delayed state", || {
            heard_since(window, before)
                .1
                .iter()
                .any(|state| state["revision"].as_u64() == Some(revision))
        })?;
        drop((first, second));
        Ok(())
    }

    /// KR-REQ-10.01: when the emit of the replacement's state fails, the host's events name a
    /// revision the page never hears told, and the owner's replay holds it.
    fn a_failed_state_emit_holds_host_events_until_replay(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        window: &WebviewWindow,
    ) -> Result<(), String> {
        let first = reached_first(app, runtime, window)?;
        let before_revision = first.owner.revision();
        let before = heard(window).len();
        first.owner.lose_the_next_emit();
        let (revision, mut second) = replaced(runtime, &first)?;
        runtime.block_on(async {
            second
                .link
                .push(
                    "session.state",
                    &json!({ "state": "live", "cursor": 44, "changed": [] }),
                )
                .await;
        });
        wait_for("the page hearing the event of the replacement", || {
            !heard_since(window, before).0.is_empty()
        })?;
        std::thread::sleep(Duration::from_secs(1));
        let (events, states) = heard_since(window, before);
        assert_eq!(events[0]["revision"], json!(revision), "{events:?}");
        assert!(
            states
                .iter()
                .all(|state| state["revision"].as_u64() != Some(revision)),
            "the state whose emit failed was heard: {states:?}"
        );
        let replay = first.owner.since(before_revision);
        assert!(!replay.resync, "the replay is not a resync");
        assert!(
            replay
                .states
                .iter()
                .any(|state| state.revision == revision && state.replaced > 0),
            "the replay holds the state the page missed"
        );
        Ok(())
    }
}
