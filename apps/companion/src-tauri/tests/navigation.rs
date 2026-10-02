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
//! * A page that loads again: two pages each hold a raw terminal view of a session a scripted
//!   worker serves. Reloading one ends that page's view, which detaches and closes its link, and
//!   leaves the other page's view open: the application's own page-load rule, installed by the same
//!   function the application's start uses, run by the web view's own load.
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
mod scripted_worker;

#[cfg(target_os = "macos")]
mod macos {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tauri::webview::NewWindowResponse;
    use tauri::{AppHandle, Manager as _, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    use super::scripted_worker::{Challenge, ScriptedWorker};

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
        // The scripted workers answer on a runtime of the check's own: the application's own
        // runtime is where the views run.
        let runtime = Arc::new(tokio::runtime::Runtime::new().expect("a runtime for the workers"));
        let (first, second) = runtime.block_on(async {
            let first = ScriptedWorker::start(Challenge::Answered);
            let second = ScriptedWorker::start_beside(&first, Challenge::Answered);
            (first, second)
        });
        let workers = Arc::new(Mutex::new(Some((first, second))));
        // A test context: the library already embeds the application's Info.plist, and a second
        // copy is a duplicate symbol.
        let paths = workers
            .lock()
            .expect("the workers")
            .as_ref()
            .map(|(first, _)| first.paths())
            .expect("the first worker");
        let app = companion_tauri::terminal::install(
            tauri::Builder::default(),
            companion_tauri::terminal::TerminalViews::at(paths),
        )
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
                let runtime = Arc::clone(&runtime);
                let workers = workers.lock().expect("the workers").take();
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || {
                    // A failed expectation inside a scripted worker panics this thread; it is
                    // a failed check like any other, and must not leave the window loop running.
                    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        resending()
                            .and_then(|()| check(&handle, &messages))
                            .and_then(|()| {
                                let (first, second) = workers.expect("the workers, once");
                                page_load(&handle, &runtime, first, second)
                            })
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

    /// How long the check waits for something the web view does, before it calls the thing never
    /// done. What it waits for is the web view's own work: a page that loads, a navigation that
    /// reaches its handler, a window that opens. On a machine with every core busy that takes as long
    /// as the machine takes, and the wait ends the moment the thing is done, so the bound only says
    /// that it will not be.
    const LIVENESS: Duration = Duration::from_secs(120);

    fn wait_for(what: &str, done: impl Fn() -> bool) -> Result<(), String> {
        let started = Instant::now();
        while !done() {
            if started.elapsed() > LIVENESS {
                return Err(format!("{what} did not happen within {LIVENESS:?}"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Sends a script to a page and waits for what it does, sending it again each time the page has
    /// loaded again since it was sent. Returns how many times it was sent.
    ///
    /// A script waits in the web view's content process until the page runs it, and it is lost with
    /// that process. The system ends the process when the graphics process it depends on stops
    /// answering, which a machine with every core busy brings about, and the application then loads
    /// the page again: a script sent once is never run, and nothing says so. A page that loads again
    /// is a condition the check can see, since `loads` moves, so a script is sent again when it does
    /// and the wait is for what the script does, bounded by `limit` whatever the page does: one that
    /// never runs the script, and one that keeps loading again.
    fn send_until(
        what: &str,
        limit: Duration,
        loads: &Loads,
        mut send: impl FnMut() -> Result<(), String>,
        done: impl Fn() -> bool,
    ) -> Result<usize, String> {
        let started = Instant::now();
        let mut sent = 0;
        loop {
            let seen = loads.load(std::sync::atomic::Ordering::SeqCst);
            send()?;
            sent += 1;
            loop {
                if done() {
                    return Ok(sent);
                }
                if started.elapsed() > limit {
                    return Err(format!(
                        "{what} did not happen within {limit:?}, after {sent} sendings"
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
                if loads.load(std::sync::atomic::Ordering::SeqCst) != seen {
                    break;
                }
            }
        }
    }

    /// Sends a window's page a script and waits for what it does, within the liveness bound.
    fn send_script(
        what: &str,
        window: &WebviewWindow,
        loads: &Loads,
        script: &str,
        done: impl Fn() -> bool,
    ) -> Result<usize, String> {
        send_until(
            what,
            LIVENESS,
            loads,
            || window.eval(script).map_err(|error| error.to_string()),
            done,
        )
    }

    /// The resend rule held to itself, without a web view: a script lost with the page that held it
    /// is sent again, one that ran is not, and a page that stays and never runs it is given up on
    /// at the limit with no second sending.
    fn resending() -> Result<(), String> {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

        let loads = Loads::default();
        let sends = AtomicUsize::new(0);
        let ran = AtomicUsize::new(0);
        let sent = send_until(
            "a script lost with its page",
            Duration::from_secs(30),
            &loads,
            || {
                if sends.fetch_add(1, SeqCst) == 0 {
                    // The page is lost with the script and loaded again.
                    loads.fetch_add(1, SeqCst);
                } else {
                    ran.fetch_add(1, SeqCst);
                }
                Ok(())
            },
            || ran.load(SeqCst) > 0,
        )?;
        if sent != 2 {
            return Err(format!("a script lost with its page was sent {sent} times"));
        }

        let sends = AtomicUsize::new(0);
        let ran = AtomicUsize::new(0);
        let sent = send_until(
            "a script that ran",
            Duration::from_secs(30),
            &loads,
            || {
                sends.fetch_add(1, SeqCst);
                ran.fetch_add(1, SeqCst);
                Ok(())
            },
            || ran.load(SeqCst) > 0,
        )?;
        if sent != 1 {
            return Err(format!("a script that ran was sent {sent} times"));
        }

        let sends = AtomicUsize::new(0);
        let never = send_until(
            "a script that does nothing",
            Duration::from_millis(300),
            &loads,
            || {
                sends.fetch_add(1, SeqCst);
                Ok(())
            },
            || false,
        );
        if never.is_ok() || sends.load(SeqCst) != 1 {
            return Err(format!(
                "a page that never ran the script was given up on after {} sendings: {never:?}",
                sends.load(SeqCst)
            ));
        }

        // A page that loads again after every sending, and never runs the script, is given up on at
        // the limit too: the wait ends, which a page that never stops loading would otherwise prevent.
        let sends = AtomicUsize::new(0);
        let churning = send_until(
            "a script on a page that keeps loading again",
            Duration::from_millis(400),
            &loads,
            || {
                sends.fetch_add(1, SeqCst);
                loads.fetch_add(1, SeqCst);
                Ok(())
            },
            || false,
        );
        if churning.is_ok() {
            return Err(format!(
                "a page that kept loading again was not given up on after {} sendings",
                sends.load(SeqCst)
            ));
        }

        // A refusal is reported as often as the script was sent at most, and at least once: a
        // second sending whose report arrives late is one more refusal, and one more than the
        // sendings is a window that was not meant to refuse.
        for (reported, sent, held) in [
            (0, 1, false),
            (1, 1, true),
            (2, 1, false),
            (1, 2, true),
            (2, 2, true),
            (3, 2, false),
        ] {
            if reported_for(reported, sent) != held {
                return Err(format!(
                    "{reported} refusals for {sent} sendings were taken as {}",
                    !held
                ));
            }
        }
        Ok(())
    }

    fn address(window: &WebviewWindow) -> String {
        window.url().map(|url| url.to_string()).unwrap_or_default()
    }

    fn bundled(window: &WebviewWindow) -> bool {
        address(window).starts_with("tauri://localhost")
    }

    /// The page loads that have finished in a window.
    type Loads = Arc<std::sync::atomic::AtomicUsize>;

    /// Opens a window on the bundle and waits until its page has loaded: a script sent to a window
    /// before then is sent to a page that is about to be replaced, and the window already reports
    /// the bundle's address while its page has not begun to load.
    fn open(app: &AppHandle, label: &str, guarded: bool) -> Result<(WebviewWindow, Loads), String> {
        let loads = Loads::default();
        let counting = Arc::clone(&loads);
        let builder = WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into()))
            .title(label)
            .inner_size(320.0, 240.0)
            .on_page_load(move |_window, payload| {
                if payload.event() == tauri::webview::PageLoadEvent::Finished {
                    counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
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
        wait_for(&format!("{label}'s page loading"), || {
            loads.load(std::sync::atomic::Ordering::SeqCst) >= 1 && bundled(&window)
        })?;
        Ok((window, loads))
    }

    /// What a failed wait for a refusal says besides what it waited for: how often the refusal was
    /// reported, where the window is, and how many loads have finished in it, which tell a refusal
    /// that never came from one reported twice, and from a page that never loaded.
    fn refusal_failure(
        failure: &str,
        messages: &Messages,
        refused: &str,
        window: &WebviewWindow,
        loads: &Loads,
    ) -> String {
        format!(
            "{failure}; it was reported {} times, the window is at {}, and {} page loads finished",
            messages.count(refused),
            address(window),
            loads.load(std::sync::atomic::Ordering::SeqCst)
        )
    }

    /// Whether a refusal was reported as often as a script that could have caused it was sent: at
    /// least once, and no more often than it was sent, which is once unless its page loaded again.
    fn reported_for(reported: usize, sent: usize) -> bool {
        (1..=sent).contains(&reported)
    }

    fn check(app: &AppHandle, messages: &Messages) -> Result<(), String> {
        // Navigation, with the production handler: the handler refuses it and the window stays on
        // the bundled interface.
        let (guarded, loads) = open(app, "guarded", true)?;
        let navigations = send_script(
            "the production handler refusing the navigation",
            &guarded,
            &loads,
            &format!("location.assign('{WEBSITE}')"),
            || messages.count(NAVIGATION_REFUSED) >= 1,
        )
        .map_err(|failure| {
            refusal_failure(&failure, messages, NAVIGATION_REFUSED, &guarded, &loads)
        })?;
        std::thread::sleep(Duration::from_secs(2));
        if !reported_for(messages.count(NAVIGATION_REFUSED), navigations) {
            return Err(refusal_failure(
                &format!(
                    "the navigation, sent {navigations} times, was not reported once at least and as often at most"
                ),
                messages,
                NAVIGATION_REFUSED,
                &guarded,
                &loads,
            ));
        }
        if !bundled(&guarded) {
            return Err(format!(
                "the guarded window left the bundle for {}",
                address(&guarded)
            ));
        }

        // Popups, with the production handler: it is asked and refuses, and no second web view
        // exists.
        let popups = send_script(
            "the production handler refusing the popup",
            &guarded,
            &loads,
            &format!("window.open('{WEBSITE}')"),
            || messages.count(WINDOW_REFUSED) >= 1,
        )
        .map_err(|failure| refusal_failure(&failure, messages, WINDOW_REFUSED, &guarded, &loads))?;
        std::thread::sleep(Duration::from_secs(2));
        if !reported_for(messages.count(WINDOW_REFUSED), popups) {
            return Err(refusal_failure(
                &format!(
                    "the popup, asked for {popups} times, was not reported once at least and as often at most"
                ),
                messages,
                WINDOW_REFUSED,
                &guarded,
                &loads,
            ));
        }
        let held = app.webview_windows().len();
        if held != 1 {
            return Err(format!("the guarded window's popup made {held} web views"));
        }
        if !bundled(&guarded) {
            return Err("the guarded window's popup navigated it".to_owned());
        }

        // The controls: without the handlers the same page leaves, and a permissive handler
        // creates the popup, so the two checks above are checks of the handlers.
        let (control, control_loads) = open(app, "control", false)?;
        send_script(
            "the control's popup",
            &control,
            &control_loads,
            &format!("window.open('{WEBSITE}')"),
            || app.webview_windows().len() >= 3,
        )?;
        send_script(
            "the control leaving the bundle",
            &control,
            &control_loads,
            &format!("location.assign('{WEBSITE}')"),
            || address(&control).starts_with(WEBSITE),
        )?;
        // The control's windows have no production handler, so nothing more was refused: no more
        // refusals than the guarded window's scripts were sent, which is exactly one each unless
        // a page loaded again, and then a late report of a script sent twice is one of them.
        if !reported_for(messages.count(NAVIGATION_REFUSED), navigations)
            || !reported_for(messages.count(WINDOW_REFUSED), popups)
        {
            return Err("a window without the production handlers reported a refusal".to_owned());
        }
        Ok(())
    }

    /// The page-load check: two pages each hold a view, and reloading one ends only its own.
    fn page_load(
        app: &AppHandle,
        runtime: &tokio::runtime::Runtime,
        mut first: ScriptedWorker,
        mut second: ScriptedWorker,
    ) -> Result<(), String> {
        use companion_tauri::terminal::{TerminalViewState, TerminalViews};

        // Each page's first load has finished before a view is opened on it, which `open` waits
        // for, so the load that ends a view here is the reload and nothing earlier.
        let (one, one_loads) = open(app, "view-one", true)?;
        let (_two, _) = open(app, "view-two", true)?;
        let heard: Arc<Mutex<Vec<(u8, TerminalViewState)>>> = Arc::default();
        let publish = |page: u8| -> companion_tauri::terminal::Publish {
            let heard = Arc::clone(&heard);
            Arc::new(move |state| {
                heard.lock().expect("the record").push((page, state));
            })
        };
        let views = app.state::<TerminalViews>();
        views.open(
            "view-one",
            first.session_id,
            kr_protocol::session::Dimensions::new(10, 2),
            publish(1),
        );
        views.open(
            "view-two",
            second.session_id,
            kr_protocol::session::Dimensions::new(10, 2),
            publish(2),
        );
        let (mut one_link, mut two_link) = runtime.block_on(async {
            let mut one_link = first.link().await;
            one_link.attach().await;
            let mut two_link = second.link().await;
            two_link.attach().await;
            (one_link, two_link)
        });
        wait_for("both views attached", || {
            heard.lock().expect("the record").len() == 2
        })?;
        if views.held() != 2 {
            return Err(format!("{} views held, not two", views.held()));
        }

        send_script(
            "the first page's view ending with its page",
            &one,
            &one_loads,
            "location.reload()",
            || views.held() == 1,
        )?;
        let sent = runtime.block_on(async { one_link.closed().await });
        if sent.len() != 1
            || sent[0].method != kr_protocol::method::Method::SessionDetach.to_string()
        {
            return Err(format!(
                "the reloaded page's view sent {sent:?} rather than its detach"
            ));
        }
        let quiet = runtime.block_on(async { two_link.quiet_for(Duration::from_secs(1)).await });
        if !quiet {
            return Err("the other page's view was sent something".to_owned());
        }
        if heard.lock().expect("the record").len() != 2 {
            return Err("a view published after its page loaded again".to_owned());
        }
        Ok(())
    }
}
