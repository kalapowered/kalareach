//! What carries one sign-in's ceremony to the browser and its answer back.
//!
//! On a desktop, the default browser opens the address and the answer comes back to the loopback
//! listener, which can take more than one request: a stray one is set aside and the wait goes on.
//! On a phone, the platform plugin's browser-backed session carries it and returns one result, or
//! a Custom Tab whose answer arrives as a verified link. Whichever carries it, each answer goes
//! through the attempt's checks, and the attempt ends with one [`Ending`].
//!
//! The phone's conversation with its session is [`converse`], over [`SessionEvents`], so the same
//! code runs against the platform plugin on a phone and against a script in a test.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use companion_platform::browser::{self, RawEvent, SessionEvent, SessionRequest};
use kr_client::services::account::{Answer, Carrier as Delivery, PendingAuthorisation, Redirect};
use tokio::sync::watch;

use super::loopback::{BindError, Callback, Listener};

/// A boxed future, so carriers stay usable behind a trait object.
pub type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How long a sign-in waits for the person before it stops.
pub const WAIT: Duration = Duration::from_secs(15 * 60);

/// How long a closed Custom Tab waits for the link that closed it.
///
/// A browser that hands the answer over as a verified link brings the application to the front,
/// and the system closes the tab on the way: the closed tab and the link reach the application
/// in either order, a moment apart. A link inside this window is the answer; without one, the tab
/// closed with nothing, which is a cancel or a browser that kept the answer.
pub const LINK_GRACE: Duration = Duration::from_secs(2);

/// Why this device cannot carry a sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// No browser here can return the answer to the application.
    NoReturningBrowser,
    /// The link is verified, but opening supported links is turned off for the application.
    LinkHandlingOff,
}

/// How one attempt will be carried.
#[derive(Clone, Debug)]
pub struct Plan {
    /// The redirect its answer comes back on.
    pub redirect: Redirect,
    #[cfg(mobile)]
    mode: companion_platform::browser::Mode,
}

/// How the carrying ended.
#[derive(Debug)]
pub enum Ending {
    /// An answer passed the address, repetition and state checks, or ended the attempt.
    Answered {
        /// What the checks made of it.
        answer: Answer,
        /// The browser's connection, on a desktop, for the page that says how it ended.
        reply: Option<Callback>,
    },
    /// The person, or the application, ended the ceremony.
    Cancelled,
    /// A Custom Tab closed without an answer.
    TabClosed,
    /// The system would not return the answer to this application.
    CouldNotReturn,
    /// Another program holds the loopback address.
    PortBusy,
    /// Nothing came back in time.
    TimedOut,
    /// The browser could not be opened.
    BrowserFailed,
}

/// Opens an address in the system's browser.
pub trait Browser: Send + Sync {
    /// Opens `url`.
    ///
    /// # Errors
    ///
    /// Returns why the browser could not be opened.
    fn open(&self, url: &str) -> Result<(), String>;
}

/// The default browser, through the opener's Rust API.
pub struct SystemBrowser<R: tauri::Runtime>(pub tauri::AppHandle<R>);

impl<R: tauri::Runtime> Browser for SystemBrowser<R> {
    fn open(&self, url: &str) -> Result<(), String> {
        tauri_plugin_opener::OpenerExt::opener(&self.0)
            .open_url(url, None::<&str>)
            .map_err(|error| error.to_string())
    }
}

/// What carries a sign-in on this device.
pub trait Carrier: Send + Sync {
    /// How an attempt would be carried now, or why it cannot be.
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>>;

    /// Opens the ceremony at `url` and waits for the attempt's answer, or for `cancel`.
    fn carry<'a>(
        &'a self,
        plan: &'a Plan,
        url: String,
        pending: &'a mut PendingAuthorisation,
        cancel: watch::Receiver<bool>,
    ) -> Boxed<'a, Ending>;
}

/// Waits until `cancel` says so.
async fn cancelled(mut cancel: watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// The desktop's carrier: the default browser, and the loopback listener.
pub struct Loopback {
    browser: Arc<dyn Browser>,
    listen: Box<dyn Fn() -> Result<Listener, BindError> + Send + Sync>,
    wait: Duration,
}

impl Loopback {
    /// The registered address, and `browser`.
    #[must_use]
    pub fn new(browser: Arc<dyn Browser>) -> Self {
        Self {
            browser,
            listen: Box::new(Listener::open),
            wait: WAIT,
        }
    }

    /// Another listener and wait, for a test.
    #[must_use]
    pub fn with_listener(
        browser: Arc<dyn Browser>,
        listen: impl Fn() -> Result<Listener, BindError> + Send + Sync + 'static,
        wait: Duration,
    ) -> Self {
        Self {
            browser,
            listen: Box::new(listen),
            wait,
        }
    }
}

impl Carrier for Loopback {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async {
            Ok(Plan {
                redirect: Redirect::Loopback,
                #[cfg(mobile)]
                mode: companion_platform::browser::Mode::CustomTab,
            })
        })
    }

    fn carry<'a>(
        &'a self,
        _plan: &'a Plan,
        url: String,
        pending: &'a mut PendingAuthorisation,
        cancel: watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async move {
            if *cancel.borrow() {
                return Ending::Cancelled;
            }
            // Bound before the browser opens, so the answer never arrives before the listener.
            let listener = match (self.listen)() {
                Ok(listener) => listener,
                Err(BindError::Busy) => return Ending::PortBusy,
                Err(BindError::Failed(error)) => {
                    tracing::warn!(%error, "the sign-in's loopback address could not be opened");
                    return Ending::PortBusy;
                }
            };
            if let Err(error) = self.browser.open(&url) {
                tracing::warn!(%error, "the browser could not be opened for a sign-in");
                return Ending::BrowserFailed;
            }
            let waiting = async {
                loop {
                    let callback = listener.next().await;
                    match pending.answer(&callback.url, Delivery::Continuing) {
                        Answer::Dropped(fault) => {
                            tracing::info!(
                                ?fault,
                                "a request to the loopback address was set aside"
                            );
                            callback.set_aside().await;
                        }
                        answer => {
                            return Ending::Answered {
                                answer,
                                reply: Some(callback),
                            };
                        }
                    }
                }
            };
            tokio::select! {
                ending = waiting => ending,
                () = cancelled(cancel) => Ending::Cancelled,
                () = tokio::time::sleep(self.wait) => Ending::TimedOut,
            }
        })
    }
}

/// A phone's browser session, as the carrier talks to it: the platform plugin's native half, or a
/// script in a test.
pub trait SessionEvents: Send + Sync {
    /// Opens the ceremony and waits for its first result.
    fn start<'a>(&'a self, request: &'a SessionRequest) -> Boxed<'a, Result<RawEvent, String>>;

    /// Waits for the attempt's next result.
    fn next<'a>(&'a self, attempt: &'a str) -> Boxed<'a, Result<RawEvent, String>>;

    /// Ends the attempt: the sheet or tab is dismissed where it can be, and the native half keeps
    /// nothing of it.
    fn cancel<'a>(&'a self, attempt: &'a str) -> Boxed<'a, ()>;
}

/// Carries one phone attempt through `events` until it ends.
///
/// A result for another attempt is a late one and is skipped. An answer goes through the attempt's
/// checks; on a Custom Tab, one the checks set aside leaves the wait going, and on a terminal
/// session any result ends the attempt. A closed Custom Tab waits `grace` for the link that closed
/// it. The person's cancel and the `wait` end it too. However it ends, the native half is told, so
/// it holds nothing of the attempt afterwards.
pub async fn converse(
    events: &dyn SessionEvents,
    request: &SessionRequest,
    pending: &mut PendingAuthorisation,
    cancel: watch::Receiver<bool>,
    wait: Duration,
    grace: Duration,
) -> Ending {
    let attempt = request.attempt.as_str();
    let delivery = if request.mode.is_terminal() {
        Delivery::Terminal
    } else {
        Delivery::Continuing
    };
    let conversation = async {
        let mut closed = false;
        let mut next = events.start(request).await;
        loop {
            let raw = match next {
                Ok(raw) => raw,
                Err(_) if closed => return Ending::TabClosed,
                Err(error) => {
                    tracing::warn!(%error, "the browser session could not be started");
                    return Ending::BrowserFailed;
                }
            };
            if raw.attempt == attempt {
                match browser::event(&raw) {
                    SessionEvent::Answer(url) => match pending.answer(&url, delivery) {
                        Answer::Dropped(fault) => {
                            tracing::info!(?fault, "a link was set aside");
                        }
                        answer => {
                            return Ending::Answered {
                                answer,
                                reply: None,
                            };
                        }
                    },
                    SessionEvent::TabClosed => closed = true,
                    SessionEvent::Cancelled => return Ending::Cancelled,
                    SessionEvent::CouldNotReturn => return Ending::CouldNotReturn,
                    SessionEvent::Failed => return Ending::BrowserFailed,
                }
                if delivery == Delivery::Terminal {
                    return Ending::CouldNotReturn;
                }
            }
            next = if closed {
                match tokio::time::timeout(grace, events.next(attempt)).await {
                    Ok(next) => next,
                    Err(_) => return Ending::TabClosed,
                }
            } else {
                events.next(attempt).await
            };
        }
    };
    let ending = tokio::select! {
        ending = conversation => ending,
        () = cancelled(cancel) => Ending::Cancelled,
        () = tokio::time::sleep(wait) => Ending::TimedOut,
    };
    events.cancel(attempt).await;
    ending
}

/// The phone's carrier: the platform plugin's browser-backed session.
#[cfg(mobile)]
pub struct Session<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

#[cfg(mobile)]
impl<R: tauri::Runtime> Session<R> {
    /// The session the platform plugin carries.
    #[must_use]
    pub const fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }

    fn platform(&self) -> tauri::State<'_, companion_platform::Platform<R>> {
        use tauri::Manager as _;
        self.app.state::<companion_platform::Platform<R>>()
    }
}

#[cfg(mobile)]
impl<R: tauri::Runtime> SessionEvents for Session<R> {
    fn start<'a>(&'a self, request: &'a SessionRequest) -> Boxed<'a, Result<RawEvent, String>> {
        Box::pin(async move {
            self.platform()
                .authenticate(request)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn next<'a>(&'a self, attempt: &'a str) -> Boxed<'a, Result<RawEvent, String>> {
        Box::pin(async move {
            self.platform()
                .next_event(attempt)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn cancel<'a>(&'a self, attempt: &'a str) -> Boxed<'a, ()> {
        Box::pin(async move {
            if let Err(error) = self.platform().cancel(attempt).await {
                tracing::warn!(%error, "the browser session could not be ended");
            }
        })
    }
}

#[cfg(mobile)]
impl<R: tauri::Runtime> Carrier for Session<R> {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async move {
            use companion_platform::browser::Mode;
            let facts = self
                .platform()
                .capabilities()
                .await
                .map_err(|_| Unavailable::NoReturningBrowser)?;
            let mode = if cfg!(target_os = "ios") {
                browser::mode(facts.https_callback == Some(true))
            } else {
                browser::android_availability(&facts).map_err(|reason| match reason {
                    browser::Unavailable::NoReturningBrowser => Unavailable::NoReturningBrowser,
                    browser::Unavailable::LinkHandlingOff => Unavailable::LinkHandlingOff,
                })?
            };
            let redirect = if mode == Mode::SessionScheme {
                Redirect::PrivateUse
            } else {
                Redirect::AppLink
            };
            Ok(Plan { redirect, mode })
        })
    }

    fn carry<'a>(
        &'a self,
        plan: &'a Plan,
        url: String,
        pending: &'a mut PendingAuthorisation,
        cancel: watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async move {
            let Some(attempt) = pending.attempt() else {
                return Ending::Cancelled;
            };
            if *cancel.borrow() {
                return Ending::Cancelled;
            }
            let request = SessionRequest {
                attempt: attempt.value().to_string(),
                url,
                mode: plan.mode,
                https_host: "reach.kala.to".to_owned(),
                https_path: "/app/oauth/callback".to_owned(),
                scheme: "to.kala.reach".to_owned(),
            };
            converse(self, &request, pending, cancel, WAIT, LINK_GRACE).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use companion_platform::browser::Mode;
    use kr_client::services::account::{AuthorisationRequest, Client, ISSUER};

    use super::*;

    /// A session that answers from a script: each step is a result after a pause, and once the
    /// script is spent it waits for ever.
    struct Script {
        steps: Mutex<VecDeque<(Duration, RawEvent)>>,
        ended: Mutex<Vec<String>>,
    }

    impl Script {
        fn new(steps: Vec<(Duration, RawEvent)>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
                ended: Mutex::new(Vec::new()),
            }
        }

        fn take(&self) -> Boxed<'_, Result<RawEvent, String>> {
            let step = self.steps.lock().expect("the script").pop_front();
            Box::pin(async move {
                match step {
                    Some((after, raw)) => {
                        tokio::time::sleep(after).await;
                        Ok(raw)
                    }
                    None => std::future::pending().await,
                }
            })
        }

        fn ended(&self) -> Vec<String> {
            self.ended.lock().expect("the record").clone()
        }
    }

    impl SessionEvents for Script {
        fn start<'a>(
            &'a self,
            _request: &'a SessionRequest,
        ) -> Boxed<'a, Result<RawEvent, String>> {
            self.take()
        }

        fn next<'a>(&'a self, _attempt: &'a str) -> Boxed<'a, Result<RawEvent, String>> {
            self.take()
        }

        fn cancel<'a>(&'a self, attempt: &'a str) -> Boxed<'a, ()> {
            self.ended
                .lock()
                .expect("the record")
                .push(attempt.to_owned());
            Box::pin(async {})
        }
    }

    /// One phone attempt on the app link: what is pending, what the native half is asked, and the
    /// state a right answer carries.
    fn attempt(mode: Mode) -> (PendingAuthorisation, SessionRequest, String) {
        let request =
            AuthorisationRequest::new(Client::Mobile, Redirect::AppLink).expect("a request");
        let url = request.url();
        let state = tauri::Url::parse(&url)
            .expect("an address")
            .query_pairs()
            .find(|(name, _)| name == "state")
            .map(|(_, value)| value.into_owned())
            .expect("a state");
        let pending = PendingAuthorisation::new(request);
        let id = pending.attempt().expect("an attempt").value().to_string();
        let request = SessionRequest {
            attempt: id,
            url,
            mode,
            https_host: "reach.kala.to".to_owned(),
            https_path: "/app/oauth/callback".to_owned(),
            scheme: "to.kala.reach".to_owned(),
        };
        (pending, request, state)
    }

    fn answer(attempt: &str, kind: &str, state: &str) -> RawEvent {
        let mut url = tauri::Url::parse("https://reach.kala.to/app/oauth/callback").expect("url");
        url.query_pairs_mut()
            .append_pair("code", "c0de")
            .append_pair("state", state)
            .append_pair("iss", ISSUER);
        RawEvent {
            attempt: attempt.to_owned(),
            kind: kind.to_owned(),
            url: Some(url.to_string()),
            code: (kind == "result").then_some(-1),
            ..RawEvent::default()
        }
    }

    fn report(attempt: &str, kind: &str, code: Option<i64>) -> RawEvent {
        RawEvent {
            attempt: attempt.to_owned(),
            kind: kind.to_owned(),
            code,
            ..RawEvent::default()
        }
    }

    /// Nobody cancels: the sender is gone, so the wait for a cancel never ends.
    fn nobody_cancels() -> watch::Receiver<bool> {
        watch::channel(false).1
    }

    fn granted(ending: &Ending) -> bool {
        matches!(
            ending,
            Ending::Answered {
                answer: Answer::Granted(_),
                ..
            }
        )
    }

    /// The emulator showed this order: Firefox handed the verified link over, the application came
    /// to the front, and the closed tab was reported first. The link is still the answer.
    #[tokio::test(start_paused = true)]
    async fn a_link_that_follows_the_closed_tab_is_the_answer() {
        for (grace, expect_granted) in [(LINK_GRACE, true), (Duration::from_millis(100), false)] {
            let (mut pending, request, state) = attempt(Mode::CustomTab);
            let script = Script::new(vec![
                (Duration::ZERO, report(&request.attempt, "closed", Some(0))),
                (
                    Duration::from_millis(500),
                    answer(&request.attempt, "link", &state),
                ),
            ]);
            let ending = converse(
                &script,
                &request,
                &mut pending,
                nobody_cancels(),
                WAIT,
                grace,
            )
            .await;
            // The control: a window shorter than the link's lateness ends the attempt as closed.
            assert_eq!(granted(&ending), expect_granted, "{grace:?}: {ending:?}");
            if !expect_granted {
                assert!(matches!(ending, Ending::TabClosed), "{ending:?}");
            }
            assert_eq!(script.ended(), std::slice::from_ref(&request.attempt));
        }
    }

    /// A tab closed with no link after it is a cancel, or a browser that kept the answer.
    #[tokio::test(start_paused = true)]
    async fn a_closed_tab_with_no_link_after_it_ends_as_closed() {
        let (mut pending, request, _) = attempt(Mode::CustomTab);
        let script = Script::new(vec![(
            Duration::ZERO,
            report(&request.attempt, "closed", Some(0)),
        )]);
        let ending = converse(
            &script,
            &request,
            &mut pending,
            nobody_cancels(),
            WAIT,
            LINK_GRACE,
        )
        .await;
        assert!(matches!(ending, Ending::TabClosed), "{ending:?}");
        assert_eq!(script.ended(), std::slice::from_ref(&request.attempt));
    }

    /// On a Custom Tab a link with another state is set aside and the wait goes on.
    #[tokio::test(start_paused = true)]
    async fn a_link_for_another_state_is_set_aside_and_the_right_one_answers() {
        let (mut pending, request, state) = attempt(Mode::CustomTab);
        let script = Script::new(vec![
            (Duration::ZERO, answer(&request.attempt, "link", "another")),
            (Duration::ZERO, answer(&request.attempt, "link", &state)),
        ]);
        let ending = converse(
            &script,
            &request,
            &mut pending,
            nobody_cancels(),
            WAIT,
            LINK_GRACE,
        )
        .await;
        assert!(granted(&ending), "{ending:?}");
    }

    /// A late result of an earlier attempt is skipped; the Auth Tab's own result answers.
    #[tokio::test(start_paused = true)]
    async fn a_late_result_of_an_earlier_attempt_is_not_this_ones() {
        let (mut pending, request, state) = attempt(Mode::AuthTab);
        let script = Script::new(vec![
            (Duration::ZERO, report("1", "result", Some(0))),
            (Duration::ZERO, answer(&request.attempt, "result", &state)),
        ]);
        let ending = converse(
            &script,
            &request,
            &mut pending,
            nobody_cancels(),
            WAIT,
            LINK_GRACE,
        )
        .await;
        assert!(granted(&ending), "{ending:?}");
    }

    /// On a terminal session a result that is not the answer ends the attempt: a failed
    /// verification says the system would not return it, and a wrong state is not waited past.
    #[tokio::test(start_paused = true)]
    async fn a_terminal_session_ends_on_its_one_result() {
        let (mut pending, request, _) = attempt(Mode::AuthTab);
        let script = Script::new(vec![(
            Duration::ZERO,
            report(&request.attempt, "result", Some(2)),
        )]);
        let ending = converse(
            &script,
            &request,
            &mut pending,
            nobody_cancels(),
            WAIT,
            LINK_GRACE,
        )
        .await;
        assert!(matches!(ending, Ending::CouldNotReturn), "{ending:?}");

        let (mut pending, request, _) = attempt(Mode::SessionHttps);
        let script = Script::new(vec![(
            Duration::ZERO,
            answer(&request.attempt, "redirected", "another"),
        )]);
        let ending = converse(
            &script,
            &request,
            &mut pending,
            nobody_cancels(),
            WAIT,
            LINK_GRACE,
        )
        .await;
        assert!(
            matches!(
                ending,
                Ending::Answered {
                    answer: Answer::Failed(_),
                    ..
                }
            ),
            "{ending:?}"
        );
    }

    /// The person's cancel, and the long wait, end the attempt and tell the native half.
    #[tokio::test(start_paused = true)]
    async fn a_cancel_or_the_long_wait_ends_the_attempt_and_the_native_half_is_told() {
        let (mut pending, request, _) = attempt(Mode::CustomTab);
        let script = Script::new(Vec::new());
        let (cancel, cancelled) = watch::channel(false);
        let press = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            cancel.send(true).expect("the attempt listens");
        };
        let (ending, ()) = tokio::join!(
            converse(&script, &request, &mut pending, cancelled, WAIT, LINK_GRACE),
            press
        );
        assert!(matches!(ending, Ending::Cancelled), "{ending:?}");
        assert_eq!(script.ended(), std::slice::from_ref(&request.attempt));

        let (mut pending, request, _) = attempt(Mode::SessionHttps);
        let script = Script::new(Vec::new());
        let ending = converse(
            &script,
            &request,
            &mut pending,
            nobody_cancels(),
            WAIT,
            LINK_GRACE,
        )
        .await;
        assert!(matches!(ending, Ending::TimedOut), "{ending:?}");
        assert_eq!(script.ended(), std::slice::from_ref(&request.attempt));
    }
}
