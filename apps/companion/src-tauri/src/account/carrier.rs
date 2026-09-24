//! What carries one sign-in's ceremony to the browser and its answer back.
//!
//! On a desktop, the default browser opens the address and the answer comes back to the loopback
//! listener, which can take more than one request: a stray one is set aside and the wait goes on.
//! On a phone, the platform plugin's browser-backed session carries it and returns one result, or
//! a Custom Tab whose answer arrives as a verified link. Whichever carries it, each answer goes
//! through the attempt's checks, and the attempt ends with one [`Ending`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use kr_client::services::account::{Answer, Carrier as Delivery, PendingAuthorisation, Redirect};
use tokio::sync::watch;

use super::loopback::{BindError, Callback, Listener};

/// A boxed future, so carriers stay usable behind a trait object.
pub type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How long a sign-in waits for the person before it stops.
pub const WAIT: Duration = Duration::from_secs(15 * 60);

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
}

#[cfg(mobile)]
impl<R: tauri::Runtime> Carrier for Session<R> {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async move {
            use companion_platform::browser::{self, Mode};
            use tauri::Manager as _;
            let platform = self.app.state::<companion_platform::Platform<R>>();
            let facts = platform
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
            use companion_platform::browser::{self, SessionEvent, SessionRequest};
            use tauri::Manager as _;
            let platform = self.app.state::<companion_platform::Platform<R>>();
            let Some(attempt) = pending.attempt() else {
                return Ending::Cancelled;
            };
            if *cancel.borrow() {
                return Ending::Cancelled;
            }
            let attempt = attempt.value().to_string();
            let request = SessionRequest {
                attempt: attempt.clone(),
                url,
                mode: plan.mode,
                https_host: "reach.kala.to".to_owned(),
                https_path: "/app/oauth/callback".to_owned(),
                scheme: "to.kala.reach".to_owned(),
            };
            let delivery = if plan.mode.is_terminal() {
                Delivery::Terminal
            } else {
                Delivery::Continuing
            };
            let conversation = async {
                let mut next = platform.authenticate(&request).await;
                loop {
                    let raw = match next {
                        Ok(raw) => raw,
                        Err(error) => {
                            tracing::warn!(%error, "the browser session could not be started");
                            return Ending::BrowserFailed;
                        }
                    };
                    if raw.attempt != attempt {
                        // A late result of an earlier attempt: not this one's.
                        next = platform.next_event(&attempt).await;
                        continue;
                    }
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
                        SessionEvent::Cancelled => return Ending::Cancelled,
                        SessionEvent::TabClosed => return Ending::TabClosed,
                        SessionEvent::CouldNotReturn => return Ending::CouldNotReturn,
                        SessionEvent::Failed => return Ending::BrowserFailed,
                    }
                    if delivery == Delivery::Terminal {
                        return Ending::CouldNotReturn;
                    }
                    next = platform.next_event(&attempt).await;
                }
            };
            tokio::select! {
                ending = conversation => ending,
                () = cancelled(cancel) => {
                    let _ = platform.cancel(&attempt).await;
                    Ending::Cancelled
                }
                () = tokio::time::sleep(WAIT) => {
                    let _ = platform.cancel(&attempt).await;
                    Ending::TimedOut
                }
            }
        })
    }
}
