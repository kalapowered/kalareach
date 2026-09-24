//! The account: signing this device in through the system browser, and what the page is told.
//!
//! Section 17: the passkey ceremony runs on the website's fixed origin in the system browser, and
//! the application is a registered public client. The page asks for a sign-in and is told where it
//! stands; it never holds the address the browser opens, a state, a verifier, a code or a token.
//! What it gets is a view: signed out (with how the last attempt ended), the browser open,
//! finishing, signed in (with the account's address, once read), ended, or not offered on this
//! device, and usage lines with nothing about money.
//!
//! One attempt runs at a time. Its answer goes through the checks in
//! [`kr_client::services::account`], its code is exchanged, and the grant is kept in the device's
//! secure store under one lock, which every managed resource then asks for tokens.

pub mod carrier;
pub mod loopback;
pub mod navigation;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use kr_client::services::account::{
    AccountService, AccountStatus, AccountUsage, Answer, AnswerFault, AuthorisationGrant,
    AuthorisationRequest, Exchanged, IdentityRead, PendingAuthorisation, SignedInAccount,
    USAGE_SCOPE, UsageResource,
};
use serde::Serialize;
use tokio::sync::watch;

use crate::error::CommandError;
use carrier::{Carrier, Ending, Unavailable};

/// The event the backend publishes the account's view on when it changes by itself.
pub const ACCOUNT_EVENT: &str = "kr://account";

/// How the last attempt, or the last sign-out, ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The person, or the application, ended the ceremony.
    Cancelled,
    /// A Custom Tab closed without an answer.
    TabClosed,
    /// The person or the service said no.
    Refused,
    /// The service could not be reached.
    Unreachable,
    /// The system would not return the answer to this application.
    CouldNotReturn,
    /// The answer was not for this attempt: its state, issuer or address.
    NotForThisSignIn,
    /// Another program holds the loopback address.
    PortBusy,
    /// Nothing came back within 15 minutes.
    TimedOut,
    /// The grant could not be kept in this device's secure store.
    NotKept,
    /// The service refused the sign-in.
    ServiceRefused,
    /// The browser could not be opened.
    BrowserFailed,
    /// Signed out, and the service has been told.
    SignedOut,
    /// Signed out here; the service is told the next time it can be.
    SignedOutPending,
    /// The sign-in could not be removed from this device.
    SignOutFailed,
}

/// Why this device offers no sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    /// No browser here can return the answer to the application.
    NoReturningBrowser,
    /// The link is verified, but opening supported links is turned off for the application.
    LinkHandlingOff,
}

/// Where this device stands, as the page is told.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AccountView {
    /// No account on this device.
    SignedOut {
        /// How the last attempt or sign-out ended, until the next one.
        outcome: Option<Outcome>,
    },
    /// No sign-in can be offered here.
    Unavailable {
        /// Why.
        reason: UnavailableReason,
    },
    /// The browser is open and the application is waiting for the person.
    BrowserOpen,
    /// The answer came back and is being exchanged.
    Finishing,
    /// An account is signed in.
    SignedIn {
        /// Its address, once read.
        email: Option<String>,
        /// The name on it, once read.
        name: Option<String>,
        /// Whether this sign-in may read usage.
        usage_readable: bool,
    },
    /// The sign-in on this device ended by itself.
    Ended,
}

/// One usage line, in words and figures for a meter.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UsageLineView {
    /// What it measures.
    pub label: String,
    /// How much has been used, in `unit`.
    pub used: f64,
    /// How much is included, in `unit`.
    pub included: f64,
    /// The unit, `GB` or `MB`.
    pub unit: String,
}

/// The account's usage, as the page is told.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UsageView {
    /// Usage, read now.
    Read {
        /// The heading the lines sit under.
        period_label: String,
        /// One line per resource.
        lines: Vec<UsageLineView>,
    },
    /// This sign-in was not granted usage.
    NotGranted,
    /// Usage could not be read.
    CouldNotRead,
    /// No account is signed in.
    SignedOut,
}

/// What the account is doing.
enum Phase {
    Idle,
    BrowserOpen { cancel: watch::Sender<bool> },
    Finishing,
}

/// Publishes a view to the page.
pub type Emit = Arc<dyn Fn(&AccountView) + Send + Sync>;

/// The account on this device.
pub struct Account {
    signed_in: Arc<SignedInAccount>,
    service: Arc<dyn AccountService>,
    carrier: Arc<dyn Carrier>,
    phase: Mutex<Phase>,
    outcome: Mutex<Option<Outcome>>,
    emit: Emit,
}

impl Account {
    /// The account kept by `signed_in`, exchanging through `service`, carried by `carrier`.
    #[must_use]
    pub fn new(
        signed_in: Arc<SignedInAccount>,
        service: Arc<dyn AccountService>,
        carrier: Arc<dyn Carrier>,
        emit: Emit,
    ) -> Self {
        Self {
            signed_in,
            service,
            carrier,
            phase: Mutex::new(Phase::Idle),
            outcome: Mutex::new(None),
            emit,
        }
    }

    /// The token source every managed resource on this device asks.
    #[must_use]
    pub fn tokens(&self) -> Arc<SignedInAccount> {
        Arc::clone(&self.signed_in)
    }

    /// Settles what an earlier run left, and publishes every change of status from here on.
    pub async fn start(self: &Arc<Self>) {
        if let Err(error) = self.signed_in.recover().await {
            tracing::warn!(%error, "the account's stored state could not be settled");
        }
        self.publish().await;
        let mut changes = self.signed_in.subscribe();
        let account = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            while changes.changed().await.is_ok() {
                account.publish().await;
            }
        });
    }

    fn outcome(&self) -> Option<Outcome> {
        *self
            .outcome
            .lock()
            .expect("the outcome lock is not poisoned")
    }

    fn set_outcome(&self, outcome: Option<Outcome>) {
        *self
            .outcome
            .lock()
            .expect("the outcome lock is not poisoned") = outcome;
    }

    fn set_phase(&self, phase: Phase) {
        *self.phase.lock().expect("the phase lock is not poisoned") = phase;
    }

    /// Where this device stands now.
    pub async fn view(&self) -> AccountView {
        {
            let phase = self.phase.lock().expect("the phase lock is not poisoned");
            match &*phase {
                Phase::BrowserOpen { .. } => return AccountView::BrowserOpen,
                Phase::Finishing => return AccountView::Finishing,
                Phase::Idle => {}
            }
        }
        match self.signed_in.status() {
            Ok(AccountStatus::SignedIn {
                email,
                name,
                scopes,
            }) => AccountView::SignedIn {
                email,
                name,
                usage_readable: scopes.iter().any(|scope| scope == USAGE_SCOPE),
            },
            Ok(AccountStatus::Ended) => AccountView::Ended,
            Ok(AccountStatus::SignedOut) | Err(_) => match self.carrier.plan().await {
                Err(Unavailable::NoReturningBrowser) => AccountView::Unavailable {
                    reason: UnavailableReason::NoReturningBrowser,
                },
                Err(Unavailable::LinkHandlingOff) => AccountView::Unavailable {
                    reason: UnavailableReason::LinkHandlingOff,
                },
                Ok(_) => AccountView::SignedOut {
                    outcome: self.outcome(),
                },
            },
        }
    }

    /// Where this device stands, reading the account's address when it has not been read yet.
    pub async fn status(&self) -> AccountView {
        let view = self.view().await;
        if matches!(view, AccountView::SignedIn { email: None, .. }) {
            if let Ok(IdentityRead::Disagreed) = self.signed_in.complete_identity().await {
                self.set_outcome(Some(Outcome::NotForThisSignIn));
            }
            return self.view().await;
        }
        view
    }

    async fn publish(&self) {
        let view = self.view().await;
        (self.emit)(&view);
    }

    /// Signs this device in: opens the ceremony in the system browser and settles when it ends.
    ///
    /// One attempt at a time: while one is open, a second press changes nothing and is told the
    /// browser is open.
    pub async fn sign_in(&self) -> AccountView {
        let (cancel, cancelled) = watch::channel(false);
        let claimed = {
            let mut phase = self.phase.lock().expect("the phase lock is not poisoned");
            let idle = matches!(*phase, Phase::Idle);
            if idle {
                *phase = Phase::BrowserOpen { cancel };
            }
            idle
        };
        if !claimed {
            return self.view().await;
        }
        self.set_outcome(None);
        let Ok(plan) = self.carrier.plan().await else {
            self.set_phase(Phase::Idle);
            self.publish().await;
            return self.view().await;
        };
        let Ok(request) = AuthorisationRequest::new(self.signed_in.client(), plan.redirect) else {
            self.set_phase(Phase::Idle);
            self.set_outcome(Some(Outcome::BrowserFailed));
            self.publish().await;
            return self.view().await;
        };
        let url = request.url();
        let mut pending = PendingAuthorisation::new(request);
        self.publish().await;

        let ending = self
            .carrier
            .carry(&plan, url, &mut pending, cancelled)
            .await;
        let outcome = match ending {
            Ending::Answered {
                answer: Answer::Granted(grant),
                reply,
            } => {
                self.set_phase(Phase::Finishing);
                self.publish().await;
                let outcome = self.finish(&grant).await;
                if let Some(reply) = reply {
                    reply.finish(page(outcome)).await;
                }
                outcome
            }
            Ending::Answered { answer, reply } => {
                let outcome = Some(match answer {
                    Answer::Refused => Outcome::Refused,
                    Answer::Failed(AnswerFault::ServiceFailure | AnswerFault::NoCode) => {
                        Outcome::ServiceRefused
                    }
                    Answer::Failed(_) | Answer::Dropped(_) | Answer::Granted(_) => {
                        Outcome::NotForThisSignIn
                    }
                });
                if let Some(reply) = reply {
                    reply.finish(page(outcome)).await;
                }
                outcome
            }
            Ending::Cancelled => Some(Outcome::Cancelled),
            Ending::TabClosed => Some(Outcome::TabClosed),
            Ending::CouldNotReturn => Some(Outcome::CouldNotReturn),
            Ending::PortBusy => Some(Outcome::PortBusy),
            Ending::TimedOut => Some(Outcome::TimedOut),
            Ending::BrowserFailed => Some(Outcome::BrowserFailed),
        };
        self.set_phase(Phase::Idle);
        self.set_outcome(outcome);
        self.publish().await;
        self.view().await
    }

    /// Exchanges a code and keeps the grant.
    async fn finish(&self, grant: &AuthorisationGrant) -> Option<Outcome> {
        match self.service.exchange(grant).await {
            Ok(Exchanged::Issued(issued)) => {
                let refresh = issued.refresh_token.clone();
                match self.signed_in.commit(issued, grant.nonce()).await {
                    Ok(()) => match self.signed_in.complete_identity().await {
                        Ok(IdentityRead::Disagreed) => Some(Outcome::NotForThisSignIn),
                        _ => None,
                    },
                    Err(error) => {
                        tracing::warn!(%error, "a sign-in could not be kept");
                        let _ = self.service.revoke(&refresh).await;
                        Some(Outcome::NotKept)
                    }
                }
            }
            Ok(Exchanged::Refused { leftover }) => {
                if let Some(leftover) = leftover {
                    let _ = self.service.revoke(&leftover).await;
                }
                Some(Outcome::ServiceRefused)
            }
            Err(error) => {
                tracing::warn!(%error, "a sign-in's code could not be exchanged");
                Some(Outcome::Unreachable)
            }
        }
    }

    /// Ends the attempt that is waiting for the browser, if one is.
    pub fn cancel(&self) {
        if let Phase::BrowserOpen { cancel } =
            &*self.phase.lock().expect("the phase lock is not poisoned")
        {
            let _ = cancel.send(true);
        }
    }

    /// Signs this device out, and tells the service.
    pub async fn sign_out(&self) -> AccountView {
        let outcome = match self.signed_in.sign_out().await {
            Ok(done) if done.service_told => Outcome::SignedOut,
            Ok(_) => Outcome::SignedOutPending,
            Err(error) => {
                tracing::warn!(%error, "a sign-out could not remove the sign-in");
                Outcome::SignOutFailed
            }
        };
        self.set_outcome(Some(outcome));
        self.publish().await;
        self.view().await
    }

    /// The account's usage.
    pub async fn usage(&self) -> UsageView {
        match self.signed_in.usage().await {
            Ok(Some(usage)) => usage_view(&usage),
            Ok(None) => UsageView::NotGranted,
            Err(error) if error.code() == kr_protocol::error::ErrorCode::HostNotConfigured => {
                UsageView::SignedOut
            }
            Err(_) => UsageView::CouldNotRead,
        }
    }
}

/// The page the browser shows once a desktop sign-in has ended.
fn page(outcome: Option<Outcome>) -> &'static str {
    outcome.map_or(
        "You are signed in to KalaReach. You can close this tab.",
        message,
    )
}

/// What an outcome says, in the application's own words.
#[must_use]
pub const fn message(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Cancelled => "Sign-in cancelled. Nothing changed.",
        Outcome::TabClosed => {
            "Sign-in cancelled. Nothing changed. If the browser stayed on reach.kala.to after you \
             signed in, it did not hand the sign-in back; a current Chrome does."
        }
        Outcome::Refused => "reach.kala.to did not sign this device in.",
        Outcome::Unreachable => {
            "reach.kala.to could not be reached. Check the connection and try again."
        }
        Outcome::CouldNotReturn => {
            "reach.kala.to could not return the sign-in to this app. Try again later."
        }
        Outcome::NotForThisSignIn => {
            "The answer that came back was not for this sign-in, so KalaReach ignored it."
        }
        Outcome::PortBusy => {
            "Another app is using port 8765, which signing in needs. Close it and try again."
        }
        Outcome::TimedOut => {
            "The browser did not come back within 15 minutes, so signing in stopped."
        }
        Outcome::NotKept => {
            "KalaReach could not keep the sign-in safely on this device, so it kept nothing."
        }
        Outcome::ServiceRefused => "reach.kala.to refused the sign-in.",
        Outcome::BrowserFailed => "The browser could not be opened, so signing in stopped.",
        Outcome::SignedOut => "Signed out on this device.",
        Outcome::SignedOutPending => {
            "Signed out on this device. reach.kala.to has not heard yet; KalaReach tells it the \
             next time it can."
        }
        Outcome::SignOutFailed => "KalaReach could not remove the sign-in from this device.",
    }
}

/// Usage lines in words and figures, with nothing about money.
fn usage_view(usage: &AccountUsage) -> UsageView {
    let period_label = usage
        .lines
        .iter()
        .find_map(|line| line.period.as_deref().and_then(month))
        .map_or_else(|| "Usage".to_owned(), |month| format!("Usage in {month}"));
    let lines = usage
        .lines
        .iter()
        .map(|line| {
            let label = match line.resource {
                UsageResource::Relay => "Relay this month",
                UsageResource::Storage => "Backup storage",
                UsageResource::Sync => "Settings sync",
            };
            let (scale, unit) = if line.allowance_bytes >= 1_000_000_000 {
                (1_000_000_000_f64, "GB")
            } else {
                (1_000_000_f64, "MB")
            };
            #[allow(
                clippy::cast_precision_loss,
                reason = "a figure for a person to read, rounded to one decimal place"
            )]
            let figure = |bytes: u64| (bytes as f64 / scale * 10.0).round() / 10.0;
            UsageLineView {
                label: label.to_owned(),
                used: figure(line.used_bytes),
                included: figure(line.allowance_bytes),
                unit: unit.to_owned(),
            }
        })
        .collect();
    UsageView::Read {
        period_label,
        lines,
    }
}

/// `2026-09` as `September 2026`.
fn month(period: &str) -> Option<String> {
    let (year, month) = period.split_once('-')?;
    let name = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    .get(month.parse::<usize>().ok()?.checked_sub(1)?)?;
    Some(format!("{name} {year}"))
}

/// A future that builds the account.
pub type Build = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<Arc<Account>, String>> + Send>> + Send + Sync,
>;

/// The account, built on first use, off the thread the platform starts the application on.
///
/// Opening the secure store on a phone asks the native half, which runs on the main thread, so
/// the account is built by the first command or by the start task, never during setup.
pub struct AccountSlot {
    build: Build,
    cell: tokio::sync::OnceCell<Arc<Account>>,
}

impl AccountSlot {
    /// A slot that builds its account with `build` when it is first asked for.
    #[must_use]
    pub fn new(build: Build) -> Self {
        Self {
            build,
            cell: tokio::sync::OnceCell::new(),
        }
    }

    /// A slot holding an account already built, for a test.
    #[must_use]
    pub fn ready(account: Arc<Account>) -> Self {
        Self {
            build: Box::new(|| Box::pin(async { Err("already built".to_owned()) })),
            cell: tokio::sync::OnceCell::new_with(Some(account)),
        }
    }

    /// The account, built and started when this is the first ask.
    ///
    /// # Errors
    ///
    /// Returns `UNAVAILABLE` when the device's secure store cannot be opened.
    pub async fn get(&self) -> Result<&Arc<Account>, CommandError> {
        self.cell
            .get_or_try_init(|| async {
                let account = (self.build)().await.map_err(|error| {
                    CommandError::unavailable(format!(
                        "KalaReach could not open this device's secure storage: {error}"
                    ))
                })?;
                account.start().await;
                Ok(account)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_client::services::account::UsageLine;

    #[test]
    fn usage_is_shown_in_figures_a_person_reads_and_names_no_money() {
        let view = usage_view(&AccountUsage {
            lines: vec![
                UsageLine {
                    resource: UsageResource::Relay,
                    used_bytes: 1_234_000_000,
                    allowance_bytes: 10_000_000_000,
                    period: Some("2026-09".to_owned()),
                },
                UsageLine {
                    resource: UsageResource::Sync,
                    used_bytes: 12_345_678,
                    allowance_bytes: 100_000_000,
                    period: None,
                },
            ],
        });
        assert_eq!(
            view,
            UsageView::Read {
                period_label: "Usage in September 2026".to_owned(),
                lines: vec![
                    UsageLineView {
                        label: "Relay this month".to_owned(),
                        used: 1.2,
                        included: 10.0,
                        unit: "GB".to_owned(),
                    },
                    UsageLineView {
                        label: "Settings sync".to_owned(),
                        used: 12.3,
                        included: 100.0,
                        unit: "MB".to_owned(),
                    },
                ],
            }
        );
        let text = serde_json::to_string(&view).expect("json");
        for word in ["price", "plan", "buy", "billing", "balance", "currency"] {
            assert!(!text.to_ascii_lowercase().contains(word), "{word}");
        }
    }

    #[test]
    fn every_outcome_is_said_in_one_or_two_sentences_and_names_no_address_to_follow() {
        for outcome in [
            Outcome::Cancelled,
            Outcome::TabClosed,
            Outcome::Refused,
            Outcome::Unreachable,
            Outcome::CouldNotReturn,
            Outcome::NotForThisSignIn,
            Outcome::PortBusy,
            Outcome::TimedOut,
            Outcome::NotKept,
            Outcome::ServiceRefused,
            Outcome::BrowserFailed,
            Outcome::SignedOut,
            Outcome::SignedOutPending,
            Outcome::SignOutFailed,
        ] {
            let said = message(outcome);
            assert!(said.ends_with('.'), "{said}");
            assert!(!said.contains("http"), "{said}");
        }
        assert_eq!(month("2026-13"), None);
        assert_eq!(month("2026-01").as_deref(), Some("January 2026"));
    }
}
