//! `kr account`: signing this host in to the managed account service, and saying where that stands.
//!
//! Managed voice spends an account's balance, so the host presents an account token of its own,
//! and the control daemon alone holds the sign-in that makes one. Both commands go through the
//! daemon under this user's own authority on this host. `sign-in` asks it to listen on the
//! loopback address the desktop client is registered with, prints the address a person opens in a
//! browser and opens it; the daemon exchanges the answer and keeps the account. `show` reads where
//! that stands.
//!
//! **Nothing the daemon holds is printed.** The address to open carries this attempt's state and
//! nonce, and is shown to the person who asked, as the command that asked for it; what is said of
//! an account is the service it belongs to, its address and the scopes it carries.

use kr_client::shown;
use kr_protocol::host_account::{
    AccountAttempt, AccountReport, AccountSignInParams, AccountSignInStarted, AccountState,
    AccountStatusParams, SignInUnavailable,
};
use kr_protocol::method::Method;

use crate::cli::EnvironmentSelector;
use crate::daemon::Daemon;
use crate::error::Result;
use crate::output::{self, Asked, Document, Line, Request};
use crate::stdout_line;

/// The port a browser forwards to a host with no display, which is the one the desktop client's
/// registered redirect names.
const FORWARDED_PORT: &str = "8765";

/// `kr account sign-in`: starts the sign-in, prints the address to open and opens it.
///
/// # Errors
///
/// Returns the daemon's refusal: this host names no managed service, a sign-in is finishing, or
/// another program holds the loopback address.
pub async fn sign_in(selector: &EnvironmentSelector, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(&kr_ipc::paths::HostPaths::discover()?, selector).await?;
    let started: AccountSignInStarted = daemon
        .mutate(Method::AccountSignIn, &AccountSignInParams {})
        .await?;
    let report: AccountReport = daemon
        .read(Method::AccountStatus, &AccountStatusParams {})
        .await?;
    let AccountState::WaitingForBrowser {
        authorise_url,
        redirect_address,
        ..
    } = &report.state
    else {
        // The attempt has already ended, such as a browser that answered before this asked.
        say(&report, json);
        return Ok(());
    };
    // Opened here, on the machine the person is at, and printed whether or not it opened: a host
    // with no display has nobody to open it for.
    let opened = open::that_detached(authorise_url).is_ok();
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("opened", opened)
                .with(
                    "authorise_url",
                    Asked::text(Request::Account, authorise_url),
                )
                .with(
                    "redirect_address",
                    Asked::text(Request::Account, redirect_address),
                )
                .with("expires_at_ms", started.expires_at_ms.get()),
        );
    } else {
        output::line(&stdout_line!(
            "Open this address in a browser to sign this host in: {}",
            Asked::text(Request::Account, authorise_url)
        ));
        output::line(&stdout_line!(
            "The browser comes back to {} on this host. On a host with no display, forward the \
             port from the machine that has the browser (ssh -L {}:127.0.0.1:{} <host>) and open \
             the address there.",
            Asked::text(Request::Account, redirect_address),
            FORWARDED_PORT,
            FORWARDED_PORT
        ));
        output::say(&shown!(
            "The host stops waiting at {} in UTC milliseconds. `kr account show` says how it \
             ended.",
            started.expires_at_ms.get()
        ));
    }
    Ok(())
}

/// `kr account show`: where this host's sign-in stands.
///
/// # Errors
///
/// Returns the daemon's refusal, or a transport failure.
pub async fn show(selector: &EnvironmentSelector, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(&kr_ipc::paths::HostPaths::discover()?, selector).await?;
    let report: AccountReport = daemon
        .read(Method::AccountStatus, &AccountStatusParams {})
        .await?;
    say(&report, json);
    Ok(())
}

/// Writes a report for a person or a script.
fn say(report: &AccountReport, json: bool) {
    if json {
        output::document(&document(report));
    } else {
        for line in lines(report) {
            output::line(&line);
        }
    }
}

/// The report as a document. The address a sign-in is opened at is left out: it is the one answer
/// of `sign-in` and is not repeated by a read.
fn document(report: &AccountReport) -> Document {
    let mut document = Document::new()
        .with("ok", true)
        .with("state", report.state.name());
    if let Some(service) = report.service.as_ref() {
        document.set("service", Asked::location(Request::Account, service));
    }
    if let Some(unavailable) = report.unavailable.as_ref() {
        document.set("unavailable", unavailable_name(*unavailable));
    }
    if let AccountState::SignedIn { email, scopes, .. } = &report.state {
        if let Some(email) = email.as_ref() {
            document.set("email", Asked::text(Request::Account, email));
        }
        document.set(
            "scopes",
            scopes
                .iter()
                .map(|scope| Asked::text(Request::Account, scope))
                .collect::<Vec<_>>(),
        );
    }
    if let Some(attempt) = report.last_attempt.as_ref() {
        document.set("last_attempt", attempt.name());
    }
    document
}

/// Where the host's sign-in stands, as lines for a person.
fn lines(report: &AccountReport) -> Vec<Line> {
    let mut lines = Vec::new();
    match (report.service.as_ref(), report.unavailable.as_ref()) {
        (Some(service), _) => lines.push(stdout_line!(
            "This host signs in at {}.",
            Asked::location(Request::Account, service)
        )),
        (None, Some(SignInUnavailable::BrokerIsAnotherService)) => lines.push(stdout_line!(
            "This host's voice.broker_origin names another service than the managed account \
             service, so there is nothing to sign in to and no account is presented."
        )),
        (None, Some(SignInUnavailable::NotUsable)) => lines.push(stdout_line!(
            "This host cannot reach the managed account service the way its configuration says: \
             the daemon's log says why."
        )),
        (None, Some(SignInUnavailable::NoBroker) | None) => lines.push(stdout_line!(
            "This host names no managed voice service: set voice.broker_origin in its \
             configuration document to the managed account service's origin."
        )),
    }
    match &report.state {
        AccountState::SignedOut => lines.push(stdout_line!(
            "No account is signed in. `kr account sign-in` signs one in."
        )),
        AccountState::WaitingForBrowser { expires_at_ms, .. } => lines.push(stdout_line!(
            "A sign-in is waiting for the browser until {} in UTC milliseconds.",
            expires_at_ms.get()
        )),
        AccountState::Finishing => lines.push(stdout_line!("A sign-in is finishing.")),
        AccountState::SignedIn {
            origin,
            email,
            scopes,
        } => {
            lines.push(match email.as_ref() {
                Some(email) => stdout_line!(
                    "{} is signed in at {}.",
                    Asked::text(Request::Account, email),
                    Asked::location(Request::Account, origin)
                ),
                None => stdout_line!(
                    "An account is signed in at {}.",
                    Asked::location(Request::Account, origin)
                ),
            });
            lines.push(stdout_line!(
                "It carries {}.",
                Asked::text(Request::Account, &scopes.join(", "))
            ));
        }
        AccountState::Ended => lines.push(stdout_line!(
            "The service ended the sign-in. `kr account sign-in` signs in again."
        )),
    }
    if let Some(attempt) = report.last_attempt.as_ref() {
        lines.push(stdout_line!(
            "The last attempt: {}.",
            attempt_words(*attempt)
        ));
    }
    lines
}

/// How an attempt ended, in words.
const fn attempt_words(attempt: AccountAttempt) -> &'static str {
    match attempt {
        AccountAttempt::SignedIn => "signed in",
        AccountAttempt::Refused => "refused in the browser",
        AccountAttempt::ServiceRefused => "the service would not sign this host in",
        AccountAttempt::NotForThisAttempt => {
            "the answer was not for this attempt, or named another account"
        }
        AccountAttempt::PortBusy => "another program held the loopback address",
        AccountAttempt::TimedOut => "nothing came back in time",
        AccountAttempt::NotKept => {
            "the service signed the account in and this host could not keep it"
        }
        AccountAttempt::Unreachable => "the service could not be reached",
        AccountAttempt::Superseded => "a newer attempt ended it",
        AccountAttempt::ListenerFailed => "the loopback address could not be opened",
        AccountAttempt::CallOpen => "a voice call was open, so the code was not spent",
    }
}

/// Why a host signs in nowhere, as a script reads it.
const fn unavailable_name(unavailable: SignInUnavailable) -> &'static str {
    match unavailable {
        SignInUnavailable::NoBroker => "no_broker",
        SignInUnavailable::BrokerIsAnotherService => "broker_is_another_service",
        SignInUnavailable::NotUsable => "not_usable",
    }
}
