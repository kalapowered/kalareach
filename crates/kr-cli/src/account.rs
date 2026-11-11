//! `kr account`: signing this host in to an account service and out of it, and saying where that
//! stands.
//!
//! Managed voice spends an account's balance and managed storage keeps an account's backups, so the
//! host presents an account token of its own, and the control daemon alone holds the sign-in that
//! makes one. Every command goes through the daemon under this user's own authority on this host.
//! `sign-in` asks it to listen on the loopback address the desktop client is registered with,
//! prints the address a person opens in a browser and opens it; the daemon exchanges the answer and
//! keeps the account. `sign-out` has the daemon remove the account and ask the service to end it.
//! `show` reads where that stands.
//!
//! A host whose `storage.origin` names a service its owner runs holds a second account, at that
//! service, for backup storage and nothing else. `--storage` on `sign-in` and `sign-out` acts on
//! that account and never on the managed one, and `show` lists it beside the managed account when
//! the host has it. `sign-in --storage` says which service it signs in at before it opens the
//! browser, and that it is not the managed account service, because a mistyped `storage.origin`
//! opens a sign-in at whatever service it names.
//!
//! **Nothing the daemon holds is printed.** The address to open carries this attempt's state and
//! nonce, and is shown to the person who asked, as the command that asked for it; what is said of
//! an account is the service it belongs to, its address and the scopes it carries.

use kr_client::shown;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::host_account::{
    AccountAttempt, AccountReport, AccountSignInParams, AccountSignInStarted, AccountSignOutParams,
    AccountSignedOut, AccountState, AccountStatusParams, SignInUnavailable,
};
use kr_protocol::method::Method;

use crate::cli::EnvironmentSelector;
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request};
use crate::stdout_line;

/// The port a browser forwards to a host with no display, which is the one the desktop client's
/// registered redirect names.
const FORWARDED_PORT: &str = "8765";

/// Which of the host's two accounts a command acts on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    /// The managed account, for voice, relay leases and managed storage.
    Managed,
    /// The account at the storage service the owner runs.
    Storage,
}

impl Which {
    const fn of(storage: bool) -> Self {
        if storage {
            Self::Storage
        } else {
            Self::Managed
        }
    }

    const fn sign_in(self) -> Method {
        match self {
            Self::Managed => Method::AccountSignIn,
            Self::Storage => Method::AccountStorageSignIn,
        }
    }

    const fn sign_out(self) -> Method {
        match self {
            Self::Managed => Method::AccountSignOut,
            Self::Storage => Method::AccountStorageSignOut,
        }
    }

    const fn status(self) -> Method {
        match self {
            Self::Managed => Method::AccountStatus,
            Self::Storage => Method::AccountStorageStatus,
        }
    }

    /// The command that signs this account in.
    const fn sign_in_command(self) -> &'static str {
        match self {
            Self::Managed => "`kr account sign-in`",
            Self::Storage => "`kr account sign-in --storage`",
        }
    }

    /// The command that signs this account out.
    const fn sign_out_command(self) -> &'static str {
        match self {
            Self::Managed => "`kr account sign-out`",
            Self::Storage => "`kr account sign-out --storage`",
        }
    }

    /// What the account is called to a person.
    const fn noun(self) -> &'static str {
        match self {
            Self::Managed => "account",
            Self::Storage => "storage account",
        }
    }

    /// What a sign-in of the account is called to a person.
    const fn sign_in_noun(self) -> &'static str {
        match self {
            Self::Managed => "sign-in",
            Self::Storage => "storage sign-in",
        }
    }
}

/// Calls the account mutation `method` of `which`.
///
/// A daemon of a release before storage accounts does not list the storage methods, and refuses
/// them as it refuses any method it does not list: `PERMISSION_DENIED`, which is also what a grant
/// without the right is refused with, and what a fence this host owes is refused with. Reads are
/// not fenced, so the status of the storage account tells the three apart
/// ([`read_storage_status`]): a daemon that lists the storage methods answers it, or refuses it
/// for a reason of its own, and its refusal of the write is returned as it is.
async fn mutate<P, T>(daemon: &mut Daemon, which: Which, method: Method, params: &P) -> Result<T>
where
    P: serde::Serialize + ?Sized,
    T: kr_protocol::wire::WireMessage,
{
    match daemon.mutate(method, params).await {
        Err(CliError::Refused(refusal))
            if which == Which::Storage && refusal.code == ErrorCode::PermissionDenied =>
        {
            Err(predates_or(daemon, refusal).await)
        }
        other => other,
    }
}

/// What a `PERMISSION_DENIED` to a storage write means: an old daemon, or a refusal of the daemon's
/// own that is returned as it is.
async fn predates_or(daemon: &mut Daemon, refusal: ProtocolError) -> CliError {
    match read_storage_status(daemon).await {
        Ok(StorageRead::Unlisted) => CliError::Other(kr_client::shown::Shown::said(
            "this host's daemon predates storage accounts, so it cannot hold an account at a \
             service you run; update it",
        )),
        Ok(_) => CliError::Refused(refusal),
        // The refusal of the caller that the status read found, which says why.
        Err(error) => error,
    }
}

/// What a read of the storage account's status found.
enum StorageRead {
    /// The daemon answered.
    Account(AccountReport),
    /// The daemon lists the method, and this host holds no storage account.
    NoAccount,
    /// The daemon does not list the method.
    Unlisted,
}

/// Reads the status of the storage account, and says what the daemon does not say in words when it
/// refuses.
///
/// A daemon that lists the method answers it, or refuses it for a reason of its own. One that
/// refuses it with `PERMISSION_DENIED` either does not list it or refuses the caller, and the
/// managed account's status, which asks for the same right and which every daemon with accounts
/// lists, says which: refused too, the refusal is the caller's and is returned as an error. The
/// refusals of a caller can end between two reads, as a membership lease that is renewed does, so
/// when the managed status is answered the storage status is read once more: answered, or refused
/// for another reason, the daemon lists the method; refused again with `PERMISSION_DENIED` while
/// the managed status was answered between the two, the daemon does not list it.
async fn read_storage_status(daemon: &mut Daemon) -> Result<StorageRead> {
    if let Some(read) = storage_status(daemon).await? {
        return Ok(read);
    }
    let _: AccountReport = daemon
        .read(Method::AccountStatus, &AccountStatusParams {})
        .await?;
    Ok(storage_status(daemon)
        .await?
        .unwrap_or(StorageRead::Unlisted))
}

/// One read of the status of the storage account: what it found, or `None` for
/// `PERMISSION_DENIED`, which says nothing alone.
async fn storage_status(daemon: &mut Daemon) -> Result<Option<StorageRead>> {
    match daemon
        .read::<_, AccountReport>(Method::AccountStorageStatus, &AccountStatusParams {})
        .await
    {
        Ok(report) => Ok(Some(StorageRead::Account(report))),
        Err(CliError::Refused(refusal)) if refusal.code == ErrorCode::HostNotConfigured => {
            Ok(Some(StorageRead::NoAccount))
        }
        Err(CliError::Refused(refusal)) if refusal.code == ErrorCode::PermissionDenied => Ok(None),
        Err(other) => Err(other),
    }
}

/// `kr account sign-in`: starts the sign-in, prints the address to open and opens it. With
/// `storage`, it is the sign-in of the account at the storage service the host's owner runs.
///
/// # Errors
///
/// Returns the daemon's refusal: this host names no managed service, or no storage service of its
/// own for `--storage`, a sign-in is finishing, or another program holds the loopback address.
pub async fn sign_in(selector: &EnvironmentSelector, json: bool, storage: bool) -> Result<()> {
    let which = Which::of(storage);
    let mut daemon = Daemon::open(&kr_ipc::paths::HostPaths::discover()?, selector).await?;
    let started: AccountSignInStarted =
        mutate(&mut daemon, which, which.sign_in(), &AccountSignInParams {}).await?;
    let report: AccountReport = daemon.read(which.status(), &AccountStatusParams {}).await?;
    let AccountState::WaitingForBrowser {
        authorise_url,
        redirect_address,
        ..
    } = &report.state
    else {
        // The attempt has already ended, such as a browser that answered before this asked.
        say(&report, which, json);
        return Ok(());
    };
    // The service is named before the browser opens: a `storage.origin` that was mistyped opens a
    // sign-in at whatever service it names, and the person can still stop it here.
    if let (Which::Storage, Some(service), false) = (which, report.service.as_ref(), json) {
        output::line(&stdout_line!(
            "This host's storage account signs in at {}, the service its storage.origin names. It \
             is not the managed account service.",
            Asked::location(Request::Account, service)
        ));
    } else if which == Which::Storage && json {
        // Standard output is the one document, which names the service after the browser has
        // opened, and a service's origin is said only there. The notice that this is not the
        // managed service goes on standard error before it opens.
        crate::report::say(&shown::Shown::said(
            "kr: this host's storage account signs in at the service its storage.origin names, \
             which is not the managed account service; the document that follows names it",
        ));
    }
    // Opened here, on the machine the person is at, and printed whether or not it opened: a host
    // with no display has nobody to open it for.
    let opened = open_browser(authorise_url);
    if json {
        let mut document = Document::new()
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
            .with("expires_at_ms", started.expires_at_ms.get());
        if let (Which::Storage, Some(service)) = (which, report.service.as_ref()) {
            document.set("service", Asked::location(Request::Account, service));
        }
        output::document(&document);
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

/// Opens `address` in the person's browser, and says whether it could.
///
/// A debug build that is given `KR_BROWSER_LOG` appends the address to that file instead, so that
/// a test of the command opens no browser on the machine it runs on. A release build has no such
/// variable.
#[cfg(debug_assertions)]
fn open_browser(address: &str) -> bool {
    use std::io::Write as _;

    let Some(log) = std::env::var_os("KR_BROWSER_LOG") else {
        return open::that_detached(address).is_ok();
    };
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .and_then(|mut file| writeln!(file, "{address}"))
        .is_ok()
}

/// Opens `address` in the person's browser, and says whether it could.
#[cfg(not(debug_assertions))]
fn open_browser(address: &str) -> bool {
    open::that_detached(address).is_ok()
}

/// `kr account sign-out`: removes this host's account and asks the service to end it. With
/// `storage`, it is the account at the storage service the host's owner runs.
///
/// # Errors
///
/// Returns the daemon's refusal: this host cannot reach the account service, holds no storage
/// service of its own for `--storage`, a sign-in is finishing, or a voice call is open.
pub async fn sign_out(selector: &EnvironmentSelector, json: bool, storage: bool) -> Result<()> {
    let which = Which::of(storage);
    let mut daemon = Daemon::open(&kr_ipc::paths::HostPaths::discover()?, selector).await?;
    let done: AccountSignedOut = mutate(
        &mut daemon,
        which,
        which.sign_out(),
        &AccountSignOutParams {},
    )
    .await?;
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("was_signed_in", done.was_signed_in)
                .with("service_told", done.service_told),
        );
    } else if !done.was_signed_in {
        output::line(&match which {
            Which::Managed => stdout_line!("No account was signed in."),
            Which::Storage => stdout_line!("No storage account was signed in."),
        });
    } else if done.service_told {
        output::line(&match which {
            Which::Managed => {
                stdout_line!("Signed out. The account service has ended the sign-in.")
            }
            Which::Storage => {
                stdout_line!("Signed out. The storage service has ended the sign-in.")
            }
        });
    } else {
        output::line(&match which {
            Which::Managed => stdout_line!(
                "Signed out. The account service could not be told, so the daemon tells it at a \
                 later start that can reach it."
            ),
            Which::Storage => stdout_line!(
                "Signed out. The storage service could not be told, so the daemon tells it at a \
                 later start that can reach it."
            ),
        });
    }
    Ok(())
}

/// `kr account show`: where this host's sign-in stands, and where its storage account stands when
/// it has one.
///
/// A host has a storage account when its daemon answers `account.storage_status`. One that is
/// refused as `HOST_NOT_CONFIGURED` has none, and one of a release before storage accounts does not
/// list the method and cannot have one (`read_storage_status` tells it from a caller that is
/// refused, whose refusal is returned).
///
/// # Errors
///
/// Returns the daemon's refusal, or a transport failure.
pub async fn show(selector: &EnvironmentSelector, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(&kr_ipc::paths::HostPaths::discover()?, selector).await?;
    let managed: AccountReport = daemon
        .read(Method::AccountStatus, &AccountStatusParams {})
        .await?;
    let storage = match read_storage_status(&mut daemon).await? {
        StorageRead::Account(report) => Some(report),
        StorageRead::NoAccount | StorageRead::Unlisted => None,
    };
    if json {
        let mut document = document(&managed);
        if let Some(storage) = &storage {
            document.set("storage_account", members(storage));
        }
        output::document(&document);
    } else {
        for line in lines(&managed, Which::Managed) {
            output::line(&line);
        }
        if let Some(storage) = &storage {
            for line in lines(storage, Which::Storage) {
                output::line(&line);
            }
        }
    }
    Ok(())
}

/// Writes a report for a person or a script.
fn say(report: &AccountReport, which: Which, json: bool) {
    if json {
        output::document(&document(report));
    } else {
        for line in lines(report, which) {
            output::line(&line);
        }
    }
}

/// The report as a document. The address a sign-in is opened at is left out: it is the one answer
/// of `sign-in` and is not repeated by a read.
fn document(report: &AccountReport) -> Document {
    let mut document = Document::new().with("ok", true);
    document.merge(members(report));
    document
}

/// What a report says of one account, as the members of a document.
fn members(report: &AccountReport) -> Document {
    let mut document = Document::new().with("state", report.state.name());
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

/// Where an account stands, as lines for a person.
fn lines(report: &AccountReport, which: Which) -> Vec<Line> {
    let mut lines = Vec::new();
    match which {
        Which::Managed => match (report.service.as_ref(), report.unavailable.as_ref()) {
            (Some(service), None) => lines.push(stdout_line!(
                "This host signs in at {}.",
                Asked::location(Request::Account, service)
            )),
            (_, Some(SignInUnavailable::BrokerIsAnotherService)) => lines.push(stdout_line!(
                "This host's voice.broker_origin names another service than the managed account \
                 service, so its managed account signs in nowhere and presents no account."
            )),
            (_, Some(SignInUnavailable::NotUsable)) => lines.push(stdout_line!(
                "This host cannot reach the managed account service the way its configuration \
                 says: when its configuration document cannot be used, `kr doctor` says how to \
                 put it right; otherwise the daemon's log says why."
            )),
            (_, Some(SignInUnavailable::NoManagedService)) | (None, None) => {
                lines.push(stdout_line!(
                    "This host names no managed service: set voice.broker_origin or relay.origin \
                     in its configuration document to the managed account service's origin to use \
                     managed voice or relay leases. A storage.origin that names a service you run \
                     has an account of its own: `kr account sign-in --storage` signs this host in \
                     there."
                ));
            }
        },
        Which::Storage => match (report.service.as_ref(), report.unavailable.as_ref()) {
            (Some(service), None) => lines.push(stdout_line!(
                "This host's storage account signs in at {}, the service its storage.origin \
                 names. It is not the managed account service.",
                Asked::location(Request::Account, service)
            )),
            _ => lines.push(stdout_line!(
                "This host cannot reach the storage service the way its configuration says: when \
                 its configuration document cannot be used, `kr doctor` says how to put it right; \
                 otherwise the daemon's log says why."
            )),
        },
    }
    match &report.state {
        AccountState::SignedOut => lines.push(stdout_line!(
            "No {} is signed in. {} signs one in.",
            which.noun(),
            which.sign_in_command()
        )),
        AccountState::WaitingForBrowser { expires_at_ms, .. } => lines.push(stdout_line!(
            "A {} is waiting for the browser until {} in UTC milliseconds.",
            which.sign_in_noun(),
            expires_at_ms.get()
        )),
        AccountState::Finishing => {
            lines.push(stdout_line!("A {} is finishing.", which.sign_in_noun()));
        }
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
            if report.unavailable.as_ref().is_some() {
                lines.push(stdout_line!(
                    "This host presents no {} while its configuration is as it is. {} ends the \
                     sign-in.",
                    which.noun(),
                    which.sign_out_command()
                ));
            }
        }
        AccountState::Ended => lines.push(stdout_line!(
            "The service ended the {}. {} signs in again.",
            which.sign_in_noun(),
            which.sign_in_command()
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
        AccountAttempt::NotKept => "this host's secret store failed, so it could not keep it",
        AccountAttempt::Unreachable => "the service could not be reached",
        AccountAttempt::Superseded => "a newer attempt ended it",
        AccountAttempt::ListenerFailed => "the loopback address could not be opened",
        AccountAttempt::CallOpen => "a voice call was open, so the account did not change",
    }
}

/// Why a host signs in nowhere, as a script reads it.
const fn unavailable_name(unavailable: SignInUnavailable) -> &'static str {
    match unavailable {
        SignInUnavailable::NoManagedService => "no_managed_service",
        SignInUnavailable::BrokerIsAnotherService => "broker_is_another_service",
        SignInUnavailable::NotUsable => "not_usable",
    }
}
