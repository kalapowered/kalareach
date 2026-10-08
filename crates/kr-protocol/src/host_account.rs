//! The host's own sign-in to the managed account service.
//!
//! Managed voice spends an account's balance, so the host presents an account token of its own. A
//! person at the host signs it in with `kr account sign-in`, which asks the control daemon over its
//! local socket: the daemon listens on the loopback address the desktop client is registered with
//! and keeps the grant that comes of the person's browser sign-in in the host's secret store.
//! `account.status` reads where that stands, and says the address the person opens.
//! `account.sign_out` removes the grant and asks the service to end it.
//!
//! The methods are served on the local socket alone. A grant on a host decides whose balance a
//! phone's call spends, so no paired device starts, ends or reads it.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::scalars::{Nullable, TimestampMs};

/// Parameters of `account.sign_in`. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountSignInParams {}

/// What `account.sign_in` answers once the daemon is listening for the browser's answer.
///
/// The address the person opens is not in it: the answer to a mutation is kept as the receipt of
/// the action, and the address carries the attempt's state and nonce. `account.status` says it.
/// Asking again with the same action answers the same attempt; asking with a new action ends the
/// attempt that is waiting and starts another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountSignInStarted {
    /// When the daemon stops waiting for the browser, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

/// Parameters of `account.sign_out`. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountSignOutParams {}

/// What `account.sign_out` answers: whether there was an account to sign out, and whether the
/// service has been told to end it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountSignedOut {
    /// Whether an account was signed in. A host with none answers `false` and changes nothing.
    pub was_signed_in: bool,
    /// Whether the service has acknowledged every revocation this host holds: the one just sent
    /// and any that were waiting. When it has not, the grant is gone from this host all the same,
    /// and the daemon sends what is left again when it next starts.
    pub service_told: bool,
}

/// Parameters of `account.status`. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusParams {}

/// Where this host's sign-in stands: the answer to `account.status`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountReport {
    /// The account service this host keeps its account for, which is also where its token is
    /// presented when its voice broker is that service. Null when the host could not set up how to
    /// reach it, and `unavailable` says why.
    pub service: Nullable<String>,
    /// Why this host does not sign in or present its account: its configuration names no voice
    /// broker, names another service than the account service, or the host could not set up how to
    /// reach the account service. A grant the host already keeps still shows in `state`, and
    /// `account.sign_out` ends it, whatever the broker is.
    pub unavailable: Nullable<SignInUnavailable>,
    /// The account this host is signed in as, or what stands in its way.
    pub state: AccountState,
    /// How the most recent attempt that has ended ended. It stays while a newer attempt waits, and
    /// is null before any attempt has ended since the daemon started or the host was signed out.
    pub last_attempt: Nullable<AccountAttempt>,
}

impl fmt::Debug for AccountReport {
    /// Names the state and the last attempt, and leaves out the signed-in account's address.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountReport")
            .field("service", &self.service.as_ref().map(|_| "<present>"))
            .field("state", &self.state.name())
            .field("last_attempt", &self.last_attempt)
            .finish()
    }
}

/// Why a host does not sign in or present its account.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SignInUnavailable {
    /// The host's configuration names no voice broker.
    NoBroker,
    /// The voice broker it names is another service than the account service the host signs in at.
    BrokerIsAnotherService,
    /// The host could not set up how to reach the account service the way its configuration says.
    NotUsable,
}

/// Where the host stands with an account.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountState {
    /// No account is signed in on this host.
    SignedOut,
    /// An attempt is waiting for the browser's answer.
    WaitingForBrowser {
        /// The address the person opens in a browser. It carries this attempt's state and nonce,
        /// so it is shown to the person who asked and to nobody else, and it is used once.
        authorise_url: String,
        /// The address on this host the browser must reach to finish, such as `127.0.0.1:8765`. A
        /// person who opens the browser on another machine forwards this port to the host.
        redirect_address: String,
        /// When the daemon stops waiting, in UTC milliseconds.
        expires_at_ms: TimestampMs,
    },
    /// The browser's answer came back and the daemon is exchanging it with the service.
    Finishing,
    /// An account is signed in.
    SignedIn {
        /// The account service the sign-in was made at.
        origin: String,
        /// The account's address, when the service said it.
        email: Nullable<String>,
        /// The scopes the grant carries, as the service issued them.
        scopes: Vec<String>,
    },
    /// The service ended the sign-in, for a refresh token it no longer accepts. Signing in again
    /// replaces it.
    Ended,
}

impl AccountState {
    /// The state's wire name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::SignedOut => "signed_out",
            Self::WaitingForBrowser { .. } => "waiting_for_browser",
            Self::Finishing => "finishing",
            Self::SignedIn { .. } => "signed_in",
            Self::Ended => "ended",
        }
    }
}

impl fmt::Debug for AccountState {
    /// Names the state, and leaves out the account's address.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// How the last sign-in attempt ended.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AccountAttempt {
    /// The account is signed in.
    SignedIn,
    /// The person refused in the browser.
    Refused,
    /// The service would not sign this host in.
    ServiceRefused,
    /// The answer that came back was not for this attempt, or the service named another account
    /// than the one that signed in.
    NotForThisAttempt,
    /// Another program held the loopback address.
    PortBusy,
    /// Nothing came back in time.
    TimedOut,
    /// The host's secret store failed, before the code was spent or after the service signed the
    /// account in, so the host kept no grant.
    NotKept,
    /// The service could not be reached to exchange the answer.
    Unreachable,
    /// A newer attempt ended this one.
    Superseded,
    /// The loopback address could not be opened for a reason other than another program holding
    /// it.
    ListenerFailed,
    /// A managed voice call was open, and a call closes under the account it started under.
    CallOpen,
}

impl AccountAttempt {
    /// The outcome's wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignedIn => "signed_in",
            Self::Refused => "refused",
            Self::ServiceRefused => "service_refused",
            Self::NotForThisAttempt => "not_for_this_attempt",
            Self::PortBusy => "port_busy",
            Self::TimedOut => "timed_out",
            Self::NotKept => "not_kept",
            Self::Unreachable => "unreachable",
            Self::Superseded => "superseded",
            Self::ListenerFailed => "listener_failed",
            Self::CallOpen => "call_open",
        }
    }
}
