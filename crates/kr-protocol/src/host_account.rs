//! The host's own sign-in to the managed account service.
//!
//! Managed voice spends an account's balance, so the host presents an account token of its own. A
//! person at the host signs it in with `kr account sign-in`, which asks the control daemon over its
//! local socket: the daemon listens on the loopback address the desktop client is registered with
//! and keeps the grant that comes of the person's browser sign-in in the host's secret store.
//! `account.status` reads where that stands, and says the address the person opens.
//!
//! Both methods are served on the local socket alone. A grant on a host decides whose balance a
//! phone's call spends, so no paired device starts or reads it.

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

/// Parameters of `account.status`. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusParams {}

/// Where this host's sign-in stands: the answer to `account.status`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountReport {
    /// The managed service this host's configuration names as its voice broker, which is where a
    /// sign-in is made and where its token is presented. Null when the host names none.
    pub service: Nullable<String>,
    /// The account this host is signed in as, or what stands in its way.
    pub state: AccountState,
    /// How the last attempt ended, until the next one begins. It is null before any attempt since
    /// the daemon started.
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
        /// The service the sign-in belongs to. A call is brokered at the service the host's
        /// configuration names, and a token from another service is never presented to it.
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
    /// The service signed the account in and the host could not keep the grant.
    NotKept,
    /// The service could not be reached to exchange the answer.
    Unreachable,
    /// A newer attempt ended this one.
    Superseded,
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
        }
    }
}
