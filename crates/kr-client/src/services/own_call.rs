//! The record a call on the host's own provider account leaves on the host.
//!
//! A call that runs on the owner's own account is paid for by the owner until the provider ends
//! it, and nothing the provider says about a deadline releases that charge. So the host writes
//! down each call before it asks the provider for it and after the provider answers, and keeps
//! the row until the provider has said the call is closed or the owner says to forget it. The row
//! holds no key, no session description and nothing that was said.
//!
//! [`OwnCallLedger`] is the interface the own-key provider writes through. This crate defines it
//! and the controller implements it over a file in the host's state directory.

use std::fmt;

use kr_protocol::ids::ActionId;

/// Where one own-key call stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CallState {
    /// The host asked the provider for a call and has not learned the provider's answer. The row
    /// has no provider session id: there is nothing to hang up.
    Creating,
    /// The provider created the call and the host wrote its session id down.
    Open,
    /// The host began to end the call and has not seen the provider confirm it.
    Closing,
    /// The host tried to end the call and the provider's answer did not say it was closed.
    Unresolved,
    /// The provider confirmed the call is closed. The mark is written before the row is deleted,
    /// so a row that stands only as `Closed` needs no provider answer and no key.
    Closed,
}

impl CallState {
    /// The word the stored row carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Open => "open",
            Self::Closing => "closing",
            Self::Unresolved => "unresolved",
            Self::Closed => "closed",
        }
    }

    /// Reads the word a stored row carries.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "creating" => Some(Self::Creating),
            "open" => Some(Self::Open),
            "closing" => Some(Self::Closing),
            "unresolved" => Some(Self::Unresolved),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }

    /// Whether a row in this state stops another own-key call from starting.
    ///
    /// Only a `Closed` row is out of the way: every other state is a call that may still be
    /// running on the owner's account.
    #[must_use]
    pub const fn blocks_a_start(self) -> bool {
        !matches!(self, Self::Closed)
    }
}

/// What the host writes down when it is about to ask the provider for a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCall {
    /// The host's own name for the call, minted before the provider is asked.
    pub call_id: String,
    /// The host's own name for this attempt to create it.
    pub attempt_id: String,
    /// The action the device's `voice.start` was sent under.
    pub action_id: ActionId,
    /// The paired device that asked, as the host knows it.
    pub device_id: String,
    /// When the host asked, in milliseconds on the host's clock.
    pub asked_ms: u64,
    /// When the host will end the call by its own deadline.
    pub closes_at_ms: u64,
}

/// One stored call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallRow {
    /// What the host wrote down before it asked.
    pub call: NewCall,
    /// Where the call stands.
    pub state: CallState,
    /// The provider's session id, once the host has written it down.
    pub provider_session_id: Option<String>,
    /// When the provider said the call would expire, for information only: the provider's own
    /// record says this is not a deadline and says nothing about closure.
    pub provider_expires_ms: Option<u64>,
    /// When the host recorded the closure, once it did.
    pub closed_ms: Option<u64>,
}

/// A refusal of the ledger's store, in words that carry nothing the row held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerError(pub String);

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LedgerError {}

/// What the ledger answers.
pub type LedgerResult<T> = std::result::Result<T, LedgerError>;

/// The durable record of the host's own-key calls.
///
/// Every write is on the disk before it returns, because a call the host asked for and did not
/// write down is one it could not end. Each write names the call it is about and changes nothing
/// else.
pub trait OwnCallLedger: Send + Sync + fmt::Debug {
    /// Writes a `Creating` row for a call the host is about to ask the provider for.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal. Nothing was written, so the provider must not be asked.
    fn begin(&self, call: &NewCall) -> LedgerResult<()>;

    /// Writes the provider's session id and moves the row to `Open`.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal, or that no `Creating` row stands for the call.
    fn record_id(
        &self,
        call_id: &str,
        provider_session_id: &str,
        provider_expires_ms: Option<u64>,
    ) -> LedgerResult<()>;

    /// Moves the row to `Closing` or `Unresolved`.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal, that no row stands for the call, or that the state is not one
    /// of the two this writes: a closure is [`record_closed`](Self::record_closed).
    fn record_state(&self, call_id: &str, state: CallState) -> LedgerResult<()>;

    /// Marks the row `Closed` at `closed_ms`. The mark is written before the row is deleted.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal, or that no row stands for the call.
    fn record_closed(&self, call_id: &str, closed_ms: u64) -> LedgerResult<()>;

    /// Every stored row, oldest first.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal.
    fn rows(&self) -> LedgerResult<Vec<CallRow>>;

    /// Deletes one row. Deleting a row that is not there is not an error.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal.
    fn delete(&self, call_id: &str) -> LedgerResult<()>;

    /// Deletes every row and says how many there were.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal. Either every row is gone or none is.
    fn forget_all(&self) -> LedgerResult<u64>;
}
