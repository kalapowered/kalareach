//! A member's lease on the host this device is paired with.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use kr_client::organisation::LeaseTimer;

use crate::account::Account;

/// Where the desk finds the account on this device, when it has one.
pub type AccountSource =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<Arc<Account>>> + Send>> + Send + Sync>;

/// What gets a member's lease for the connections of a device.
#[derive(Clone)]
pub struct LeaseDesk {
    _account: AccountSource,
    _timer: Arc<dyn LeaseTimer>,
}

impl LeaseDesk {
    /// A desk that finds the account with `account` and waits by `timer`.
    #[must_use]
    pub fn new(account: AccountSource, timer: Arc<dyn LeaseTimer>) -> Self {
        Self {
            _account: account,
            _timer: timer,
        }
    }
}
