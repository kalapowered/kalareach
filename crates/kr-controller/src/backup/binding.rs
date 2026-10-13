//! The account a host's backups belong to, as a request is held to it.
//!
//! The bundle that opens a restore is written under one account's token, and every object the host
//! uploads belongs to the principal that paid for it. A host that signed in as another account
//! after its setup would leave the bundle under one and the objects under the other, which no
//! restore could join, and a deletion asked of the service under the wrong account would be
//! answered "not found" and written down as done. A check before a pass does not help, because a
//! client asks for its token on each request, so the binding is made where the token is handed out.
//!
//! The binding is the committed setup's, and only that: a cell initialised from the setup row when
//! the store is opened and switched in the hold in which a setup commits. With no setup there is
//! nothing owed to an account yet and the cell is empty. It carries an epoch that every switch
//! advances, which a request in flight is held to: the carrier notes the epoch at the top of each
//! iteration, and a request that passed its checks before a replacement committed and asks for its
//! token after it is refused before it is signed.

use std::sync::{Arc, Mutex, PoisonError};

use kr_client::services::AccountMark;

tokio::task_local! {
    /// The epoch the carrier noted at the top of the iteration the task is in.
    pub(crate) static ITERATION_EPOCH: u64;
}

/// Runs `future` as one iteration of the carrier that noted `epoch` at its top, so that a request
/// inside it that asks for its token after the binding was switched is refused.
pub fn in_iteration<F: std::future::Future>(
    epoch: u64,
    future: F,
) -> impl std::future::Future<Output = F::Output> {
    ITERATION_EPOCH.scope(epoch, future)
}

/// What a request's token is checked against.
#[derive(Debug, Default)]
pub struct Binding {
    cell: Mutex<Cell>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Cell {
    mark: Option<AccountMark>,
    epoch: u64,
}

/// What the cell held when it was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The mark of the account the backups belong to, once a setup is committed.
    pub mark: Option<AccountMark>,
    /// How many times the binding has been switched.
    pub epoch: u64,
}

impl Binding {
    /// A binding with nothing owed to any account.
    #[must_use]
    pub fn unbound() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A binding of an account that was recorded, as the store opens it.
    #[must_use]
    pub fn of(mark: AccountMark) -> Arc<Self> {
        Arc::new(Self {
            cell: Mutex::new(Cell {
                mark: Some(mark),
                epoch: 0,
            }),
        })
    }

    /// What the cell holds now.
    #[must_use]
    pub fn read(&self) -> Bound {
        let cell = self.cell.lock().unwrap_or_else(PoisonError::into_inner);
        Bound {
            mark: cell.mark,
            epoch: cell.epoch,
        }
    }

    /// Switches the binding to the account of a setup that committed, and advances the epoch.
    ///
    /// Nothing else sets it, and it is set inside the hold of the store in which the setup
    /// committed.
    pub(super) fn switch(&self, mark: AccountMark) {
        let mut cell = self.cell.lock().unwrap_or_else(PoisonError::into_inner);
        cell.mark = Some(mark);
        cell.epoch = cell.epoch.saturating_add(1);
    }
}
