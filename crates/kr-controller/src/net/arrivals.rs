//! The mutations a paired device has sent that this host is serving and has not yet routed.
//!
//! A host claims the route of an action before it dispatches it, and that route is how it knows, when
//! it refuses a repeat on its own account, that an earlier copy may have been carried out. A copy
//! that is still before its own claim has left no route. The repeat that meets it is refused with
//! nothing to read, and a definite refusal tells the device the action did not happen, although the
//! copy goes on to claim and carry it out.
//!
//! This set is what the route cannot say yet. A call is entered when it arrives and leaves when it
//! has claimed the route of its action or has ended, so it holds as many entries as there are calls
//! in progress, and none for a call that has gone: not for one that was refused, and not for one
//! whose connection ended and whose work was dropped. It is kept in memory only. A daemon that
//! restarts has no call before its claim, and a call before its claim has dispatched nothing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::scalars::Digest256;

/// The request a call carries: the actor that sent it, its action identifier, and its payload.
pub(crate) type Carried = (ActorId, ActionId, Digest256);

/// The calls that have arrived and have not yet claimed the route of their action.
#[derive(Debug, Default)]
pub(crate) struct Arrivals {
    held: Mutex<HashMap<Carried, Vec<u64>>>,
    next: AtomicU64,
}

impl Arrivals {
    /// Enters a call that carries `request`, until the returned entry is released or dropped.
    pub(crate) fn arrive(self: &Arc<Self>, request: Carried) -> Arrival {
        let call = self.next.fetch_add(1, Ordering::Relaxed);
        self.held().entry(request.clone()).or_default().push(call);
        Arrival {
            arrivals: Arc::clone(self),
            request,
            call,
        }
    }

    /// Whether a call other than `own` carries `request` and has not claimed its route.
    pub(crate) fn another_carries(&self, request: &Carried, own: Option<&Arrival>) -> bool {
        self.held().get(request).is_some_and(|calls| {
            calls
                .iter()
                .any(|call| own.is_none_or(|own| own.call != *call))
        })
    }

    fn held(&self) -> std::sync::MutexGuard<'_, HashMap<Carried, Vec<u64>>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The number of calls entered, for a test of the bound.
    #[cfg(test)]
    pub(crate) fn entered(&self) -> usize {
        self.held().values().map(Vec::len).sum()
    }
}

/// One call's entry in [`Arrivals`], which leaves the set when it is dropped.
#[derive(Debug)]
pub(crate) struct Arrival {
    arrivals: Arc<Arrivals>,
    request: Carried,
    call: u64,
}

impl Drop for Arrival {
    fn drop(&mut self) {
        let mut held = self.arrivals.held();
        if let Some(calls) = held.get_mut(&self.request) {
            calls.retain(|call| *call != self.call);
            if calls.is_empty() {
                held.remove(&self.request);
            }
        }
    }
}
