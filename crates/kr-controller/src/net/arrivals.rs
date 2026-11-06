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
//!
//! A mutation is entered when the transport's reader has read it from the device's stream
//! ([`kr_transport::listener::HostHandler::frame_read`]), and not when the connection's handler
//! reaches it. It waits in the connection's queue, or is read ahead and held behind the request
//! being answered, and is on this host either way and will be carried out when its turn comes. The
//! entry travels with the frame, and leaves with the call or, if the frame is dropped unserved,
//! with the frame.
//!
//! A mutation the device has sent and the reader has not yet read from the stream has no entry.
//!
//! A close whose route cannot be recorded goes on without one, because a stop is let through when
//! storage fails, and its work continues on a task of its own after the connection has ended. The
//! task keeps the call's entry until it ends, so a copy of the close that arrives meanwhile finds
//! the entry in place of the route. When the work ends having reached the worker, the request is
//! kept as one that was carried out with no route ([`Arrival::settle_without_a_route`]), so a copy
//! that arrives later still finds something to read: the last [`UNROUTED_KEPT`] such closes, in
//! memory only. A close that never reached the worker did nothing and keeps nothing. A daemon that
//! restarts has none, and a copy of a close it carried out before the restart is asked as a
//! request the host never routed.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use kr_protocol::envelope::MutationRequest;
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::scalars::Digest256;

/// The request a call carries: the actor that sent it, its action identifier, and its payload.
pub(crate) type Carried = (ActorId, ActionId, Digest256);

/// The request `mutation` is, as the set of calls that have not yet claimed keeps it.
pub(crate) fn request_of(actor_id: &ActorId, mutation: &MutationRequest) -> Option<Carried> {
    kr_protocol::digest::mutation_digest(mutation, actor_id)
        .ok()
        .map(|digest| (actor_id.clone(), mutation.action_id, digest))
}

/// How many closes that were carried out with no route recorded are remembered, oldest first out.
/// Such a close needs storage to refuse a write that a stop is let through despite, so there are
/// few, and the bound is a ceiling for a store that fails for a long time.
pub(crate) const UNROUTED_KEPT: usize = 256;

/// The calls that have arrived and have not yet claimed the route of their action.
#[derive(Debug, Default)]
pub(crate) struct Arrivals {
    held: Mutex<HashMap<Carried, Vec<u64>>>,
    /// The requests of closes whose work has ended and which have no route, with the number of the
    /// call that carried each, newest last.
    unrouted: Mutex<VecDeque<(Carried, u64)>>,
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

    /// Whether a call other than `own` carries `request` and has not claimed its route, or a close
    /// of it, made by a call other than `own`, was carried out with no route.
    ///
    /// The call that made a close does not count itself, before or after its work has ended: a
    /// first close that is refused before anything is dispatched is refused as ever.
    pub(crate) fn another_carries(&self, request: &Carried, own: Option<&Arrival>) -> bool {
        let others = |call: &u64| own.is_none_or(|own| own.call != *call);
        let held = self
            .held()
            .get(request)
            .is_some_and(|calls| calls.iter().any(others));
        held || self
            .unrouted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(kept, call)| kept == request && others(call))
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

impl Arrival {
    /// Whether this entry is the one of `request`.
    pub(crate) fn carries(&self, request: &Carried) -> bool {
        self.request == *request
    }

    /// Keeps the request as one that was carried out with no route recorded, for the copies that
    /// arrive after the work that carried it out has ended and its entry has gone.
    pub(crate) fn settle_without_a_route(&self) {
        let mut unrouted = self
            .arrivals
            .unrouted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // One entry for each call that carried the request, so that a copy among them still meets
        // the entry of the call that settled before it.
        if !unrouted
            .iter()
            .any(|(kept, call)| *kept == self.request && *call == self.call)
        {
            unrouted.push_back((self.request.clone(), self.call));
        }
        while unrouted.len() > UNROUTED_KEPT {
            unrouted.pop_front();
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(number: usize) -> Carried {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&u64::try_from(number).expect("a number").to_le_bytes());
        (
            ActorId::new("device:test").expect("an actor"),
            ActionId::new(kr_protocol::scalars::Uuid::from_bytes(
                bytes[..16].try_into().expect("sixteen bytes"),
            )),
            Digest256::from_bytes(bytes),
        )
    }

    /// A close carried out with no route is kept after its work, for the copies that come later,
    /// and the call that made it is not one of them: a first close refused before anything is
    /// dispatched is refused as ever, whether its work has ended before it words the refusal or
    /// not.
    #[test]
    fn a_close_kept_without_a_route_is_a_copy_to_every_call_but_the_one_that_made_it() {
        let arrivals = Arc::new(Arrivals::default());
        let carried = request(1);
        let first = arrivals.arrive(carried.clone());
        assert!(!arrivals.another_carries(&carried, Some(&first)));

        first.settle_without_a_route();
        assert!(
            !arrivals.another_carries(&carried, Some(&first)),
            "the call does not count itself"
        );
        drop(first);
        let copy = arrivals.arrive(carried.clone());
        assert!(
            arrivals.another_carries(&carried, Some(&copy)),
            "a copy meets what the first kept"
        );
        assert!(
            !arrivals.another_carries(&request(2), Some(&copy)),
            "another request is not met"
        );
    }

    /// Two calls carry one close and neither records a route. Each settles when its work ends, and
    /// the call whose entry goes first still meets the other's.
    #[test]
    fn each_call_that_carried_a_close_meets_the_entries_of_the_others() {
        let arrivals = Arc::new(Arrivals::default());
        let carried = request(1);
        let first = arrivals.arrive(carried.clone());
        let second = arrivals.arrive(carried.clone());
        second.settle_without_a_route();
        first.settle_without_a_route();
        drop(first);
        assert!(
            arrivals.another_carries(&carried, Some(&second)),
            "the second call meets what the first kept"
        );
    }

    /// Only the last [`UNROUTED_KEPT`] closes are kept, oldest out.
    #[test]
    fn the_closes_kept_without_a_route_are_bounded() {
        let arrivals = Arc::new(Arrivals::default());
        for number in 0..=UNROUTED_KEPT {
            arrivals.arrive(request(number)).settle_without_a_route();
        }
        assert!(
            !arrivals.another_carries(&request(0), None),
            "the oldest is gone"
        );
        assert!(arrivals.another_carries(&request(1), None));
    }
}
