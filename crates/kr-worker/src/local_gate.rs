//! What this session's local owner may do, as the control daemon last told this worker.
//!
//! On a host that is exclusively organisation-managed the local owner answers to a membership
//! lease like a member (section 17): "expired membership blocks further organisation-mediated
//! reads and mutations even if the transport remains connected". The worker serves a local caller
//! directly, under its own authority, so the hold has to be here as well as at the control
//! daemon's door. This is the one place that decides it.
//!
//! The state is one of four. `Open` needs no lease. `Closed` has none live. `Until` has one, and
//! carries that lease's two ends together: the worker refuses at the earlier of them, the
//! continuous end by the machine's own clock and the UTC end through this worker's time contract,
//! which decides no copy that carries a UTC deadline when it maps no usable floor. `Unannounced`
//! is a worker its daemon has not yet told, or one whose daemon has changed since a lease was
//! told: it refuses what is held exactly as `Closed` does, because a bound that carries a lease
//! must not outlive the daemon that held the lease.
//!
//! Nothing here waits: a check is a read of the state under a lock that nothing else is taken
//! under, two clock reads and an atomic, so it can be made where a lock or a writer is held.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ControllerGeneration, RequestId};
use kr_protocol::worker::{LocalAccess, LocalBound};

use crate::action::time::{TimeContract, UtcDeadline};

/// What the worker holds of the control daemon's statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bound {
    /// Not told, or told by a daemon that is no longer the one speaking.
    Unannounced,
    /// No lease is needed.
    Open,
    /// A lease is needed and none is live.
    Closed,
    /// One lease is live, with its two ends.
    Until {
        boot_deadline_ms: u64,
        utc_deadline_ms: u64,
    },
}

/// Why a held method is refused to a local caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The control daemon has not said what the local owner may do.
    NotTold,
    /// The host is exclusively organisation-managed and no lease of its own key is live.
    Closed,
    /// The lease that was live has ended, or its end cannot be decided here.
    Ended,
}

impl Refused {
    /// What a person is told.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::NotTold => {
                "this host has not yet told this session what its local owner may do, so this \
                 request is refused until it has"
            }
            Self::Closed => {
                "this host is exclusively organisation-managed and its local owner's membership \
                 lease is not live; present one with `kr organisation present`"
            }
            Self::Ended => {
                "this host is exclusively organisation-managed and its local owner's membership \
                 lease has ended; present a new one with `kr organisation present`"
            }
        }
    }
}

/// What a held method is allowed, while it is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allowed {
    /// The earliest the work this allows may run to, on the machine's continuous clock in
    /// milliseconds since boot: the lease's continuous end, or its UTC end laid over the
    /// continuous clock at this moment, whichever is earlier. `None` when no lease bounds it.
    pub end_boot_ms: Option<u64>,
    /// The lease's UTC end, kept beside it so that work that waits (queued input) is checked
    /// against the UTC end again when it is about to be written. `None` when no lease bounds it.
    pub end_utc_ms: Option<u64>,
}

/// What applying a statement of the control daemon did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The statement is now the state. `tightened` is whether it takes access away that the state
    /// before it gave: a move to `Closed`, to an earlier end, or from `Open` to a lease. The
    /// local connections that hold something are withdrawn then.
    Accepted {
        /// Whether the statement takes away access the state before it gave.
        tightened: bool,
    },
    /// A statement the worker already holds, or an older one of the same generation: the worker
    /// answers with the sequence it holds.
    Stale {
        /// The sequence the worker holds.
        held: u64,
    },
    /// The same sequence with another content: refused.
    Conflict,
}

#[derive(Debug)]
struct Inner {
    bound: Bound,
    /// The generation whose statement `bound` is, when one has been told.
    generation: Option<ControllerGeneration>,
    /// The sequence of that statement.
    sequence: u64,
}

/// The gate. One per worker, shared by its connections and its writers.
pub struct LocalGate {
    inner: Mutex<Inner>,
    clock: Arc<dyn kr_ipc::clock::SharedClock>,
    time: Arc<TimeContract>,
    /// How many times the state has been restricted: a move to `Closed`, `Unannounced`, an
    /// earlier end, or from `Open` to a lease. A mutation that passed the gate under one state and
    /// is dispatched under a later restriction is refused.
    restrictions: AtomicU64,
}

impl std::fmt::Debug for LocalGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalGate")
            .field("inner", &self.inner)
            .field("restrictions", &self.restrictions)
            .finish_non_exhaustive()
    }
}

impl LocalGate {
    /// A gate that needs no lease, for a worker no control daemon tells (a test, a tool).
    #[must_use]
    pub fn open(clock: Arc<dyn kr_ipc::clock::SharedClock>, time: Arc<TimeContract>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                bound: Bound::Open,
                generation: None,
                sequence: 0,
            }),
            clock,
            time,
            restrictions: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Makes this worker refuse what is held until its daemon has said what is allowed: the state
    /// of a worker whose launch specification says its daemon tells workers.
    pub fn hold_until_told(&self) {
        let mut inner = self.lock();
        inner.bound = Bound::Unannounced;
        inner.generation = None;
        inner.sequence = 0;
    }

    /// How many times the state has been restricted.
    #[must_use]
    pub fn restrictions(&self) -> u64 {
        self.restrictions.load(Ordering::Acquire)
    }

    /// Whether a held method is allowed to a local caller now, and to what end.
    ///
    /// # Errors
    ///
    /// Returns why it is refused.
    pub fn check(&self) -> Result<Allowed, Refused> {
        let bound = self.lock().bound;
        match bound {
            Bound::Open => Ok(Allowed {
                end_boot_ms: None,
                end_utc_ms: None,
            }),
            Bound::Unannounced => Err(Refused::NotTold),
            Bound::Closed => Err(Refused::Closed),
            Bound::Until {
                boot_deadline_ms,
                utc_deadline_ms,
            } => {
                // The machine's continuous clock is read first and the wall clock after it, so a
                // pause between the two readings shortens the time laid over the first and never
                // lengthens it.
                let boot_now = self.clock.boot_elapsed_ms();
                if boot_now >= boot_deadline_ms {
                    return Err(Refused::Ended);
                }
                // The worker decides no copy that carries a UTC deadline when it maps no usable
                // floor, and one passed at a reading not yet on record is not an expiry the host
                // has established: both refuse here, as they do for a forwarded copy.
                if self.time.check_utc_deadline(utc_deadline_ms) != UtcDeadline::Ahead {
                    return Err(Refused::Ended);
                }
                // The UTC remainder laid over the continuous clock as read above. Whichever end is
                // earlier decides how long the work this allows may run.
                let remaining = utc_deadline_ms.saturating_sub(self.time.settled_utc_ms());
                let laid = boot_now.saturating_add(remaining);
                Ok(Allowed {
                    end_boot_ms: Some(boot_deadline_ms.min(laid)),
                    end_utc_ms: Some(utc_deadline_ms),
                })
            }
        }
    }

    /// Applies the statement of the generation that holds this worker's authority.
    pub fn apply(&self, generation: ControllerGeneration, access: LocalAccess) -> Applied {
        let mut inner = self.lock();
        let sequence = access.sequence.get();
        let incoming = match access.bound {
            LocalBound::Open => Bound::Open,
            LocalBound::Closed => Bound::Closed,
            LocalBound::Until {
                boot_deadline_ms,
                utc_deadline_ms,
            } => Bound::Until {
                boot_deadline_ms: boot_deadline_ms.get(),
                utc_deadline_ms: utc_deadline_ms.get(),
            },
        };
        let same_generation = inner.generation == Some(generation);
        if same_generation && sequence < inner.sequence {
            return Applied::Stale {
                held: inner.sequence,
            };
        }
        if same_generation && sequence == inner.sequence {
            return if inner.bound == incoming {
                Applied::Stale { held: sequence }
            } else {
                Applied::Conflict
            };
        }
        let tightened = tightens(inner.bound, incoming);
        inner.bound = incoming;
        inner.generation = Some(generation);
        inner.sequence = sequence;
        drop(inner);
        if tightened {
            self.restrictions.fetch_add(1, Ordering::AcqRel);
        }
        Applied::Accepted { tightened }
    }

    /// A newer controller generation has been accepted. A bound that carries a lease does not
    /// outlive the daemon that held the lease, so it becomes `Unannounced`; `Open` and `Closed`
    /// carry none and stay until the new generation's first statement. Returns whether access was
    /// taken away, and the local connections that hold something are withdrawn then.
    pub fn generation_accepted(&self, generation: ControllerGeneration) -> bool {
        let mut inner = self.lock();
        if inner.generation == Some(generation) {
            return false;
        }
        inner.generation = Some(generation);
        inner.sequence = 0;
        let tightened = matches!(inner.bound, Bound::Until { .. });
        if tightened {
            inner.bound = Bound::Unannounced;
        }
        drop(inner);
        if tightened {
            self.restrictions.fetch_add(1, Ordering::AcqRel);
        }
        tightened
    }
}

/// Whether moving from `before` to `after` takes away access `before` gave.
fn tightens(before: Bound, after: Bound) -> bool {
    match (before, after) {
        (Bound::Closed | Bound::Unannounced, _) => false,
        (_, Bound::Closed | Bound::Unannounced) => true,
        (Bound::Open, Bound::Until { .. }) => true,
        (
            Bound::Until {
                boot_deadline_ms: before_boot,
                utc_deadline_ms: before_utc,
            },
            Bound::Until {
                boot_deadline_ms: after_boot,
                utc_deadline_ms: after_utc,
            },
        ) => after_boot < before_boot || after_utc < before_utc,
        (Bound::Until { .. }, Bound::Open) | (Bound::Open, Bound::Open) => false,
    }
}

/// What the writer does with a frame bound for a local connection.
#[derive(Debug)]
pub enum Verdict {
    /// Write it as it is.
    Write,
    /// Write this in its place: the refusal of a held request whose answer the host no longer
    /// shows. The effect, if it was one, stays recorded.
    Replace(Box<ControlFrame>),
    /// Do not write it, and withdraw the connection: it is a stream frame, or a response that
    /// cannot be replaced.
    Stop,
}

/// What holds one connection's frames to the local owner's lease, at the writer.
///
/// Every frame a local connection is sent passes the writer, so this is where no path is left
/// unchecked: a response produced late (a launch or an upstream operation answered later), a
/// retained result, an ordinary read, and the frames of a subscription or an attachment's output.
/// A response is refused in place of its result only when it answers a held request, which the
/// connection recorded when it read the request; a frame of a stream is not written at all, and
/// the connection is withdrawn.
pub struct LocalWrites {
    gate: Arc<LocalGate>,
    local: std::sync::atomic::AtomicBool,
    /// The requests read on this connection that are waiting for their answer, by identifier, and
    /// how many of each kind. Clients choose identifiers and this worker does not check that they
    /// are unique, so a response cannot say which request it answers: when an identifier is in use
    /// by a held request, the response is treated as the held one's, which refuses more and never
    /// less.
    waiting: Mutex<std::collections::BTreeMap<RequestId, Waiting>>,
    withdraw: Arc<dyn Fn() + Send + Sync>,
}

/// The requests of one identifier that are waiting for their answer.
#[derive(Clone, Copy, Debug, Default)]
struct Waiting {
    /// How many of them answer to the lease.
    held: u32,
    /// How many do not.
    free: u32,
}

impl std::fmt::Debug for LocalWrites {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalWrites")
            .field("local", &self.is_local())
            .finish_non_exhaustive()
    }
}

impl LocalWrites {
    /// A record for a connection that has not yet said what it is. `withdraw` ends what the
    /// connection holds; it is called from a task of its own, never under a lock.
    #[must_use]
    pub fn new(gate: Arc<LocalGate>, withdraw: Arc<dyn Fn() + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            gate,
            local: std::sync::atomic::AtomicBool::new(false),
            waiting: Mutex::new(std::collections::BTreeMap::new()),
            withdraw,
        })
    }

    /// Records whether the connection is a local client, as its hello says.
    pub fn set_local(&self, local: bool) {
        self.local.store(local, Ordering::Release);
    }

    /// Whether the connection is a local client.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.local.load(Ordering::Acquire)
    }

    fn waiting(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<RequestId, Waiting>> {
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records a request that is waiting for its answer and does not answer to the lease, as every
    /// request is until it is known to be a held one that the lease admits. A connection that is
    /// not a local client records nothing.
    pub fn free_request(&self, request_id: RequestId) {
        if self.is_local() {
            self.waiting().entry(request_id).or_default().free += 1;
        }
    }

    /// Records that a request recorded by [`Self::free_request`] answers to the lease, so its
    /// answer is held to it when written.
    pub fn hold_request(&self, request_id: RequestId) {
        if self.is_local() {
            let mut waiting = self.waiting();
            let entry = waiting.entry(request_id).or_default();
            entry.free = entry.free.saturating_sub(1);
            entry.held += 1;
        }
    }

    /// Decides what to do with `frame`, under the writer.
    #[must_use]
    pub fn verdict(&self, frame: &ControlFrame) -> Verdict {
        if !self.is_local() {
            return Verdict::Write;
        }
        let Err(refused) = self.gate.check() else {
            return Verdict::Write;
        };
        match frame {
            // A frame of a stream carries session content: it is not written, and the connection
            // ends what it holds.
            ControlFrame::Notification(_) => Verdict::Stop,
            ControlFrame::Response(response) => {
                let held = self
                    .waiting()
                    .get(&response.request_id)
                    .is_some_and(|waiting| waiting.held > 0);
                if !held {
                    return Verdict::Write;
                }
                Verdict::Replace(Box::new(ControlFrame::Response(Response {
                    request_id: response.request_id,
                    outcome: Outcome::Error(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        format!(
                            "{} The result of this request is withheld. If it changed anything, \
                             the change stands, and the request is not to be repeated under a new \
                             identifier.",
                            refused.detail()
                        ),
                    )),
                })))
            }
            // The opening exchange, the host's own keep-alive and window renewal, and any other
            // frame that carries no session content.
            _ => Verdict::Write,
        }
    }

    /// Notes that the final answer to a request recorded here has been dealt with, written or
    /// replaced, and says which kind of request it was. The count that goes down is that kind's:
    /// the request itself knows whether the lease admitted it as a held method, so a request of
    /// another kind under the same identifier is never counted off for it. A response to a frame
    /// that carries no recorded request counts nothing off.
    pub fn answered(&self, request_id: RequestId, held: bool) {
        let mut waiting = self.waiting();
        if let Some(entry) = waiting.get_mut(&request_id) {
            if held {
                entry.held = entry.held.saturating_sub(1);
            } else {
                entry.free = entry.free.saturating_sub(1);
            }
            if entry.held == 0 && entry.free == 0 {
                waiting.remove(&request_id);
            }
        }
    }

    /// Withdraws the connection, from a task of its own: the writer that asks is holding the
    /// connection's writer, which a withdrawal takes.
    pub fn withdraw_soon(&self) {
        let withdraw = Arc::clone(&self.withdraw);
        tokio::spawn(async move { withdraw() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_ipc::clock::SharedClock as _;
    use kr_protocol::scalars::U64;

    fn gate() -> LocalGate {
        LocalGate::open(
            Arc::new(kr_ipc::clock::SystemSharedClock),
            Arc::new(TimeContract::system(
                kr_ipc::identity::boot_identity().expect("a boot identity"),
                "test",
            )),
        )
    }

    fn statement(sequence: u64, bound: LocalBound) -> LocalAccess {
        LocalAccess {
            sequence: U64::new(sequence),
            bound,
        }
    }

    fn generation(n: u64) -> ControllerGeneration {
        ControllerGeneration::new(n)
    }

    /// A worker that is told nothing refuses what is held once it is made to wait, serves it when
    /// it is told `Open`, and refuses it again when told `Closed`; a statement of a lower sequence
    /// or the same one changes nothing, and the same sequence with another content is a conflict.
    #[test]
    fn the_gate_follows_the_statements_of_its_daemon_in_order() {
        let gate = gate();
        gate.hold_until_told();
        assert_eq!(gate.check(), Err(Refused::NotTold));
        let first = generation(1);
        assert_eq!(
            gate.apply(first, statement(1, LocalBound::Open)),
            Applied::Accepted { tightened: false }
        );
        assert!(gate.check().is_ok());
        assert_eq!(
            gate.apply(first, statement(2, LocalBound::Closed)),
            Applied::Accepted { tightened: true }
        );
        assert_eq!(gate.check(), Err(Refused::Closed));
        assert_eq!(
            gate.apply(first, statement(1, LocalBound::Open)),
            Applied::Stale { held: 2 }
        );
        assert_eq!(gate.check(), Err(Refused::Closed));
        assert_eq!(
            gate.apply(first, statement(2, LocalBound::Closed)),
            Applied::Stale { held: 2 }
        );
        assert_eq!(
            gate.apply(first, statement(2, LocalBound::Open)),
            Applied::Conflict
        );
        // A newer generation replaces the state whatever its sequence.
        assert_eq!(
            gate.apply(generation(2), statement(1, LocalBound::Open)),
            Applied::Accepted { tightened: false }
        );
        assert!(gate.check().is_ok());
    }

    /// A lease bound does not outlive the daemon that told it; `Open` and `Closed` carry no lease
    /// and stay; a connection of the generation already accepted changes nothing.
    #[test]
    fn a_newer_generation_turns_only_a_lease_bound_into_waiting() {
        let gate = gate();
        let far = kr_ipc::clock::SystemSharedClock.boot_elapsed_ms() + 3_600_000;
        gate.hold_until_told();
        let first = generation(1);
        assert!(!gate.generation_accepted(first));
        gate.apply(
            first,
            statement(
                1,
                LocalBound::Until {
                    boot_deadline_ms: U64::new(far),
                    utc_deadline_ms: U64::new(u64::MAX),
                },
            ),
        );
        // No floor is mapped here, so a lease bound is refused by the UTC check; what this shows
        // is the state change, not the check.
        assert!(!gate.generation_accepted(first), "the same generation");
        assert!(gate.generation_accepted(generation(2)), "a lease is taken");
        assert_eq!(gate.check(), Err(Refused::NotTold));

        gate.apply(generation(2), statement(1, LocalBound::Open));
        assert!(!gate.generation_accepted(generation(3)), "Open stays");
        assert!(gate.check().is_ok());
        gate.apply(generation(3), statement(1, LocalBound::Closed));
        assert!(!gate.generation_accepted(generation(4)), "Closed stays");
        assert_eq!(gate.check(), Err(Refused::Closed));
    }

    /// A move that takes access away is counted as a restriction, so a request admitted before it
    /// and dispatched after it is refused, and a move to a later end or to `Open` is not.
    #[test]
    fn a_restriction_is_a_move_that_takes_access_away() {
        let gate = gate();
        let g = generation(1);
        let until = |boot: u64, utc: u64| LocalBound::Until {
            boot_deadline_ms: U64::new(boot),
            utc_deadline_ms: U64::new(utc),
        };
        let counted = |before: u64| gate.restrictions() > before;
        let before = gate.restrictions();
        gate.apply(g, statement(1, until(100, 100)));
        assert!(counted(before), "Open to a lease");
        let before = gate.restrictions();
        gate.apply(g, statement(2, until(200, 200)));
        assert!(!counted(before), "a later end");
        gate.apply(g, statement(3, until(150, 200)));
        assert!(counted(before), "an earlier continuous end");
        let before = gate.restrictions();
        gate.apply(g, statement(4, until(150, 100)));
        assert!(counted(before), "an earlier UTC end");
        let before = gate.restrictions();
        gate.apply(g, statement(5, LocalBound::Open));
        assert!(!counted(before), "Open gives more");
        gate.apply(g, statement(6, LocalBound::Closed));
        assert!(counted(before), "Closed");
        let before = gate.restrictions();
        gate.apply(g, statement(7, LocalBound::Open));
        assert!(!counted(before), "Closed to Open");
    }

    fn response(request_id: u64) -> ControlFrame {
        ControlFrame::Response(Response {
            request_id: RequestId::new(request_id),
            outcome: Outcome::Ok(kr_protocol::envelope::ParamsValue::empty()),
        })
    }

    /// Once the lease is over, a frame of a stream is not written, the answer to a held request
    /// is replaced by its refusal, and the answer to a request that is not held is written.
    #[test]
    fn after_the_end_the_writer_stops_streams_and_replaces_the_answer_to_a_held_request() {
        let gate = Arc::new(gate());
        gate.apply(generation(1), statement(1, LocalBound::Closed));
        let writes = LocalWrites::new(Arc::clone(&gate), Arc::new(|| {}));
        writes.set_local(true);
        writes.free_request(RequestId::new(7));
        writes.hold_request(RequestId::new(7));
        writes.free_request(RequestId::new(8));
        assert!(matches!(writes.verdict(&response(7)), Verdict::Replace(_)));
        assert!(matches!(writes.verdict(&response(8)), Verdict::Write));
        assert!(matches!(
            writes.verdict(&ControlFrame::Notification(
                kr_protocol::envelope::Notification {
                    stream_id: kr_protocol::ids::StreamId::new("test".to_owned())
                        .expect("a stream identifier"),
                    sequence: kr_protocol::ids::EventSequence::new(1),
                    event_type: kr_protocol::ids::EventType::new("session.output")
                        .expect("an event type"),
                    payload: kr_protocol::envelope::ParamsValue::empty(),
                }
            )),
            Verdict::Stop
        ));
    }

    /// A client may reuse a request identifier, and an answer cannot say which request it answers.
    /// While a held request waits under an identifier, no answer of that identifier is taken for
    /// a request that is not held, and a request of the other kind that ends first counts off its
    /// own kind only, so a held request's answer is never written for want of its mark and no
    /// mark outlives the requests it was made for.
    #[test]
    fn a_request_counts_off_its_own_kind_and_a_held_requests_mark_outlives_the_others() {
        let gate = Arc::new(gate());
        gate.apply(generation(1), statement(1, LocalBound::Closed));
        let writes = LocalWrites::new(Arc::clone(&gate), Arc::new(|| {}));
        writes.set_local(true);
        // A held request waits for a launch; a request of the same identifier that is not held
        // is read and answered meanwhile.
        writes.free_request(RequestId::new(7));
        writes.hold_request(RequestId::new(7));
        writes.free_request(RequestId::new(7));
        writes.answered(RequestId::new(7), false);
        assert!(
            matches!(writes.verdict(&response(7)), Verdict::Replace(_)),
            "the held request's answer, written after the end, is replaced"
        );
        writes.answered(RequestId::new(7), true);
        assert!(
            matches!(writes.verdict(&response(7)), Verdict::Write),
            "and once every request of the identifier is answered nothing is held under it"
        );

        // The held request ends first: the one that is not held is left, and is not taken for it.
        writes.free_request(RequestId::new(9));
        writes.hold_request(RequestId::new(9));
        writes.free_request(RequestId::new(9));
        writes.answered(RequestId::new(9), true);
        assert!(
            matches!(writes.verdict(&response(9)), Verdict::Write),
            "what is left under the identifier is a request that is not held"
        );
        writes.answered(RequestId::new(9), false);
        assert!(matches!(writes.verdict(&response(9)), Verdict::Write));
    }
}
