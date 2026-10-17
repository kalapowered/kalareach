//! Telling session workers what the host's local owner may do (section 17).
//!
//! On a host that is exclusively organisation-managed the local owner answers to a membership
//! lease like a member, and a session's worker serves a local caller directly, so the worker has
//! to hold the same line the daemon's door holds. This daemon says what the local owner may do,
//! in a statement of its own ([`LocalAccess`]) that carries a sequence, to every worker that
//! states it can take one.
//!
//! Every sender computes the bound under the policy's lock and draws a new sequence only when it
//! differs from the last one drawn, and sends that pair: none sends a pair it stored earlier. A
//! worker is told after it is a participant of every barrier (it has a registry row), before it
//! is visible to clients, and again whenever the bound changes, until it acknowledges.

use std::collections::BTreeMap;
use std::sync::Mutex;

use kr_ipc::client::BoundLink;
use kr_protocol::ids::{DeviceId, SessionId};
use kr_protocol::scalars::U64;
use kr_protocol::worker::{LocalAccess, LocalBound};

use super::Controller;
use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};
use crate::grants::policy::LocalOwnerBound;

/// How long the publisher waits before it looks at the workers again when nothing woke it.
const REPEAT: std::time::Duration = std::time::Duration::from_secs(2);

/// What this daemon has said, and what each worker has said back.
#[derive(Debug, Default)]
pub(crate) struct LocalAccessState {
    drawn: Mutex<Drawn>,
    /// What this daemon knows of each worker: whether it states `local.access/1`, and the
    /// highest sequence it has acknowledged.
    workers: Mutex<BTreeMap<SessionId, Worker>>,
    wake: std::sync::Arc<tokio::sync::Notify>,
    /// The launches this run of the daemon made: a worker born from one of these starts holding
    /// its local owner to the lease until it is told, so an enablement need not wait for it.
    launching: Mutex<std::collections::BTreeSet<kr_protocol::worker::ReservationId>>,
}

#[derive(Debug, Default)]
struct Drawn {
    sequence: u64,
    /// What the policy said when the last statement was drawn, and the statement drawn for it.
    /// A statement is converted for the worker once for each distinct answer of the policy, and
    /// sent again unchanged: converting an unchanged lease again would read two clocks at two
    /// moments and differ by a millisecond, which a worker takes for a lease that ends sooner.
    last: Option<(LocalOwnerBound, LocalAccess)>,
}

/// What this daemon knows of one worker's side of the statement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Worker {
    /// Whether its hello answer stated `local.access/1`: `None` while no link to it has been
    /// opened, which counts as lacking it wherever the answer matters.
    pub states: Option<bool>,
    /// The highest sequence it acknowledged.
    pub acknowledged: u64,
}

impl LocalAccessState {
    /// Wakes the publisher: something the bound is computed from changed.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    fn lock_drawn(&self) -> std::sync::MutexGuard<'_, Drawn> {
        self.drawn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_workers(&self) -> std::sync::MutexGuard<'_, BTreeMap<SessionId, Worker>> {
        self.workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Draws the statement for `owner`: the last one again when the policy's answer has not
    /// changed, the next one otherwise, converted by `convert` only in that case. Called with the
    /// policy's lock held, so the pair is drawn in the order the policy changes.
    fn draw(&self, owner: LocalOwnerBound, convert: impl FnOnce() -> LocalBound) -> LocalAccess {
        let mut drawn = self.lock_drawn();
        if let Some((held, statement)) = drawn.last
            && held == owner
        {
            return statement;
        }
        drawn.sequence += 1;
        let statement = LocalAccess {
            sequence: U64::new(drawn.sequence),
            bound: convert(),
        };
        drawn.last = Some((owner, statement));
        statement
    }

    /// Records what a worker's hello said and what it acknowledged.
    pub(crate) fn note_worker(
        &self,
        session_id: SessionId,
        states: bool,
        acknowledged: Option<u64>,
    ) {
        let mut workers = self.lock_workers();
        let worker = workers.entry(session_id).or_default();
        worker.states = Some(states);
        if let Some(sequence) = acknowledged {
            worker.acknowledged = worker.acknowledged.max(sequence);
        }
    }

    /// Records a launch this run of the daemon is making.
    pub(crate) fn launching(&self, reservation_id: kr_protocol::worker::ReservationId) {
        self.launching
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(reservation_id);
    }

    fn made_here(&self, reservation_id: kr_protocol::worker::ReservationId) -> bool {
        self.launching
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&reservation_id)
    }

    /// Notes that a worker exists and has not (yet) been heard from.
    pub(crate) fn touch(&self, session_id: SessionId) {
        self.lock_workers().entry(session_id).or_default();
    }

    /// What is known of a worker.
    pub(crate) fn worker(&self, session_id: SessionId) -> Worker {
        self.lock_workers()
            .get(&session_id)
            .copied()
            .unwrap_or_default()
    }
}

impl Controller {
    /// The device identity the host's local owner presents a lease as.
    pub(crate) fn local_owner_device(&self) -> DeviceId {
        DeviceId::new(self.paths.environment_id().get())
    }

    /// What the host's local owner may do now, as the statement to send: the bound computed under
    /// the policy's lock, and the sequence drawn with it.
    pub(crate) fn local_access_now(&self) -> LocalAccess {
        // The continuous clock first, then the wall clock: see `protocol_bound`.
        let now = self.clock.now();
        let now_ms = self.settled_utc_now();
        let policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bound = policy.local_owner_bound(self.local_owner_device(), now, now_ms);
        self.local_access.draw(bound, || self.protocol_bound(bound))
    }

    /// What the host's local owner may do now.
    pub(crate) fn local_owner_bound_now(&self) -> LocalOwnerBound {
        let now = self.clock.now();
        let now_ms = self.settled_utc_now();
        self.policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .local_owner_bound(self.local_owner_device(), now, now_ms)
    }

    /// Whether the host is exclusively organisation-managed and its local owner has no live
    /// lease: what a local caller may then ask for is the recovery set and nothing else.
    pub(crate) fn local_owner_is_closed(&self) -> bool {
        self.local_owner_bound_now() == LocalOwnerBound::Closed
    }

    /// Holds a local caller's use of `method` to the local owner's membership lease, at the
    /// daemon's door.
    ///
    /// A method the host does not hold to the lease ([`kr_protocol::method::local_hold`]) is served
    /// whatever the lease says, and so is every method on a host that is not exclusively
    /// organisation-managed. Otherwise the lease must be live, and the work it admits may run no
    /// longer than the lease does: the earlier of its continuous end and its UTC end laid over the
    /// continuous clock now.
    ///
    /// # Errors
    ///
    /// Returns the refusal of a held method when no lease is live.
    pub(crate) fn local_hold(
        &self,
        method: kr_protocol::method::Method,
    ) -> Result<Option<kr_transport::clock::ContinuousInstant>> {
        if kr_protocol::method::local_hold(method) == kr_protocol::method::LocalHold::Free {
            return Ok(None);
        }
        // The continuous clock is read first and the wall clock after it, so a pause between the
        // two readings shortens the time laid over the continuous clock and never lengthens it.
        let now = self.clock.now();
        let now_ms = self.settled_utc_now();
        let bound = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .local_owner_bound(self.local_owner_device(), now, now_ms);
        match bound {
            LocalOwnerBound::Open => Ok(None),
            LocalOwnerBound::Closed => Err(ControllerError::PermissionDenied {
                detail: "this host is exclusively organisation-managed and its local owner's \
                         membership lease is not live; present one with `kr organisation present`"
                    .to_owned(),
            }),
            LocalOwnerBound::Until { continuous, utc_ms } => {
                let remaining = std::time::Duration::from_millis(utc_ms.saturating_sub(now_ms));
                let laid = now.checked_add(remaining).unwrap_or(continuous);
                Ok(Some(continuous.min(laid)))
            }
        }
    }

    /// A request that a held read must be refused at the door, once the local owner's lease is no
    /// longer live, as the reply to send.
    pub(crate) fn read_refused(
        &self,
        request: &kr_protocol::envelope::Request,
    ) -> Option<kr_protocol::envelope::ControlFrame> {
        let method = request.method.method()?;
        let error = self.local_hold(method).err()?;
        Some(super::error_reply(
            request.request_id,
            error.code(),
            error.to_string(),
        ))
    }

    /// The caller a local request is decided as for pairing and owner confirmation: the host's own
    /// account, limited to the recovery set while the local owner has no live lease.
    pub(crate) fn local_caller(
        &self,
        actor_id: &kr_protocol::ids::ActorId,
    ) -> super::net::owner::Caller {
        super::net::owner::Caller::local(actor_id.clone())
            .confirming_recovery_only(self.local_owner_is_closed())
    }

    /// The bound as a worker is told it: the lease's continuous end laid over the machine's own
    /// boot clock, which the worker reads.
    fn protocol_bound(&self, bound: LocalOwnerBound) -> LocalBound {
        match bound {
            LocalOwnerBound::Open => LocalBound::Open,
            LocalOwnerBound::Closed => LocalBound::Closed,
            LocalOwnerBound::Until { continuous, utc_ms } => {
                // The clock the worker reads is read first and the daemon's after it, so a pause
                // between the two readings shortens what is laid over the first and never
                // lengthens it.
                let boot_now = self.shared_clock.boot_elapsed_ms();
                let remaining = continuous.saturating_duration_since(self.clock.now());
                let boot_ms = boot_now
                    .saturating_add(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX));
                LocalBound::Until {
                    boot_deadline_ms: U64::new(boot_ms),
                    utc_deadline_ms: U64::new(utc_ms),
                }
            }
        }
    }

    /// Tells the worker behind `client` what the local owner may do, and settles: it is told again
    /// until the sequence it acknowledged is the one in force. A worker whose level cannot read the
    /// statement is sent nothing, and its link goes on.
    ///
    /// Returns the sequence the worker acknowledged, or nothing for a worker that cannot be told.
    pub(crate) async fn tell_link(
        &self,
        session_id: SessionId,
        client: &mut BoundLink,
    ) -> Result<Option<u64>> {
        let mut frame = self.local_access_now();
        #[cfg(test)]
        self.after_the_local_access_is_drawn.wait().await;
        loop {
            let ack = match client.announce_local_access(frame).await {
                Ok(ack) => ack,
                Err(kr_ipc::IpcError::NotInLevel(_)) => {
                    self.local_access.note_worker(session_id, false, None);
                    return Ok(None);
                }
                Err(error) => return Err(ControllerError::from(error)),
            };
            let held = ack.sequence.get();
            if held < frame.sequence.get() {
                return Err(ControllerError::supervision(
                    "a worker holds an older statement of what the local owner may do than the \
                     one it was sent",
                ));
            }
            self.local_access
                .note_worker(session_id, true, Some(frame.sequence.get()));
            let now = self.local_access_now();
            if now.sequence == frame.sequence {
                return Ok(Some(held));
            }
            frame = now;
        }
    }

    /// Tells a worker the directory lists, over the daemon's pooled link to it.
    pub(crate) async fn tell_worker(&self, worker: &KnownWorker) -> Result<()> {
        let session_id = worker.descriptor.session_id;
        let mut link = self.worker_client(worker).await?;
        match self.tell_link(session_id, link.client()).await {
            Ok(_) => {
                link.give_back();
                Ok(())
            }
            // The link is dropped, not returned: a failed exchange leaves a stream position
            // nothing knows.
            Err(error) => Err(error),
        }
    }

    /// Tells every worker the directory lists that has not acknowledged the statement in force.
    /// One whose hello has not been read is reached by opening the link, which learns it; one
    /// known to lack the capability is sent nothing.
    pub(crate) async fn tell_workers(&self) {
        let current = self.local_access_now().sequence.get();
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        for worker in workers {
            let known = self.local_access.worker(worker.descriptor.session_id);
            match known.states {
                Some(false) => continue,
                Some(true) if known.acknowledged >= current => continue,
                _ => {}
            }
            self.local_access.touch(worker.descriptor.session_id);
            let _ =
                tokio::time::timeout(super::workers::WORKER_EXCHANGE, self.tell_worker(&worker))
                    .await;
        }
    }

    /// The sessions whose workers cannot be told what the local owner may do, as the registry
    /// stands: every recorded worker that has not been told (one never reached counts as lacking
    /// it), and every claimed or fenced reservation that this run of the daemon did not make,
    /// whose worker may still be alive.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the rows cannot be read.
    pub(crate) fn workers_without_local_enforcement_in(
        &self,
        registry: &crate::registry::Registry,
    ) -> Result<Vec<SessionId>> {
        use crate::registry::LaunchPhase;
        let mut lacking = std::collections::BTreeSet::new();
        for worker in registry.workers()? {
            if self.local_access.worker(worker.session_id).states != Some(true) {
                lacking.insert(worker.session_id);
            }
        }
        for phase in [LaunchPhase::Claimed, LaunchPhase::Fenced] {
            for reservation in registry.reservations_in(phase)? {
                // A reservation fenced before any worker claimed it handed nobody a specification,
                // so there is no worker behind it.
                if phase == LaunchPhase::Fenced && reservation.claimed_key.is_none() {
                    continue;
                }
                if !self.local_access.made_here(reservation.reservation_id) {
                    lacking.insert(reservation.session_id);
                }
            }
        }
        Ok(lacking.into_iter().collect())
    }

    /// Starts the publisher: it tells the workers what the local owner may do whenever the bound
    /// changes, and again every few seconds until each has acknowledged, so a worker that was
    /// away when a frame was sent is told when it can be.
    pub(crate) fn start_local_access_publisher(self: &std::sync::Arc<Self>) {
        let controller = std::sync::Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(strong) = controller.upgrade() else {
                    return;
                };
                strong.tell_workers().await;
                let wake = std::sync::Arc::clone(&strong.local_access.wake);
                // Not held across the wait: the daemon holds its environment until the last
                // reference to it ends.
                drop(strong);
                let notified = wake.notified();
                tokio::pin!(notified);
                // Registered before the wait, so a wake between the pass above and here is kept.
                notified.as_mut().enable();
                let _ = tokio::time::timeout(REPEAT, notified).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_transport::clock::{ContinuousClock as _, ManualClock};

    /// A lease that has not changed is sent again as it was, not converted again: two readings of
    /// two clocks at two moments differ by a millisecond, and a worker takes a lease that ends a
    /// millisecond sooner for one that was cut short and withdraws what its local owner holds.
    #[test]
    fn a_statement_is_converted_once_for_each_answer_of_the_policy() {
        let state = LocalAccessState::default();
        let clock = ManualClock::new();
        let lease = LocalOwnerBound::Until {
            continuous: clock.now(),
            utc_ms: 5,
        };
        let until = |boot_deadline_ms: u64| LocalBound::Until {
            boot_deadline_ms: U64::new(boot_deadline_ms),
            utc_deadline_ms: U64::new(5),
        };
        let first = state.draw(lease, || until(1_000));
        let again = state.draw(lease, || until(1_001));
        assert_eq!(
            again, first,
            "the same lease is the same statement, byte for byte"
        );
        let renewed = state.draw(
            LocalOwnerBound::Until {
                continuous: clock.now(),
                utc_ms: 6,
            },
            || until(2_000),
        );
        assert_eq!(renewed.sequence.get(), first.sequence.get() + 1);
        let closed = state.draw(LocalOwnerBound::Closed, || LocalBound::Closed);
        assert_eq!(closed.sequence.get(), renewed.sequence.get() + 1);
    }
}
