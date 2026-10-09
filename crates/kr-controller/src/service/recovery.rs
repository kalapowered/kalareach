//! The creates and claims an earlier daemon left unresolved, and the workers it left running.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::Endpoint;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::session::{ClosureReason, SessionState, SessionSummary};
use kr_protocol::worker::{ReservationId, WorkerDescriptor};

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, WorkerRecord};

use super::Controller;

/// The reservations a look or a publication holds, and who is waiting for them.
#[derive(Debug, Default)]
pub(super) struct Reservations {
    held: std::sync::Mutex<std::collections::BTreeSet<ReservationId>>,
    /// Woken whenever a reservation is given back.
    given_back: tokio::sync::Notify,
    /// How many callers are waiting for a reservation now, for this crate's own tests.
    #[cfg(test)]
    waiting: std::sync::atomic::AtomicUsize,
}

impl Reservations {
    /// How many callers are waiting for a reservation to be given back.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        self.waiting.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A caller counted as waiting for a reservation for as long as it is.
#[cfg(test)]
struct Waiting<'a>(&'a Reservations);

#[cfg(test)]
impl<'a> Waiting<'a> {
    fn begin(reservations: &'a Reservations) -> Self {
        reservations
            .waiting
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(reservations)
    }
}

#[cfg(test)]
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0
            .waiting
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One reservation, held by whichever of a look and a publication took it.
///
/// Giving it back wakes everybody who is waiting, and each of them looks for the one reservation it
/// came for: whoever was waiting for this one takes it, and the rest wait again.
///
/// A hold is shared, and the reservation is given back when the last holder lets go of it. It
/// belongs to no request, so it can go where the work it covers goes: a publication takes a share
/// of it into the task it runs on ([`Controller::publish_worker`]), and a request that stops
/// waiting for that task gives nothing back.
#[derive(Clone, Debug)]
pub(super) struct ReservationHold {
    /// Kept only for what its drop does, once the last share of it is gone.
    _share: Arc<Held>,
}

#[derive(Debug)]
struct Held {
    reservations: Arc<Reservations>,
    reservation_id: ReservationId,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.reservations
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.reservation_id);
        self.reservations.given_back.notify_waiters();
    }
}

/// The task that stops what a crashed session owned and records its closure.
type Cleanup = tokio::task::JoinHandle<Result<Option<kr_protocol::session::ClosureRecord>>>;

impl Controller {
    /// Resolves every create that a previous daemon did not finish.
    ///
    /// The rule is the one section 24 asks for: a launch that is confirmed not to have started is
    /// resolved and stops occupying the environment; a launch that may have started is preserved,
    /// never respawned, and keeps its slot until something confirms what happened to it.
    pub(super) async fn recover_reservations(&self) -> Result<()> {
        // Every cleanup a scan starts is waited for, whether or not the scan went on to the end:
        // the tasks are the caller's, and an error does not drop them.
        let mut cleanups = Vec::new();
        let mut outcome = self.scan_reservations(&mut cleanups).await;
        if outcome.is_ok() {
            // The workers a start meets are started beside the claimed ones, so a daemon that
            // finds both kinds waits for the longest cleanup and not for one kind and then the
            // other.
            outcome = self.scan_workers(&mut cleanups).await;
        }
        for task in cleanups {
            let _ = task.await;
        }
        outcome
    }

    /// The scan of [`Self::recover_reservations`]: resolves what it can and starts, into
    /// `cleanups`, the cleanup of every claimed worker confirmed gone.
    async fn scan_reservations(&self, cleanups: &mut Vec<Cleanup>) -> Result<()> {
        let unresolved = {
            let registry = self.registry.lock().await;
            let mut rows = registry.reservations_in(LaunchPhase::Reserved)?;
            rows.extend(registry.reservations_in(LaunchPhase::Spawned)?);
            rows.extend(registry.reservations_in(LaunchPhase::Claimed)?);
            rows
        };
        for reservation in unresolved {
            match reservation.phase {
                // Nothing was ever handed to the service manager: the phase moves to `spawned`
                // before the call and this one never got there.
                LaunchPhase::Reserved => {
                    let mut registry = self.registry.lock().await;
                    registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                }
                // Spawned and never claimed. A worker starts its shell only after the rendezvous
                // hands it a launch specification, and that never happened, so an ended process
                // means nothing came of this launch. A process still running, or one the kernel
                // will not describe, keeps its slot.
                LaunchPhase::Spawned => match reservation.launcher_identity.as_ref() {
                    Some(identity) => {
                        if matches!(
                            kr_ipc::identity::process_state(identity),
                            kr_ipc::identity::ProcessState::Ended
                        ) {
                            let mut registry = self.registry.lock().await;
                            registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                        }
                    }
                    // Spawned with no launcher recorded: the daemon died between handing the launch
                    // to the service manager and writing down what it returned. A process may be
                    // running, but it cannot have started a shell: a worker starts one only after
                    // the rendezvous hands it a launch specification, and this reservation's claim
                    // was never consumed. Resolving it as failed both frees the slot and fences it,
                    // because a claim is admitted only against a reservation that is still spawned.
                    None => {
                        let mut registry = self.registry.lock().await;
                        registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                    }
                },
                // Claimed. This worker received its launch specification, so it may have started a
                // shell. It is recovered by challenge where it still answers, and recorded as an
                // abnormal closure where its process is confirmed gone; a claim is never resolved
                // as though nothing had run.
                LaunchPhase::Claimed => {
                    let held = self.hold_reservation(reservation.reservation_id).await;
                    // A worker confirmed gone has what its session owned stopped on a task of its
                    // own; every such task is started before any is waited for, so a daemon that
                    // starts beside several of them costs one bound and not one each.
                    if let Some(task) = self.recover_claim_started(&reservation, &held).await? {
                        cleanups.push(task);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Recovers a worker whose claim was consumed but whose session never reached the directory.
    ///
    /// The caller holds the reservation (`held`), which the publication of the worker shares until
    /// it is over.
    async fn recover_claim(
        &self,
        reservation: &crate::registry::Reservation,
        held: &ReservationHold,
    ) -> Result<()> {
        match self.recover_claim_started(reservation, held).await? {
            Some(task) => match task.await {
                Ok(outcome) => outcome.map(|_| ()),
                Err(ended) if ended.is_panic() => std::panic::resume_unwind(ended.into_panic()),
                Err(_) => Err(ControllerError::supervision(
                    "this daemon stopped before it finished closing a session whose worker had gone",
                )),
            },
            None => Ok(()),
        }
    }

    /// [`Self::recover_claim`] up to the point where a worker confirmed gone has what its session
    /// owned stopped, which runs on a task this daemon owns and is returned for the caller to wait
    /// for, so that a request that goes does not stop it half way and a start can run several at
    /// once.
    async fn recover_claim_started(
        &self,
        reservation: &crate::registry::Reservation,
        held: &ReservationHold,
    ) -> Result<Option<Cleanup>> {
        let endpoint = self.paths.worker_endpoint(reservation.display_number)?;
        let challenged = match reservation.claimed_key {
            Some(key) => Some(
                self.challenge(&endpoint, &key, reservation.session_id)
                    .await,
            ),
            None => None,
        };
        if let Some(Err(refused)) = &challenged {
            report_unretained(reservation.display_number, refused);
        }
        if let Some(Ok((proof, described))) = challenged
            && let Some(key) = reservation.claimed_key
        {
            // The worker is alive and is the one this reservation admitted. Its descriptor and its
            // registry row are rebuilt from its own signed answer.
            self.adopt(
                reservation.display_number,
                &key,
                &proof,
                &endpoint,
                described,
                held,
            )
            .await?;
            let mut registry = self.registry.lock().await;
            registry.resolve_claim(reservation.reservation_id, LaunchPhase::Live)?;
            return Ok(None);
        }
        let ended = reservation
            .launcher_identity
            .as_ref()
            .is_some_and(|identity| {
                matches!(
                    kr_ipc::identity::process_state(identity),
                    kr_ipc::identity::ProcessState::Ended
                )
            });
        if ended {
            // The worker that held this claim is gone. It may have started a shell, so this is
            // recorded as a session that ended abnormally rather than as a launch that never
            // happened, and the coverage says the host did not watch it end.
            let identity = reservation
                .launcher_identity
                .clone()
                .expect("the identity was just read");
            // What the session owned is stopped, as it is for any other crash.
            return Ok(self.crash_flight_soon(
                reservation.session_id,
                reservation.display_number,
                identity,
                ClosureReason::WorkerCrash,
            ));
        }
        Ok(None)
    }

    /// Looks again for a worker whose claim this daemon has not resolved.
    ///
    /// A daemon that restarts while a managed session is still qualifying is refused its own
    /// startup challenge, because a worker whose root integration has never qualified proves
    /// nothing for the session it is still making. That worker qualifies a moment later, and
    /// nothing would look again until the next restart. So every request that goes looking for a
    /// session looks here too: a reservation still recorded as claimed is a live process this
    /// daemon has not adopted yet.
    ///
    /// A claim whose worker is gone is resolved the same way it is at startup, and one whose worker
    /// is alive and still unqualified is simply left for the next look.
    pub(super) async fn recover_claims(&self) -> Result<()> {
        let claimed = {
            let registry = self.registry.lock().await;
            registry.reservations_in(LaunchPhase::Claimed)?
        };
        for reservation in claimed {
            // One session's failure is not another's, and a list asks about every session. A
            // reservation that cannot be recovered now is left claimed for the next look.
            let _ = self.recover_unresolved(reservation.reservation_id).await;
        }
        Ok(())
    }

    /// Looks again for one session's own unresolved claim, and says what went wrong.
    ///
    /// The same look as [`Self::recover_claims`], for a caller that asked about one session and is
    /// owed the reason rather than a session that is simply not there.
    pub(super) async fn recover_claim_for(
        &self,
        session_id: kr_protocol::ids::SessionId,
    ) -> Result<()> {
        let reservation = {
            let registry = self.registry.lock().await;
            registry.reservation_for_session(session_id)?
        };
        let Some(reservation) = reservation else {
            return Ok(());
        };
        self.recover_unresolved(reservation.reservation_id).await
    }

    /// Recovers one claim, after asking again whether it is still this daemon's to recover.
    ///
    /// The reservation is read here rather than trusted from whatever the caller saw, because a
    /// challenge takes time and the answer can be stale by the time its turn comes: a create that
    /// finished during an earlier challenge in the same scan has already resolved its own claim and
    /// published its worker, and challenging that worker again would present a second generation
    /// token and fence the connection this daemon is already using.
    ///
    /// Three things say it is not this daemon's to recover: a reservation that is no longer
    /// claimed, a create this daemon is still running, and a worker already in the directory.
    async fn recover_unresolved(&self, reservation_id: ReservationId) -> Result<()> {
        let held = self.hold_reservation(reservation_id).await;
        let reservation = {
            let registry = self.registry.lock().await;
            registry.reservation(reservation_id)?
        };
        let Some(reservation) = reservation else {
            return Ok(());
        };
        if reservation.phase != LaunchPhase::Claimed
            || self.pending.lock().await.contains_key(&reservation_id)
            || self
                .directory
                .lock()
                .await
                .get(reservation.session_id)
                .is_some()
        {
            return Ok(());
        }
        self.recover_claim(&reservation, &held).await
    }

    /// Takes one reservation from whatever else would look at it, and gives it back on drop.
    ///
    /// Only that reservation: a caller waiting here is waiting for one worker's own turn, never for
    /// a scan of somebody else's.
    pub(super) async fn hold_reservation(&self, reservation_id: ReservationId) -> ReservationHold {
        loop {
            // Created before the set is read, so a reservation given back between the two is not
            // missed: a wake from that moment on is already counted for this waiter, and the wait
            // below ends at once rather than sleeping through it.
            let given_back = self.reservations.given_back.notified();
            {
                let mut held = self
                    .reservations
                    .held
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if held.insert(reservation_id) {
                    return ReservationHold {
                        _share: Arc::new(Held {
                            reservations: Arc::clone(&self.reservations),
                            reservation_id,
                        }),
                    };
                }
            }
            #[cfg(test)]
            let _waiting = Waiting::begin(&self.reservations);
            given_back.await;
        }
    }

    /// Restores the directory entry of every worker the registry records.
    ///
    /// A daemon that crashed between recording a worker and publishing its descriptor left a row
    /// with nothing on disk pointing at it. The row carries the key and the endpoint, which is
    /// everything a challenge needs, and the worker's own answer carries everything a descriptor
    /// needs.
    pub(super) async fn recover_workers(&self) -> Result<()> {
        let mut cleanups = Vec::new();
        let outcome = self.scan_workers(&mut cleanups).await;
        for task in cleanups {
            let _ = task.await;
        }
        outcome
    }

    /// The scan of [`Self::recover_workers`]: adopts the workers that answer and starts, into
    /// `cleanups` and on a task this daemon owns, what each worker confirmed gone owned stopped.
    /// The caller waits for the tasks, whatever this returns.
    async fn scan_workers(&self, cleanups: &mut Vec<Cleanup>) -> Result<()> {
        let rows = {
            let registry = self.registry.lock().await;
            registry.workers()?
        };
        for row in rows {
            if self.directory.lock().await.get(row.session_id).is_some() {
                continue;
            }
            // A fenced reservation is one the host stopped trusting. Publishing its worker again
            // because a descriptor happened to be missing would undo the fence through the back
            // door, so recovery leaves it alone and it stays out of the directory.
            let reservation = {
                let registry = self.registry.lock().await;
                registry.reservation_for_session(row.session_id)?
            };
            let Some(reservation) = reservation else {
                continue;
            };
            if reservation.phase == LaunchPhase::Fenced {
                continue;
            }
            // This row's own reservation, taken from whatever else would look at it. A challenge
            // here presents a generation token too, and one presented while that worker's own
            // report is being published fences the connection the daemon has just opened.
            let held = self.hold_reservation(reservation.reservation_id).await;
            // The directory again, now that nothing else can be publishing into it: the report may
            // have landed while this row was waiting its turn.
            if self.directory.lock().await.get(row.session_id).is_some() {
                continue;
            }
            let Ok(endpoint) = Endpoint::from_path(&row.endpoint) else {
                continue;
            };
            match self
                .challenge(&endpoint, &row.public_key, row.session_id)
                .await
            {
                Ok((proof, described)) => {
                    self.adopt(
                        row.display_number,
                        &row.public_key,
                        &proof,
                        &endpoint,
                        described,
                        &held,
                    )
                    .await?;
                }
                // A worker that does not answer is not necessarily gone. Reconciliation asks the
                // kernel; only a confirmed death produces a closure record.
                Err(refused) => {
                    report_unretained(row.display_number, &refused);
                    // Every crashed session's cleanup is started before any is waited for: a
                    // daemon that starts beside several of them costs one bound, not one each.
                    match self.reconcile_soon(row.session_id) {
                        Some(task) => cleanups.push(task),
                        None => {
                            let _ = self.reconcile(row.session_id).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Challenges a worker against a key this daemon already holds, presents its generation, and
    /// then asks the worker to describe its session ([`crate::directory::describe`]), which it may
    /// not do.
    pub(super) async fn challenge(
        &self,
        endpoint: &Endpoint,
        worker_public_key: &kr_protocol::scalars::AuthorisationKey,
        session_id: SessionId,
    ) -> Result<(
        kr_protocol::worker::WorkerVerifyProof,
        Option<SessionSummary>,
    )> {
        let identity = &self.identity;
        let generation = self.generation;
        let boot = self.boot_identity.clone();
        let endpoint_text = endpoint.as_text();
        let (proof, mut client) =
            tokio::time::timeout(crate::directory::RECONNECT_TIMEOUT, async move {
                let mut client = LocalClient::connect(
                    endpoint,
                    LocalClientKind::Controller,
                    self.build_id.clone(),
                )
                .await?;
                let proof = client
                    .challenge_worker(
                        worker_public_key,
                        session_id,
                        SessionEpoch::V1,
                        &endpoint_text,
                    )
                    .await?;
                client
                    .present_generation(move |nonce| {
                        identity
                            .generation_token(generation, &boot, nonce)
                            .map_err(kr_ipc::IpcError::from)
                    })
                    .await?;
                Ok::<_, ControllerError>((proof, client))
            })
            .await
            .map_err(|_| {
                ControllerError::supervision("the worker did not answer its challenge in time")
            })??;
        let described = crate::directory::describe(&mut client, session_id).await;
        Ok((proof, described))
    }

    /// Records a recovered worker and republishes its descriptor, and admits the worker with the
    /// description of its session it gave after its challenge, where it gave one.
    ///
    /// `held` is the reservation the worker was started for, which the publication shares until it
    /// is over ([`Self::publish_worker`]).
    pub(super) async fn adopt(
        &self,
        display_number: kr_protocol::session::DisplayNumber,
        worker_public_key: &kr_protocol::scalars::AuthorisationKey,
        proof: &kr_protocol::worker::WorkerVerifyProof,
        endpoint: &Endpoint,
        described: Option<SessionSummary>,
        held: &ReservationHold,
    ) -> Result<()> {
        let record = WorkerRecord {
            session_id: proof.session_id,
            display_number,
            public_key: *worker_public_key,
            process_identity: proof.process_start_identity.clone(),
            endpoint: proof.endpoint.clone(),
            profile: WorkerProfile::HeadlessUser,
            state: SessionState::Live,
            // A worker starts having acknowledged nothing. The first announcement it receives is
            // what moves this.
            acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
        };
        {
            let mut registry = self.registry.lock().await;
            // The challenge waited for the worker, and the session may have closed meanwhile. Its
            // closure is the fact, and a row written after it would be a worker for a session that
            // has ended, with nothing left to end it.
            if registry.closure(proof.session_id)?.is_some() {
                return Ok(());
            }
            // The desktop it says it is bound to, where it was asked and described its own session:
            // one that could not be asked, or described another, keeps the identity its row already
            // has.
            registry.adopt_worker(
                &record,
                described
                    .as_ref()
                    .filter(|summary| summary.session_id == proof.session_id)
                    .map(|summary| &summary.desktop),
            )?;
        }
        #[cfg(test)]
        self.before_a_worker_is_published.wait().await;
        let descriptor = WorkerDescriptor {
            session_id: proof.session_id,
            session_epoch: proof.session_epoch,
            environment_id: self.paths.environment_id(),
            display_number,
            boot_identity: proof.boot_identity.clone(),
            process_start_identity: proof.process_start_identity.clone(),
            protocol_version: proof.protocol_version,
            endpoint: proof.endpoint.clone(),
            worker_public_key: *worker_public_key,
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: kr_ipc::now_ms(),
        };
        self.publish_worker(
            KnownWorker {
                descriptor,
                endpoint: endpoint.clone(),
            },
            described,
            held,
        )
        .await
    }
}

/// Says, in this daemon's log, that a worker recovery reached runs at a compatibility level this
/// daemon's release does not retain, by that level.
///
/// Such a worker is alive and is left so: it is not adopted, since this daemon could not read or
/// write its frames, and it is not closed, since nothing about it has ended. Its session runs on,
/// unreached by this daemon, until it closes or a daemon of a release that retains its level
/// serves the environment again. An update of this host waits for such a worker rather than make
/// one, so this is met only by a daemon started outside an update.
fn report_unretained(
    display_number: kr_protocol::session::DisplayNumber,
    refused: &ControllerError,
) {
    if let ControllerError::Ipc(kr_ipc::IpcError::UnretainedLevel { worker, level }) = refused {
        eprintln!(
            "kr-controller: session {} runs {worker}, and this daemon speaks to workers at protocol \
             level {level} only: the session is left running, unreached by this daemon, until it \
             closes or a daemon of its own release serves this environment",
            display_number.get()
        );
    }
}
