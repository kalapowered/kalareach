//! Closing a session, and recording how it ended, once.

use std::path::PathBuf;
use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, SessionCloseParams, SessionCloseResult, SessionState,
};
use kr_protocol::worker::ReservationId;
use kr_transport::window::AcceptedDeadline;

use crate::error::{ControllerError, Result};
use crate::supervision::JobRetirement;

use super::admission::remaining_deadline;
use super::workers::UNACCOUNTED_WORKER;
use super::{Controller, encode, parse};

/// How long a closing worker is watched before the controller stops waiting for it to end.
pub const CLOSURE_WATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a close waits for the worker that owns the session.
///
/// Section 7's own timing for a closure: five seconds for the processes to stop and two more to
/// drain their output. A worker that has not answered a close by then has taken longer than the
/// whole closure is allowed to take, so this daemon stops waiting for it rather than holding the
/// one connection it has to that worker for whoever asks next. The bound covers acquiring that
/// connection as well as the exchange over it, because a caller queueing behind a worker that
/// stopped answering waits exactly as long as one talking to it.
pub const CLOSE_EXCHANGE: std::time::Duration = std::time::Duration::from_millis(
    kr_worker::session::GRACE_PERIOD.as_millis() as u64
        + kr_worker::session::DRAIN_PERIOD.as_millis() as u64,
);

impl Controller {
    /// Tells every worker holding a close for this action that the caller has its acceptance.
    ///
    /// The worker cannot know when the daemon finished passing the reply on, and it must not
    /// signal a process group whose command is still waiting to read its own answer.
    pub(super) async fn confirm_delivery(&self, action_id: kr_protocol::ids::ActionId) {
        let links: Vec<(SessionId, Arc<tokio::sync::Mutex<Option<LocalClient>>>)> = self
            .connections
            .lock()
            .await
            .iter()
            .map(|(session_id, link)| (*session_id, Arc::clone(link)))
            .collect();
        for (session_id, slot) in links {
            // A worker with no link has nothing to be told: one is not opened for this. A link that
            // is written to is the daemon's own like any other, so one that does not take the
            // notice whole, or whose future is dropped part way, is given up with the lease.
            let Some(mut link) = self.link_in(session_id, slot.lock_owned().await) else {
                continue;
            };
            if link.client().confirm_delivery(action_id).await.is_ok() {
                link.give_back();
            }
        }
    }

    /// Proxies a close to the worker that owns the session.
    ///
    /// The caller's envelope is forwarded, not replaced. The action identifier is the durable
    /// identity of the caller's action, and rewriting it here would give the worker a different
    /// action from the one the caller asked for: a retry would then find no receipt, and the
    /// caller's own identifier would name nothing.
    pub(super) async fn session_close(
        self: &Arc<Self>,
        mutation: &MutationRequest,
        actor: &kr_protocol::actor::ActorEnvelope,
        accepted: Option<AcceptedDeadline>,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params: SessionCloseParams = parse(&mutation.params)?;
        let worker = self.directory.lock().await.get(params.session_id).cloned();
        let Some(worker) = worker else {
            let registry = self.registry.lock().await;
            let closure = registry.closure(params.session_id)?;
            drop(registry);
            return match closure {
                // A duplicate close returns the existing state rather than closing anything again.
                Some(closure) => encode(&SessionCloseResult {
                    session_id: params.session_id,
                    state: SessionState::Closed,
                    durability: closure.durability,
                    closure: Nullable::some(closure),
                    // The record is the answer, and no worker is left to describe the session.
                    session: None,
                }),
                None => Err(ControllerError::UnknownSession {
                    session: params.session_id.to_string(),
                }),
            };
        };
        // One budget for the whole exchange, started before the wait for the connection. Section 7
        // gives a closure five seconds to stop its processes and two more to drain them, and this
        // daemon holds one connection per worker: a worker that stops answering would otherwise
        // hold that connection for every later caller, and the wait for it would be unbounded on
        // both sides of the handover.
        let budget = tokio::time::Instant::now() + CLOSE_EXCHANGE;
        let result = {
            // The connection comes first. Waiting for it can take as long as whatever else is using
            // it, and a deadline computed before that wait would hand the worker time that had
            // already been spent queueing.
            let mut link = tokio::time::timeout_at(budget, self.worker_client(&worker))
                .await
                .map_err(|_| {
                    // Nothing was dispatched: this close never reached the worker, and the link it
                    // was queueing for belongs to whoever is holding it. The caller can ask again.
                    ControllerError::supervision(
                        "the connection to the worker that owns this session did not come free in \
                         time, so nothing was closed",
                    )
                })??;
            // The admission is checked here rather than before the wait, because this is where
            // the wait was. A deadline that ran out while this close queued does not stop it
            // reaching the worker, because the worker is the only thing that knows whether it
            // already holds this action's receipt; what a spent deadline stops is a *first*
            // admission, and the worker refuses that for the same reason this daemon would have.
            // The authority half is different: it refuses outright, because disclosing anything
            // under authority that has been withdrawn is what the contract forbids. A refusal
            // here is no exchange, so the link goes back as it came.
            let checked = async {
                // Inside the same budget as the exchange: this daemon is holding the worker's link
                // while it asks, and a registry another operation is holding must not let that
                // link be held past what a closure is allowed to take.
                let registry = tokio::time::timeout_at(budget, self.registry.lock())
                    .await
                    .map_err(|_| {
                        ControllerError::supervision(
                            "this daemon could not read its own authority in time, so nothing was \
                             closed",
                        )
                    })?;
                match self.check_admission(&registry, &carried) {
                    Ok(()) => {}
                    Err(ControllerError::WindowExpired { .. }) => {}
                    Err(error) => return Err(error),
                }
                drop(registry);
                // Remote dispatch additionally needs a live lease, taken at the moment the
                // dispatch runs rather than one that was valid when the request arrived. Its own
                // remaining time then bounds the deadline the worker is given.
                Ok(self.dispatch_lease(params.session_id, actor).await?)
            }
            .await;
            let lease_deadline = match checked {
                Ok(lease_deadline) => lease_deadline,
                Err(error) => {
                    link.give_back();
                    return Err(error);
                }
            };
            // What the worker is told is the accepted deadline itself, on the machine's own
            // continuous clock: the same clock the worker reads, so the deadline does not restart
            // on arrival and nothing has to guess at what the journey cost. A deadline already
            // spent is forwarded as spent - nought is in every boot's past - rather than as a
            // refusal, so the worker answers from what it holds and admits nothing new.
            let accepted_deadline_boot_ms = accepted
                .and_then(|accepted| {
                    remaining_deadline(
                        &*self.shared_clock,
                        &*self.clock,
                        accepted.deadline,
                        lease_deadline,
                    )
                })
                .unwrap_or_else(|| U64::new(0));
            match tokio::time::timeout_at(
                budget,
                link.client().forward(
                    mutation,
                    actor,
                    // A local caller acts under the operating-system identity the listener
                    // authenticated rather than under a grant, so there are no rights to narrow
                    // what it asked for.
                    &CanonicalSet::new(),
                    accepted_deadline_boot_ms,
                ),
            )
            .await
            {
                Ok(Ok(result)) => {
                    link.give_back();
                    result
                }
                // The path this daemon announces authority revisions over is gone, whether it
                // ended or stopped answering. Renewal stops with it: section 9 lets a remote
                // dispatch lease be renewed only after the worker has acknowledged the revision,
                // and this daemon can no longer hear an acknowledgement from that worker. The link
                // is closed and the path given up as it goes out of scope.
                Ok(Err(error)) => return Err(error.into()),
                // The close was written and no answer came back inside the time a closure is
                // allowed to take. The client is retired rather than returned to the shared slot:
                // its exchange was abandoned part way through, so the next caller to pick it up
                // would read this close's reply as the answer to its own request. Whether the
                // worker acted on it is not known, which is what the caller is told: section 9
                // does not let an interrupted dispatch be reported as a refusal.
                Err(_) => {
                    return Err(ControllerError::Uncertain {
                        detail:
                            "the worker did not answer this close within the time a closure is \
                                 given, so whether the session is stopping is not known"
                                .to_owned(),
                    });
                }
            }
        };
        match result {
            Ok(value) => {
                // A retry of an action this worker settled without closing anything answers with
                // its receipt rather than a close result. That is the right answer to the caller's
                // retry, so it is passed through as it stands: reading it as a close result would
                // turn the receipt the caller asked for into a decoding failure.
                let Ok(reply) = value.to_typed::<SessionCloseResult>() else {
                    return Ok(value);
                };
                self.settle_close_answer(params.session_id, &reply).await?;
                encode(&reply)
            }
            Err(error) => Err(ControllerError::InvalidArgument(error.to_string())),
        }
    }

    /// Settles a worker's answer to a close of `session_id` that this daemon passes on, whether
    /// the worker gave it now or from its journal, and on either door: every answer a close gets
    /// is settled here, before it goes, so none reaches its caller without this daemon knowing
    /// what it said.
    ///
    /// An answer with the worker's own account of how its session ended is recorded, written
    /// through the same boundary as every other closure so that nothing this daemon writes
    /// afterwards can replace it. One without is the worker's acceptance: the session is closing,
    /// as the worker's description in it says, until its closure is recorded
    /// ([`Self::close_accepted`]). The answer itself is not changed.
    ///
    /// # Errors
    ///
    /// Returns an error when a closure the answer carries cannot be recorded.
    pub(crate) async fn settle_close_answer(
        self: &Arc<Self>,
        session_id: SessionId,
        answer: &SessionCloseResult,
    ) -> Result<()> {
        match answer.closure.as_ref() {
            Some(record) => self.retire(record).await,
            None => {
                self.close_accepted(session_id, answer.session.as_ref())
                    .await;
                Ok(())
            }
        }
    }

    /// Settles what follows a worker's acceptance of a close this daemon passed to it.
    ///
    /// The session is closing from here until its closure is recorded, which is what a read that
    /// meets the worker on its way out is answered with (`Directory::ending`), from the worker's
    /// own description of the session where the acceptance carries one. Nothing is asked of the
    /// worker here: the link the acceptance came over is the one the worker is holding its close
    /// on until the caller has the acceptance, and an exchange that ended that link would start
    /// the close early. Something also has to notice when the worker finishes, so the tombstone is
    /// written and the descriptor removed rather than left pointing at a process that has gone.
    async fn close_accepted(
        self: &Arc<Self>,
        session_id: SessionId,
        described: Option<&kr_protocol::session::SessionSummary>,
    ) {
        self.directory
            .lock()
            .await
            .accepted_close(session_id, described);
        tokio::spawn(Arc::clone(self).watch_closure(session_id, ClosureReason::CloseRequested));
    }

    /// Waits for a closing worker to end, then records its closure and retires it.
    ///
    /// The worker's acceptance says `closing`, because section 7 gives the requester its answer
    /// before anything is signalled. Something still has to notice when the closure finishes, and
    /// that is this: it watches the process identity the registry holds, and writes the record once
    /// the kernel agrees the worker is gone.
    pub async fn watch_closure(self: Arc<Self>, session_id: SessionId, reason: ClosureReason) {
        let deadline = std::time::Instant::now() + CLOSURE_WATCH_TIMEOUT;
        loop {
            let identity = {
                let registry = self.registry.lock().await;
                registry
                    .workers()
                    .ok()
                    .and_then(|workers| {
                        workers
                            .into_iter()
                            .find(|record| record.session_id == session_id)
                    })
                    .map(|record| record.process_identity)
            };
            let Some(identity) = identity else {
                // The session has left this daemon's directory, which is what recording a closure
                // does, so something else finished what this watcher was waiting for.
                self.review_power_soon();
                return;
            };
            match kr_ipc::identity::process_state(&identity) {
                kr_ipc::identity::ProcessState::Ended => {
                    let _ = self
                        .record_final(
                            session_id,
                            reason,
                            &identity,
                            &crate::archive::ArchiveService::nothing_fenced(session_id),
                            true,
                        )
                        .await;
                    // The closure this watcher was waiting on has finished, so what it was
                    // counted as is over. Whoever asked for it is not waiting for this.
                    self.review_power_soon();
                    return;
                }
                kr_ipc::identity::ProcessState::Running
                | kr_ipc::identity::ProcessState::Unknown { .. } => {}
            }
            if std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    /// Reconciles a session whose worker cannot be reached.
    ///
    /// If the recorded process is gone the session is closed and recorded as an abnormal closure,
    /// which is what section 24 requires when the controller detects a worker's death. If the
    /// process is still running, or the kernel will not say, nothing is recorded: a controller that
    /// cannot reach a worker has not established that the worker is dead.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn reconcile(&self, session_id: SessionId) -> Result<Option<ClosureRecord>> {
        let record = {
            let registry = self.registry.lock().await;
            registry
                .workers()?
                .into_iter()
                .find(|record| record.session_id == session_id)
        };
        let Some(record) = record else {
            return Ok(None);
        };
        // The archive takes exclusive recovery ownership, and only on its own terms: the kernel
        // is asked whether the recorded process is the process that was recorded, and only then
        // is the endpoint fenced. A query the platform declines is not death, and leaves the
        // session alone. Nothing here creates a worker.
        let archive = self.archive();
        let Ok(ownership) =
            archive.take_ownership(session_id, record.display_number, &record.process_identity)
        else {
            return Ok(None);
        };
        // Section 9's recovery rules are the worker's, and a worker that crashed never ran them.
        // They run once here instead, before anything is served: a dispatch marker with no
        // authoritative outcome becomes `unknown`, and an accepted intent with no marker is
        // rejected. A failure is not a reason to leave the session open, so the closure is still
        // written; what says the store was not reconciled is the archive, which reports an action
        // still accepted or still dispatching when a reader asks.
        let _ = archive.recover_journal(&ownership);
        let reason = self.why_a_worker_is_gone(session_id, record.profile);
        // Section 7's second half, before the session identity is released: whatever the session
        // still owns is fenced, and what this host cannot account for is recorded. A closure
        // written before that would be a closure a crash between the two could not lead back to.
        let reported = ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        };
        let fenced = archive.fence_owned(&ownership, &reported);
        let closure = self
            .record_final(session_id, reason, &record.process_identity, &fenced, true)
            .await?;
        Ok(Some(closure))
    }

    /// Returns the reason a worker that is confirmed gone ended, where this host can establish
    /// one.
    ///
    /// A desktop-bound worker whose desktop has gone went with it: the platform ended the job with
    /// the login session it was in, which is what a logout does, and the worker had no chance to
    /// write its own record. The desktop the session was created on is in the worker's own
    /// journal, which outlives the worker, so the platform can be asked about that login session
    /// by name. That is an answer rather than a guess even after the person has logged in again,
    /// and it is an answer about the right session on a host where one user holds several at once:
    /// the desktop this daemon itself is in says nothing about another login's.
    ///
    /// Everything else is a worker that ended for reasons this host does not know, including a
    /// desktop it could not read: an unreadable platform is not a logout.
    fn why_a_worker_is_gone(&self, session_id: SessionId, profile: WorkerProfile) -> ClosureReason {
        if profile != WorkerProfile::DesktopBound {
            return ClosureReason::WorkerCrash;
        }
        let Some(recorded) = self.recorded_desktop(session_id) else {
            return ClosureReason::WorkerCrash;
        };
        match kr_worker::desktop::recorded_presence(&recorded) {
            // The login session this session was created on is not there any more.
            kr_worker::desktop::Presence::Ended => ClosureReason::DesktopLost,
            kr_worker::desktop::Presence::Present | kr_worker::desktop::Presence::Unknown => {
                ClosureReason::WorkerCrash
            }
        }
    }

    /// Returns the desktop a session was created on, from its own journal.
    ///
    /// The journal is in the environment's state directory and outlives the worker that wrote it,
    /// which is what makes this readable after the worker has gone.
    fn recorded_desktop(
        &self,
        session_id: SessionId,
    ) -> Option<kr_protocol::identity::DesktopBinding> {
        self.archive().bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        let journal = kr_worker::journal::Journal::open_read_only(path).ok()?;
        journal
            .read_session(session_id)
            .ok()
            .flatten()
            .map(|summary| summary.desktop)
    }

    /// Records how a session ended, once.
    ///
    /// The whole of it is one transaction: the closure already recorded is the answer where there
    /// is one, and where there is not, the record written here is the only one written. Four paths
    /// reach a closure for the same session, because the closure watcher, this daemon's own
    /// reconciliation, a worker handing over its own account and the answer a worker gives a paired
    /// device all produce one, and a second record would replace the first rather than adding to
    /// it.
    pub(super) async fn record_final(
        &self,
        session_id: SessionId,
        reason: ClosureReason,
        identity: &kr_protocol::identity::ProcessStartIdentity,
        fenced: &crate::archive::Fenced,
        death_validated: bool,
    ) -> Result<ClosureRecord> {
        let _finalising = self.finalising.lock().await;
        if let Some(existing) = self.registry.lock().await.closure(session_id)? {
            return Ok(existing);
        }
        // The worker's own journal is the authority on how its session ended. It recorded the
        // root's exit status, what it stopped and how much of that it could account for; a record
        // written from outside knows none of those.
        //
        // The worker's own journal is read only where the caller established that the worker
        // ended. Writing this closure removes both the registry's worker row and the published
        // descriptor, which are the two things a later read asks about, so a closure written over
        // an unconfirmed death has to carry that fact itself - see `surviving` below - and must
        // not open the store on the way.
        if death_validated && let Some(recovered) = self.recovered_closure(session_id) {
            self.write_closure(&recovered).await?;
            return Ok(recovered);
        }
        // Nothing authoritative survived. What is written instead says so: the coverage is
        // incomplete and the root's result is absent rather than invented.
        // A worker this host saw end is terminated; one it did not is not, whatever else is true
        // of the session. Saying otherwise in the record would be the record claiming the one
        // thing this host could not establish.
        let mut terminated = Vec::new();
        let mut surviving = fenced.surviving.clone();
        if death_validated {
            terminated.push(kr_protocol::session::TerminatedProcess {
                identity: identity.clone(),
                name: Nullable::some("the session's worker".to_owned()),
                forced: false,
            });
        } else {
            surviving.push(kr_protocol::session::SurvivingResource {
                kind: UNACCOUNTED_WORKER.to_owned(),
                detail: format!(
                    "this host closed the session without confirming that its worker, {}, ended",
                    identity.pid.get()
                ),
            });
        }
        // Whatever the fence did reach, recorded where a later reader is served it rather than
        // only where this daemon can see it.
        terminated.extend(fenced.stopped.iter().map(|identity| {
            kr_protocol::session::TerminatedProcess {
                identity: identity.clone(),
                name: Nullable::some("a process this session still owned".to_owned()),
                forced: true,
            }
        }));
        let record = ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated,
            surviving,
            // The controller confirmed the worker process ended. It does not claim to have
            // discovered every application that worker may have started, and a recovery or a
            // fence that could not finish is another thing it cannot account for.
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            // Section 23 defines this as whether the *record* was written durably, which is what
            // `write_closure` below does or fails doing. It says nothing about whether the
            // session's own store was reconciled: a recovery pass that was skipped or failed is
            // reported by the archive, which reads the store rather than this record.
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        };
        self.write_closure(&record).await?;
        Ok(record)
    }

    /// Records a closure from outside this daemon's own bookkeeping, unless one is already
    /// recorded, and looks at the sleep setting afterwards.
    ///
    /// This is the entry point for a closure a worker hands over in its answer to a close, on
    /// either door (`Self::settle_close_answer`). It holds the same lock across its check and
    /// its write as `Self::record_final`, so a worker's own account of how its session ended can
    /// never be replaced by a later record, whichever path carried it. A session that has ended is
    /// work that has ended, so the setting is looked at once the record is written; the caller's
    /// own answer never waits for that.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn retire(self: &Arc<Self>, record: &ClosureRecord) -> Result<()> {
        let written = {
            let _finalising = self.finalising.lock().await;
            if self
                .registry
                .lock()
                .await
                .closure(record.session_id)?
                .is_some()
            {
                // Somebody else recorded this closure first. That it is recorded at all is what
                // the setting is about, so the look below happens either way.
                Ok(())
            } else {
                self.write_closure(record).await
            }
        };
        // Outside the lock, and before the result is returned: the registry row is written before
        // the descriptor is removed, so a failure after that point is a closure that counts as
        // finished with an error to report about the tidying.
        self.review_power_soon();
        written
    }

    /// Records a closed session, removes its descriptor and forgets its key.
    ///
    /// The caller holds `finalising` and has found that no closure is recorded yet. Nothing else
    /// may write one: two writers without that hold would let this daemon's own account of a
    /// worker it found gone replace the worker's own.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be written.
    pub(super) async fn write_closure(&self, record: &ClosureRecord) -> Result<()> {
        let mut registry = self.registry.lock().await;
        registry.record_closure(record)?;
        // The barrier is told in the section that records the closure, under the registry's lock
        // and before anything is awaited. A worker that has ended satisfies the barrier, and the
        // barrier keeps a participant it has ever heard of: a retired worker left to stay pending
        // for every later revocation, because nothing would be left to say that it ended, is what
        // a request dropped at one of the waits below would otherwise leave.
        self.leases.worker_ended(record.session_id);
        // The reservation outlives the closure, and it names the job the worker was started as and
        // the process that job ran. A read that fails here costs that job nothing but time: the next
        // start of this daemon looks at every job it has defined.
        let reservation = registry
            .reservation_for_session(record.session_id)
            .ok()
            .flatten();
        drop(registry);
        if let Some(reservation) = reservation {
            self.retire_job_when_ended(reservation.reservation_id, reservation.launcher_identity);
        }
        // This daemon's own view of the session goes as soon as the closure is recorded, before
        // the published descriptor is removed and whether or not that succeeds. The closure is
        // the fact; a worker kept in the directory after it would be a session this daemon still
        // asked about, still counted as work outstanding, and still answered for.
        self.directory.lock().await.remove(record.session_id);
        self.connections.lock().await.remove(&record.session_id);
        // The attention store reads what is left of the session's sources from its journal and
        // then ends its live conditions, on a task of its own: a closure is not held up by it.
        {
            let module = Arc::clone(&self.attention);
            let reach = self.attention_reach();
            let session_id = record.session_id;
            tokio::spawn(async move {
                module.session_closed(reach.as_ref(), session_id).await;
            });
        }
        // A closed session has no window to report on, and a create token that replays one is
        // answered from the closure record.
        self.presentations.lock().await.remove(&record.session_id);
        // The worker leaves the plugin admissions' set with its session: at once where the
        // closure confirms its end, and otherwise once the kernel says its process ended.
        let unaccounted = record
            .surviving
            .iter()
            .any(|resource| resource.kind == UNACCOUNTED_WORKER);
        self.plugin_bridge.closed(record.session_id, !unaccounted);
        // The session has stopped being work this host counts, and this is the line where that
        // became true of everything the counting reads: the record is written and the session has
        // left the directory a demand scan takes its list from. Every path that records a closure
        // reaches here, so the look at the setting happens here rather than at each of them, and
        // it happens before the tidying below, which can fail.
        if let Some(controller) = self.me.upgrade() {
            controller.review_power_soon();
        }
        // The directory the worker ran in goes with the session. It holds nothing the closure
        // record needs, and one per session that nothing removes would outlive every session this
        // host has ever run. A worker still on its way out may be holding it; on the platforms
        // where that refuses the removal, the next start writes the directory again.
        let _ = std::fs::remove_dir_all(self.paths.worker_dir(record.session_id));
        kr_ipc::descriptor::retire(&self.paths, record.session_id)?;
        Ok(())
    }

    /// Removes the job a worker was started as, once that worker has ended.
    ///
    /// The job goes when its process has ended, not when the session's closure is recorded: a
    /// worker hands its closure over before it exits, and removing a job whose process is still
    /// running would end that process part way through its own closure. The kernel is asked first
    /// where the launch recorded a process, because asking it starts nothing; launchd is then asked
    /// until it lets the job go, because it collects an ended process a moment after the kernel
    /// says the process has ended, and a launch that recorded no process may still have one
    /// running. A job still running after [`CLOSURE_WATCH_TIMEOUT`] keeps its job until the next
    /// start of this daemon looks again.
    ///
    /// Nothing is waited for where this environment defined no job for the worker, which is every
    /// worker a platform other than macOS starts.
    pub(super) fn retire_job_when_ended(
        &self,
        reservation_id: ReservationId,
        launched: Option<kr_protocol::identity::ProcessStartIdentity>,
    ) {
        let jobs = self.paths.jobs_dir();
        if !crate::supervision::defines_worker_job(&jobs, reservation_id) {
            return;
        }
        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + CLOSURE_WATCH_TIMEOUT;
            if let Some(identity) = launched {
                while !matches!(
                    kr_ipc::identity::process_state(&identity),
                    kr_ipc::identity::ProcessState::Ended
                ) && tokio::time::Instant::now() < deadline
                {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
            // One look whatever the kernel said, then one each second, and none begun once the
            // bound has passed, however long a look waits for a thread to run on.
            let Some(mut left) = retire_worker_job_aside(jobs.clone(), reservation_id, None).await
            else {
                return;
            };
            loop {
                if matches!(left, JobRetirement::Gone) {
                    return;
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                tokio::time::sleep(
                    std::time::Duration::from_secs(1).min(deadline.saturating_duration_since(now)),
                )
                .await;
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                let Some(next) = retire_worker_job_aside(
                    jobs.clone(),
                    reservation_id,
                    Some(deadline.into_std()),
                )
                .await
                else {
                    break;
                };
                left = next;
            }
            if let JobRetirement::Unsettled(detail) = left {
                eprintln!(
                    "kr-controller: the job of the worker started for reservation {reservation_id} \
                     could not be removed: {detail}"
                );
            }
        });
    }
}

/// Removes a worker's job on a thread that may block, since the platform is asked with commands
/// of its own, and says what it found.
///
/// `None` where the removal was not begun, because the thread it waited for ran only after
/// `not_after`, or where that thread ended without saying.
async fn retire_worker_job_aside(
    jobs: PathBuf,
    reservation_id: ReservationId,
    not_after: Option<std::time::Instant>,
) -> Option<JobRetirement> {
    tokio::task::spawn_blocking(move || {
        if not_after.is_some_and(|not_after| std::time::Instant::now() >= not_after) {
            return None;
        }
        Some(crate::supervision::retire_worker_job(&jobs, reservation_id))
    })
    .await
    .ok()
    .flatten()
}
