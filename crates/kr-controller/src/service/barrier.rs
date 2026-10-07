//! The authority revision, the fence debts a restrictive change owes, the barrier and the debt
//! pass.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_protocol::action::RevocationBarrier;
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::ids::{ActorId, AuthorityRevision, SessionId};
use kr_transport::lease::WorkerBinding;

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};

use super::Controller;
use super::workers::WORKER_EXCHANGE;

/// How many pages of one worker's fence evidence this daemon collects in one announcement.
///
/// The names are in the worker's journal, so there is no bound on how many a busy session can
/// produce; what is bounded is how long one announcement spends collecting them. A worker with
/// more than this many pages keeps the rest, the report says how many have not arrived, and the
/// next announcement continues from where this one stopped.
const MAX_EVIDENCE_PAGES: usize = 64;

/// How many times one announcement asks again for a page of evidence that a worker refused because
/// its dispatch boundary was held, in all the pages it collects.
///
/// A worker takes the boundary without waiting and refuses an announcement while a mutation, a
/// generation another link presents or a maintenance pass is inside it, which is a matter of
/// moments. The pause before the first of these is [`PAGE_RETRY_PAUSE`] and it doubles up to
/// [`PAGE_RETRY_LONGEST_PAUSE`], so the retries together wait about five seconds at most, which is
/// one worker exchange. A worker still busy after that leaves the rest of its names to the next
/// announcement, and the report says how many are outstanding.
const MAX_PAGE_RETRIES: u32 = 10;

/// The pause before the first retry of a refused page.
const PAGE_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(20);

/// The longest pause before a retry of a refused page.
const PAGE_RETRY_LONGEST_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);

/// What one announcement may spend collecting a worker's fence evidence.
struct EvidenceBudget {
    /// How many more page exchanges it may make.
    pages: usize,
    /// How many more times it may ask again for a page the worker refused for now.
    retries: u32,
}

/// How far one restrictive change reaches when the barrier that retires it fences connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// Every connection this daemon has admitted.
    Host,
    /// The connections of one revoked device. Every other connection is admitted again at the
    /// revision the barrier advances to, so one device's revocation is not everybody's reconnect.
    Device(kr_protocol::ids::DeviceId),
}

/// The restrictive changes whose fence debt no barrier has retired (section 26).
///
/// A change that narrows authority some copy may still hold writes its own debt row before its
/// restriction takes effect ([`crate::grants::GrantDirectory::owe_fence`]). The row is **pending**
/// here until the change has tried to take effect, and **published** from then on, whether or not
/// the restriction landed: a barrier that fences for a restriction that failed is one more than was
/// needed, which is harmless, and nothing stays pending for ever. A pending debt refuses nothing,
/// and no barrier captures it, because its restriction is not in force yet. Every debt on disk is
/// published when a daemon starts.
///
/// A published debt is **covered** while the change that published it is on its way to its own
/// barrier ([`OwnBarrier`]), and **left** to the debt pass otherwise: a start published it, its
/// change raised no barrier of its own, or that barrier could not take its first step. The pass
/// captures only what is left to it, so it never takes a debt from the change about to capture it.
///
/// A barrier moves what it captures to **retiring** until its rows are deleted, so no later
/// barrier of this run captures them again; rows it could not delete stay retiring, and the next
/// start raises one more barrier for them.
#[derive(Debug, Default)]
pub(super) struct Debts {
    pending: BTreeMap<crate::grants::store::DebtId, Reach>,
    pub(super) published: BTreeMap<crate::grants::store::DebtId, Published>,
    pub(super) retiring: std::collections::BTreeSet<crate::grants::store::DebtId>,
}

/// One published debt ([`Debts`]).
#[derive(Clone, Copy, Debug)]
pub(super) struct Published {
    /// How far the barrier that retires it fences connections.
    pub(super) reach: Reach,
    /// Whether the change that published it is still on its way to its own barrier.
    pub(super) covered: bool,
}

/// A change's own barrier, on its way to the debts the change has just published.
///
/// A change publishes its debts the moment its restriction has been tried, and raises its own
/// barrier at once ([`Controller::barrier`]). Until that barrier's first step the debts are
/// covered, and the debt pass leaves them alone, so it never races the change to them. A change
/// that never takes that step, because it returned early or its caller stopped waiting, drops this
/// instead: whatever of its debts is still published is left to the pass, which is woken for it.
#[must_use = "a change's debts wait for the debt pass unless its own barrier is raised"]
pub(crate) struct OwnBarrier {
    debts: Vec<crate::grants::store::DebtId>,
    held: Arc<std::sync::Mutex<Debts>>,
    pass: Arc<tokio::sync::Notify>,
}

impl OwnBarrier {
    /// Covers the debts `other` covers as well, for a change that published in two steps.
    pub(crate) fn and(mut self, mut other: Self) -> Self {
        self.debts.append(&mut other.debts);
        self
    }
}

impl Drop for OwnBarrier {
    fn drop(&mut self) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut left = false;
        for debt in &self.debts {
            if let Some(published) = held.published.get_mut(debt) {
                published.covered = false;
                left = true;
            }
        }
        drop(held);
        if left {
            self.pass.notify_one();
        }
    }
}

impl std::fmt::Debug for OwnBarrier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnBarrier")
            .field("debts", &self.debts)
            .finish_non_exhaustive()
    }
}

/// Which published debts a barrier's first step captures ([`Controller::withdraw`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Capture {
    /// Every one: a change's own barrier, which retires whatever else is owed with its own.
    Every,
    /// Only those left to the debt pass ([`Debts`]).
    Left,
}

/// How often the daemon raises a barrier for debts no barrier has retired, and how soon after a
/// barrier that could not be raised it tries again.
pub const DEBT_PASS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// How often a task that holds its daemon only while something else holds it too looks at whether
/// it has become the daemon's last holder ([`while_held`]).
const LAST_HOLDER_LOOK: std::time::Duration = std::time::Duration::from_millis(50);

/// When the debt pass looks again.
#[derive(Debug)]
pub(super) enum PassSchedule {
    /// At every tick of an interval, whatever the pass did between two of them.
    Every(tokio::time::Interval),
    /// Whenever this host's own tests say, and never otherwise.
    #[cfg(test)]
    ByHand(tokio::sync::mpsc::UnboundedReceiver<()>),
}

impl PassSchedule {
    /// Every `period`, from now.
    pub(super) fn every(period: std::time::Duration) -> Self {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self::Every(interval)
    }

    /// Waits for the next pass.
    async fn next(&mut self) {
        match self {
            Self::Every(interval) => {
                interval.tick().await;
            }
            #[cfg(test)]
            Self::ByHand(passes) => {
                if passes.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// The debt pass: it raises a barrier for every debt left to it ([`Debts`]) at each of `passes`,
/// and at once whenever `woken` is notified, which a change that leaves it a debt does
/// ([`OwnBarrier`]).
///
/// A pass captures at once, whatever an earlier barrier of the pass is still waiting for: each
/// barrier's workers are told on a task of its own, one barrier's after another's, and the debts a
/// pass captures while one is being told are told next. So while storage takes a barrier, a debt
/// left to the pass stays published for no longer than one pass, and every admission and forward
/// is refused meanwhile ([`Controller::check_fence`]).
///
/// The pass holds the daemon weakly, and strongly only through [`while_held`], so a daemon whose
/// owner lets it go lets its environment go too, without waiting for a barrier the pass raised to
/// reach its workers. Such a barrier is left as a stop would leave it: its rows stay on disk, and
/// the next start raises one more barrier for them.
async fn debt_pass(
    daemon: std::sync::Weak<Controller>,
    woken: Arc<tokio::sync::Notify>,
    mut passes: PassSchedule,
) {
    // What the pass has captured and not yet told the workers about, and the telling under way.
    let mut untold: Vec<crate::grants::store::DebtId> = Vec::new();
    let mut telling: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        let told = tokio::select! {
            () = until_told(&mut telling) => true,
            () = passes.next() => false,
            () = woken.notified() => false,
        };
        if told {
            telling = None;
        } else {
            match while_held(&daemon, async |controller: &Controller| {
                controller.withdraw(Capture::Left).await
            })
            .await
            {
                // The daemon has gone, or goes now that this pass has let it go.
                None => return,
                Some(Ok(captured)) => untold.extend(captured.into_iter().flatten()),
                Some(Err(error)) => eprintln!(
                    "kr-controller: a barrier this host owes could not be raised yet, so nothing \
                     is admitted or forwarded until it is: {error}"
                ),
            }
        }
        if telling.is_none() && !untold.is_empty() {
            let captured = std::mem::take(&mut untold);
            let daemon = daemon.clone();
            telling = Some(tokio::spawn(async move {
                let told = while_held(&daemon, async |controller: &Controller| {
                    #[cfg(test)]
                    controller.before_the_pass_tells.wait().await;
                    controller.tell(&captured).await
                })
                .await;
                if let Some(Err(error)) = told {
                    eprintln!(
                        "kr-controller: the workers could not all be told of a barrier this host \
                         raised, so the next start raises one more for its debts: {error}"
                    );
                }
            }));
        }
        if daemon.strong_count() == 0 {
            return;
        }
    }
}

/// Waits for the telling under way to end, and for ever while there is none.
async fn until_told(telling: &mut Option<tokio::task::JoinHandle<()>>) {
    match telling {
        // One that failed has ended all the same.
        Some(handle) => drop(handle.await),
        None => std::future::pending().await,
    }
}

/// Runs `work` on the daemon `daemon` names while something besides this task holds the daemon
/// too, and answers `None` once it has gone or this task has let it go.
///
/// The daemon's own tasks hold it weakly, so none of them is what keeps a daemon, and its
/// environment lock, alive once its owner has let it go. A task that has to hold it across a wait
/// it cannot bound itself, as a barrier waits for its workers, holds it through this: every
/// [`LAST_HOLDER_LOOK`] it looks at whether it has become the daemon's last holder, and once it
/// has, it abandons the work and lets the daemon go.
async fn while_held<T>(
    daemon: &std::sync::Weak<Controller>,
    work: impl AsyncFnOnce(&Controller) -> T,
) -> Option<T> {
    let controller = daemon.upgrade()?;
    let mut working = std::pin::pin!(work(&controller));
    let mut looks = tokio::time::interval(LAST_HOLDER_LOOK);
    looks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            done = &mut working => return Some(done),
            _ = looks.tick() => {
                if Arc::strong_count(&controller) == 1 {
                    return None;
                }
            }
        }
    }
}

impl Controller {
    /// Announces the environment's current authority revision to every worker it knows about.
    ///
    /// A revocation is not complete when the daemon records it. It is complete for a worker when
    /// that worker has acknowledged the revision that removed the authority **and** fenced the
    /// undispatched actions it affects, or when the worker is confirmed ended. Anything else is
    /// pending, and this reports which, along with every action whose dispatch transition had
    /// already won the serial race and may therefore have executed.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn announce_authority_revision(&self) -> Result<RevocationBarrier> {
        // Taken before anything is read, so a worker that ends while this runs is held until it is
        // over, whatever happens to it, and the revision is recorded in the section that reads it.
        let round = self.leases.begin_round();
        let revision = {
            let registry = self.registry.lock().await;
            let revision = registry.authority_revision()?;
            round.at(revision);
            revision
        };
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        // Membership comes from the registry, not from the verified directory. A worker whose
        // challenge failed, or that this daemon has never reached, is outside the directory and
        // still durably recorded: a revocation is not complete for a worker this daemon cannot
        // account for, and reporting over the directory alone would let a replacement daemon that
        // has reached nobody report success.
        let known: Vec<SessionId> = {
            let registry = self.registry.lock().await;
            registry
                .workers()?
                .into_iter()
                .map(|worker| worker.session_id)
                .collect()
        };
        let mut attempted: Vec<SessionId> = Vec::new();
        for worker in workers {
            let session_id = worker.descriptor.session_id;
            attempted.push(session_id);
            // The binding is taken before the announcement travels, so an acknowledgement that
            // arrives over a control path this daemon has already given up on lifts nothing.
            // The control path is registered before the announcement travels, so an
            // acknowledgement is measured against a binding this daemon actually holds. Without
            // it a replacement daemon would compare every answer against a binding of zero. A
            // session that closed since the directory was read has no worker to announce to, and
            // nothing is made of it.
            let Some(binding) = self.bind_worker(session_id).await? else {
                continue;
            };
            let outcome = {
                match tokio::time::timeout(WORKER_EXCHANGE, self.worker_client(&worker)).await {
                    Ok(Ok(mut link)) => {
                        // Bounded, because a worker that will not answer must not stop the
                        // revocation from reporting `pending` for it, and must not stop the
                        // announcement reaching the workers after it. Section 9 makes waiting the
                        // opposite of completion.
                        let notice = kr_protocol::worker::AuthorityRevisionNotice {
                            environment_id: self.paths.environment_id(),
                            revision,
                            evidence_from: 0,
                        };
                        #[cfg(feature = "testing")]
                        self.record_announcement(session_id, &notice);
                        let answered = tokio::time::timeout(
                            WORKER_EXCHANGE,
                            link.client().announce_revision(notice),
                        )
                        .await;
                        match answered {
                            Ok(Ok(ack)) => {
                                link.give_back();
                                Some(ack)
                            }
                            // An exchange that failed or ran out leaves a client whose stream
                            // position nothing knows, so the link is closed rather than returned,
                            // and the path it was on is given up with it as it goes out of scope.
                            Ok(Err(_)) | Err(_) => None,
                        }
                    }
                    // The wait for the link ran out: another operation holds it, and what that
                    // operation does with it is its own to answer for, so nothing is given up
                    // here. A link that could not be opened has given up its own path.
                    Ok(Err(_)) | Err(_) => None,
                }
            };
            match outcome {
                Some(ack) if ack.revision.get() >= revision.get() => {
                    // The barrier first, because it is what validates the binding: this
                    // announcement was made over one control path, and another exchange can lose
                    // that path and advance the binding while this one waits. Recording the
                    // acknowledgement in the registry before the barrier had judged it would let a
                    // stale answer move `revision_pending` even where the barrier refused it.
                    //
                    // Under the binding this announcement was made over, not whatever the binding
                    // is now.
                    // Whether this worker reported what its fence did, which is the half of the
                    // acknowledgement the durable row stands for. Recording the revision for a
                    // worker that said nothing about its fence would make `revision_pending` and
                    // the barrier disagree, and the barrier is the one section 9 defines.
                    let evidenced = ack.fence.is_some();
                    let accepted =
                        self.leases
                            .acknowledge(session_id, binding, ack.revision, ack.fence);
                    if accepted && evidenced {
                        {
                            let mut registry = self.registry.lock().await;
                            registry.record_acknowledged_revision(session_id, ack.revision)?;
                        }
                        // The evidence travels a page at a time, because one acknowledgement is
                        // one control frame. The barrier holds on the first page, which is the
                        // acknowledgement itself; what these further exchanges complete is the
                        // naming section 9 requires, and each one is bounded like the first.
                        #[cfg(feature = "testing")]
                        self.after_an_acknowledgement.wait().await;
                        self.collect_owed_evidence(session_id, binding, revision)
                            .await;
                    }
                }
                // A worker that is confirmed gone answers the question a different way: it can no
                // longer act under anything. A closure this records tells the barrier in the
                // section that records it.
                _ => {
                    self.reconcile(session_id).await?;
                }
            }
        }
        // Every durably recorded worker the directory does not list. Those are the ones this
        // daemon has never reached or has given up on verifying, and the announcement cannot go to
        // them: what can still be established is whether they are gone. A worker confirmed ended
        // satisfies the barrier as surely as one that acknowledged, and one that is still running
        // stays pending rather than being left unaccounted for because nobody could see it.
        for session_id in &known {
            if attempted.contains(session_id) {
                continue;
            }
            self.reconcile(*session_id).await?;
        }
        // The report is taken inside one section of the registry, which is also where a closure is
        // recorded and the barrier is told of it. The workers it covers are those that were
        // recorded when this began and have no closure: a worker that closed since is ended and
        // needs no place in it, and a closure cannot land between this read and the report. A row
        // is removed only by recording a closure, so a session with a closure is not a worker even
        // where an earlier build's recovery wrote its row again.
        let mut registry = self.registry.lock().await;
        let mut covered = Vec::new();
        for session_id in known {
            if registry.closure(session_id)?.is_none() {
                covered.push(session_id);
            }
        }
        let report = round.report(revision, covered);
        // The one place a fence debt is settled. Every worker has acknowledged this revision or is
        // confirmed ended, which is the whole of what a completed revocation is; nothing else -
        // not an effect that succeeded, not a restart, not a document that stopped being usable -
        // may clear it.
        if report.holds() {
            registry.settle_fence(revision)?;
        }
        Ok(report)
    }

    /// Establishes a worker's control path, unless its session has closed.
    ///
    /// The one place this daemon makes a record of a worker in its barrier. Taken under the
    /// registry's lock, which is where a closure is recorded and the barrier is told of it, so the
    /// worker is either bound before its closure and ended by it, or the closure is seen here and
    /// nothing is made. A worker that closed is gone for good: its record would never end.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(crate) async fn bind_worker(&self, session_id: SessionId) -> Result<Option<WorkerBinding>> {
        let registry = self.registry.lock().await;
        if registry.closure(session_id)?.is_some() {
            return Ok(None);
        }
        Ok(Some(self.leases.bind(session_id)))
    }

    /// Returns the binding in force for a worker, binding it first when nothing is held of it, and
    /// nothing for a session that has closed ([`Self::bind_worker`]).
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(crate) async fn binding_or_bind(
        &self,
        session_id: SessionId,
    ) -> Result<Option<WorkerBinding>> {
        let registry = self.registry.lock().await;
        if registry.closure(session_id)?.is_some() {
            return Ok(None);
        }
        Ok(Some(self.leases.binding_or_bind(session_id)))
    }

    /// Asks a worker for the rest of the fence evidence it owes, a page at a time.
    ///
    /// The revision in force comes first, because that is the revocation someone is waiting on.
    /// After it come the older revocations whose names this daemon has not finished collecting: a
    /// page whose exchange failed before a newer revision was installed would otherwise never be
    /// asked for again, and section 9 requires the actions a fence could not take back to be named
    /// in *that* revocation's result. Every page in the whole sequence comes out of one budget, so
    /// a worker with several unfinished revocations cannot make one announcement unbounded.
    pub(super) async fn collect_owed_evidence(
        &self,
        session_id: SessionId,
        binding: kr_transport::lease::WorkerBinding,
        revision: AuthorityRevision,
    ) {
        #[cfg(feature = "testing")]
        let pages = MAX_EVIDENCE_PAGES.min(
            self.evidence_pages_limit
                .load(std::sync::atomic::Ordering::SeqCst),
        );
        #[cfg(not(feature = "testing"))]
        let pages = MAX_EVIDENCE_PAGES;
        let mut budget = EvidenceBudget {
            pages,
            retries: MAX_PAGE_RETRIES,
        };
        self.collect_fence_evidence(session_id, binding, revision, &mut budget)
            .await;
        for older in self.leases.evidence_outstanding(session_id, revision) {
            if budget.pages == 0 {
                return;
            }
            self.collect_fence_evidence(session_id, binding, older, &mut budget)
                .await;
        }
    }

    /// Asks a worker for the rest of one revocation's fence evidence, a page at a time.
    ///
    /// One page arrives with the acknowledgement; this is how the names that did not fit follow.
    /// It stops when the worker says nothing remains, when an exchange fails, or when the budget
    /// runs out: a worker that kept reporting names remaining would otherwise keep this daemon
    /// asking, and a revocation that cannot finish reporting is still a revocation that holds.
    ///
    /// A page the worker refuses because its dispatch boundary is held is asked for again after a
    /// pause that doubles each time ([`MAX_PAGE_RETRIES`]), because the worker has said to come
    /// again and the names are what the revocation's result owes section 9. The exchange was
    /// answered to its end, so the link goes back and the worker's lease keeps renewing. A refusal
    /// of any other kind, a failed exchange and a retry budget that has run out stop the
    /// collection as before.
    async fn collect_fence_evidence(
        &self,
        session_id: SessionId,
        binding: kr_transport::lease::WorkerBinding,
        revision: AuthorityRevision,
        budget: &mut EvidenceBudget,
    ) {
        let mut pause = PAGE_RETRY_PAUSE;
        while budget.pages > 0 {
            budget.pages -= 1;
            let Some(from) = self.leases.evidence_owed(session_id, revision) else {
                return;
            };
            let notice = kr_protocol::worker::AuthorityRevisionNotice {
                environment_id: self.paths.environment_id(),
                revision,
                evidence_from: from,
            };
            let answered = {
                // A wait for the link that runs out is not a loss of the path: another operation
                // holds it. A link that could not be opened has given up its own path.
                let Ok(Ok(mut link)) =
                    tokio::time::timeout(WORKER_EXCHANGE, self.worker_client_of(session_id)).await
                else {
                    return;
                };
                #[cfg(feature = "testing")]
                self.record_announcement(session_id, &notice);
                match tokio::time::timeout(WORKER_EXCHANGE, link.client().announce_revision(notice))
                    .await
                {
                    Ok(Ok(ack)) => {
                        link.give_back();
                        Some(Some(ack))
                    }
                    // Refused for now: the answer was read to its end, so the link goes back and
                    // the page is asked for again.
                    Ok(Err(kr_ipc::IpcError::IdentityUnavailable { detail, .. }))
                        if detail.starts_with(ErrorCode::ResourceUnavailable.as_str()) =>
                    {
                        link.give_back();
                        Some(None)
                    }
                    // Closed with its path given up as the link goes out of scope.
                    Ok(Err(_)) | Err(_) => None,
                }
            };
            let Some(answered) = answered else {
                return;
            };
            let Some(ack) = answered else {
                // The attempt was not a page: it does not count against the pages, and the
                // retries have their own bound.
                budget.pages += 1;
                if budget.retries == 0 {
                    return;
                }
                budget.retries -= 1;
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(PAGE_RETRY_LONGEST_PAUSE);
                continue;
            };
            if !self
                .leases
                .acknowledge(session_id, binding, ack.revision, ack.fence)
            {
                return;
            }
        }
    }

    /// Revokes this host's authority as it stands: one restrictive change of its own, retired by
    /// the barrier (`Self::barrier`) this raises at once.
    ///
    /// Advancing the revision invalidates every outstanding dispatch lease at once, because a lease
    /// carries the revision it was issued at, and deregisters every connection admitted under the
    /// authority that has just been withdrawn. Both happen before the announcement travels, so
    /// nothing can be admitted under the old revision while the new one is on its way.
    ///
    /// The change is its barrier, so a stop before it leaves nothing withdrawn and nothing owed: its
    /// debt is held in memory alone.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be written. The debt stays published then, every
    /// admission and forward is refused, and the debt pass, woken for it, raises the barrier.
    pub async fn revoke_authority(&self) -> Result<RevocationBarrier> {
        let own = self.publish_debts(&[(crate::grants::store::DebtId::fresh(), Reach::Host)]);
        self.barrier(own).await
    }

    /// Writes one restrictive change's fence debt before its restriction takes effect, and holds it
    /// as pending until the change has tried to take effect ([`Debts`]).
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written. The change does not happen then: a
    /// restriction whose debt is not on disk is one a stop could leave with no barrier after it.
    pub(crate) fn owe_debt(
        &self,
        covers: &str,
        reach: Reach,
    ) -> Result<crate::grants::store::DebtId> {
        let debt = self
            .sharing
            .grants()
            .owe_fence(covers, kr_ipc::now_ms().get())?;
        self.debts().pending.insert(debt, reach);
        Ok(debt)
    }

    /// Publishes the debts of a change that has just tried to take effect ([`Debts`]), covered by
    /// the barrier the change raises next, which it hands this answer to ([`Self::barrier`]).
    ///
    /// Called at once after the restriction, with nothing awaited in between, so a request that
    /// stops waiting after its restriction cannot leave a debt its change owes unpublished. From
    /// here a barrier owes them, and every admission and forward is refused until one retires them.
    /// A change with nothing to publish passes no debts, and its barrier retires what others owe.
    pub(crate) fn publish_debts(
        &self,
        debts: &[(crate::grants::store::DebtId, Reach)],
    ) -> OwnBarrier {
        let mut held = self.debts();
        for (debt, reach) in debts {
            held.pending.remove(debt);
            held.published.insert(
                *debt,
                Published {
                    reach: *reach,
                    covered: true,
                },
            );
        }
        drop(held);
        OwnBarrier {
            debts: debts.iter().map(|(debt, _)| *debt).collect(),
            held: Arc::clone(&self.debts),
            pass: Arc::clone(&self.debt_pass),
        }
    }

    /// Publishes the debt of a change made where nothing can wait, and leaves its barrier to the
    /// debt pass, which this wakes.
    ///
    /// A voice revocation runs inside the voice coordinator's lock. A voice grant's withdrawal owes
    /// no fence, but its cascade can also withdraw a grant delegated from it that is not a voice
    /// grant, and that debt is published here the moment the store has committed, so every
    /// admission and forward is refused until the barrier retires it.
    pub(crate) fn publish_and_fence(&self, debt: crate::grants::store::DebtId) {
        drop(self.publish_debts(&[(debt, Reach::Host)]));
    }

    pub(super) fn debts(&self) -> std::sync::MutexGuard<'_, Debts> {
        self.debts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Raises the one barrier every restrictive change on this host is retired by, for a change
    /// that has just published its debts under `own`.
    ///
    /// Its first step ([`Self::withdraw`]) captures every published debt, the change's own and
    /// whatever else is owed, and advances the revision once for all of them; `own` is let go
    /// after it, so whatever of the change's debts that step could not capture is left to the debt
    /// pass. Its second step ([`Self::tell`]) tells the workers and deletes the rows. With nothing
    /// captured it advances nothing and reports the barrier as it stands, which is how a debt that
    /// a concurrent barrier already retired is answered.
    ///
    /// A debt is captured only once its restriction was attempted, and only one barrier captures
    /// it, so the revision that retires it advanced after that restriction. A stop after the
    /// revision advanced and before the rows were deleted leaves them on disk; the next start
    /// publishes them, and its first barrier advances one more revision for them. That repeat
    /// withdraws and grants nothing.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be written or read. A debt the first step could
    /// not capture stays published then, so admission and forwarding stay refused until the debt
    /// pass raises its barrier.
    pub(crate) async fn barrier(&self, own: OwnBarrier) -> Result<RevocationBarrier> {
        let withdrawn = self.withdraw(Capture::Every).await;
        drop(own);
        match withdrawn? {
            Some(captured) => self.tell(&captured).await,
            None => self.announce_authority_revision().await,
        }
    }

    /// A barrier's first step. Inside the registry critical section that advances the revision,
    /// it captures the published debts `capture` names, and nothing else: memory is the one record
    /// of which debts a barrier may take, so no row read from disk can be captured before its
    /// restriction, twice, or after an earlier barrier captured it. A row on disk that no change
    /// of this run holds is published only by a start, before anything is served. The revision
    /// advances once for all of them and they move to retiring; the connections admitted under what
    /// they withdrew are deregistered in the same section. The lease issuer adopts the revision in
    /// that section too, before the debts are let go, so no lease is issued on the revision it
    /// replaces while the withdrawal is owed ([`Self::dispatch_lease`]). Then the host policy
    /// follows the revision, and the network connections that lost their registration are closed.
    ///
    /// With nothing captured it advances nothing and answers `None`.
    async fn withdraw(
        &self,
        capture: Capture,
    ) -> Result<Option<Vec<crate::grants::store::DebtId>>> {
        let captured = {
            let mut registry = self.registry.lock().await;
            let captured: BTreeMap<crate::grants::store::DebtId, Reach> = self
                .debts()
                .published
                .iter()
                .filter(|(_, published)| capture == Capture::Every || !published.covered)
                .map(|(debt, published)| (*debt, published.reach))
                .collect();
            if captured.is_empty() {
                None
            } else {
                // The store's lock order is the registry first, then the connections. Admission
                // takes the same two in the same order, so a connection cannot be registered
                // against a revision this has already replaced.
                registry.advance_authority_revision()?;
                let revision = registry.authority_revision()?;
                let host_wide = captured.values().any(|reach| *reach == Reach::Host);
                let mut admitted = self.admitted_table();
                if host_wide {
                    admitted.retain(|_, connection| connection.admitted_revision >= revision);
                } else {
                    let revoked: std::collections::BTreeSet<ActorId> = captured
                        .values()
                        .filter_map(|reach| match reach {
                            Reach::Device(device_id) => {
                                Some(kr_transport::listener::device_principal(device_id))
                            }
                            Reach::Host => None,
                        })
                        .collect();
                    // The connections that were not withdrawn hold authority these changes did not
                    // touch, so they are admitted at the revision now in force. Work they had
                    // already admitted still carries the revision it was admitted under, and is
                    // refused inside its own transaction as before.
                    admitted.retain(|_, connection| !revoked.contains(&connection.actor_id));
                    for connection in admitted.values_mut() {
                        connection.admitted_revision = revision;
                    }
                }
                drop(admitted);
                // The issuer adopts the revision while the debts are still published. A debt is
                // published without the revision moving, so the issuer holds every worker's
                // acknowledgement of the revision in force and renews on it, and only the fence
                // keeps a lease from being handed out: let go of the debts first and a lease taken
                // between the two is a lease for the revision this section has just replaced, with
                // nothing left to refuse it. Adopted first, a lease is refused until the worker has
                // acknowledged the new revision.
                #[cfg(feature = "testing")]
                self.before_the_leases_adopt.wait();
                self.leases.revoke(revision);
                let mut debts = self.debts();
                for debt in captured.keys() {
                    debts.published.remove(debt);
                    debts.retiring.insert(*debt);
                }
                Some((revision, captured, host_wide))
            }
        };
        let Some((revision, captured, host_wide)) = captured else {
            return Ok(None);
        };
        // The host policy decides a paired device's request against the revision in force, so it
        // follows this one. A grant issued from now on carries it, and a policy left at the
        // previous revision would refuse that grant as claiming a revision this host never issued.
        self.policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .advance_authority_revision(revision);
        if host_wide {
            // The registrations are gone; the connections that held them are told. A frame already
            // waiting for its peer is stopped by its connection closing, not by the next check.
            self.fence_network_connections().await;
        }
        Ok(Some(captured.into_keys().collect()))
    }

    /// A barrier's second step: every worker is told the revision in force, the policy and the
    /// feed record it, and the rows of the debts the first step captured are deleted, last,
    /// because that is the record that their barrier finished. A row this cannot delete stays on
    /// disk, and the next start raises one more barrier for it.
    async fn tell(&self, captured: &[crate::grants::store::DebtId]) -> Result<RevocationBarrier> {
        let barrier = self.announce_authority_revision().await?;
        self.update_policy(|policy| {
            policy.advance_authority_revision(barrier.authority_revision);
        })?;
        {
            // The feed numbers its entries from the same sequence the registry does, so a feed
            // entry cannot later claim a revision a local revocation has already used.
            let mut feed = self.authority_feed();
            feed.note_revision(barrier.authority_revision);
            self.sharing.grants().store_feed(&feed.snapshot())?;
        }
        match self.sharing.grants().fence_completed(captured) {
            Ok(()) => {
                let mut debts = self.debts();
                for debt in captured {
                    debts.retiring.remove(debt);
                }
            }
            Err(error) => eprintln!(
                "kr-controller: could not delete the fence debts a completed barrier retired, so \
                 the next start raises one more barrier for them: {error}"
            ),
        }
        Ok(barrier)
    }

    /// Raises a barrier for every debt left to the debt pass ([`Debts`]): the debts a start found
    /// on disk, and those whose change raised no barrier of its own or whose barrier could not
    /// take its first step.
    ///
    /// # Errors
    ///
    /// Returns the barrier's error; a debt it could not capture stays published.
    pub(crate) async fn raise_owed_barrier(&self) -> Result<Option<RevocationBarrier>> {
        match self.withdraw(Capture::Left).await? {
            Some(captured) => self.tell(&captured).await.map(Some),
            None => Ok(None),
        }
    }

    /// Starts the debt pass ([`debt_pass`]), which raises a barrier for every debt left to it at
    /// each of `passes`, and at once whenever a change leaves it one.
    pub(super) fn start_debt_pass(self: &Arc<Self>, passes: PassSchedule) {
        tokio::spawn(debt_pass(
            Arc::downgrade(self),
            Arc::clone(&self.debt_pass),
            passes,
        ));
    }

    /// Returns which workers have not yet acknowledged the environment's authority revision.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub async fn revision_pending(&self) -> Result<Vec<SessionId>> {
        let registry = self.registry.lock().await;
        let revision = registry.authority_revision()?;
        Ok(registry
            .workers()?
            .into_iter()
            .filter(|worker| worker.acknowledged_revision.get() < revision.get())
            .map(|worker| worker.session_id)
            .collect())
    }

    /// Refuses while this host owes a fence it could not raise.
    ///
    /// Asked by [`Self::check_admission`] under the registry lock and by
    /// [`Self::check_registration`] from inside the work a mutation has begun, so no admitted
    /// mutation acts while the fence is owed, whichever service performs it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] while the fence is owed.
    pub(super) fn check_fence(&self) -> Result<()> {
        // A restriction whose barrier has not retired it stops everything that barrier would have
        // fenced. The revision did not advance, so the registry still reports every connection as
        // admitted; refusing here is what keeps work admitted under withdrawn authority from being
        // dispatched while the withdrawal is still owed. A pending debt refuses nothing: its
        // restriction is not in force yet.
        if !self.debts().published.is_empty() {
            return Err(ControllerError::PermissionDenied {
                detail: "this host withdrew authority and the fence that withdrawal owes could \
                         not be raised yet, so nothing admitted under it is dispatched; run kr \
                         doctor to see what stopped it"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Holds a published debt, or lets every one go, for this host's own tests of what refuses
    /// while a barrier is owed. The debt is covered, so the debt pass leaves it to the test.
    #[cfg(test)]
    pub(super) fn hold_fence(&self, held: bool) {
        let mut debts = self.debts();
        if held {
            debts.published.insert(
                crate::grants::store::DebtId::fresh(),
                Published {
                    reach: Reach::Host,
                    covered: true,
                },
            );
        } else {
            debts.published.clear();
        }
    }

    /// Reads the fence this environment owes, and why it could not be read when it could not.
    ///
    /// A debt this host cannot read is not a debt it may call settled, so an unreadable registry
    /// answers with the revision in force rather than with nothing. The alternative is a report
    /// that says every worker has answered because the file holding the answer would not open.
    pub(super) async fn fence_owed(&self) -> (Option<AuthorityRevision>, Option<Sentence>) {
        match self.registry.lock().await.fence_owed() {
            Ok(owed) => (owed, None),
            Err(error) => (
                Some(self.leases.authority_revision()),
                Some(
                    Sentence::new()
                        .stated("the fence this host owes could not be read: ")
                        .withheld(ContentClass::Message, &error.to_string()),
                ),
            ),
        }
    }
}
