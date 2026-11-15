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

/// A barrier and what each of its entries read, taken together.
pub(crate) type Announced = (
    RevocationBarrier,
    BTreeMap<SessionId, crate::authority::Reads>,
);

/// How many pages of one worker's fence evidence this daemon collects in one announcement.
///
/// The names are in the worker's journal, so there is no bound on how many a busy session can
/// produce; what is bounded is how long one announcement spends collecting them. A worker with
/// more than this many pages keeps the rest, the report says how many have not arrived, and the
/// daemon asks for the rest again, from where this one stopped.
const MAX_EVIDENCE_PAGES: usize = 64;

/// How many times an announcement asks again for a page of evidence that a worker refused because
/// its dispatch boundary was held, in all the pages it collects from all the workers.
///
/// A worker takes the boundary without waiting and refuses an announcement while a mutation, a
/// generation another link presents or a maintenance pass is inside it, which is a matter of
/// moments. The pause before the first of these is [`PAGE_RETRY_PAUSE`] and it doubles up to
/// [`PAGE_RETRY_LONGEST_PAUSE`], so the retries together wait about five seconds at most, which is
/// one worker exchange. The bound is the announcement's and not each worker's, so a host with many
/// busy workers does not wait for each of them in turn. A worker still busy after the bound leaves
/// the rest of its names to the daemon's own collection ([`evidence_pass`]), and the report says
/// how many are outstanding. The pages are asked for once every worker has been asked for its
/// acknowledgement, so a busy worker holds up the pages of the workers after it and never their
/// acknowledgements.
const MAX_PAGE_RETRIES: u32 = 10;

/// How many times the read-back at a restart asks again, for one worker, for a revision's first
/// page that the worker refused because its dispatch boundary was held.
///
/// The pause before the first of these is [`PAGE_RETRY_PAUSE`] and it doubles, so the retries wait
/// 140 milliseconds at most. A worker holds the boundary for a moment when another of the
/// daemon's links presents its generation, which is the case this covers. The bound is the
/// worker's own, so a worker that stays busy cannot cut the walk of another.
const MAX_READ_BACK_RETRIES: u32 = 3;

/// How often the daemon looks for names a worker still owes, apart from the announcements that
/// ask for them.
const EVIDENCE_PASS_INTERVAL: std::time::Duration = DEBT_PASS_INTERVAL;

/// The pause before the first retry of a refused page.
const PAGE_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(20);

/// The longest pause before a retry of a refused page.
const PAGE_RETRY_LONGEST_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);

/// What one announcement may spend collecting a worker's fence evidence.
struct EvidenceBudget {
    /// How many more page exchanges it may make.
    pages: usize,
}

/// How many more times an announcement may ask again for a page a worker refused for now, and how
/// long it pauses before it does, across every worker it collects from.
#[derive(Debug)]
struct Retries {
    left: u32,
    pause: std::time::Duration,
    /// Whether the collection is the evidence pass's and not an announcement's, which this host's
    /// own tests tell apart: a pass is not an announcement they count. Compiled away in every
    /// shipped build.
    #[cfg(feature = "testing")]
    by_the_pass: bool,
}

impl Retries {
    /// What a whole announcement may spend.
    fn for_an_announcement() -> Self {
        Self {
            left: MAX_PAGE_RETRIES,
            pause: PAGE_RETRY_PAUSE,
            #[cfg(feature = "testing")]
            by_the_pass: false,
        }
    }

    /// What the read-back at a restart may spend on one worker: a few retries of a refusal for now,
    /// besides the one exchange for each revision it asks about.
    fn for_the_read_back() -> Self {
        Self {
            left: MAX_READ_BACK_RETRIES,
            ..Self::for_an_announcement()
        }
    }

    /// What one run of the evidence pass may spend.
    fn for_the_pass() -> Self {
        Self {
            #[cfg(feature = "testing")]
            by_the_pass: true,
            ..Self::for_an_announcement()
        }
    }

    /// Waits before the next retry and says whether there is one, taking it from what is left.
    async fn wait(&mut self) -> bool {
        if self.left == 0 {
            return false;
        }
        self.left -= 1;
        tokio::time::sleep(self.pause).await;
        self.pause = (self.pause * 2).min(PAGE_RETRY_LONGEST_PAUSE);
        true
    }
}

/// How far one restrictive change reaches when the barrier that retires it fences connections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// Every connection this daemon has admitted.
    Host,
    /// The connections of one revoked device. Every other connection is admitted again at the
    /// revision the barrier advances to, so one device's revocation is not everybody's reconnect.
    Device(kr_protocol::ids::DeviceId),
    /// The connections acting under these grants, which a share's revocation withdrew with its
    /// descendants, or a call's voice grant, which no connection acts under: the barrier then
    /// withdraws none and only moves the revision. A connection that acts under any other grant,
    /// and the owner's own, are admitted again at the revision the barrier advances to.
    Grants {
        /// Every grant the revocation reached.
        grants: std::collections::BTreeSet<kr_protocol::ids::GrantId>,
        /// The ones that carry `terminal.input` or `terminal.geometry`, which are the only ones a
        /// worker holds an input lease or the size of a session under, and so the only ones it is
        /// told.
        holding_leases: std::collections::BTreeSet<kr_protocol::ids::GrantId>,
    },
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
    /// What each of the latest revisions withdrew, by revision, for the announcement of it: the
    /// grants and devices, or none for a revision that withdrew authority this daemon cannot name.
    ///
    /// A daemon that restarts keeps none, and a revision with no entry is announced as the whole
    /// host's, which fences every caller under a grant.
    reaches: BTreeMap<u64, Option<std::sync::Arc<Named>>>,
    /// The revision the next barrier advances the registry to at least, when the authority feed
    /// holds revisions above it ([`Controller::catch_up_with_the_feed`]). Memory alone: the
    /// registry's fence debt is what a stop leaves owed.
    floor: Option<AuthorityRevision>,
}

/// The grants and the devices one revision withdrew authority from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Named {
    grants: std::collections::BTreeSet<kr_protocol::ids::GrantId>,
    devices: std::collections::BTreeSet<kr_protocol::ids::DeviceId>,
}

impl Named {
    /// How many names a notice carries for this.
    fn len(&self) -> usize {
        self.grants.len() + self.devices.len()
    }

    fn joined(&self, other: &Self) -> Self {
        Self {
            grants: self.grants.union(&other.grants).copied().collect(),
            devices: self.devices.union(&other.devices).copied().collect(),
        }
    }
}

/// How many revisions' reaches the daemon keeps for their announcements.
///
/// A worker is told every revision at the barrier that advances it, and one it was refused keeps
/// the reach it was refused with, so it needs more than the revision before the one it holds only
/// when it answered none of this many announcements in a row, each of which a device would have to
/// cause by a revocation of its own. A worker further behind than this is fenced as the whole
/// host's, which is safe.
const KEPT_REVISION_REACHES: usize = 256;

/// One published debt ([`Debts`]).
#[derive(Clone, Debug)]
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
            match while_held(&daemon, async |controller: &Arc<Controller>| {
                controller.withdraw(Capture::Left, &[]).await
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
                let told = while_held(&daemon, async |controller: &Arc<Controller>| {
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

/// What came of telling a worker the revisions it has not fenced.
pub(crate) enum Told {
    /// The worker acknowledged the last of them.
    Acknowledged(kr_protocol::worker::AuthorityRevisionAck),
    /// The worker answered that its dispatch boundary is held for the moment. The exchange was
    /// read to its end, so the link is good, and the worker has recorded what it owes.
    Refused,
    /// An exchange failed or ran out, so what the link holds nobody knows.
    Failed,
}

/// What came of one exchange with a worker.
enum Answer<T> {
    /// The worker answered.
    Given(T),
    /// The worker refused for the moment, which is an answer.
    Refused,
    /// The exchange failed or ran out.
    Failed,
}

/// Whether a worker's error says that it cannot decide now and the request is to be made again.
fn refused_for_now(error: &kr_ipc::IpcError) -> bool {
    matches!(
        error,
        kr_ipc::IpcError::IdentityUnavailable { detail, .. }
            if detail.starts_with(ErrorCode::ResourceUnavailable.as_str())
    )
}

/// What one ask of a pending worker came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Asked {
    /// The worker acknowledged the revision in force.
    Acknowledged,
    /// The worker answered that its dispatch boundary is held for the moment.
    Refused,
    /// The link could not be opened, or the ask ran out, or it failed.
    Failed,
}

/// How soon the daemon asks a pending worker again after an answer: the pass's own interval.
const ASK_INTERVAL: std::time::Duration = DEBT_PASS_INTERVAL;

/// How much earlier than its time an ask may be made, so that a worker due at the next pass is
/// asked at it.
const PASS_JITTER: std::time::Duration = std::time::Duration::from_millis(250);

/// How long one ask of a pending worker may take in all: the exchange, bounded by
/// [`super::net::ACKNOWLEDGEMENT_TIMEOUT`], and the collection of the names an acknowledgement
/// leaves, which an ask that is cut leaves to the pass's own collection.
pub(super) const PASS_ASK_BOUND: std::time::Duration =
    super::net::ACKNOWLEDGEMENT_TIMEOUT.saturating_add(WORKER_EXCHANGE);

/// The longest wait that is scheduled after an ask that failed. The ask is made at the first pass
/// that falls after the wait, so the gap between two asks can be longer.
const ASK_INTERVAL_LONGEST: std::time::Duration = std::time::Duration::from_secs(60);

/// When the pass next asks each worker it has asked.
///
/// A refusal costs one frame on a link that is still good, so the worker is asked again at the
/// first pass that falls five seconds after the ask began. An ask that could not open a link or
/// ran out costs a link attempt and the whole of its acknowledgement time: the wait before the next
/// one, counted from its end, doubles from five seconds to a minute at most, and the ask is made
/// at the first pass after it. An answer of any kind puts the wait back to five seconds. A worker
/// whose earlier presentation is still waiting at its dispatch boundary is not asked at all. Only
/// memory: the registry decides each pass who is pending.
#[derive(Debug, Default)]
pub(super) struct AskPace {
    workers: BTreeMap<SessionId, Pace>,
}

/// One worker's place in the asking.
#[derive(Debug, Clone, Copy)]
struct Pace {
    /// The interval after the last ask that did not answer.
    interval: std::time::Duration,
    /// The first instant it may be asked again.
    next_at: tokio::time::Instant,
}

impl AskPace {
    /// Forgets the workers that are no longer pending: an acknowledgement and an end both put the
    /// worker back at the beginning.
    fn keep_only(&mut self, pending: &[SessionId]) {
        self.workers
            .retain(|session_id, _| pending.contains(session_id));
    }

    /// Whether `session_id` may be asked at the pass that began at `tick`.
    ///
    /// A pass begins a little after its time, by as much as the wake-up took, and the next one
    /// begins a little after its own: a worker asked at one pass is due at the next however the two
    /// delays compare, which is what [`PASS_JITTER`] says.
    fn due(&self, session_id: SessionId, tick: tokio::time::Instant) -> bool {
        self.workers
            .get(&session_id)
            .is_none_or(|pace| tick + PASS_JITTER >= pace.next_at)
    }

    /// Records what the ask that began at `began` and ended at `ended` came to.
    fn record(
        &mut self,
        session_id: SessionId,
        asked: Asked,
        began: tokio::time::Instant,
        ended: tokio::time::Instant,
    ) {
        let pace = match asked {
            Asked::Acknowledged | Asked::Refused => Pace {
                interval: ASK_INTERVAL,
                next_at: began + ASK_INTERVAL,
            },
            Asked::Failed => {
                let interval = self
                    .workers
                    .get(&session_id)
                    .map_or(ASK_INTERVAL, |pace| pace.interval);
                let interval = (interval * 2).min(ASK_INTERVAL_LONGEST);
                Pace {
                    interval,
                    next_at: ended + interval,
                }
            }
        };
        self.workers.insert(session_id, pace);
    }
}

/// The evidence pass: at each of `passes` it asks the workers that still owe names for them, and
/// then asks the workers that have not acknowledged the revision in force ([`AskPace`]).
///
/// An announcement asks a busy worker for its pages only for so long ([`MAX_PAGE_RETRIES`]) and
/// reports what it did not get. Nothing else would ask again, since the debt the revocation owed
/// is settled once its barrier holds, so the names would wait for some other announcement. They
/// are asked for here, on a task of their own: a pass that waits for a worker must not hold up the
/// debt pass, whose barrier is what lets the host admit work again. They land in the report of the
/// revision they belong to, which is what an answer to a repeat of that revocation reads.
async fn evidence_pass(daemon: std::sync::Weak<Controller>, mut passes: PassSchedule) {
    let mut pace = AskPace::default();
    loop {
        passes.next().await;
        let tick = tokio::time::Instant::now();
        let held = while_held(&daemon, async |controller: &Arc<Controller>| {
            // The names that workers owe are asked for before any worker that is pending is, so
            // that one worker that does not answer cannot stop them.
            controller.collect_names_owed().await;
            controller.ask_pending_workers(&mut pace, tick).await;
        })
        .await;
        if held.is_none() {
            return;
        }
    }
}

/// Runs `futures` together on the task that awaits this, and answers what each returned, in order.
///
/// Nothing is spawned, so what is still running when this is dropped is dropped with it.
pub(super) async fn all_at_once<T>(
    futures: impl IntoIterator<Item = impl std::future::Future<Output = T>>,
) -> Vec<T> {
    let mut running: Vec<_> = futures
        .into_iter()
        .map(|future| Some(Box::pin(future)))
        .collect();
    let mut answers: Vec<Option<T>> = running.iter().map(|_| None).collect();
    std::future::poll_fn(|context| {
        let mut waiting = false;
        for (running, answer) in running.iter_mut().zip(answers.iter_mut()) {
            if let Some(future) = running {
                match future.as_mut().poll(context) {
                    std::task::Poll::Ready(value) => {
                        *answer = Some(value);
                        *running = None;
                    }
                    std::task::Poll::Pending => waiting = true,
                }
            }
        }
        if waiting {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    answers.into_iter().flatten().collect()
}

/// Waits for the telling under way to end, and for ever while there is none.
async fn until_told(telling: &mut Option<tokio::task::JoinHandle<()>>) {
    match telling {
        // One that failed has ended all the same.
        Some(handle) => drop(handle.await),
        None => std::future::pending().await,
    }
}

/// How many tasks hold the daemon through [`while_held`] now.
///
/// Those tasks are the daemon's only holders once its owner has let it go, and each one has to
/// know that without counting the others as owners. The count and the daemon's strong count are
/// read under one lock. A task is counted only after it holds the daemon and is taken out before
/// it lets the daemon go, so the count is never above the references these tasks hold: a strong
/// count that is no higher than it means nothing else holds the daemon.
#[derive(Debug, Default)]
pub(super) struct TaskHolds(std::sync::Mutex<usize>, #[cfg(test)] TaskWaits);

impl TaskHolds {
    fn count(&self) -> std::sync::MutexGuard<'_, usize> {
        #[cfg(test)]
        match self.0.try_lock() {
            Ok(guard) => return guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => self.1.says_it_waits(),
        }
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Arms the record for `task`: `waits` is called once, when `task` asks for the count and finds
    /// its guard held, just before it waits for it.
    #[cfg(test)]
    pub(super) fn say_when_it_waits(
        &self,
        task: tokio::task::Id,
        waits: impl FnOnce() + Send + 'static,
    ) {
        *self
            .1
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(WaitFor {
            task,
            waits: Box::new(waits),
        });
    }
}

/// What a test has armed to hear of a task that has to wait for the task count's guard: the task,
/// and what to call when it does. A task that finds the guard free says nothing, so a case that
/// holds the guard hears of the task that ought to wait there by an event, and of one that does not
/// by the event that follows it, never by the lack of one.
#[cfg(test)]
#[derive(Default)]
pub(super) struct TaskWaits(std::sync::Mutex<Option<WaitFor>>);

/// The task a test listens for at the task count's guard, and what to call when it waits there.
#[cfg(test)]
struct WaitFor {
    task: tokio::task::Id,
    waits: Box<dyn FnOnce() + Send>,
}

#[cfg(test)]
impl TaskWaits {
    fn says_it_waits(&self) {
        let waits = {
            let mut armed = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if armed
                .as_ref()
                .is_some_and(|armed| tokio::task::try_id() == Some(armed.task))
            {
                armed.take()
            } else {
                None
            }
        };
        if let Some(armed) = waits {
            (armed.waits)();
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for TaskWaits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskWaits")
    }
}

/// What a test has armed a [`TaskPause`] with.
#[cfg(test)]
struct Armed {
    task: tokio::task::Id,
    arrived: Box<dyn FnOnce() + Send>,
    go: std::sync::mpsc::Receiver<()>,
}

/// A point in a task's run that holds the daemon through [`while_held`], where a test stops one
/// named task: between the two counts of its look at whether it is the daemon's last holder, or
/// after its work is over and before it leaves the count.
///
/// The task says there that it has arrived and waits until the test lets it go. The wait holds
/// the thread, because the look holds the task count there and cannot await. A test that stops a
/// task here therefore does not wait on the runtime's timers while the task stands: the thread it
/// holds may be the one that drives them. Armed for one task and for one arrival, so no other
/// task is stopped by it, whichever of them gets there first.
#[cfg(test)]
#[derive(Default)]
pub(super) struct TaskPause(std::sync::Mutex<Option<Armed>>);

#[cfg(test)]
impl TaskPause {
    /// Arms the pause for `task`'s next arrival. `arrived` is called when the task is there.
    /// Returns the end that lets the task go on.
    pub(super) fn arm_for(
        &self,
        task: tokio::task::Id,
        arrived: impl FnOnce() + Send + 'static,
    ) -> std::sync::mpsc::SyncSender<()> {
        let (release, go) = std::sync::mpsc::sync_channel(1);
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Armed {
            task,
            arrived: Box::new(arrived),
            go,
        });
        release
    }

    /// Waits here when the pause is armed for the task that has arrived.
    fn wait(&self) {
        let armed = {
            let mut slot = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot
                .as_ref()
                .is_some_and(|armed| tokio::task::try_id() == Some(armed.task))
            {
                slot.take()
            } else {
                None
            }
        };
        if let Some(armed) = armed {
            (armed.arrived)();
            let _ = armed.go.recv();
        }
    }
}

/// One task's place in [`TaskHolds`], given up before the task lets go of the daemon.
struct TaskHold(Arc<TaskHolds>);

impl TaskHold {
    fn begin(holds: &Arc<TaskHolds>) -> Self {
        *holds.count() += 1;
        Self(Arc::clone(holds))
    }
}

impl Drop for TaskHold {
    fn drop(&mut self) {
        *self.0.count() -= 1;
    }
}

/// Runs `work` on the daemon `daemon` names while something besides the tasks that run work this
/// way holds the daemon too, and answers `None` once it has gone or this task has let it go.
///
/// The daemon's own tasks hold it weakly, so none of them is what keeps a daemon, and its
/// environment lock, alive once its owner has let it go. A task that has to hold it across a wait
/// it cannot bound itself, as a barrier waits for its workers, holds it through this: every
/// [`LAST_HOLDER_LOOK`] it looks at whether the tasks that hold the daemon this way ([`TaskHolds`])
/// are its only holders, and once they are, it abandons the work and lets the daemon go. Two such
/// tasks do not keep each other's daemon alive.
pub(super) async fn while_held<T>(
    daemon: &std::sync::Weak<Controller>,
    work: impl AsyncFnOnce(&Arc<Controller>) -> T,
) -> Option<T> {
    let controller = daemon.upgrade()?;
    // Declared after the daemon, so it is given up first.
    let _hold = TaskHold::begin(&controller.task_holds);
    let mut working = std::pin::pin!(work(&controller));
    let mut looks = tokio::time::interval(LAST_HOLDER_LOOK);
    looks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            done = &mut working => {
                #[cfg(test)]
                controller.before_a_task_leaves_the_count.wait();
                return Some(done);
            }
            _ = looks.tick() => {
                // The count is taken first, so that a task that begins in between can only make
                // this look see more holders than tasks: it takes the daemon before it counts
                // itself. The count's guard is kept while the daemon's own count is read, for a
                // task that ENDS in between: it takes itself out of the count first and lets go
                // of the daemon after. Read without the guard, the count would still include that
                // task while the daemon's no longer does, and the look would take the owner for
                // one of the tasks. Kept, the ending task waits at the guard until this look has
                // read both.
                let tasks = controller.task_holds.count();
                #[cfg(test)]
                controller.between_the_task_counts.wait();
                if Arc::strong_count(&controller) <= *tasks {
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
    /// Every worker is asked for its acknowledgement first. The pages of evidence an
    /// acknowledgement leaves are asked for once all of them have been, one worker after another
    /// (`Self::collect_owed_evidence`), so a worker that keeps refusing its pages holds up the
    /// pages of the workers after it and the report, and never another worker's acknowledgement,
    /// which is what the barrier holds on and what renews that worker's lease.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn announce_authority_revision(&self) -> Result<RevocationBarrier> {
        self.announce_reading().await.map(|(barrier, _)| barrier)
    }

    /// As [`Self::announce_authority_revision`], with what each entry of the barrier read, taken
    /// with it ([`crate::authority::Reads`]).
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub(crate) async fn announce_reading(&self) -> Result<Announced> {
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
        let recorded: BTreeMap<SessionId, AuthorityRevision> = {
            let registry = self.registry.lock().await;
            registry
                .workers()?
                .into_iter()
                .map(|worker| (worker.session_id, worker.acknowledged_revision))
                .collect()
        };
        let known: Vec<SessionId> = recorded.keys().copied().collect();
        let mut attempted: Vec<SessionId> = Vec::new();
        // The workers that acknowledged, with the binding each acknowledged under: the pages of
        // evidence that follow an acknowledgement are asked for once every worker has been asked
        // for its own.
        let mut acknowledged: Vec<(SessionId, WorkerBinding)> = Vec::new();
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
                        // What the host's local owner may do goes first, so the worker
                        // acknowledges the revision only after it holds the bound in force. A
                        // worker that cannot be told is pending, as one that cannot be reached.
                        let told = tokio::time::timeout(
                            WORKER_EXCHANGE,
                            self.tell_link(session_id, link.client()),
                        )
                        .await;
                        if !matches!(told, Ok(Ok(_))) {
                            drop(link);
                            None
                        } else {
                            // Bounded, because a worker that will not answer must not stop the
                            // revocation from reporting `pending` for it, and must not stop the
                            // announcement reaching the workers after it. Section 9 makes waiting
                            // the opposite of completion.
                            let answered = self
                                .tell_revisions(
                                    session_id,
                                    binding,
                                    &mut link,
                                    revision,
                                    recorded
                                        .get(&session_id)
                                        .copied()
                                        .unwrap_or_else(|| AuthorityRevision::new(0)),
                                    Some(WORKER_EXCHANGE),
                                )
                                .await;
                            // An exchange that failed or ran out leaves a client whose stream
                            // position nothing knows, so the link is closed rather than returned,
                            // and the path it was on is given up with it as it goes out of scope.
                            // A refusal for the moment is an exchange read to its end: the link is
                            // good, so it goes back, and the daemon's later asks of a worker that
                            // stays busy use it instead of opening a link that waits at the
                            // worker's dispatch boundary.
                            match answered {
                                Told::Acknowledged(ack) => {
                                    link.give_back();
                                    Some(ack)
                                }
                                Told::Refused => {
                                    link.give_back();
                                    None
                                }
                                Told::Failed => None,
                            }
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
                    let accepted = self.leases.acknowledge_announced(
                        session_id,
                        binding,
                        ack.revision,
                        ack.fence,
                    );
                    if accepted && evidenced {
                        {
                            let mut registry = self.registry.lock().await;
                            registry.record_acknowledged_revision(session_id, ack.revision)?;
                        }
                        // The evidence travels a page at a time, because one acknowledgement is
                        // one control frame. The barrier holds on the first page, which is the
                        // acknowledgement itself; what the further exchanges complete is the
                        // naming section 9 requires. They wait until every worker has been asked,
                        // because a worker that keeps refusing its pages is asked again for
                        // seconds, and the workers after it have an acknowledgement to give.
                        #[cfg(feature = "testing")]
                        self.after_an_acknowledgement.wait().await;
                        acknowledged.push((session_id, binding));
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
        // One bound on the asking again for the whole announcement, so many busy workers do not
        // cost the time of each.
        let mut retries = Retries::for_an_announcement();
        for (session_id, binding) in acknowledged {
            self.collect_owed_evidence_within(session_id, binding, revision, &mut retries)
                .await;
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
        let (report, reads) =
            round.report_with_reads(revision, covered, &std::collections::BTreeMap::new());
        // The one place a fence debt is settled. Every worker has acknowledged this revision or is
        // confirmed ended, which is the whole of what a completed revocation is; nothing else -
        // not an effect that succeeded, not a restart, not a document that stopped being usable -
        // may clear it.
        if report.holds() {
            registry.settle_fence(revision)?;
        }
        Ok((report, reads))
    }

    /// The barrier of one revision as the daemon holds it now, without asking a worker anything.
    ///
    /// The workers it covers are those recorded and not closed, as the end of an announcement
    /// takes them, so what it names of each is what the daemon has collected since the revision
    /// was announced.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(super) async fn barrier_as_it_stands(
        &self,
        revision: AuthorityRevision,
    ) -> Result<RevocationBarrier> {
        self.barrier_as_it_stands_reading(revision, &BTreeMap::new())
            .await
            .map(|(barrier, _)| barrier)
    }

    /// As [`Self::barrier_as_it_stands`], with what each entry read, and with the entries of the
    /// workers named in `through` also reading those revisions: a repeat's own read of the
    /// revisions that the answer it repeats had read ([`crate::authority::AuthorityBarrier`]'s
    /// `report_reading`). The announcement's own state does not change.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(super) async fn barrier_as_it_stands_reading(
        &self,
        revision: AuthorityRevision,
        through: &BTreeMap<SessionId, Vec<AuthorityRevision>>,
    ) -> Result<Announced> {
        let round = self.leases.begin_round();
        round.at(revision);
        let registry = self.registry.lock().await;
        let mut covered = Vec::new();
        for worker in registry.workers()? {
            if registry.closure(worker.session_id)?.is_none() {
                covered.push(worker.session_id);
            }
        }
        Ok(round.report_with_reads(revision, covered, through))
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
        self.collect_owed_evidence_within(
            session_id,
            binding,
            revision,
            &mut Retries::for_an_announcement(),
        )
        .await;
    }

    /// As [`Self::collect_owed_evidence`], asking again for a refused page out of `retries`, which
    /// a caller that collects from several workers shares among them.
    async fn collect_owed_evidence_within(
        &self,
        session_id: SessionId,
        binding: kr_transport::lease::WorkerBinding,
        revision: AuthorityRevision,
        retries: &mut Retries,
    ) {
        let mut budget = self.evidence_budget();
        self.collect_fence_evidence(session_id, binding, revision, &mut budget, retries, false)
            .await;
        // The revisions announced to the worker that a result it holds a report for reads and the
        // worker has said nothing about, because the announcement was refused or lost. Its fence
        // may have run for them since, and what it named is part of those results: each is asked
        // for, its pages as well as its first, out of the same budget. They are older than this
        // revision, which the worker acknowledged, so asking makes it fence nothing.
        for earlier in self.leases.unasked_before(session_id, revision) {
            if budget.pages == 0 {
                return;
            }
            self.collect_fence_evidence(session_id, binding, earlier, &mut budget, retries, true)
                .await;
        }
        for older in self.leases.evidence_outstanding(session_id, revision) {
            if budget.pages == 0 {
                return;
            }
            self.collect_fence_evidence(session_id, binding, older, &mut budget, retries, false)
                .await;
        }
    }

    /// What one announcement may spend collecting a worker's fence evidence.
    fn evidence_budget(&self) -> EvidenceBudget {
        #[cfg(feature = "testing")]
        let pages = MAX_EVIDENCE_PAGES.min(
            self.evidence_pages_limit
                .load(std::sync::atomic::Ordering::SeqCst),
        );
        #[cfg(not(feature = "testing"))]
        let pages = MAX_EVIDENCE_PAGES;
        EvidenceBudget { pages }
    }

    /// Tells a worker the revisions it has not fenced, over the link the caller holds, oldest
    /// first, and answers the acknowledgement of the last, which is the one the barrier waits on.
    /// It answers [`Told::Refused`] when the worker said that its dispatch boundary is held for
    /// the moment, and [`Told::Failed`] when an exchange failed or ran out, `bound` after it began
    /// when one is given.
    ///
    /// Each is a revision of its own, acknowledged as one ([`Self::note_earlier_acknowledgement`]).
    /// All are recorded as announced before any is sent, and with them what the result of each reads
    /// besides its own report ([`crate::authority::AuthorityBarrier::announced`]): the worker's
    /// fence may run for any of them whatever becomes of the answer, and which answer this daemon
    /// accepts does not change what it names.
    pub(crate) async fn tell_revisions(
        &self,
        session_id: SessionId,
        binding: WorkerBinding,
        link: &mut super::workers::WorkerLink,
        revision: AuthorityRevision,
        held: AuthorityRevision,
        bound: Option<std::time::Duration>,
    ) -> Told {
        let mut notices = self.revision_notices(revision, held, 0);
        let told: Vec<AuthorityRevision> = notices.iter().map(|notice| notice.revision).collect();
        self.leases.announced(session_id, held, &told);
        let last = notices.pop().expect("an announcement is made");
        for notice in notices {
            #[cfg(feature = "testing")]
            self.record_announcement(session_id, &notice);
            let ack = match Self::exchange(bound, link.client().announce_revision(notice)).await {
                Answer::Given(ack) => ack,
                Answer::Refused => return Told::Refused,
                Answer::Failed => return Told::Failed,
            };
            self.note_earlier_acknowledgement(session_id, binding, ack)
                .await;
        }
        #[cfg(feature = "testing")]
        self.record_announcement(session_id, &last);
        match Self::exchange(bound, link.client().announce_revision(last)).await {
            Answer::Given(ack) => Told::Acknowledged(ack),
            Answer::Refused => Told::Refused,
            Answer::Failed => Told::Failed,
        }
    }

    /// The answer of one exchange with a worker, or what became of it when it gave none: refused
    /// for the moment, or failed or took longer than `bound`.
    async fn exchange<T>(
        bound: Option<std::time::Duration>,
        exchange: impl std::future::Future<Output = std::result::Result<T, kr_ipc::IpcError>>,
    ) -> Answer<T> {
        let answered = match bound {
            Some(bound) => match tokio::time::timeout(bound, exchange).await {
                Ok(answered) => answered,
                Err(_) => return Answer::Failed,
            },
            None => exchange.await,
        };
        match answered {
            Ok(answer) => Answer::Given(answer),
            Err(error) if refused_for_now(&error) => Answer::Refused,
            Err(_) => Answer::Failed,
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
    ///
    /// `unasked` says the worker has been asked nothing of this revision yet, so that the first
    /// page starts at nought and its answer makes the worker's report of the revision.
    async fn collect_fence_evidence(
        &self,
        session_id: SessionId,
        binding: kr_transport::lease::WorkerBinding,
        revision: AuthorityRevision,
        budget: &mut EvidenceBudget,
        retries: &mut Retries,
        mut unasked: bool,
    ) {
        while budget.pages > 0 {
            budget.pages -= 1;
            let from = if unasked {
                0
            } else {
                let Some(from) = self.leases.evidence_owed(session_id, revision) else {
                    return;
                };
                from
            };
            // A continuation asks for names of a revision the worker has already fenced, so it
            // names no reach.
            let notice = kr_protocol::worker::AuthorityRevisionNotice {
                environment_id: self.paths.environment_id(),
                revision,
                reach: kr_protocol::worker::RevisionReach::Host,
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
                if !retries.by_the_pass {
                    self.record_announcement(session_id, &notice);
                }
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
                if !retries.wait().await {
                    return;
                }
                continue;
            };
            if !self
                .leases
                .acknowledge(session_id, binding, ack.revision, ack.fence)
            {
                return;
            }
            unasked = false;
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
                    reach: reach.clone(),
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

    /// Publishes the debt a voice revocation wrote, if it wrote one, raises its barrier on a task
    /// of its own, and returns the wait for it.
    ///
    /// A voice revocation commits where nothing can wait: through a seam that is not asynchronous,
    /// which a replacement of the standing grant also runs under the coordinator's lock and a stop
    /// runs with no lock held. A voice grant's withdrawal owes a fence only while a close forwarded
    /// under it can still run at a worker, and the fence is the workers holding the revision that
    /// refuses it. Its reach is the connections acting under the grants withdrawn, and none acts
    /// under a call's grant: every connection stays admitted, at the revision now in force, so the
    /// answer to the stop that withdrew the grant, and every other answer on the link it was sent
    /// on, is delivered. The debt is published the moment the store has committed, so every
    /// admission and forward is refused until the barrier retires it.
    ///
    /// A revocation that finds the grant already withdrawn while a close is still on its way under
    /// it owes a fence of its own: the earlier change's revision may not be in force yet, so this
    /// change advances it, after reading the grant, and the answer carries where the workers stand.
    ///
    /// The caller waits outside its lock and before it answers, and is given the barrier as it
    /// stands when the wait ends, pending workers named. The barrier runs on its own task, so a
    /// caller that stops waiting leaves it running; the task holds the daemon only while something
    /// besides it does ([`while_held`]), and a daemon that has gone leaves the debt on disk for the
    /// next start. Where there is no runtime to run it on, the debt is left to the debt pass.
    pub(crate) fn fence_voice_revocation(
        self: &Arc<Self>,
        revocation: &crate::grants::GrantRevocation,
    ) -> Option<kr_voice::Fence> {
        let debt = revocation.debt?;
        let reach = Reach::Grants {
            grants: revocation
                .revoked
                .iter()
                .chain(revocation.reached.iter())
                .copied()
                .collect(),
            holding_leases: revocation.reached_holding_leases.clone(),
        };
        let own = self.publish_debts(&[(debt, reach)]);
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let daemon = Arc::downgrade(self);
        let barrier = runtime.spawn(async move {
            while_held(&daemon, async move |controller: &Arc<Controller>| {
                controller.barrier(own).await
            })
            .await
        });
        Some(Box::pin(async move {
            match barrier.await {
                Ok(Some(Ok(barrier))) => Ok(barrier),
                Ok(Some(Err(error))) => Err(kr_voice::VoiceError::Host(
                    kr_protocol::error::ProtocolError::new(
                        error.code(),
                        format!(
                            "the withdrawal stands, and this host could not finish the fence it \
                             owes ({error})"
                        ),
                    ),
                )),
                Ok(None) | Err(_) => Err(kr_voice::VoiceError::Host(
                    kr_protocol::error::ProtocolError::new(
                        ErrorCode::ResourceUnavailable,
                        "this host stopped before the fence the withdrawal owes was raised; the \
                         withdrawal stands, and the host raises the fence when it starts again"
                            .to_owned(),
                    ),
                )),
            }
        }))
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
        self.barrier_reading(own).await.map(|(barrier, _)| barrier)
    }

    /// As [`Self::barrier`], with what each entry of the barrier read, for the record an answer is
    /// kept with.
    ///
    /// # Errors
    ///
    /// As [`Self::barrier`].
    pub(crate) async fn barrier_reading(&self, own: OwnBarrier) -> Result<Announced> {
        let withdrawn = self.withdraw(Capture::Every, &own.debts).await;
        drop(own);
        match withdrawn? {
            Some(captured) => self.tell_reading(&captured).await,
            None => self.announce_reading().await,
        }
    }

    /// The published debts one barrier takes: the ones `first` names, then the rest while what they
    /// name together still fits one notice, so that a revision is always told exactly. A debt
    /// that does not fit stays published and has a barrier of its own; one that reaches the whole
    /// host is taken whatever else is, since that revision is the whole host's.
    fn capturable(
        &self,
        capture: &Capture,
        first: &[crate::grants::store::DebtId],
    ) -> BTreeMap<crate::grants::store::DebtId, Reach> {
        let mut candidates: Vec<(crate::grants::store::DebtId, Reach)> = self
            .debts()
            .published
            .iter()
            .filter(|(_, published)| *capture == Capture::Every || !published.covered)
            .map(|(debt, published)| (*debt, published.reach.clone()))
            .collect();
        candidates.sort_by_key(|(debt, _)| !first.contains(debt));
        let mut captured = BTreeMap::new();
        let mut names = 0_usize;
        for (debt, reach) in candidates {
            let weight = match &reach {
                Reach::Host => 0,
                Reach::Device(_) => 1,
                Reach::Grants { holding_leases, .. } => holding_leases.len(),
            };
            if captured.is_empty()
                || reach == Reach::Host
                || names + weight <= kr_protocol::worker::MAX_REVISION_REACH_NAMES
            {
                names += weight;
                captured.insert(debt, reach);
            }
        }
        captured
    }

    /// Whose authority the debts one revision captured withdrew, or none when that is the whole
    /// host's or cannot be named.
    ///
    /// A debt that reaches every connection is the whole host. The others are the grants that carry
    /// `terminal.input` or `terminal.geometry` and the devices they name. A delegation tree cannot hold more grants than a
    /// notice names ([`crate::grants::MAX_GRANTS_PER_TREE`]), so a revocation is named exactly; what
    /// is left to name more is a tree from before that limit, and the fence it owes is the whole
    /// host's. That fence can go once no tree is left that holds more than the limit.
    fn reach_of(
        captured: &BTreeMap<crate::grants::store::DebtId, Reach>,
    ) -> Option<std::sync::Arc<Named>> {
        let mut named = Named::default();
        for reach in captured.values() {
            match reach {
                Reach::Host => return None,
                Reach::Device(device_id) => {
                    named.devices.insert(*device_id);
                }
                Reach::Grants { holding_leases, .. } => {
                    named.grants.extend(holding_leases.iter().copied());
                }
            }
        }
        (named.len() <= kr_protocol::worker::MAX_REVISION_REACH_NAMES)
            .then(|| std::sync::Arc::new(named))
    }

    /// Takes the acknowledgement of a revision older than the one a barrier waits on, which a worker
    /// that missed it gave while it was told the revisions in order: it is news about that
    /// revision and nothing else, as an acknowledgement of an older revision is. What the result of
    /// the revision reads of the notices before it was recorded with the announcement.
    pub(crate) async fn note_earlier_acknowledgement(
        &self,
        session_id: SessionId,
        binding: WorkerBinding,
        ack: kr_protocol::worker::AuthorityRevisionAck,
    ) {
        let evidenced = ack.fence.is_some();
        let revision = ack.revision;
        if self
            .leases
            .acknowledge(session_id, binding, revision, ack.fence)
            && evidenced
        {
            let _ = self
                .registry
                .lock()
                .await
                .record_acknowledged_revision(session_id, revision);
        }
    }

    /// What the revisions a worker has not fenced withdrew, up to `revision`, in the notices it is
    /// told them by: each is the last revision of a group and says which revision it follows.
    ///
    /// `held` is the revision the worker last acknowledged, as this daemon recorded it, so the
    /// reach covers the revisions after it and no older ones: a lease the worker holds from before
    /// is a lease its holder took after those revisions, and a notice that named the holders of an
    /// older revision again would take it. The revisions are grouped, oldest first, as many to a
    /// group as their names together fit one notice, so a worker that was not told one revision
    /// before the next advanced is told every one of them by name. A revision this daemon holds no
    /// reach for, because it restarted since or it passed what a notice carries, is the whole
    /// host's: the worker is told that revision as such, and the ones after it by name. A worker
    /// that was refused revisions joins its own exact record of them.
    fn reach_groups(
        &self,
        revision: AuthorityRevision,
        held: AuthorityRevision,
    ) -> Vec<(AuthorityRevision, kr_protocol::worker::RevisionReach)> {
        use kr_protocol::worker::RevisionReach;

        let host = || vec![(revision, RevisionReach::Host)];
        if held.get() >= revision.get()
            || revision.get() - held.get() > KEPT_REVISION_REACHES as u64
        {
            return host();
        }
        // The entries are taken under the lock and joined outside it: they are shared, not copied.
        let entries: Vec<(u64, Option<std::sync::Arc<Named>>)> = {
            let debts = self.debts();
            (held.get() + 1..=revision.get())
                .map(|at| (at, debts.reaches.get(&at).cloned().flatten()))
                .collect()
        };
        let unnamed = entries.iter().rev().find(|(_, entry)| entry.is_none());
        let mut groups = Vec::new();
        let mut start = held.get() + 1;
        if let Some((at, _)) = unnamed {
            if *at == revision.get() {
                return host();
            }
            groups.push((AuthorityRevision::new(*at), RevisionReach::Host));
            start = at + 1;
        }
        let bound = kr_protocol::worker::MAX_REVISION_REACH_NAMES;
        let within = |since: u64, named: Named| RevisionReach::Within {
            since: AuthorityRevision::new(since),
            grants: named.grants.into_iter().collect(),
            devices: named.devices.into_iter().collect(),
        };
        let mut group = Named::default();
        let mut since = start - 1;
        let mut previous = since;
        for (at, entry) in entries.iter().filter(|(at, _)| *at >= start) {
            let named = entry.as_deref().cloned().unwrap_or_default();
            let joined = group.joined(&named);
            if joined.len() > bound && previous >= start {
                groups.push((AuthorityRevision::new(previous), within(since, group)));
                group = named;
                since = at - 1;
            } else {
                group = joined;
            }
            previous = *at;
        }
        groups.push((revision, within(since, group)));
        // More notices than reports kept would have the reports of the first let go before the
        // result of the last reads them, and a worker that far behind is fenced as the whole
        // host's.
        if groups.len() > crate::authority::MAX_HELD_FENCE_REPORTS {
            return host();
        }
        groups
    }

    /// The announcements of `revision` to a worker that last acknowledged `held`, as this daemon
    /// recorded it, oldest first: the last is the one the barrier waits on.
    ///
    /// They name whose authority the revisions withdrew ([`Self::reach_groups`]) only for the
    /// first page of the revision's evidence: a continuation asks for names of a revision the
    /// worker has already fenced.
    pub(crate) fn revision_notices(
        &self,
        revision: AuthorityRevision,
        held: AuthorityRevision,
        evidence_from: u64,
    ) -> Vec<kr_protocol::worker::AuthorityRevisionNotice> {
        let notice =
            |revision, reach, evidence_from| kr_protocol::worker::AuthorityRevisionNotice {
                environment_id: self.paths.environment_id(),
                revision,
                reach,
                evidence_from,
            };
        if evidence_from != 0 {
            return vec![notice(
                revision,
                kr_protocol::worker::RevisionReach::Host,
                evidence_from,
            )];
        }
        self.reach_groups(revision, held)
            .into_iter()
            .map(|(revision, reach)| notice(revision, reach, 0))
            .collect()
    }

    /// The last announcement of [`Self::revision_notices`], for a test that reads one.
    #[cfg(test)]
    pub(crate) fn revision_notice(
        &self,
        revision: AuthorityRevision,
        held: AuthorityRevision,
        evidence_from: u64,
    ) -> kr_protocol::worker::AuthorityRevisionNotice {
        self.revision_notices(revision, held, evidence_from)
            .pop()
            .expect("an announcement is made")
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
        first: &[crate::grants::store::DebtId],
    ) -> Result<Option<Vec<crate::grants::store::DebtId>>> {
        let captured = {
            let mut registry = self.registry.lock().await;
            let captured = self.capturable(&capture, first);
            if captured.is_empty() {
                None
            } else {
                // The store's lock order is the registry first, then the connections. Admission
                // takes the same two in the same order, so a connection cannot be registered
                // against a revision this has already replaced.
                let floor = self.debts().floor;
                match floor {
                    Some(floor) => registry.advance_authority_revision_to(floor)?,
                    None => registry.advance_authority_revision()?,
                };
                self.debts().floor = None;
                let revision = registry.authority_revision()?;
                let host_wide = captured.values().any(|reach| *reach == Reach::Host);
                let reach = Self::reach_of(&captured);
                let revoked_grants: std::collections::BTreeSet<kr_protocol::ids::GrantId> =
                    captured
                        .values()
                        .filter_map(|reach| match reach {
                            Reach::Grants { grants, .. } => Some(grants.iter().copied()),
                            Reach::Host | Reach::Device(_) => None,
                        })
                        .flatten()
                        .collect();
                let mut admitted = self.admitted_withdraw();
                if host_wide {
                    admitted.retain(|_, connection| connection.admitted_revision >= revision);
                } else {
                    let revoked: std::collections::BTreeSet<ActorId> = captured
                        .values()
                        .filter_map(|reach| match reach {
                            Reach::Device(device_id) => {
                                Some(kr_transport::listener::device_principal(device_id))
                            }
                            Reach::Host | Reach::Grants { .. } => None,
                        })
                        .collect();
                    // The connections that were not withdrawn hold authority these changes did not
                    // touch, so they are admitted at the revision now in force. Work they had
                    // already admitted still carries the revision it was admitted under, and is
                    // refused inside its own transaction as before.
                    admitted.retain(|_, connection| {
                        !revoked.contains(&connection.actor_id)
                            && connection.acts_under_none_of(&revoked_grants)
                    });
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
                debts.reaches.insert(revision.get(), reach);
                while debts.reaches.len() > KEPT_REVISION_REACHES {
                    debts.reaches.pop_first();
                }
                Some((revision, captured))
            }
        };
        let Some((revision, captured)) = captured else {
            return Ok(None);
        };
        // The host policy decides a paired device's request against the revision in force, so it
        // follows this one. A grant issued from now on carries it, and a policy left at the
        // previous revision would refuse that grant as claiming a revision this host never issued.
        self.policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .advance_authority_revision(revision);
        // The registrations are gone; the connections that held them are told. A frame already
        // waiting for its peer is stopped by its connection closing, not by the next check. Only a
        // connection whose registration went is closed, so a narrower reach closes only its own.
        self.fence_network_connections().await;
        Ok(Some(captured.into_keys().collect()))
    }

    /// A barrier's second step: every worker is told the revision in force, the policy and the
    /// feed record it, and the rows of the debts the first step captured are deleted, last,
    /// because that is the record that their barrier finished. A row this cannot delete stays on
    /// disk, and the next start raises one more barrier for it.
    async fn tell(&self, captured: &[crate::grants::store::DebtId]) -> Result<RevocationBarrier> {
        self.tell_reading(captured)
            .await
            .map(|(barrier, _)| barrier)
    }

    /// As [`Self::tell`], with what each entry of the barrier read.
    async fn tell_reading(&self, captured: &[crate::grants::store::DebtId]) -> Result<Announced> {
        #[cfg(any(test, feature = "testing"))]
        self.before_a_barrier_tells.wait().await;
        let (barrier, reads) = self.announce_reading().await?;
        self.update_policy(|policy| {
            policy.advance_authority_revision(barrier.authority_revision);
        })?;
        {
            // The feed numbers its entries from the same sequence the registry does, so a feed
            // entry cannot later claim a revision a local revocation has already used.
            let mut feed = self.authority_feed();
            feed.note_revision(barrier.authority_revision);
            self.keep_feed(&mut feed)?;
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
        Ok((barrier, reads))
    }

    /// Raises the registry to the revision the authority feed holds for this host, in one barrier
    /// that fences every worker and withdraws every connection admitted under the state the
    /// registry was restored to.
    ///
    /// The revision moves to the feed's, or one past where it stands when that is higher, so the
    /// next revocation this host issues is numbered above everything it has issued. The barrier is
    /// the whole host's. A stop before it lands leaves the registry's fence debt owed, and the
    /// feed's pass finds the registry still behind and does this again.
    ///
    /// # Errors
    ///
    /// Returns the barrier's error; the registry stays where it was.
    pub(crate) async fn catch_up_with_the_feed(
        &self,
        feed_revision: AuthorityRevision,
    ) -> Result<RevocationBarrier> {
        self.debts().floor = Some(feed_revision);
        let own = self.publish_debts(&[(crate::grants::store::DebtId::fresh(), Reach::Host)]);
        let barrier = self.barrier(own).await;
        if barrier.is_err() {
            self.debts().floor = None;
        }
        barrier
    }

    /// Raises a barrier for every debt left to the debt pass ([`Debts`]): the debts a start found
    /// on disk, and those whose change raised no barrier of its own or whose barrier could not
    /// take its first step.
    ///
    /// # Errors
    ///
    /// Returns the barrier's error; a debt it could not capture stays published.
    pub(crate) async fn raise_owed_barrier(&self) -> Result<Option<RevocationBarrier>> {
        match self.withdraw(Capture::Left, &[]).await? {
            Some(captured) => self.tell(&captured).await.map(Some),
            None => Ok(None),
        }
    }

    /// Starts the debt pass ([`debt_pass`]), which raises a barrier for every debt left to it at
    /// each of `passes`, and at once whenever a change leaves it one, and the evidence pass
    /// ([`evidence_pass`]) beside it.
    pub(super) fn start_debt_pass(self: &Arc<Self>, passes: PassSchedule) {
        tokio::spawn(debt_pass(
            Arc::downgrade(self),
            Arc::clone(&self.debt_pass),
            passes,
        ));
        tokio::spawn(evidence_pass(
            Arc::downgrade(self),
            PassSchedule::every(EVIDENCE_PASS_INTERVAL),
        ));
    }

    /// Reads back, once, what each worker an earlier run recorded still holds of the revocations it
    /// acknowledged before this run started, on a task of its own that the start does not wait for.
    ///
    /// A restart loses what this daemon had collected: the pages it had half collected, and the
    /// report a repeat of a revocation reads. The worker keeps a revocation's names until a daemon
    /// has taken them all, and a replacement controller has taken none, so it still holds them
    /// for the newest [`kr_worker::journal::MAX_HELD_REVOCATIONS`] revocations. The first page is
    /// asked for each of the revisions at or below the one the registry holds the worker as having
    /// acknowledged, that many at most, in one exchange each. A worker that answers that its
    /// dispatch boundary is held for the moment is asked again, at most [`MAX_READ_BACK_RETRIES`]
    /// times for the walk of that worker, so a worker takes the exchanges for its revisions and
    /// those retries, and a worker that stays busy ends only its own walk. The answers
    /// carry into no result: each opens a report of its own, which a repeat of that revocation
    /// reads, and the pages that follow the first are collected by the evidence pass. The daemon keeps a report for
    /// [`crate::authority::MAX_HELD_FENCE_REPORTS`] revisions of a worker in all, so the older of
    /// these go first when the start's own announcement has read more. A revision older than those
    /// answers as it was first given.
    pub(super) fn recover_what_workers_hold(
        self: &Arc<Self>,
        workers: Vec<(SessionId, AuthorityRevision)>,
    ) {
        let daemon = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            while_held(&daemon, async move |controller: &Arc<Controller>| {
                controller.read_back_what_workers_hold(&workers).await;
            })
            .await;
        });
        #[cfg(feature = "testing")]
        {
            *self
                .read_back
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
        }
        #[cfg(not(feature = "testing"))]
        drop(task);
    }

    /// As [`Self::recover_what_workers_hold`], on this task.
    async fn read_back_what_workers_hold(&self, workers: &[(SessionId, AuthorityRevision)]) {
        for (session_id, held) in workers {
            // Each worker has retries of its own, so one that stays busy does not cut the walk of
            // another.
            let mut retries = Retries::for_the_read_back();
            let oldest = held
                .get()
                .saturating_sub(kr_worker::journal::MAX_HELD_REVOCATIONS as u64 - 1)
                .max(1);
            // A worker whose session has closed is bound no more, and holds nothing to give.
            let Ok(Some(binding)) = self.binding_or_bind(*session_id).await else {
                continue;
            };
            for revision in (oldest..=held.get()).rev().map(AuthorityRevision::new) {
                // The start's own announcement asked about some of these.
                if self.leases.reported(*session_id, revision) {
                    continue;
                }
                // One exchange for the first page; the pages that follow are the pass's.
                let mut budget = EvidenceBudget { pages: 1 };
                self.collect_fence_evidence(
                    *session_id,
                    binding,
                    revision,
                    &mut budget,
                    &mut retries,
                    true,
                )
                .await;
                // A worker that did not answer is not asked again for the older ones.
                if !self.leases.reported(*session_id, revision) {
                    break;
                }
            }
        }
    }

    /// Asks every worker that still owes names of a revocation for them, out of one bound on the
    /// asking again ([`evidence_pass`]).
    async fn collect_names_owed(&self) {
        let owing = self.leases.owing_names();
        if owing.is_empty() {
            return;
        }
        // Held as an announcement holds its round, so a worker that ends while this runs keeps
        // the names it had given until this is over. An announcement collects the same names and
        // is the one that matters when it runs, so this gives way to it.
        let Some(round) = self.leases.begin_round_if_idle() else {
            return;
        };
        let revision = {
            let registry = self.registry.lock().await;
            let Ok(revision) = registry.authority_revision() else {
                return;
            };
            round.at(revision);
            revision
        };
        let mut retries = Retries::for_the_pass();
        for session_id in owing {
            // A worker whose session has closed is bound no more, and owes nothing it can give.
            let Ok(Some(binding)) = self.binding_or_bind(session_id).await else {
                continue;
            };
            self.collect_owed_evidence_within(session_id, binding, revision, &mut retries)
                .await;
        }
    }

    /// The workers that have not acknowledged the revision in force, which the pass asks and the
    /// doctor counts: those the registry holds as not having acknowledged it and, while the fence is
    /// owed, those the barrier as it stands counts pending.
    ///
    /// The two differ after a restart: a worker's row can say that it acknowledged the revision
    /// before the daemon stopped, while the start's announcement to it was refused and this
    /// daemon's barrier counts it pending. The fence is settled only when the barrier holds, so a
    /// worker that only the barrier counts is asked all the same.
    pub(super) async fn pending_workers(&self) -> Result<Vec<SessionId>> {
        let (mut pending, owed_at) = {
            let registry = self.registry.lock().await;
            let revision = registry.authority_revision()?;
            let pending: Vec<SessionId> = registry
                .workers()?
                .into_iter()
                .filter(|worker| worker.acknowledged_revision.get() < revision.get())
                .map(|worker| worker.session_id)
                .collect();
            let owed_at = registry.fence_owed()?.map(|_| revision);
            (pending, owed_at)
        };
        if let Some(revision) = owed_at
            && let Ok(barrier) = self.barrier_as_it_stands(revision).await
        {
            for session_id in barrier.pending() {
                if !pending.contains(&session_id) {
                    pending.push(session_id);
                }
            }
        }
        Ok(pending)
    }

    /// Asks the workers that have not acknowledged the revision in force, those whose pace
    /// ([`AskPace`]) allows it at `tick`, and settles the fence this host owes once none is pending.
    ///
    /// Nothing else asks a worker again on a timer: an announcement asks each worker once, so a
    /// worker that was refused for the moment, or could not be reached, stays pending until a start,
    /// a restriction, a repeated change or a request that needs its lease asks it. The asks of one
    /// pass are made together and the whole of each is bounded by [`PASS_ASK_BOUND`], so no
    /// worker is asked twice at once and one that does not answer does not hold the others for
    /// longer than that.
    /// A pending worker the directory does not list cannot be sent anything: what can be
    /// established for it is whether it has ended, which is asked here.
    pub(super) async fn ask_pending_workers(
        self: &Arc<Self>,
        pace: &mut AskPace,
        tick: tokio::time::Instant,
    ) {
        if let Ok(pending) = self.pending_workers().await {
            pace.keep_only(&pending);
            let mut due = Vec::new();
            for session_id in pending {
                let listed = self.directory.lock().await.get(session_id).is_some();
                // A worker the directory does not list cannot be sent anything, and one whose
                // earlier presentation has not been decided must not be sent another: what can be
                // established for either is whether it has ended, and that is asked here. The
                // presentation is decided when the worker answers it, refuses it or ends, and the
                // ask follows at the pass after.
                if !listed || self.presentation_in_flight(session_id) {
                    if let Err(error) = self.reconcile(session_id).await {
                        eprintln!(
                            "kr-controller: whether the worker of session {session_id} has ended \
                             could not be established: {error}"
                        );
                    }
                } else if pace.due(session_id, tick) {
                    due.push(session_id);
                }
            }
            let asks = due.into_iter().map(|session_id| async move {
                let began = tokio::time::Instant::now();
                #[cfg(feature = "testing")]
                self.pending_asks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((session_id, began));
                // The whole ask is bounded, the exchange and what follows an answer: the names an
                // acknowledgement leaves are asked for by the pass beside it when it is cut, so
                // what is cut is never lost.
                let asked =
                    tokio::time::timeout(PASS_ASK_BOUND, self.ask_worker_revision(session_id))
                        .await
                        .map_or(Asked::Failed, |asked| asked.unwrap_or(Asked::Failed));
                (session_id, asked, began, tokio::time::Instant::now())
            });
            for (session_id, asked, began, ended) in all_at_once(asks).await {
                pace.record(session_id, asked, began, ended);
            }
        }
        self.settle_the_fence_owed().await;
    }

    /// Settles the fence this host owes when every worker has acknowledged the revision in force
    /// or is confirmed ended.
    ///
    /// The revision and the workers that have not acknowledged it are read in one section of the
    /// registry, and the fence is settled only once the barrier as it stands holds for that
    /// revision and the revision is still the one in force: a later revocation's fence is its own
    /// and is never settled by this one.
    async fn settle_the_fence_owed(&self) {
        let revision = {
            let registry = self.registry.lock().await;
            let (Ok(Some(_)), Ok(revision), Ok(workers)) = (
                registry.fence_owed(),
                registry.authority_revision(),
                registry.workers(),
            ) else {
                return;
            };
            if workers
                .iter()
                .any(|worker| worker.acknowledged_revision.get() < revision.get())
            {
                return;
            }
            revision
        };
        let Ok(barrier) = self.barrier_as_it_stands(revision).await else {
            return;
        };
        if !barrier.holds() {
            return;
        }
        let mut registry = self.registry.lock().await;
        if registry
            .authority_revision()
            .is_ok_and(|now| now == revision)
            && let Err(error) = registry.settle_fence(revision)
        {
            eprintln!("kr-controller: the fence this host owed could not be settled: {error}");
        }
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

    /// Holds a published debt, or lets every one go, for tests of what refuses while a barrier is
    /// owed. The debt is covered, so the debt pass leaves it to the test.
    #[cfg(any(test, feature = "testing"))]
    pub fn hold_fence(&self, held: bool) {
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
